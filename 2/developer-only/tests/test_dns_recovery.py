"""v5.11.1: DNS snapshot bug (single DNS server saved as characters) and the offline-lock recovery paths."""
import json
import os
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "parent-package-template" / "program-DO-NOT-OPEN"))
import agent  # noqa: E402
import dnsfilter  # noqa: E402

# Exactly what the test laptop had saved in state.json (single router DNS split into characters).
CORRUPT = [{"InterfaceIndex": 4, "Servers": []},
           {"InterfaceIndex": 15, "Servers": list("192.168.18.1")},
           {"InterfaceIndex": 1, "Servers": []}]


def test_clean_servers_shapes():
    assert agent.clean_servers("192.168.18.1") == ["192.168.18.1"]
    assert agent.clean_servers(["8.8.8.8", "8.8.4.4"]) == ["8.8.8.8", "8.8.4.4"]
    assert agent.clean_servers(list("192.168.18.1")) == ["192.168.18.1"]
    assert agent.clean_servers(["127.0.0.1", "::1"]) == []
    assert agent.clean_servers(None) == []


def test_snapshot_handles_single_server_string(monkeypatch):
    out = json.dumps([{"InterfaceIndex": 15, "Servers": "192.168.18.1"}, {"InterfaceIndex": 4, "Servers": None}])
    monkeypatch.setattr(agent, "run", lambda *a, **k: types.SimpleNamespace(stdout=out, stderr="", returncode=0))
    monkeypatch.setattr(agent, "save_state", lambda: None)
    agent.state.pop("dnsOriginal", None)
    assert agent.snapshot_dns()
    assert agent.state["dnsOriginal"][0]["Servers"] == ["192.168.18.1"]
    agent.state.pop("dnsOriginal", None)


def test_old_corrupt_snapshot_is_repaired_and_used(monkeypatch):
    monkeypatch.setitem(agent.state, "dnsOriginal", json.loads(json.dumps(CORRUPT)))
    monkeypatch.setattr(agent, "save_state", lambda: None)
    assert agent.snapshot_dns()
    assert agent.compute_upstreams(False) == ["192.168.18.1", "1.1.1.1", "8.8.8.8"]
    assert agent.compute_upstreams(True)[:2] == ["1.1.1.3", "1.0.0.3"]
    assert "8.8.8.8" in agent.compute_upstreams(True)


def test_restore_uses_real_address_not_characters(monkeypatch):
    monkeypatch.setitem(agent.state, "dnsOriginal", json.loads(json.dumps(CORRUPT)))
    calls = []
    monkeypatch.setattr(agent, "run", lambda cmd, timeout=20: calls.append(cmd) or types.SimpleNamespace(returncode=0, stderr="", stdout=""))
    agent.restore_original_dns()
    scripts = [c[-1] for c in calls if "Set-DnsClientServerAddress" in c[-1]]
    assert any("'192.168.18.1'" in x and "InterfaceIndex 15" in x for x in scripts)
    assert not any("'1','9'" in x for x in scripts)


def _nt(monkeypatch):
    monkeypatch.setattr(agent, "os", types.SimpleNamespace(name="nt", environ={}))
    monkeypatch.setattr(agent, "log", lambda m: None)
    monkeypatch.setattr(agent, "save_state", lambda: None)


def test_failopen_resets_dns_when_internet_up_but_names_fail(monkeypatch):
    _nt(monkeypatch)
    reset = []
    monkeypatch.setattr(agent, "reset_loopback_dns", lambda: reset.append(1) or 1)
    monkeypatch.setattr(agent, "internet_state", lambda: {"net": True, "dns": False})
    agent.state.update(dnsLocal=True, syncFails=2)
    agent.state.pop("dnsBypassUntil", None)
    agent.dns_failopen_check()
    assert reset and agent.state["dnsLocal"] is False and agent.state["dnsBypassUntil"] > __import__("time").time()


def test_failopen_leaves_offline_pc_alone_and_waits_for_three_failures(monkeypatch):
    _nt(monkeypatch)
    reset = []
    monkeypatch.setattr(agent, "reset_loopback_dns", lambda: reset.append(1) or 1)
    monkeypatch.setattr(agent, "internet_state", lambda: {"net": False, "dns": False})
    agent.state.update(dnsLocal=True, syncFails=0)
    for _ in range(5):
        agent.dns_failopen_check()
    assert not reset
    monkeypatch.setattr(agent, "internet_state", lambda: {"net": True, "dns": False})
    agent.state.update(dnsLocal=True, syncFails=0)
    agent.dns_failopen_check(); agent.dns_failopen_check()
    assert not reset  # only the 2nd failure so far


def test_routing_skipped_during_failopen_window(monkeypatch):
    _nt(monkeypatch)
    monkeypatch.setattr(agent, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not touch DNS")))
    agent.state["dnsBypassUntil"] = __import__("time").time() + 300
    agent.apply_dns_routing({}, True)
    agent.state.pop("dnsBypassUntil", None)


def test_filter_tries_last_good_upstream_first(monkeypatch):
    seen = []

    class FakeSock:
        def __init__(self, *a, **k): self.addr = None
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def settimeout(self, t): pass
        def sendto(self, data, addr):
            seen.append(addr[0]); self.addr = addr[0]; self.data = data
            if addr[0] == "10.9.9.9":
                raise OSError("dead")
        def recvfrom(self, n): return (self.data, (self.addr, 53))

    monkeypatch.setattr(dnsfilter.socket, "socket", FakeSock)
    f = dnsfilter.DnsFilter(lambda h: (False, ""), lambda: ["10.9.9.9", "1.1.1.1"])
    pkt = b"\x12\x34" + b"\x00" * 10
    assert f._forward(pkt, False) == pkt
    assert seen == ["10.9.9.9", "1.1.1.1"] and f._good == "1.1.1.1"
    seen.clear()
    assert f._forward(pkt, False) == pkt
    assert seen == ["1.1.1.1"]  # dead server no longer slows every lookup


def test_save_state_retries_when_state_file_is_briefly_locked(monkeypatch, tmp_path):
    monkeypatch.setattr(agent, "STATE", tmp_path / "state.json")
    monkeypatch.setattr(agent.time, "sleep", lambda s: None)
    real, calls = Path.replace, [0]

    def flaky(self, target):
        calls[0] += 1
        if calls[0] < 3:
            raise PermissionError("[WinError 5] Access is denied")
        return real(self, target)

    monkeypatch.setattr(Path, "replace", flaky)
    agent.save_state()
    assert calls[0] == 3 and (tmp_path / "state.json").exists()

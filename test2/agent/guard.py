"""Enforcement engine: screen-time accounting, device lock, app/game/browser blocking and timeline events.

`tick()` runs every few seconds. It never talks to Firebase; it only reads the effective policy and the
operating system (through the injected `sysi`) and produces the status fields the dashboard displays.
"""
from __future__ import annotations
import collections, datetime as dt, os, time
import policy as P
from macsys import top_app, is_user_app_main

MAX_TIMELINE, MAX_EVENTS, MAX_SITES, MAX_HIST_DAYS = 400, 40, 300, 14


class Guard:
    def __init__(self, state: dict, sysi, prompter=None, save=lambda: None, log=lambda *a, **k: None, clock=time.time):
        self.state, self.sys, self.prompter, self._save, self.log, self.clock = state, sysi, prompter, save, log, clock
        self.policy: dict = {}
        self.dns_events = collections.deque(maxlen=500)     # filled by the DNS thread, drained in tick()
        self.session = {"present": False, "user": "", "uid": -1, "locked": False}
        self.decision = P.Decision(False, "none", "")
        self.lock_info = None
        self.msg = ""
        self.locked_since = None
        self.last_lock_try = 0.0
        self.last_tick = None
        self.prev_apps = None
        self.prev_user = None
        self.prev_screen_locked = None
        self.warned: set = set()
        self.recent: dict = {}          # de-duplication of repeated events
        self.last_save = 0.0
        self.dirty = False
        for k, v in (("usedSec", 0), ("hist", {}), ("appsSec", {}), ("events", []), ("timeline", []),
                     ("sites", []), ("siteHits", {}), ("sitePrompted", {}), ("blocked", [])):
            self.state.setdefault(k, v)

    # ------------------------------------------------------------ helpers
    def set_policy(self, policy: dict):
        self.policy = policy or {}

    def on_dns_block(self, rule, host, ts):             # called from the DNS thread
        self.dns_events.append((rule, host, ts))

    def event(self, message, kind, dedupe=0, **extra):
        now = int(self.clock())
        key = (message, kind)
        if dedupe and now - self.recent.get(key, 0) < dedupe:
            return
        self.recent[key] = now
        item = {"at": now, "message": message, "kind": kind, **extra}
        self.state["timeline"] = ([item] + self.state["timeline"])[:MAX_TIMELINE]
        self.state["events"] = ([item] + self.state["events"])[:MAX_EVENTS]
        self.dirty = True

    def event_at(self, at, message, kind, **extra):
        """Record an event that happened at a known time (used for browser history), keeping newest first."""
        item = {"at": int(at), "message": message, "kind": kind, **extra}
        self.state["timeline"] = sorted([item] + self.state["timeline"], key=lambda x: x["at"], reverse=True)[:MAX_TIMELINE]
        self.state["events"] = self.state["timeline"][:MAX_EVENTS]
        self.dirty = True

    def _site_row(self, host):
        for row in self.state["sites"]:
            if row.get("d") == host:
                return row
        row = {"d": host, "n": 0, "l": 0, "b": 0, "bl": 0, "g": False, "c": "", "k": 0}
        self.state["sites"].append(row)
        return row

    def _roll_day(self, now_dt):
        today = str(now_dt.date())
        if self.state.get("day") == today:
            return
        old = self.state.get("day")
        if old:
            self.state["hist"][old] = int(round(self.state["usedSec"] / 60))
        for k in sorted(self.state["hist"])[:-MAX_HIST_DAYS]:
            self.state["hist"].pop(k, None)
        self.state.update(day=today, usedSec=0, appsSec={})
        self.warned.clear()
        self.dirty = True

    # ------------------------------------------------------------ one pass
    def tick(self, now=None):
        now = now if now is not None else self.clock()
        now_dt = dt.datetime.fromtimestamp(now)
        self._roll_day(now_dt)
        sess = self.session = self.sys.session()
        self._session_events(sess)
        if self.policy.get("protectionOff"):
            self.decision, self.lock_info, self.msg, self.locked_since = P.Decision(False, "none", ""), None, "", None
            self.last_tick = now
            self._maybe_save(now)
            return
        step = 0.0 if self.last_tick is None else min(max(now - self.last_tick, 0.0), 15.0)   # sleep gaps are not "use"
        self.last_tick = now
        mine = []
        if sess["present"]:
            mine = [p for p in self.sys.processes() if p["uid"] == sess["uid"]]
        self._drain_dns()
        self._apps(mine, sess, now)

        day = self.state["day"]
        before = P.lock_decision(self.policy, now, self.state["usedSec"], day, now_dt)
        counting = sess["present"] and not sess["locked"] and not before.locked
        if counting and step:
            self.state["usedSec"] += step
            front = self.sys.frontmost_app(sess["uid"])
            if front:
                self.state["appsSec"][front] = self.state["appsSec"].get(front, 0) + step
        self.state["hist"][day] = int(self.state["usedSec"] // 60)
        self.decision = P.lock_decision(self.policy, now, self.state["usedSec"], day, now_dt)
        self._enforce_lock(sess, now)
        if counting:
            self._low_time_warning(now_dt)
        self._maybe_save(now)

    # ------------------------------------------------------------ parts
    def _session_events(self, sess):
        user = sess["user"] if sess["present"] else ""
        if self.prev_user is not None and user != self.prev_user:
            if user:
                self.event(f"User signed in: {user}", "user")
            if self.prev_user:
                self.event(f"User signed out: {self.prev_user}", "user")
        self.prev_user = user
        if sess["present"]:
            if self.prev_screen_locked is not None and sess["locked"] != self.prev_screen_locked:
                self.event("Screen locked" if sess["locked"] else "Screen unlocked", "screen", dedupe=5)
            self.prev_screen_locked = sess["locked"]
        else:
            self.prev_screen_locked = None

    def _apps(self, procs, sess, now):
        running, kill = set(), {}
        for p in procs:
            name, _ = top_app(p["path"])
            base = os.path.basename(p["path"])
            cands = {name or "", base}
            if base == "java" and "minecraft" in p.get("args", "").lower():
                cands.add("minecraft")
            blocked, kind, token = P.app_verdict(cands, self.policy)
            if blocked:
                kill.setdefault((name or base, kind), []).append(p["pid"])
            elif name and is_user_app_main(p["path"]):
                running.add(name)
        for (name, kind), pids in kill.items():
            self.sys.kill_pids(pids)
            what = {"app": "application", "game": "game", "browser": "browser"}[kind]
            self.event(f"Blocked application: {name}", "block", dedupe=20)
            self.state["blocked"] = ([name] + [x for x in self.state["blocked"] if x != name])[:20]
            self.dirty = True
            if self.prompter:
                self.prompter.prompt("app", name.lower(), f"“{name}” is blocked by your parent. Would you like to ask for permission to use this {what}?",
                                     f"Blocked {what}: {name}")
        if self.prev_apps is not None:
            for name in sorted(running - self.prev_apps):
                self.event(f"Application started: {name}", "app", dedupe=5)
        self.prev_apps = running

    def _drain_dns(self):
        while self.dns_events:
            rule, host, ts = self.dns_events.popleft()
            ts = int(ts)
            hit = self.state["siteHits"].setdefault(rule, {"n": 0, "last": 0})
            if ts - hit["last"] >= 10:          # a browser retries a lookup several times; count it once
                hit["n"] += 1
                row = self._site_row(rule)
                row["b"] += 1
                row["bl"] = ts
                self.event(f"Blocked website: {rule}", "block", dedupe=10, d=rule)
                # Persist the prompt cooldown with device state so an agent restart
                # cannot repeatedly show the same parent-blocking popup. A site may
                # prompt again after ten minutes, allowing a genuinely new request.
                if self.prompter:
                    prompted = self.state.setdefault("sitePrompted", {})
                    last_prompt = float(prompted.get(rule, 0) or 0)
                    if ts - last_prompt >= 600:
                        shown = self.prompter.prompt(
                            "site", rule,
                            f"“{rule}” is blocked by your parent. Would you like to ask for permission to open it?",
                            f"Blocked website: {rule}")
                        if shown:
                            prompted[rule] = ts
                            if len(prompted) > 200:
                                oldest = min(prompted, key=prompted.get)
                                prompted.pop(oldest, None)
                            self.dirty = True
            hit["last"] = max(hit["last"], ts)
            if len(self.state["siteHits"]) > 200:
                oldest = min(self.state["siteHits"], key=lambda k: self.state["siteHits"][k]["last"])
                self.state["siteHits"].pop(oldest, None)
            self.dirty = True

    def _enforce_lock(self, sess, now):
        dec = self.decision
        if not dec.locked:
            if self.locked_since is not None:
                self.event("Device unlocked", "screen")
            self.lock_info, self.msg, self.locked_since = None, "", None
            return
        self.msg = dec.reason
        if self.locked_since is None:
            self.locked_since = int(now)
            self.event(f"Device locked: {dec.reason}", "screen")
        at = (self.lock_info or {}).get("at", int(now))
        if not sess["present"]:
            self.lock_info = {"ok": True, "note": "Nobody is signed in; the Mac is at the login window.", "at": at, "checked": int(now)}
        elif sess["locked"]:
            self.lock_info = {"ok": True, "note": f"Screen is locked. {dec.reason}", "at": at, "checked": int(now)}
        elif now - self.last_lock_try >= 4:
            ok, how = self.sys.lock_screen(sess["uid"])
            self.last_lock_try = now
            self.lock_info = {"ok": ok, "at": at, "checked": int(now),
                              "note": f"{dec.reason} Locking the screen ({how})." if ok else f"{dec.reason} Could not lock: {how}"}
            if not ok:
                self.log(f"lock failed: {how}")

    def _low_time_warning(self, now_dt):
        rem = P.remaining_seconds(self.policy, self.state["usedSec"], now_dt.date(), self.state["day"])
        if rem is not None and 0 < rem <= 300 and "5min" not in self.warned and self.prompter:
            self.warned.add("5min")
            self.prompter.prompt("time", "screen time", "Only 5 minutes of screen time are left today. Would you like to ask your parent for more?",
                                 "5 minutes of screen time left", minutes=30)

    def _maybe_save(self, now):
        if self.dirty and now - self.last_save >= 10:
            self.dirty, self.last_save = False, now
            self._save()

    # ------------------------------------------------------------ output
    def status_fields(self) -> dict:
        s, sess = self.state, self.session
        used = int(s["usedSec"])
        return {
            "day": s.get("day", ""), "used": used // 60, "usedSec": used,
            "hist": dict(s["hist"]), "apps": {k: round(v / 60, 1) for k, v in s["appsSec"].items() if v >= 6},
            "events": s["events"][:MAX_EVENTS], "timeline": s["timeline"][:MAX_TIMELINE], "sites": s["sites"][:MAX_SITES],
            "siteHits": {k: dict(v) for k, v in s["siteHits"].items()}, "blockedProcesses": list(s["blocked"]),
            "lock": self.lock_info, "msg": self.msg,
            "active": bool(sess["present"] and not sess["locked"]),
            "childState": "no-user-session" if not sess["present"] else ("locked" if sess["locked"] else "active"),
        }

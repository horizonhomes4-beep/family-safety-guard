"""Child requests ("more time", "allow this site/app"): pop-up on the Mac -> Firestore request -> e-mail.

Field names and types follow firestore.rules exactly: the agent may only create a request with the keys
type, target, minutes, note, reason, winUser, createdAt, status, emailed and later set emailed/emailError/emailedAt.
"""
from __future__ import annotations
import json, threading, time
import requests as _requests

EMAILJS = "https://api.emailjs.com/api/v1.0/email/send"
CREATE_KEYS = ("type", "target", "minutes", "note", "reason", "winUser", "createdAt", "status", "emailed")


def enc(v):
    if isinstance(v, bool):
        return {"booleanValue": v}
    if isinstance(v, int):
        return {"integerValue": str(v)}
    if isinstance(v, float):
        return {"doubleValue": v}
    if v is None:
        return {"nullValue": None}
    return {"stringValue": str(v)}


def dec(f):
    for k in ("stringValue", "booleanValue", "doubleValue"):
        if k in f:
            return f[k]
    if "integerValue" in f:
        return int(f["integerValue"])
    return None


def build_request(kind, target, minutes, note, reason, user, now=None):
    doc = {"type": kind, "target": str(target or "")[:120], "minutes": int(minutes or 0), "note": str(note or "")[:300],
           "reason": str(reason or "")[:200], "winUser": str(user or ""), "createdAt": int(now or time.time()),
           "status": "pending", "emailed": False}
    assert set(doc) == set(CREATE_KEYS)
    return doc


def email_text(child, req):
    what = {"time": f"{req.get('minutes') or 30} more minutes of screen time",
            "site": f"access to the website {req.get('target')}",
            "app": f"permission to use {req.get('target')}",
            "message": "to send a message"}.get(req.get("type"), "something")
    subject = f"{child or 'Your child'} is asking for {what}" if req.get("type") != "message" else f"Message from {child or 'your child'}"
    body = f"{child or 'Your child'} asked for {what} on the Mac."
    if req.get("reason"):
        body += f"\nReason shown on the Mac: {req['reason']}"
    if req.get("note"):
        body += f"\nTheir note: \"{req['note']}\""
    body += "\n\nOpen the ParentGuard dashboard, Requests tab, to approve or decline."
    return subject, body


def send_email(notify: dict, child: str, req: dict, post=None):
    """Send through EmailJS to every recipient. Returns (ok, error_text)."""
    post = post or _requests.post
    if not notify or notify.get("enabled") is False:
        return False, "e-mail notifications are switched off"
    need = [notify.get(k) for k in ("serviceId", "templateId", "publicKey")]
    recipients = [r for r in notify.get("recipients", []) if r]
    if not all(need) or not recipients:
        return False, "e-mail is not configured (Admin > Request e-mail notifications)"
    subject, body = email_text(child, req)
    errors = []
    for to in recipients:
        payload = {"service_id": notify["serviceId"], "template_id": notify["templateId"], "user_id": notify["publicKey"],
                   "template_params": {"to_email": to, "subject": subject, "message": body, "child_name": child or "",
                                       "from_name": "@M Family Safety Guard"}}
        if notify.get("privateKey"):
            payload["accessToken"] = notify["privateKey"]
        try:
            r = post(EMAILJS, json=payload, timeout=20)
            if r.status_code != 200:
                errors.append(f"{to}: {r.text[:100]}")
        except Exception as exc:
            errors.append(f"{to}: {type(exc).__name__}")
    return (not errors), "; ".join(errors)[:200]


class Requests:
    """Talks to devices/{id}/requests with the agent's authenticated `call(method, url, **kw)`."""

    def __init__(self, call, db, device_id):
        self.call, self.base = call, f"{db}/devices/{device_id}"

    def create(self, doc):
        r = self.call("POST", f"{self.base}/requests", json={"fields": {k: enc(v) for k, v in doc.items()}})
        r.raise_for_status()
        return r.json()["name"].rsplit("/", 1)[-1]

    def get(self, rid):
        r = self.call("GET", f"{self.base}/requests/{rid}")
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return {k: dec(v) for k, v in r.json().get("fields", {}).items()}

    def mark_email(self, rid, ok, error=""):
        fields = {"emailed": ok} if ok else {"emailError": error or "failed"}
        if ok:
            fields["emailedAt"] = int(time.time())
        mask = "&".join(f"updateMask.fieldPaths={k}" for k in fields)
        r = self.call("PATCH", f"{self.base}/requests/{rid}?{mask}", json={"fields": {k: enc(v) for k, v in fields.items()}})
        r.raise_for_status()

    def notify_config(self):
        r = self.call("GET", f"{self.base}/private/notify")
        if r.status_code != 200:
            return {}
        try:
            return json.loads(r.json().get("fields", {}).get("json", {}).get("stringValue", "{}"))
        except ValueError:
            return {}


class Prompter:
    """Shows the child-side pop-ups without blocking the enforcement loop, and turns answers into requests."""
    ASK = "Ask my parent"

    def __init__(self, reqs: Requests, show, child_name, get_session, get_notify, log):
        self.reqs, self.show, self.child_name = reqs, show, child_name
        self.get_session, self.get_notify, self.log = get_session, get_notify, log
        self.last: dict = {}        # (kind,target) -> last prompt time
        self.last_any = 0.0
        self.busy = threading.Lock()
        self.pending: dict = {}     # request id -> description

    def allowed(self, key, per_key=600, overall=45):
        now = time.time()
        if now - self.last.get(key, 0) < per_key or now - self.last_any < overall:
            return False
        self.last[key], self.last_any = now, now
        return True

    def prompt(self, kind, target, text, reason, minutes=30):
        """kind: 'time' | 'site' | 'app'. Fire-and-forget."""
        sess = self.get_session()
        if not sess.get("present") or sess.get("locked") or not self.allowed((kind, target)):
            return False
        threading.Thread(target=self._run, args=(kind, target, text, reason, minutes, sess), daemon=True).start()
        return True

    def _run(self, kind, target, text, reason, minutes, sess):
        if not self.busy.acquire(blocking=False):
            return
        try:
            res = self.show(sess["uid"], sess["user"], text, ["Not now", self.ASK], self.ASK, 60)
            if not res or res.get("gave_up") or res.get("button") != self.ASK:
                return
            note = self.show(sess["uid"], sess["user"], "Add a short message for your parent (optional):",
                             ["Send"], "Send", 90, answer=True, icon="note")
            doc = build_request(kind, target, minutes, (note or {}).get("text", ""), reason, sess["user"])
            rid = self.reqs.create(doc)
            self.pending[rid] = f"{kind}:{target}"
            self.log(f"Request sent to parent: {kind} {target}", force=True)
            ok, err = send_email(self.get_notify(), self.child_name(), doc)
            self.reqs.mark_email(rid, ok, err)
            self.show(sess["uid"], sess["user"], "Your request was sent. You will see the answer here.", ["OK"], "OK", 15, icon="note")
        except Exception as exc:
            self.log(f"request failed: {type(exc).__name__}: {exc}", force=True)
        finally:
            self.busy.release()

    def poll(self):
        """Tell the child what the parent decided."""
        for rid in list(self.pending):
            try:
                req = self.reqs.get(rid)
            except Exception:
                continue
            if req is None:
                self.pending.pop(rid, None)
            elif req.get("status") != "pending":
                self.pending.pop(rid, None)
                sess = self.get_session()
                if sess.get("present") and not sess.get("locked"):
                    word = "approved" if req["status"] == "approved" else "declined"
                    threading.Thread(target=self.show, daemon=True, args=(
                        sess["uid"], sess["user"], f"Your parent {word} your request ({self.pending_text(req)}).",
                        ["OK"], "OK", 30), kwargs={"icon": "note"}).start()

    @staticmethod
    def pending_text(req):
        t = req.get("type")
        return f"{req.get('minutes') or 30} more minutes" if t == "time" else str(req.get("target") or t)

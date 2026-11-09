"""Interactive desktop notice for @M Family Safety Guard.

Runs in each signed-in Windows user's session. It shows the SYSTEM agent's notices and lets
the child send a request (more time, please allow this site/app, or a message) to the parent
and administrator. Requests are written to a shared drop folder; the agent validates them,
stores them in Firestore and e-mails the people listed on the Admin page.
"""
from __future__ import annotations
import getpass, json, os, time, tkinter as tk, uuid, webbrowser
from tkinter import ttk
from pathlib import Path

ROOT = Path(__file__).resolve().parent
NOTICE = ROOT / "notice.json"
SHARED = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "MFamilySafetyGuard" / "notices" / "notice.json"
APPDATA = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "MFamilySafetyGuard"
SEEN = APPDATA / "notice-seen.txt"
REQ_DIR = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "MFamilySafetyGuard" / "requests"
EMAIL = "mathcloudtutorial@gmail.com"
WEBSITE = "https://mathcloudtutorial.com"
WHATSAPP = "https://wa.me/2349129225442"

# ---- design tokens (visual only) -------------------------------------------------------------
BG, PANEL, INK, MUTED = "#050d1c", "#0e1c33", "#f4f8ff", "#9fb2cf"
FONT = "Segoe UI"
EMOJI = "Segoe UI Emoji"
LINE, CARD2 = "#1d3252", "#0a1529"
RED, AMBER, GREEN, BLUE = "#ff5d6c", "#ffc15e", "#14a37f", "#2b6cb0"
GREEN_HI, BLUE_HI = "#1cc199", "#3a82d0"
ACCENT, ACCENT2 = "#38bdf8", "#6366f1"
SOFT = "#dbe6f6"
ICONS = {"site": "🌐", "app": "🧩"}


def _rgb(c: str) -> tuple[int, int, int]:
    c = c.lstrip("#")
    return int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)


def mix(c1: str, c2: str, t: float) -> str:
    """Blend two hex colours (t=0 -> c1, t=1 -> c2)."""
    a, b = _rgb(c1), _rgb(c2)
    return "#%02x%02x%02x" % tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def log(msg: str) -> None:
    try:
        APPDATA.mkdir(parents=True, exist_ok=True)
        with (APPDATA / "notice.log").open("a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
    except Exception:
        pass


def fallback_box(data: dict) -> None:
    """If the full-screen window cannot open (for example tkinter is missing), still show a Windows message box."""
    try:
        import ctypes
        text = str(data.get("reason", "This action is blocked by family safety settings."))
        ctypes.windll.user32.MessageBoxW(0, text, "@M Family Safety Guard", 0x40 | 0x1000 | 0x10000)
    except Exception:
        pass


def read_notice() -> dict | None:
    """Newest notice from the shared folder or the install folder."""
    best = None
    for path in (SHARED, NOTICE):
        try:
            d = json.loads(path.read_text(encoding="utf-8"))
            if best is None or int(d.get("at", 0)) > int(best.get("at", 0)):
                best = d
        except Exception:
            continue
    return best


def seen_id() -> int:
    try:
        return int(SEEN.read_text(encoding="utf-8").strip())
    except Exception:
        return 0


def remember(value: int) -> None:
    try:
        APPDATA.mkdir(parents=True, exist_ok=True)
        SEEN.write_text(str(value), encoding="utf-8")
    except Exception:
        pass


def send_request(rtype: str, target: str, minutes: int, note: str, reason: str) -> bool:
    """Drop a request file for the agent. Written atomically so the agent never reads half a file."""
    try:
        REQ_DIR.mkdir(parents=True, exist_ok=True)
        data = {"type": rtype, "target": target, "minutes": minutes, "note": note[:300],
                "reason": reason[:200], "user": getpass.getuser(), "at": int(time.time())}
        tmp = REQ_DIR / f"{uuid.uuid4().hex}.tmp"
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        tmp.replace(tmp.with_suffix(".json"))
        return True
    except Exception:
        return False


# ---- reusable visual widgets -------------------------------------------------------------------
def make_button(parent, text, command, bg, hover, size=12, padx=18, pady=9, fg="white", border=None):
    """Flat button with a hover colour and an optional 1px outline."""
    b = tk.Button(parent, text=text, command=command, font=(FONT, size, "bold"), bg=bg, fg=fg,
                  activebackground=hover, activeforeground=fg, relief="flat", bd=0, padx=padx, pady=pady,
                  cursor="hand2", disabledforeground="#6d86a6",
                  highlightthickness=1 if border else 0, highlightbackground=border or bg, highlightcolor=border or bg)
    b.bind("<Enter>", lambda _e: b.config(bg=hover) if str(b["state"]) != "disabled" else None)
    b.bind("<Leave>", lambda _e: b.config(bg=bg) if str(b["state"]) != "disabled" else None)
    return b


def gradient_strip(parent, c1: str, c2: str, height: int = 4) -> tk.Canvas:
    """Thin horizontal gradient line that redraws itself to the window width."""
    cv = tk.Canvas(parent, height=height, bg=c1, highlightthickness=0, bd=0)

    def draw(e):
        cv.delete("all")
        w = max(e.width, 2)
        steps = min(w, 160)
        for i in range(steps):
            x0, x1 = int(i * w / steps), int((i + 1) * w / steps) + 1
            cv.create_rectangle(x0, 0, x1, height, fill=mix(c1, c2, i / max(steps - 1, 1)), width=0)
    cv.bind("<Configure>", draw)
    return cv


def icon_badge(parent, icon: str, colour: str, size: int = 120, bg: str = BG) -> tk.Canvas:
    """Round icon with soft halo rings."""
    cv = tk.Canvas(parent, width=size, height=size, bg=bg, highlightthickness=0)
    c = size / 2
    cv.create_oval(2, 2, size - 2, size - 2, fill=mix(bg, colour, 0.10), outline="")
    cv.create_oval(14, 14, size - 14, size - 14, fill=mix(bg, colour, 0.20), outline="")
    cv.create_oval(26, 26, size - 26, size - 26, fill=mix(bg, colour, 0.32), outline=colour, width=2)
    cv.create_text(c, c + 1, text=icon, font=(EMOJI, int(size * 0.30)), fill=INK)
    return cv


class ScrollPage:
    """A centred page that scrolls vertically (mouse wheel, scrollbar, keyboard) so nothing is ever cut off."""
    MAXW = 980

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.wrapped: list[tuple[tk.Label, int, float]] = []
        holder = tk.Frame(root, bg=BG)
        holder.pack(fill="both", expand=True)
        style = ttk.Style(root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Guard.Vertical.TScrollbar", background="#27466f", troughcolor=BG, bordercolor=BG,
                        arrowcolor=INK, lightcolor="#27466f", darkcolor="#27466f", gripcount=0, width=12)
        style.map("Guard.Vertical.TScrollbar", background=[("active", "#3a68a0")])
        self.canvas = tk.Canvas(holder, bg=BG, highlightthickness=0, bd=0, yscrollincrement=24)
        self.bar = ttk.Scrollbar(holder, orient="vertical", command=self.canvas.yview, style="Guard.Vertical.TScrollbar")
        self.canvas.configure(yscrollcommand=self.bar.set)
        self.bar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.page = tk.Frame(self.canvas, bg=BG)
        self.win = self.canvas.create_window((0, 0), window=self.page, anchor="nw")
        self.page.grid_columnconfigure(0, weight=1)
        self.page.grid_columnconfigure(2, weight=1)
        self.col = tk.Frame(self.page, bg=BG)
        self.col.grid(row=0, column=1, sticky="n", pady=(14, 44))
        self.canvas.bind("<Configure>", self._on_canvas)
        self.page.bind("<Configure>", lambda _e: self._sync())
        root.bind_all("<MouseWheel>", self._wheel)
        root.bind_all("<Button-4>", self._wheel)
        root.bind_all("<Button-5>", self._wheel)
        root.bind("<Up>", lambda _e: self._scroll(-2))
        root.bind("<Down>", lambda _e: self._scroll(2))
        root.bind("<Prior>", lambda _e: self._scroll(-1, "pages"))
        root.bind("<Next>", lambda _e: self._scroll(1, "pages"))
        root.bind("<Home>", lambda _e: self._jump(0.0))
        root.bind("<End>", lambda _e: self._jump(1.0))

    def label(self, parent, text: str, margin: int = 80, frac: float = 1.0, **kw) -> tk.Label:
        """Label whose wrap width follows the page width. margin = horizontal space used by the parents,
        frac = share of the page width the label's container occupies (e.g. 0.5 for a half-width tile)."""
        lab = tk.Label(parent, text=text, **kw)
        self.wrapped.append((lab, margin, frac))
        return lab

    def card(self, accent: str | None = None, bg: str = PANEL, pady=(0, 16)) -> tk.Frame:
        outer = tk.Frame(self.col, bg=mix(LINE, accent, 0.35) if accent else LINE)
        outer.pack(fill="x", pady=pady)
        if accent:
            tk.Frame(outer, bg=accent, width=6).pack(side="left", fill="y")
        inner = tk.Frame(outer, bg=bg, padx=28, pady=20)
        inner.pack(side="left", fill="both", expand=True, padx=(0 if accent else 1, 1), pady=1)
        return inner

    def _needs_scroll(self) -> bool:
        return self.page.winfo_reqheight() > self.canvas.winfo_height()

    def _sync(self) -> None:
        self.canvas.configure(scrollregion=(0, 0, self.canvas.winfo_width(), max(self.page.winfo_reqheight(), self.canvas.winfo_height())))
        if not self._needs_scroll():
            self.canvas.yview_moveto(0)

    def _on_canvas(self, e) -> None:
        self.canvas.itemconfigure(self.win, width=e.width)
        cw = max(340, min(self.MAXW, e.width - 56))
        self.page.grid_columnconfigure(1, minsize=cw)
        for lab, margin, frac in self.wrapped:
            try:
                lab.config(wraplength=max(140, int(cw * frac) - margin))
            except tk.TclError:
                pass
        self.root.after(30, self._sync)

    def _scroll(self, amount: int, what: str = "units") -> None:
        if self._needs_scroll():
            self.canvas.yview_scroll(amount, what)

    def _jump(self, frac: float) -> None:
        try:
            typing = isinstance(self.root.focus_get(), tk.Entry)
        except Exception:
            typing = False
        if self._needs_scroll() and not typing:
            self.canvas.yview_moveto(frac)

    def _wheel(self, e) -> None:
        if not self._needs_scroll():
            return
        num = getattr(e, "num", 0)
        if num == 4:
            step = -3
        elif num == 5:
            step = 3
        else:
            delta = getattr(e, "delta", 0)
            step = 0 if not delta else (-3 if delta > 0 else 3)
        if step:
            self.canvas.yview_scroll(step, "units")


def show_answer(data: dict) -> None:
    """Small window telling the child how the parent answered. Stays 2 minutes unless closed."""
    root = tk.Tk()
    root.title("@M Family Safety Guard")
    root.configure(bg=BG)
    root.attributes("-topmost", True)
    w, h = 600, 400
    root.geometry(f"{w}x{h}+{(root.winfo_screenwidth() - w) // 2}+{(root.winfo_screenheight() - h) // 3}")
    text = str(data.get("reason", ""))
    ok = "approved" in text
    accent = GREEN_HI if ok else ACCENT
    gradient_strip(root, accent, ACCENT2 if not ok else "#5ee6b8", 6).pack(fill="x")

    head = tk.Frame(root, bg=CARD2, highlightbackground=LINE, highlightthickness=1)
    head.pack(fill="x")
    tk.Label(head, text="🛡️", font=(EMOJI, 14), bg=CARD2, fg=INK).pack(side="left", padx=(16, 6), pady=8)
    tk.Label(head, text="@M Family Safety Guard", font=(FONT, 11, "bold"), bg=CARD2, fg=SOFT).pack(side="left")

    body = tk.Frame(root, bg=BG)
    body.pack(fill="both", expand=True, padx=28, pady=(14, 18))
    icon_badge(body, "✅" if ok else "ℹ️", accent, size=88).pack()
    tk.Label(body, text=("REQUEST APPROVED" if ok else "MESSAGE FROM YOUR PARENT"), font=(FONT, 10, "bold"),
             bg=mix(BG, accent, 0.18), fg=accent, padx=12, pady=3).pack(pady=(10, 0))
    tk.Label(body, text="Your parent has answered" if ok else "Please read this message", font=(FONT, 11), bg=BG, fg=MUTED).pack(pady=(8, 0))
    tk.Label(body, text=text, font=(FONT, 15, "bold"), bg=BG, fg=INK, wraplength=w - 90, justify="center").pack(pady=(6, 14))
    make_button(body, "OK", root.destroy, GREEN, GREEN_HI, size=12, padx=44, pady=9).pack()
    root.after(120000, root.destroy)
    root.mainloop()


def show_notice(data: dict) -> None:
    root = tk.Tk()
    root.title("@M Family Safety Guard blockage")
    root.configure(bg=BG)
    root.attributes("-fullscreen", True)
    root.attributes("-topmost", True)
    root.protocol("WM_DELETE_WINDOW", root.destroy)
    root.bind("<Escape>", lambda _e: root.destroy())

    reason = str(data.get("reason") or "This activity is not permitted by the current family safety settings.")
    ttype, target = str(data.get("ttype", "message")), str(data.get("target", ""))
    lock_at = int(data.get("lockAt", 0) or 0)

    # ---- fixed top bar: brand on the left, date/time and Close on the right ------------------
    gradient_strip(root, ACCENT, ACCENT2, 4).pack(fill="x", side="top")
    topbar = tk.Frame(root, bg=CARD2, highlightbackground=LINE, highlightthickness=1)
    topbar.pack(fill="x", side="top")
    logo = tk.Frame(topbar, bg=mix(CARD2, ACCENT, 0.25), padx=8, pady=4)
    logo.pack(side="left", padx=(20, 12), pady=10)
    tk.Label(logo, text="🛡️", font=(EMOJI, 16), bg=logo["bg"], fg=INK).pack()
    names = tk.Frame(topbar, bg=CARD2)
    names.pack(side="left")
    tk.Label(names, text="@M Family Safety Guard", font=(FONT, 14, "bold"), bg=CARD2, fg=INK).pack(anchor="w")
    tk.Label(names, text="Parental protection • Mathcloud Tech Services", font=(FONT, 9), bg=CARD2, fg=MUTED).pack(anchor="w")
    make_button(topbar, "✕  Close", root.destroy, "#b3263e", "#d03a54", size=11, padx=18, pady=7).pack(side="right", padx=20, pady=12)
    clock = tk.Label(topbar, text="", font=(FONT, 11), bg=CARD2, fg=MUTED)
    clock.pack(side="right", padx=(0, 8))

    def tick_clock() -> None:
        clock.config(text=time.strftime("%A, %d %B %Y   •   %H:%M"))
        root.after(15000, tick_clock)
    tick_clock()

    page = ScrollPage(root)
    lab = page.label

    # ---- hero ------------------------------------------------------------------------------------
    hero = tk.Frame(page.col, bg=BG)
    hero.pack(fill="x", pady=(10, 20))
    icon_badge(hero, ICONS.get(ttype, "⛔"), RED, size=124).pack()
    lab(hero, "This action has been blocked", margin=20, font=(FONT, 30, "bold"), fg=INK, bg=BG, justify="center").pack(pady=(12, 8))
    tk.Label(hero, text="  BLOCKED BY FAMILY SAFETY SETTINGS  ", font=(FONT, 10, "bold"), fg=AMBER,
             bg=mix(BG, AMBER, 0.16), pady=5).pack()

    # ---- why it was blocked ---------------------------------------------------------------------
    rc = page.card(accent=RED)
    tk.Label(rc, text="WHY THIS WAS BLOCKED", font=(FONT, 9, "bold"), fg=RED, bg=PANEL).pack(anchor="w")
    lab(rc, reason, margin=120, font=(FONT, 18), fg=SOFT, bg=PANEL, justify="left", anchor="w").pack(fill="x", pady=(8, 0))

    # ---- countdown (only when the PC is about to lock) ---------------------------------------
    countdown = lab(page.col, "", margin=20, font=(FONT, 15, "bold"), fg="#ffb3b3", bg=mix(BG, RED, 0.18), pady=12, padx=14, justify="center")
    if lock_at:
        countdown.pack(fill="x", pady=(0, 16))

    def tick() -> None:
        if lock_at:
            left = lock_at - int(time.time())
            countdown.config(text=f"⏳  This PC will lock in {left} seconds. Send your request now if you need more time." if left > 0
                             else "🔒  This PC is locking. You can still send a request below.")
        root.after(1000, tick)
    tick()

    # ---- what is active on this device ----------------------------------------------------------
    dev = data.get("device") or {}
    if dev:
        info = page.card()
        tk.Label(info, text="What is on this device right now", font=(FONT, 15, "bold"), fg=INK, bg=PANEL).pack(anchor="w", pady=(0, 12))
        left, limit, used = dev.get("left"), dev.get("limit"), int(dev.get("used", 0) or 0)
        if limit:
            frac = max(0.0, min(1.0, used / float(limit)))
            colour = RED if frac > 0.9 else AMBER if frac > 0.7 else "#5ee6b8"
            cap = tk.Frame(info, bg=PANEL)
            cap.pack(fill="x")
            tk.Label(cap, text="DAILY SCREEN TIME", font=(FONT, 9, "bold"), fg=MUTED, bg=PANEL).pack(side="left")
            tk.Label(cap, text=f"{int(frac * 100)}% used", font=(FONT, 10, "bold"), fg=colour, bg=PANEL).pack(side="right")
            bar = tk.Canvas(info, height=14, bg=PANEL, highlightthickness=0)
            bar.pack(fill="x", pady=(6, 14))

            def draw_bar(e, b=bar, f=frac, c=colour):
                b.delete("all")
                b.create_rectangle(0, 2, e.width, 12, fill="#0a1529", outline=LINE)
                if f > 0:
                    b.create_rectangle(1, 3, max(2, int((e.width - 1) * f)), 11, fill=c, width=0)
            bar.bind("<Configure>", draw_bar)

        screen_detail = (f"of {limit} min today ({left} min left)" if limit is not None else "today (no daily limit)")
        sites_extra = (" + " + ", ".join(dev.get("filters", []))) if dev.get("filters") else ""
        apps_extra = " + common games" if dev.get("games") else ""
        tiles = [
            ("⏱", "SCREEN TIME", f"{used} min used", screen_detail),
            ("🕒", "ALLOWED HOURS", str(dev.get("hours", "")) or "-", ""),
            ("🌐", "WEBSITES BLOCKED", str(dev.get("sites", 0)), "on the block list" + sites_extra),
            ("🧩", "APPS BLOCKED", str(dev.get("apps", 0)), "on the block list" + apps_extra),
        ]
        grid = tk.Frame(info, bg=PANEL)
        grid.pack(fill="x")
        grid.grid_columnconfigure(0, weight=1, uniform="tile")
        grid.grid_columnconfigure(1, weight=1, uniform="tile")
        for i, (icon, title, value, detail) in enumerate(tiles):
            tile = tk.Frame(grid, bg=CARD2, padx=16, pady=14, highlightbackground=LINE, highlightthickness=1)
            tile.grid(row=i // 2, column=i % 2, sticky="nsew", padx=(0, 8) if i % 2 == 0 else (8, 0), pady=6)
            head = tk.Frame(tile, bg=CARD2)
            head.pack(fill="x")
            tk.Label(head, text=icon, font=(EMOJI, 12), bg=CARD2, fg=INK).pack(side="left")
            tk.Label(head, text="  " + title, font=(FONT, 9, "bold"), bg=CARD2, fg=AMBER).pack(side="left")
            lab(tile, value, margin=130, frac=0.5, anchor="w", justify="left", font=(FONT, 17, "bold"), fg=INK, bg=CARD2).pack(fill="x", pady=(8, 0))
            if detail:
                lab(tile, detail, margin=130, frac=0.5, anchor="w", justify="left", font=(FONT, 10), fg=MUTED, bg=CARD2).pack(fill="x")

    # ---- ask your parent ------------------------------------------------------------------------
    box = page.card()
    tk.Label(box, text="Need something? Ask your parent or guardian", font=(FONT, 16, "bold"), fg=INK, bg=PANEL).pack(anchor="w")
    tk.Label(box, text="Your request is sent to your parent and the administrator by e-mail.", font=(FONT, 10), fg=MUTED, bg=PANEL).pack(anchor="w", pady=(2, 0))
    tk.Label(box, text="WHY DO YOU NEED IT? (OPTIONAL)", font=(FONT, 9, "bold"), fg=MUTED, bg=PANEL).pack(anchor="w", pady=(16, 5))
    note = tk.Entry(box, font=(FONT, 13), relief="flat", bg="#f4f8ff", fg="#10223a", insertbackground="#10223a",
                    highlightthickness=2, highlightbackground=LINE, highlightcolor=ACCENT)
    note.pack(fill="x", ipady=9)
    btnrow = tk.Frame(box, bg=PANEL)
    btnrow.pack(fill="x", pady=(16, 0))
    timerow = tk.Frame(box, bg=PANEL)
    timerow.pack(fill="x", pady=(10, 0))
    status = lab(box, "", margin=120, font=(FONT, 12, "bold"), fg="#7ee0b0", bg=PANEL, justify="left", anchor="w")
    status.pack(fill="x", pady=(12, 0))
    buttons: list[tk.Button] = []
    minutes = tk.IntVar(value=30)

    def go(rtype: str, tgt: str, label: str) -> None:
        mins = minutes.get() if rtype == "time" else 0
        if send_request(rtype, tgt, mins, note.get().strip(), reason):
            status.config(text=f"✓ Request sent: {label}. Your parent and administrator have been e-mailed. Please wait for their answer.", fg="#7ee0b0")
            for b in buttons:
                b.config(state="disabled", bg="#16294a")
        else:
            status.config(text="Could not send the request. Please ask your parent in person.", fg="#ff9f9f")

    def add(text: str, rtype: str, tgt: str, bg: str = BLUE, hover: str = BLUE_HI, parent=None) -> None:
        b = make_button(parent or btnrow, text, lambda: go(rtype, tgt, text.split(" ", 1)[-1]), bg, hover, size=13, padx=18, pady=11)
        b.pack(side="left", padx=(0, 10), pady=3)
        buttons.append(b)

    if ttype == "site" and target:
        add(f"🌐 Please allow {target}", "site", target, GREEN, GREEN_HI)
    elif ttype == "app" and target:
        add(f"🧩 Please allow {target}", "app", target, GREEN, GREEN_HI)
    add("💬 Send a message", "message", "")

    # More time is useful for every kind of block, and essential for a lock.
    add("⏱ Give me more time", "time", "", parent=timerow)
    tk.Label(timerow, text="for", font=(FONT, 11), fg=MUTED, bg=PANEL).pack(side="left", padx=(2, 8))
    for m in (15, 30, 60):
        tk.Radiobutton(timerow, text=f"{m} min", variable=minutes, value=m, indicatoron=False, font=(FONT, 11, "bold"),
                       bg="#12294a", fg=SOFT, selectcolor=BLUE, activebackground=BLUE_HI, activeforeground="white",
                       relief="flat", bd=0, padx=14, pady=8, cursor="hand2", highlightthickness=0).pack(side="left", padx=(0, 6), pady=3)

    # ---- contact -----------------------------------------------------------------------------------
    contact = page.card()
    tk.Label(contact, text="Questions? Contact Mathcloud Tech Services", font=(FONT, 14, "bold"), fg=SOFT, bg=PANEL).pack(anchor="w", pady=(0, 10))
    links = tk.Frame(contact, bg=PANEL)
    links.pack(anchor="w")
    for label, url in (("💬  WhatsApp +2349129225442", WHATSAPP), ("✉  Email Mathcloud", "mailto:" + EMAIL), ("🌐  Products & Services", WEBSITE)):
        make_button(links, label, lambda u=url: webbrowser.open(u), PANEL, "#16294a", size=11, padx=16, pady=9, fg=SOFT, border="#2c4a75").pack(side="left", padx=(0, 10), pady=3)

    # ---- close ----------------------------------------------------------------------------------------
    foot = tk.Frame(page.col, bg=BG)
    foot.pack(fill="x", pady=(8, 0))
    lab(foot, "This window stays open until you press Close, even after the PC is unlocked.", margin=20, font=(FONT, 10), fg=MUTED, bg=BG, justify="center").pack()
    make_button(foot, "I UNDERSTAND  /  CLOSE", root.destroy, GREEN, GREEN_HI, size=14, padx=48, pady=14).pack(pady=(14, 4))
    root.mainloop()


TITLES = {"site": ("Website blocked", "🌐"), "app": ("App blocked", "🧩"), "time": ("Screen time", "⏱"), "message": ("Blocked", "⛔")}


def show_notice_card(data: dict) -> None:
    """The one notice window: a single centred card, no scrolling. Replaces the old full-page layout."""
    root = tk.Tk()
    root.title("@M Family Safety Guard")
    root.configure(bg=BG)
    root.geometry(f"{root.winfo_screenwidth()}x{root.winfo_screenheight()}+0+0")  # explicit size as well as fullscreen
    root.attributes("-fullscreen", True)
    root.attributes("-topmost", True)
    root.protocol("WM_DELETE_WINDOW", root.destroy)
    root.bind("<Escape>", lambda _e: root.destroy())
    root.update_idletasks()
    sh = max(root.winfo_screenheight(), 600)
    k = min(1.0, (sh - 30) / 790.0)           # shrink type and spacing on short screens so the card always fits

    def S(n: int) -> int:
        return max(1, int(round(n * k)))

    reason = str(data.get("reason") or "This activity is not permitted by the current family safety settings.")
    ttype, target = str(data.get("ttype", "message")), str(data.get("target", ""))
    lock_at = int(data.get("lockAt", 0) or 0)
    title, icon = TITLES.get(ttype, TITLES["message"])
    if ttype == "time":
        title = "Time to take a break" if lock_at else "Screen time is over"
    accent = AMBER if ttype == "time" else RED

    cw = min(880, max(560, root.winfo_screenwidth() - 120))
    outer = tk.Frame(root, bg=mix(LINE, accent, 0.45), width=cw)
    outer.place(relx=0.5, rely=0.5, anchor="center")
    card = tk.Frame(outer, bg=PANEL)
    card.pack(padx=1, pady=1)
    gradient_strip(card, accent, ACCENT2, 5).pack(fill="x")
    body = tk.Frame(card, bg=PANEL, padx=S(36), pady=S(22), width=cw - 4)
    body.pack(fill="both")

    # ---- header -------------------------------------------------------------------------------------
    head = tk.Frame(body, bg=PANEL)
    head.pack(fill="x")
    tk.Label(head, text="🛡️", font=(EMOJI, S(18)), bg=PANEL, fg=INK).pack(side="left")
    names = tk.Frame(head, bg=PANEL)
    names.pack(side="left", padx=(10, 0))
    tk.Label(names, text="@M Family Safety Guard", font=(FONT, S(14), "bold"), bg=PANEL, fg=INK).pack(anchor="w")
    tk.Label(names, text="Parental protection • Mathcloud Tech Services", font=(FONT, S(9)), bg=PANEL, fg=MUTED).pack(anchor="w")
    clock = tk.Label(head, text="", font=(FONT, S(10)), bg=PANEL, fg=MUTED)
    clock.pack(side="right")

    def tick_clock() -> None:
        clock.config(text=time.strftime("%A %d %B  •  %H:%M"))
        root.after(15000, tick_clock)
    tick_clock()
    tk.Frame(body, bg=LINE, height=1).pack(fill="x", pady=(S(14), S(10)))

    # ---- what happened --------------------------------------------------------------------------------
    hero = tk.Frame(body, bg=PANEL)
    hero.pack(fill="x")
    icon_badge(hero, icon, accent, size=S(92), bg=PANEL).pack(side="left", padx=(0, S(22)))
    text = tk.Frame(hero, bg=PANEL)
    text.pack(side="left", fill="x", expand=True)
    tk.Label(text, text=title, font=(FONT, S(26), "bold"), bg=PANEL, fg=INK, anchor="w").pack(anchor="w")
    if target:
        tk.Label(text, text=f"  {target}  ", font=(FONT, S(12), "bold"), bg=mix(PANEL, accent, 0.22), fg=SOFT, pady=3).pack(anchor="w", pady=(S(6), 0))
    tk.Label(text, text=reason, font=(FONT, S(13)), bg=PANEL, fg=SOFT, justify="left", anchor="w", wraplength=cw - S(230)).pack(anchor="w", pady=(S(8), 0))

    countdown = tk.Label(body, text="", font=(FONT, S(13), "bold"), fg="#ffb3b3", bg=mix(PANEL, RED, 0.22), pady=S(9), padx=12)
    if lock_at:
        countdown.pack(fill="x", pady=(S(14), 0))

    def tick() -> None:
        if lock_at:
            left = lock_at - int(time.time())
            countdown.config(text=f"⏳  This PC will lock in {left} seconds. Send your request now if you need more time." if left > 0
                             else "🔒  This PC is locking. You can still send a request below.")
        root.after(1000, tick)
    tick()

    # ---- device summary: three compact tiles -------------------------------------------------------
    dev = data.get("device") or {}
    if dev:
        row = tk.Frame(body, bg=PANEL)
        row.pack(fill="x", pady=(S(16), 0))
        limit, used, left = dev.get("limit"), int(dev.get("used", 0) or 0), dev.get("left")
        filters = dev.get("filters") or []
        tiles = [("⏱", "SCREEN TIME", f"{used} min used", f"of {limit} min ({left} left)" if limit is not None else "no daily limit"),
                 ("🕒", "ALLOWED HOURS", str(dev.get("hours", "-")), "today"),
                 ("🛡", "PROTECTION", f"{len(filters)} filters on" if filters else "Custom list", f"{dev.get('sites', 0)} sites • {dev.get('apps', 0)} apps blocked")]
        for i, (ic, ttl, val, sub) in enumerate(tiles):
            row.grid_columnconfigure(i, weight=1, uniform="t")
            tile = tk.Frame(row, bg=CARD2, padx=S(14), pady=S(10), highlightbackground=LINE, highlightthickness=1)
            tile.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else S(8), 0))
            tk.Label(tile, text=f"{ic}  {ttl}", font=(FONT, S(8), "bold"), bg=CARD2, fg=AMBER).pack(anchor="w")
            tk.Label(tile, text=val, font=(FONT, S(15), "bold"), bg=CARD2, fg=INK).pack(anchor="w", pady=(S(4), 0))
            tk.Label(tile, text=sub, font=(FONT, S(9)), bg=CARD2, fg=MUTED).pack(anchor="w")

    # ---- ask a parent --------------------------------------------------------------------------------
    tk.Frame(body, bg=LINE, height=1).pack(fill="x", pady=(S(16), S(12)))
    tk.Label(body, text="Need something? Ask your parent", font=(FONT, S(14), "bold"), bg=PANEL, fg=INK).pack(anchor="w")
    note = tk.Entry(body, font=(FONT, S(12)), relief="flat", bg="#f4f8ff", fg="#10223a", insertbackground="#10223a",
                    highlightthickness=2, highlightbackground=LINE, highlightcolor=ACCENT)
    note.insert(0, "")
    note.pack(fill="x", ipady=S(7), pady=(S(8), 0))
    tk.Label(body, text="Why do you need it? (optional)", font=(FONT, S(9)), bg=PANEL, fg=MUTED).pack(anchor="w", pady=(S(3), S(8)))
    btnrow = tk.Frame(body, bg=PANEL)
    btnrow.pack(fill="x")
    status = tk.Label(body, text="", font=(FONT, S(11), "bold"), fg="#7ee0b0", bg=PANEL, justify="left", anchor="w", wraplength=cw - S(90))
    status.pack(fill="x", pady=(S(8), 0))
    buttons: list[tk.Button] = []
    minutes = tk.IntVar(value=30)

    def go(rtype: str, tgt: str, label: str) -> None:
        mins = minutes.get() if rtype == "time" else 0
        if send_request(rtype, tgt, mins, note.get().strip(), reason):
            status.config(text=f"✓ Request sent ({label}). Your parent has been notified. Please wait for their answer.", fg="#7ee0b0")
            for b in buttons:
                b.config(state="disabled", bg="#16294a")
        else:
            status.config(text="Could not send the request. Please ask your parent in person.", fg="#ff9f9f")

    def add(text: str, rtype: str, tgt: str, bg: str = BLUE, hover: str = BLUE_HI) -> None:
        b = make_button(btnrow, text, lambda: go(rtype, tgt, text.split(" ", 1)[-1]), bg, hover, size=S(11), padx=S(14), pady=S(9))
        b.pack(side="left", padx=(0, S(8)))
        buttons.append(b)

    if ttype == "site" and target:
        add(f"🌐 Please allow {target}", "site", target, GREEN, GREEN_HI)
    elif ttype == "app" and target:
        add(f"🧩 Please allow {target}", "app", target, GREEN, GREEN_HI)
    add("💬 Send a message", "message", "")
    add("⏱ More time", "time", "")
    for m in (15, 30, 60):
        tk.Radiobutton(btnrow, text=f"{m} min", variable=minutes, value=m, indicatoron=False, font=(FONT, S(10), "bold"), bg="#12294a", fg=SOFT,
                       selectcolor=BLUE, activebackground=BLUE_HI, activeforeground="white", relief="flat", bd=0, padx=S(10), pady=S(7),
                       cursor="hand2", highlightthickness=0).pack(side="left", padx=(0, S(4)))

    # ---- footer ------------------------------------------------------------------------------------------
    tk.Frame(body, bg=LINE, height=1).pack(fill="x", pady=(S(14), S(10)))
    foot = tk.Frame(body, bg=PANEL)
    foot.pack(fill="x")
    for label, url in (("💬 WhatsApp", WHATSAPP), ("✉ Email", "mailto:" + EMAIL), ("🌐 Website", WEBSITE)):
        make_button(foot, label, lambda u=url: webbrowser.open(u), PANEL, "#16294a", size=S(9), padx=S(10), pady=S(6), fg=SOFT, border="#2c4a75").pack(side="left", padx=(0, S(6)))
    make_button(foot, "I UNDERSTAND", root.destroy, GREEN, GREEN_HI, size=S(12), padx=S(34), pady=S(10)).pack(side="right")
    root.mainloop()


_instance_handle = None


def single_instance() -> bool:
    """One helper per Windows session (named mutex in the Local namespace). A second copy exits immediately,
    which is what previously caused two notice pages to open at the same time."""
    global _instance_handle
    try:
        import ctypes
        _instance_handle = ctypes.windll.kernel32.CreateMutexW(None, False, "Local\\MFamilySafetyGuardNoticeHelper")
        return ctypes.windll.kernel32.GetLastError() != 183  # ERROR_ALREADY_EXISTS
    except Exception:
        return True  # not Windows (tests): allow


def main() -> None:
    if not single_instance():
        log("another notice helper is already running in this session; exiting")
        return
    last = seen_id()
    shown: dict[str, float] = {}
    log("notice helper started")
    while True:
        try:
            data = read_notice()
            if data:
                ident = int(data.get("id", 0))
                fresh = time.time() - int(data.get("at", 0)) <= 60
                key = f"{data.get('kind')}|{data.get('ttype')}|{data.get('target')}"
                # != (not >): the id may restart after a reinstall, so a different id is always a new notice
                if ident != last and fresh and time.time() - shown.get(key, 0) > 120:
                    last = ident
                    remember(last)
                    shown[key] = time.time()
                    log(f"showing notice {ident}: {data.get('reason', '')}")
                    try:
                        (show_answer if data.get("kind") == "answer" else show_notice_card)(data)
                    except Exception as exc:
                        log(f"window failed: {exc!r}")
                        fallback_box(data)
                    # Anything published while the window was open was already covered by it: never open a second page.
                    newest = read_notice()
                    if newest:
                        last = int(newest.get("id", last))
                        remember(last)
        except Exception as exc:
            log(f"loop error: {exc!r}")
        time.sleep(1)


if __name__ == "__main__":
    main()

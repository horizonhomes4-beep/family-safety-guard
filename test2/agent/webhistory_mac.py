"""Consent-based recent browser history reader for macOS.
Reads Safari, Chrome/Chromium-family and Firefox history databases for the active console user.
Only new navigations from the last hour on first enrollment are imported.
Full Disk Access may be required by macOS privacy controls.
"""
from __future__ import annotations
import sqlite3, tempfile, time
from pathlib import Path
from urllib.parse import urlsplit

EPOCH_1601 = 11644473600
CHROMIUM_OK = {0, 1, 2, 5, 6, 7, 8, 9, 10}
FIREFOX_OK = {1, 2, 3, 5, 6, 9}

def find_sources(home=None):
    home = Path(home) if home else Path.home()
    out=[]
    chromium = [
        ("Chrome", home / "Library/Application Support/Google/Chrome", True),
        ("Edge", home / "Library/Application Support/Microsoft Edge", True),
        ("Brave", home / "Library/Application Support/BraveSoftware/Brave-Browser", True),
        ("Vivaldi", home / "Library/Application Support/Vivaldi", True),
        ("Opera", home / "Library/Application Support/com.operasoftware.Opera", False),
        ("Opera GX", home / "Library/Application Support/com.operasoftware.OperaGX", False),
    ]
    for label, base, profiles in chromium:
        if not base.is_dir(): continue
        dirs=[d for d in base.iterdir() if d.is_dir() and (d.name == "Default" or d.name.startswith("Profile "))] if profiles else [base]
        for d in dirs:
            hist=d/"History"
            if hist.is_file(): out.append({"key":str(hist),"browser":label,"user":home.name,"kind":"chromium","path":hist})
    # Safari stores visit history in a SQLite database under the active user's Library.
    safari = home/"Library/Safari/History.db"
    if safari.is_file():
        out.append({"key":str(safari),"browser":"Safari","user":home.name,"kind":"safari","path":safari})
    ff=home/"Library/Application Support/Firefox/Profiles"
    if ff.is_dir():
        for d in ff.iterdir():
            db=d/"places.sqlite"
            if db.is_file(): out.append({"key":str(db),"browser":"Firefox","user":home.name,"kind":"firefox","path":db})
    return out

def clean_url(url):
    try: u=urlsplit(url)
    except ValueError: return None
    if u.scheme not in ("http","https") or not u.hostname: return None
    host=u.hostname.lower().strip(".")
    if host == "localhost" or "." not in host: return None
    return host, f"{u.scheme}://{host}{u.path}"[:140]

def snapshot(path, tmp):
    """Take a transactionally consistent SQLite snapshot, including committed WAL data.

    Copying the main database file and its WAL separately can capture different moments
    while a browser is writing, producing a stale or malformed history snapshot.
    SQLite's backup API coordinates with the live database and avoids that race.
    """
    dst = tmp / path.name
    source = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)
    target = sqlite3.connect(dst)
    try:
        source.backup(target, pages=256, sleep=0.05)
    finally:
        target.close()
        source.close()
    return dst

def read_source(src,last_id,since,limit,tmp,first):
    snap=snapshot(src["path"],tmp)
    con=sqlite3.connect(snap.resolve().as_uri()+"?mode=ro",uri=True,timeout=3)
    kind=src["kind"]
    try:
        if kind == "safari":
            # Safari visit_time is seconds since 2001-01-01 (CFAbsoluteTime).
            max_id=int(con.execute("SELECT MAX(id) FROM history_visits").fetchone()[0] or 0)
            if not first and last_id > max_id: first=True
            sql=("SELECT v.id,v.visit_time,1,i.url,COALESCE(v.title,'') "
                 "FROM history_visits v JOIN history_items i ON i.id=v.history_item WHERE " +
                 ("v.visit_time>=? " if first else "v.id>? ") + "ORDER BY v.id LIMIT ?")
            arg=(since-978307200) if first else last_id
            rows=con.execute(sql,(arg,limit)).fetchall()
            top=int(rows[-1][0]) if rows else max_id
        else:
            chromium=kind=="chromium"
            table="visits" if chromium else "moz_historyvisits"
            max_id = int(con.execute(f"SELECT MAX(id) FROM {table}").fetchone()[0] or 0)
            if not first and last_id > max_id: first=True
            if chromium:
                sql=("SELECT v.id,v.visit_time,v.transition,u.url,u.title FROM visits v JOIN urls u ON u.id=v.url WHERE "+("v.visit_time>=? " if first else "v.id>? ")+"ORDER BY v.id LIMIT ?")
                arg=int((since+EPOCH_1601)*1_000_000) if first else last_id
            else:
                sql=("SELECT h.id,h.visit_date,h.visit_type,p.url,p.title FROM moz_historyvisits h JOIN moz_places p ON p.id=h.place_id WHERE "+("h.visit_date>=? " if first else "h.id>? ")+"ORDER BY h.id LIMIT ?")
                arg=int(since*1_000_000) if first else last_id
            rows=con.execute(sql,(arg,limit)).fetchall()
            top=int(rows[-1][0]) if rows else max_id
    finally: con.close()
    result=[]
    for vid,vt,visit_kind,url,title in rows:
        if kind == "safari":
            ts=int(float(vt)+978307200)
        elif kind == "chromium":
            if (visit_kind & 0xff) not in CHROMIUM_OK: continue
            ts=int(vt/1_000_000-EPOCH_1601)
        else:
            if visit_kind not in FIREFOX_OK: continue
            ts=int(vt/1_000_000)
        cleaned=clean_url(url)
        if not cleaned: continue
        result.append({"t":ts,"host":cleaned[0],"u":cleaned[1],"title":" ".join((title or "").split())[:90],"browser":src["browser"],"user":src["user"]})
    return result,top

def collect(marks,now=None,first_window=3600,limit=300,home=None):
    now=now or time.time(); visits=[]; ok=[]; errors=[]
    with tempfile.TemporaryDirectory(prefix="mfg-history-") as td:
        root=Path(td)
        for i,src in enumerate(find_sources(home)):
            tmp=root/str(i);tmp.mkdir()
            try:
                first=src["key"] not in marks
                found,top=read_source(src,int(marks.get(src["key"],0)),int(now-first_window),limit,tmp,first)
                marks[src["key"]]=top;visits.extend(found);ok.append(src["browser"])
            except Exception as exc:
                errors.append(f"{src['browser']}: {type(exc).__name__}: {exc}")
    visits.sort(key=lambda x:x["t"])
    return visits,sorted(set(ok)),errors[:8]

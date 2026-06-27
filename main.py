"""

Routarr: Plex to Tunarr routing companion

Runs on port 6942. All config via the built-in Settings UI.

State persists in SQLite at /data/routarr.db



Optional env vars (pre-fill empty settings on first start):

  PLEX_URL           http://192.168.1.x:32400

  PLEX_TOKEN         your-plex-token

  PLEX_SOURCE_ID     auto-detected if blank

  TUNARR_URL         http://192.168.1.x:8000

  JELLYFIN_URL       http://192.168.1.x:8096   (optional)

  JELLYFIN_API_KEY   your-jellyfin-api-key      (optional)


"""

import os, json, re, time, sqlite3, asyncio, secrets, hashlib, logging, urllib.parse, subprocess

from html import unescape

from fastapi import FastAPI, Request

from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from contextlib import contextmanager

from datetime import datetime, timezone, timedelta

from pathlib import Path

from typing import Optional

import httpx



logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("routarr")


def _tunarr_img(pic: str, base: str) -> str:
    """Rewrite any host in a Tunarr image path to use our configured base URL.

    Tunarr sometimes embeds its own public hostname in image URLs (e.g.
    http://tunarr.kandyland.one/images/...) even when Routarr has it stored
    as an internal IP.  By stripping the foreign host and prepending our
    configured base we guarantee the proxy allowlist check passes."""
    if not pic:
        return ""
    base = base.rstrip("/")
    if pic.startswith("http"):
        p = urllib.parse.urlparse(pic)
        path = p.path + (("?" + p.query) if p.query else "")
        return base + path
    return base + (pic if pic.startswith("/") else "/" + pic)


# ── Database ──────────────────────────────────────────────────────────────────



DB_PATH = Path("/data/routarr.db")

DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# Migrate from old name on first run after rename
_OLD_DB = DB_PATH.parent / "pilotarr.db"

if _OLD_DB.exists() and not DB_PATH.exists():

    _OLD_DB.rename(DB_PATH)



def get_db():

    db = sqlite3.connect(str(DB_PATH))

    db.row_factory = sqlite3.Row

    return db



@contextmanager

def db_conn():

    db = get_db()

    try:

        yield db

        db.commit()

    except Exception:

        db.rollback()

        raise

    finally:

        db.close()



def init_db():

    with db_conn() as db:

        db.executescript("""

            CREATE TABLE IF NOT EXISTS settings (

                key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT ''

            );

            CREATE TABLE IF NOT EXISTS routing_rules (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                name TEXT, section_id TEXT, label TEXT DEFAULT '',

                channel_id TEXT, channel_name TEXT, priority INTEGER DEFAULT 0

            );

            CREATE TABLE IF NOT EXISTS process_presets (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                name TEXT UNIQUE NOT NULL,

                dedupe INTEGER DEFAULT 1,

                shuffle TEXT DEFAULT 'cyclic',

                pad_minutes INTEGER DEFAULT 15

            );

            CREATE TABLE IF NOT EXISTS routed_items (

                rating_key TEXT PRIMARY KEY,

                channel_id TEXT,

                channel_name TEXT,

                routed_at INTEGER

            );



            CREATE TABLE IF NOT EXISTS channel_health_log (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                channel_id TEXT,

                channel_name TEXT,

                status TEXT,

                detail TEXT,

                checked_at INTEGER

            );

            CREATE TABLE IF NOT EXISTS sessions (

                token TEXT PRIMARY KEY,

                username TEXT NOT NULL,

                expires_at INTEGER NOT NULL

            );

            CREATE TABLE IF NOT EXISTS activity_log (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                ts INTEGER NOT NULL,

                ok INTEGER DEFAULT 1,

                msg TEXT NOT NULL,

                action_type TEXT DEFAULT '',

                source TEXT DEFAULT '',

                library TEXT DEFAULT '',

                channel TEXT DEFAULT '',

                title TEXT DEFAULT ''

            );

            CREATE TABLE IF NOT EXISTS channel_dirty (

                channel_id TEXT PRIMARY KEY,

                dirty_since INTEGER

            );

            CREATE TABLE IF NOT EXISTS channel_proc_settings (

                channel_id   TEXT PRIMARY KEY,

                channel_name TEXT,

                dedupe       INTEGER DEFAULT 1,

                shuffle      TEXT DEFAULT 'cyclic',

                pad_minutes  INTEGER DEFAULT 15,

                updated_at   INTEGER

            );

        """)

    seed_from_env()



def seed_from_env():

    """Pre-fill any empty settings from env vars. Runs every startup; safe to re-run."""

    env_map = {

        "plex_url":         os.environ.get("PLEX_URL", ""),

        "plex_token":       os.environ.get("PLEX_TOKEN", ""),

        "plex_source_id":   os.environ.get("PLEX_SOURCE_ID", ""),

        "tunarr_url":       os.environ.get("TUNARR_URL", ""),

        "jellyfin_url":     os.environ.get("JELLYFIN_URL", ""),

        "jellyfin_api_key": os.environ.get("JELLYFIN_API_KEY", ""),

    }

    with db_conn() as db:

        for k, v in env_map.items():

            if not v:

                continue

            row = db.execute("SELECT value FROM settings WHERE key=?", (k,)).fetchone()

            if not row or not row["value"]:

                db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (k, v))



init_db()



def backup_db():

    """Copy routarr.db to routarr.db.bak on startup (rolling single backup)."""

    try:

        import shutil

        src = DB_PATH

        bak = DB_PATH.parent / "routarr.db.bak"

        if src.exists():

            shutil.copy2(str(src), str(bak))

    except Exception:

        pass



backup_db()


# -- Auth ---------------------------------------------------------------------



_sessions: dict = {}  # token -> username  (populated from DB on startup)

_SESSION_TTL = 86400 * 30  # 30 days

# Brute-force protection: track failed login timestamps per IP
_login_failures: dict = {}  # ip -> [timestamp, ...]
_LOGIN_WINDOW = 300         # 5-minute sliding window
_LOGIN_MAX_FAILS = 10       # block after this many failures in the window

# General rate-limiter used for expensive endpoints (scan, route-all, process)
_rate_buckets: dict = {}    # (ip, endpoint_key) -> [timestamps]


def _rate_ok(ip: str, key: str, max_calls: int, window: int) -> bool:
    """Return True if the request is within the rate limit, False if it should be blocked.

    Sliding-window counter: we keep a list of timestamps for each (ip, key) pair and
    count how many fall within the last `window` seconds.
    """
    now = time.time()
    bk = (ip, key)
    recent = [t for t in _rate_buckets.get(bk, []) if now - t < window]
    if len(recent) >= max_calls:
        return False
    recent.append(now)
    _rate_buckets[bk] = recent
    return True


def _load_sessions():
    """Restore valid sessions from DB so restarts don't log users out."""
    now = int(time.time())
    with db_conn() as db:
        db.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
        rows = db.execute("SELECT token, username FROM sessions WHERE expires_at > ?", (now,)).fetchall()
    for r in rows:
        _sessions[r["token"]] = r["username"]


_load_sessions()



def _hash_pw(pw: str) -> str:

    salt = secrets.token_hex(16)

    h = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 100000).hex()

    return salt + ':' + h



def _verify_pw(pw: str, stored: str) -> bool:

    if not stored or ':' not in stored:

        return False

    salt, h = stored.split(':', 1)

    return hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 100000).hex() == h



def _auth_cfg():

    with db_conn() as db:

        u = db.execute("SELECT value FROM settings WHERE key='auth_username'").fetchone()

        p = db.execute("SELECT value FROM settings WHERE key='auth_password_hash'").fetchone()

    return ((u['value'] if u and u['value'] else ''), (p['value'] if p and p['value'] else ''))



def _auth_on() -> bool:

    u, p = _auth_cfg()

    return bool(u and p)



def _seed_default_auth():

    """Seed admin/routarr if no credentials are set yet."""

    u, p = _auth_cfg()

    if u or p:

        return

    salt = secrets.token_hex(16)

    pw_hash = salt + ':' + hashlib.pbkdf2_hmac('sha256', b'routarr', salt.encode(), 100000).hex()

    with db_conn() as db:

        db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('auth_username','admin')")

        db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('auth_password_hash',?)", (pw_hash,))



_seed_default_auth()



_LOGIN_CSS = (

    '*{box-sizing:border-box;margin:0;padding:0}'

    'body{font-family:system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;overflow:hidden;background:linear-gradient(160deg,#1d1a56 0%,#09090e 65%)}'

    '.kb-layer{position:fixed;inset:0;background-size:cover;background-position:center;z-index:0;opacity:0;transition:opacity 2s ease-in-out;will-change:transform,opacity}'

    '.kb-layer.on{opacity:.28;animation:kenburns 14s ease-in-out forwards}'

    '@keyframes kenburns{'
    '0%{transform:scale(1) translate(0%,0%)}'
    '50%{transform:scale(1.08) translate(-1.5%,-0.8%)}'
    '100%{transform:scale(1.14) translate(-2.5%,-1.5%)}}'

    '.card{position:relative;z-index:1;background:rgba(9,9,14,.72);border:1px solid rgba(136,126,203,.18);border-radius:14px;padding:42px 38px;width:340px;backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);box-shadow:0 8px 40px rgba(0,0,0,.65)}'

    '.logo{font-size:22px;font-weight:700;color:#887ecb;text-align:center;margin-bottom:28px;letter-spacing:1px}'

    'label{font-size:11px;font-weight:700;color:#4d7080;text-transform:uppercase;letter-spacing:.5px;display:block;margin-bottom:5px}'

    'input{width:100%;background:rgba(15,15,26,.85);border:1px solid #1c1c32;border-radius:6px;padding:10px 12px;color:#dde8ec;font-size:14px;outline:none;margin-bottom:14px;transition:border .15s}'

    'input:focus{border-color:#887ecb}'

    '.sbtn{width:100%;background:#887ecb;color:#09090e;border:none;border-radius:6px;padding:11px;font-size:14px;font-weight:700;cursor:pointer;letter-spacing:.3px}'

    '.sbtn:hover{background:#9d94d4}'

    '.lerr{color:#c46c71;font-size:13px;margin-bottom:12px;text-align:center;padding:8px;background:rgba(196,108,113,.08);border-radius:6px;border:1px solid rgba(196,108,113,.2)}'

    '.lgwrap{position:relative;z-index:1;display:flex;flex-direction:column;align-items:center;gap:18px}'

    '.lglabel{font-size:11px;text-transform:uppercase;letter-spacing:2.5px;color:rgba(221,232,236,.35);font-weight:600;text-align:center}'

)



def _login_page(error: str = '') -> HTMLResponse:

    e = '<div class="lerr">' + error + '</div>' if error else ''

    html = (

        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'

        '<meta name="viewport" content="width=device-width,initial-scale=1">'

        '<title>Routarr</title>'

        '<style>' + _LOGIN_CSS + '</style>'

        '</head><body>'

        '<div id="bg0" class="kb-layer"></div>'
        '<div id="bg1" class="kb-layer"></div>'

        '<div class="lgwrap"><div class="lglabel">Your Media Sources</div><div class="card">'

        '<div class="logo">&#9654; ROUTARR</div>'

        + e +

        '<form id="lf" method="post" action="/login" onsubmit="_li(event)">'

        '<label>Username</label>'

        '<input id="lu" name="username" type="text" autocomplete="username" autofocus required>'

        '<label>Password</label>'

        '<input id="lp" name="password" type="password" autocomplete="current-password" required>'

        '<div id="lerrdyn" style="color:#c46c71;font-size:13px;margin-bottom:8px;display:none"></div>'

        '<button type="submit" class="sbtn">Sign in</button>'

        '</form>'

        '<script>'

        # Ken Burns: fetch idents client-side so the page renders instantly,
        # then images fade in async (no blocking Tunarr call on page load).
        '(async function(){'
        'const L=[document.getElementById("bg0"),document.getElementById("bg1")];'
        'let a=0,i=0,ids=[];'
        'function _show(li,url){'
        'const l=L[li];'
        'l.style.backgroundImage="url("+url+")";'
        'l.style.animation="none";void l.offsetWidth;l.style.animation="";'
        'l.classList.add("on");}'
        'function _next(){'
        'if(!ids.length)return;'
        'i=(i+1)%ids.length;'
        'const n=1-a;_show(n,ids[i]);L[a].classList.remove("on");a=n;}'
        'try{'
        'const r=await fetch("/api/channel-idents");'
        'const data=await r.json();'
        'ids=data.filter(ch=>ch.ident).map(ch=>"/api/proxy-image?url="+encodeURIComponent(ch.ident));'
        'if(ids.length){i=Math.floor(Math.random()*ids.length);_show(0,ids[i]);setInterval(_next,8000);}'
        '}catch(ex){console.warn("[Routarr] ident load failed:",ex);}'
        '})()'

        'async function _li(e){e.preventDefault();const u=document.getElementById("lu").value,p=document.getElementById("lp").value,ed=document.getElementById("lerrdyn");try{const r=await fetch("/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:u,password:p})});const d=await r.json();if(d.ok){window.location=d.redirect||"/";return;}ed.textContent=d.error||"Sign in failed";ed.style.display="block";}catch(ex){ed.textContent="Request failed";ed.style.display="block";}}'

        '</script>'

        '</div><div class="lglabel">To Tunarr</div></div></body></html>'

    )

    return HTMLResponse(html)



def migrate_db():

    """Add columns introduced after initial schema."""

    with db_conn() as db:

        try:

            db.execute("ALTER TABLE routing_rules ADD COLUMN source TEXT DEFAULT 'plex'")

        except Exception:

            pass  # already exists

        try:

            db.execute("ALTER TABLE routing_rules ADD COLUMN label_excl TEXT DEFAULT ''")

        except Exception:

            pass  # already exists

        try:

            db.execute("ALTER TABLE routing_rules ADD COLUMN title_filter TEXT DEFAULT ''")

        except Exception:

            pass  # already exists

        try:

            db.execute("ALTER TABLE routing_rules ADD COLUMN title_excl TEXT DEFAULT ''")

        except Exception:

            pass  # already exists

        try:

            db.execute("ALTER TABLE routing_rules ADD COLUMN auto_route INTEGER DEFAULT 0")

        except Exception:

            pass  # already exists

        try:

            db.execute("ALTER TABLE channel_proc_settings ADD COLUMN preset_name TEXT DEFAULT ''")

        except Exception:

            pass  # already exists

migrate_db()





# ── Config ────────────────────────────────────────────────────────────────────



def cfg(key: str, default: str = "") -> str:

    with db_conn() as db:

        row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()

        val = row["value"] if row else ""

        return val if val else default  # empty string → use default



def cfg_all() -> dict:

    with db_conn() as db:

        return {r["key"]: r["value"] for r in

                db.execute(

                    "SELECT key, value FROM settings WHERE key NOT LIKE '\\_%' ESCAPE '\\'",

                ).fetchall()}



def cfg_set(updates: dict):

    with db_conn() as db:

        for k, v in updates.items():

            db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (k, v))



# ── URL validation ────────────────────────────────────────────────────────────

_URL_SETTINGS = {"plex_url", "tunarr_url", "jellyfin_url", "plex_public_url", "jellyfin_public_url"}


def _valid_url(v: str) -> bool:
    """A settings URL must be empty (unconfigured) or start with http(s)://."""
    return not v or v.startswith(("http://", "https://"))


# ── Library mapping (Plex section → Tunarr library UUID) ─────────────────────



def get_library_mappings() -> dict:

    raw = cfg("library_mappings", "{}")

    try:

        return json.loads(raw)

    except Exception:

        return {}



def section_to_lib(section_id: str) -> str:

    return get_library_mappings().get(section_id, "")



# ── Routing ───────────────────────────────────────────────────────────────────



def routing_rules() -> list[dict]:

    with db_conn() as db:

        # Within same priority: specific-label rules before catch-alls (label='')

        # so a catch-all doesn't shadow a more-specific rule at the same priority.

        return [dict(r) for r in db.execute(

            "SELECT * FROM routing_rules"

            " ORDER BY priority DESC, CASE WHEN label='' THEN 1 ELSE 0 END, id"

        ).fetchall()]



def mark_routed(rating_key: str, channel_id: str, channel_name: str):

    with db_conn() as db:

        db.execute(

            "INSERT OR REPLACE INTO routed_items (rating_key, channel_id, channel_name, routed_at)"

            " VALUES (?,?,?,?)",

            (rating_key, channel_id, channel_name, int(time.time()))

        )



def unmark_routed(rating_key: str):

    with db_conn() as db:

        db.execute("DELETE FROM routed_items WHERE rating_key=?", (rating_key,))



def mark_channel_dirty(channel_id: str):

    with db_conn() as db:

        db.execute(

            "INSERT OR REPLACE INTO channel_dirty(channel_id, dirty_since) VALUES(?, ?)",

            (channel_id, int(time.time()))

        )



def clear_channel_dirty(channel_id: str):

    with db_conn() as db:

        db.execute("DELETE FROM channel_dirty WHERE channel_id = ?", (channel_id,))



def get_routed_items() -> dict:

    """Returns {rating_key: {channel_id, channel_name, routed_at}}"""

    with db_conn() as db:

        return {r["rating_key"]: dict(r) for r in

                db.execute("SELECT * FROM routed_items").fetchall()}



def resolve_channel(section_id: str, labels: list[str], title: str = "") -> Optional[tuple[str, str]]:

    _title_lc = title.lower()

    for rule in routing_rules():

        if rule["section_id"] not in ("*", section_id):

            continue

        # Empty label = catch-all for this section.

        # Non-empty label = comma-separated genres that ALL must appear in the item's genre list.

        if rule["label"] != "":

            required = [g.strip() for g in rule["label"].split(",") if g.strip()]

            if not all(g in labels for g in required):

                continue

        excl = [g.strip() for g in rule.get("label_excl", "").split(",") if g.strip()]

        if excl and any(g in labels for g in excl):

            continue

        tf = rule.get("title_filter", "").strip()

        if tf and _title_lc and not any(t in _title_lc for t in [x.strip().lower() for x in tf.split(",") if x.strip()]):

            continue

        te = rule.get("title_excl", "").strip()

        if te and _title_lc and any(t in _title_lc for t in [x.strip().lower() for x in te.split(",") if x.strip()]):

            continue

        return rule["channel_id"], rule["channel_name"]

    return None



def resolve_channel_full(section_id: str, labels: list, title: str = "") -> Optional[tuple]:

    """Like resolve_channel but also returns matched rule id."""

    _title_lc = title.lower()

    for rule in routing_rules():

        if rule["section_id"] not in ("*", section_id):

            continue

        if rule["label"] != "":

            required = [g.strip() for g in rule["label"].split(",") if g.strip()]

            if not all(g in labels for g in required):

                continue

        excl = [g.strip() for g in rule.get("label_excl", "").split(",") if g.strip()]

        if excl and any(g in labels for g in excl):

            continue

        tf = rule.get("title_filter", "").strip()

        if tf and _title_lc and not any(t in _title_lc for t in [x.strip().lower() for x in tf.split(",") if x.strip()]):

            continue

        te = rule.get("title_excl", "").strip()

        if te and _title_lc and any(t in _title_lc for t in [x.strip().lower() for x in te.split(",") if x.strip()]):

            continue

        return rule["channel_id"], rule["channel_name"], rule["id"]

    return None



# ── Cache ─────────────────────────────────────────────────────────────────────



_cache: dict = {}



def cache_get(key, ttl=1800):

    e = _cache.get(key)

    return e["v"] if e and time.time() - e["t"] < ttl else None



_CACHE_MAX = 500  # prune when we exceed this many entries


def cache_set(key, value):

    _cache[key] = {"t": time.time(), "v": value}

    if len(_cache) > _CACHE_MAX:

        cutoff = time.time() - 1800

        stale = [k for k, v in list(_cache.items()) if v["t"] < cutoff]

        for k in stale:

            _cache.pop(k, None)



def cache_clear():

    _cache.clear()



# ── Plex ──────────────────────────────────────────────────────────────────────



async def plex_get(client, path, params=None):

    base = cfg("plex_url")

    if not base:

        raise ValueError("Plex URL not configured. Go to Settings.")

    # Send the token as a header, not a query param, so it doesn't appear in
    # web server access logs or browser history.
    r = await client.get(

        f"{base}{path}",

        params=params or {},

        headers={"X-Plex-Token": cfg("plex_token")},

        timeout=30,

    )

    r.raise_for_status()

    return r.text



def xml_tags(xml, tag):

    return [dict((k, unescape(v)) for k, v in re.findall(r'(\w+)="([^"]*)"', m.group(1)))

            for m in re.finditer(rf'<{tag}([^>]*?)/?>', xml, re.DOTALL)]



async def plex_sections_list(client) -> list[dict]:

    cached = cache_get("plex_sections", ttl=300)

    if cached:

        return cached

    xml = await plex_get(client, "/library/sections")

    result = [{"id": a.get("key",""), "title": a.get("title","?"), "type": a.get("type","movie")}

              for a in xml_tags(xml, "Directory") if a.get("key")]

    cache_set("plex_sections", result)

    return result



async def plex_item_labels(client, rk):

    """Read Genre tags from a Plex show/movie (user-set via Edit → Tags → Genres)."""

    try:

        xml = await plex_get(client, f"/library/metadata/{rk}")

        return [unescape(m.group(1)) for m in re.finditer(r'<Genre[^>]*tag="([^"]*)"', xml)]

    except Exception:

        return []



async def plex_episodes(client, rk):

    xml = await plex_get(client, f"/library/metadata/{rk}/allLeaves")

    clean = re.sub(r'(?:thumb|art|grandparentThumb|parentThumb|Guid|guid|Image|Source)="[^"]*"', "", xml)

    return [m.group(1) for m in re.finditer(r'ratingKey="(\d+)"', clean)]



async def plex_new_content(client, days=14):

    cached = cache_get(f"plex_new_{days}", ttl=300)

    if cached:

        return cached



    try:

        all_secs = await plex_sections_list(client)

    except Exception:

        all_secs = []

    sec_map = {s["id"]: s for s in all_secs}



    # Respect per-library scan frequency config

    try:

        _freq_cfg = json.loads(cfg("library_scan_freq") or "{}")

    except Exception:

        _freq_cfg = {}



    # Filter out skipped sections; sort priority first

    def _sec_order(s):

        f = _freq_cfg.get(s["id"], "normal")

        return 0 if f == "priority" else (1 if f == "normal" else 2)



    routed_ids_ordered = [

        s["id"] for s in sorted(all_secs, key=_sec_order)

        if _freq_cfg.get(s["id"], "normal") != "skip"

    ]



    _scan_state["total_libs"] = len(routed_ids_ordered)

    _scan_state["done_libs"] = 0



    all_time = (days == 0)

    cutoff = 0 if all_time else (int(datetime.now(timezone.utc).timestamp()) - days * 86400)

    container_size = "10000" if all_time else "500"

    routed_db = get_routed_items()

    items = []



    for sec_id in routed_ids_ordered:

        sec = sec_map.get(sec_id, {})

        _scan_state["current_lib"] = sec.get("title", f"Library {sec_id}")

        is_show = sec.get("type") == "show"

        media_type = "2" if is_show else "1"

        tag        = "Directory" if is_show else "Video"

        kind       = "show" if is_show else "movie"



        try:

            xml = await plex_get(client, f"/library/sections/{sec_id}/all",

                                 {"type": media_type, "sort": "addedAt:desc",

                                  "X-Plex-Container-Size": container_size})

        except Exception:

            _scan_state["done_libs"] += 1

            continue



        # Collect items that pass the date filter first, then fetch all their
        # genres in parallel rather than one request at a time.
        section_attrs = []

        for attrs in xml_tags(xml, tag):

            added_at = int(attrs.get("addedAt", 0))

            if not all_time and added_at < cutoff:

                break

            section_attrs.append(attrs)

        # asyncio.gather fires all the HTTP requests at the same time and
        # waits for all of them to finish, much faster than sequential awaits.
        genres_list = await asyncio.gather(
            *[plex_item_labels(client, a["ratingKey"]) for a in section_attrs]
        )

        for attrs, genres in zip(section_attrs, genres_list):

            added_at = int(attrs.get("addedAt", 0))

            resolved = resolve_channel(sec_id, genres, title=attrs.get("title", ""))

            rk_str   = attrs["ratingKey"]

            routed   = routed_db.get(rk_str)

            if resolved and resolved[0] == "__skip__" and not routed:

                mark_routed(rk_str, "__skip__", "Skip")

                routed = {"channel_id": "__skip__", "channel_name": "Skip", "routed_at": int(time.time())}

            items.append({

                "ratingKey":         rk_str,

                "title":             attrs.get("title", "?"),

                "year":              attrs.get("year", ""),

                "kind":              kind,

                "sectionId":         sec_id,

                "sectionTitle":      sec.get("title", f"Section {sec_id}"),

                "labels":            genres,

                "targetChannel":     resolved[0] if resolved else None,

                "targetChannelName": resolved[1] if resolved else None,

                "addedAt":           added_at,

                "alreadyRouted":     bool(routed),

                "routedTo":          routed["channel_name"] if routed else None,

                "routedAt":          routed["routed_at"]    if routed else None,

            })



        _scan_state["done_libs"] += 1



    cache_set(f"plex_new_{days}", items)

    return items





# ── Jellyfin ──────────────────────────────────────────────────────────────────



async def jf_get(client, path, params=None):

    base = cfg("jellyfin_url")

    key  = cfg("jellyfin_api_key")

    if not base or not key:

        raise ValueError("Jellyfin not configured. Add jellyfin_url and jellyfin_api_key in Settings.")

    r = await client.get(

        f"{base.rstrip('/')}{path}",

        headers={"X-Emby-Token": key},

        params=params or {},

        timeout=30,

    )

    r.raise_for_status()

    return r.json()



async def jf_tunarr_libs(client) -> list:

    """Enabled Jellyfin libraries from Tunarr /api/media-sources."""

    cached = cache_get("jf_tunarr_libs", ttl=3600)

    if cached:

        return cached

    tunarr = cfg("tunarr_url")

    if not tunarr:

        return []

    try:

        r = await client.get(f"{tunarr}/api/media-sources", timeout=10)

        if not r.is_success:

            return []

        result = []

        for src_entry in r.json():

            if src_entry.get("type") == "jellyfin":

                for lib in src_entry.get("libraries", []):

                    if lib.get("enabled") and lib.get("mediaType") not in ("tracks",):

                        result.append({

                            "ext_key":       lib["externalKey"],

                            "tunarr_lib_id": lib["id"],

                            "name":          lib["name"],

                            "media_type":    lib["mediaType"],

                        })

        cache_set("jf_tunarr_libs", result)

        return result

    except Exception:

        return []



async def jellyfin_lib_index(client, tunarr_lib_id: str) -> dict:

    """Index Tunarr programs for one Jellyfin library, keyed by Jellyfin item UUID."""

    cached = cache_get(f"jflib_{tunarr_lib_id}", ttl=3600)

    if cached:

        return cached

    tunarr = cfg("tunarr_url")

    if not tunarr:

        return {}

    try:

        r = await client.get(f"{tunarr}/api/media-libraries/{tunarr_lib_id}/programs", timeout=120)

        r.raise_for_status()

        index = {}

        for p in r.json():

            for ident in p.get("program", {}).get("identifiers", []):

                if ident.get("type") == "jellyfin":

                    index[ident["id"]] = p

        cache_set(f"jflib_{tunarr_lib_id}", index)

        return index

    except Exception:

        return {}



async def jellyfin_combined_index(client) -> dict:

    """Union of all enabled Jellyfin library indexes: JF item UUID → Tunarr program."""

    cached = cache_get("jf_combined_idx", ttl=1800)

    if cached:

        return cached

    libs = await jf_tunarr_libs(client)

    combined = {}

    for lib in libs:

        idx = await jellyfin_lib_index(client, lib["tunarr_lib_id"])

        combined.update(idx)

    cache_set("jf_combined_idx", combined)

    return combined



async def jellyfin_new_content(client, days: int = 14) -> list:

    """Scan all enabled Jellyfin libraries for recently-added content."""

    if not cfg("jellyfin_api_key") or not cfg("jellyfin_url"):

        return []

    cached = cache_get(f"jf_new_{days}", ttl=300)

    if cached:

        return cached



    libs = await jf_tunarr_libs(client)

    if not libs:

        return []



    try:

        _jf_freq = json.loads(cfg("library_scan_freq") or "{}")

    except Exception:

        _jf_freq = {}

    libs = [lib for lib in libs if _jf_freq.get(f"jf:{lib['tunarr_lib_id']}", "normal") != "skip"]

    if not libs:

        return []

    routed_db = get_routed_items()

    cutoff_ts = int(datetime.now(timezone.utc).timestamp()) - days * 86400



    items = []

    for lib in libs:

        ext_key      = lib["ext_key"]

        lib_name     = lib["name"]

        media_type   = lib["media_type"]

        section_id   = f"jf:{lib['tunarr_lib_id']}"

        include_types = ("Movie" if media_type == "movies"

                         else "Series" if media_type == "shows"

                         else "Movie,Series,Video")

        try:

            data = await jf_get(client, "/Items", {

                "ParentId":         ext_key,

                "IncludeItemTypes": include_types,

                "Recursive":        True,

                "SortBy":           "DateCreated",

                "SortOrder":        "Descending",

                "Fields":           "Tags,Genres,DateCreated,ProviderIds",

                "Limit":            500,

            })

        except Exception:

            continue



        for item in data.get("Items", []):

            date_str = item.get("DateCreated", "")

            try:

                item_dt  = datetime.fromisoformat(date_str.replace("Z", "+00:00"))

                added_ts = int(item_dt.timestamp())

            except Exception:

                added_ts = 0



            if added_ts and added_ts < cutoff_ts:

                break   # sorted desc; once past cutoff, stop



            jf_id    = item["Id"]

            kind     = "movie" if item.get("Type") in ("Movie", "Video") else "show"

            labels   = list(dict.fromkeys(item.get("Tags", []) + item.get("Genres", [])))

            resolved = resolve_channel(section_id, labels, title=item.get("Name", ""))

            rk_str   = f"jf:{jf_id}"

            routed   = routed_db.get(rk_str)

            if resolved and resolved[0] == "__skip__" and not routed:

                mark_routed(rk_str, "__skip__", "Skip")

                routed = {"channel_id": "__skip__", "channel_name": "Skip", "routed_at": int(time.time())}

            items.append({

                "ratingKey":         rk_str,

                "source":            "jellyfin",

                "title":             item.get("Name", "?"),

                "year":              item.get("ProductionYear", ""),

                "kind":              kind,

                "sectionId":         section_id,

                "sectionTitle":      f"JF: {lib_name}",

                "labels":            labels,

                "targetChannel":     resolved[0] if resolved else None,

                "targetChannelName": resolved[1] if resolved else None,

                "addedAt":           added_ts,

                "alreadyRouted":     bool(routed),

                "routedTo":          routed["channel_name"] if routed else None,

                "routedAt":          routed["routed_at"]    if routed else None,

            })



    cache_set(f"jf_new_{days}", items)

    return items



# ── Tunarr ────────────────────────────────────────────────────────────────────



async def tunarr_lib_index(client, lib_id):

    cached = cache_get(f"lib_{lib_id}")

    if cached:

        return cached

    tunarr = cfg("tunarr_url")

    if not tunarr:

        raise ValueError("Tunarr URL not configured. Go to Settings.")

    r = await client.get(f"{tunarr}/api/media-libraries/{lib_id}/programs", timeout=120)

    r.raise_for_status()

    index = {}

    for p in r.json():

        for ident in p.get("program", {}).get("identifiers", []):

            # Index by plex ratingKey (type=="plex" is the right discriminator);

            # do NOT filter by sourceId because plex_source_id may be stale/wrong.

            if ident.get("type") == "plex":

                index[ident["id"]] = p

    cache_set(f"lib_{lib_id}", index)

    return index



async def tunarr_channels(client):

    cached = cache_get("channels", ttl=120)

    if cached:

        return cached

    tunarr = cfg("tunarr_url")

    if not tunarr:

        raise ValueError("Tunarr URL not configured. Go to Settings.")

    last_exc = None

    for attempt in range(4):           # retry up to 4× (covers Tunarr restart delay)

        try:

            r = await client.get(f"{tunarr}/api/channels", timeout=15)

            r.raise_for_status()

            break

        except Exception as e:

            last_exc = e

            if attempt < 3:

                await asyncio.sleep(3)  # Tunarr takes ~3-10s to restart

    else:

        raise last_exc

    tunarr_base = tunarr.rstrip("/")

    def _icon(c):

        icon = c.get("icon", {})

        path = icon.get("path", "") if isinstance(icon, dict) else str(icon or "")

        if not path:

            return None

        return _tunarr_img(path, tunarr_base)

    def _ident(c):

        pic = (c.get("offline") or {}).get("picture", "")

        if not pic or "ChatGPT" in pic:

            return None

        return _tunarr_img(pic, tunarr_base)

    result = sorted(

        [{"id": c["id"], "name": c.get("name", c["id"]),

          "number": c.get("number", 0), "count": c.get("programCount", 0),

          "icon": _icon(c), "ident": _ident(c)}

         for c in r.json()],

        key=lambda c: c["number"]

    )

    cache_set("channels", result)

    return result



# ── Post-processing ───────────────────────────────────────────────────────────



# Tracks tunarr program IDs → show ratingKey, populated during routing.

# Used by cyclic shuffle to group episodes from the same show.

# Cleared when cache is cleared; survives restarts only until next routing run.

_channel_show_groups: dict = {}   # channel_id → {show_rk: [program_id, ...]}





async def fetch_channel_lineup(client, channel_id: str) -> list:

    """Fetch the current raw lineup items for a channel via the Tunarr API."""

    # Try the Tunarr API

    tunarr = cfg("tunarr_url")

    r = await client.get(f"{tunarr}/api/channels/{channel_id}/programming",

                         params={"offset": 0, "limit": 100000}, timeout=60)

    r.raise_for_status()

    data = r.json()

    # Handle multiple possible response shapes

    if isinstance(data, list):

        raw = data

    else:

        raw = None

        for key in ("lineup", "items", "programs"):

            if key in data and isinstance(data[key], list):

                raw = data[key]; break

        if raw is None:

            raise ValueError(f"Unexpected programming response (keys: {list(data.keys())})")

    # Normalise items: some endpoints nest program details under "program" sub-object

    items = []

    for item in raw:

        t = item.get("type", "content")

        if t == "content":

            pid  = item.get("id") or (item.get("program") or {}).get("id")

            dur  = item.get("duration", 0)

            if pid:

                items.append({"type": "content", "id": pid, "duration": dur})

        elif t == "flex":

            dur = item.get("duration", 0)

            if dur > 0:

                items.append({"type": "flex", "duration": dur})

    return items



def pp_dedupe(items: list) -> tuple[list, int]:

    """Remove duplicate content items, keeping the first occurrence."""

    seen, result, removed = set(), [], 0

    for item in items:

        if item.get("type") == "content":

            pid = item.get("id")

            if pid in seen:

                removed += 1; continue

            seen.add(pid)

        result.append(item)

    return result, removed



def pp_shuffle(items: list, show_groups: dict, mode: str) -> list:

    """Shuffle content items. mode='cyclic' interleaves by show; mode='random' shuffles freely.

    Flex/redirect items are discarded here and re-inserted by pp_pad."""

    import random

    content = [i for i in items if i.get("type") == "content"]

    if mode == "random":

        random.shuffle(content)

        return content

    if mode == "cyclic":

        # Build program_id → show_rk reverse map from _channel_show_groups

        prog_to_show: dict = {}

        for show_rk, prog_ids in show_groups.items():

            for pid in prog_ids:

                prog_to_show[pid] = show_rk

        # Group content items by show; unknown programs each form their own singleton group

        groups: dict = {}

        for item in content:

            pid = item.get("id", "")

            key = prog_to_show.get(pid, f"\x00{pid}")  # prefix keeps unknowns last

            groups.setdefault(key, []).append(item)

        # Shuffle episode order within each identified show

        for key, grp in groups.items():

            if not key.startswith("\x00"):

                random.shuffle(grp)

        # Cyclic (round-robin) interleave across groups

        group_lists = list(groups.values())

        result, max_len = [], max((len(g) for g in group_lists), default=0)

        for i in range(max_len):

            for g in group_lists:

                if i < len(g):

                    result.append(g[i])

        return result

    return content  # mode=='none' but called incorrectly; return as-is



def pp_pad(items: list, pad_minutes: int) -> list:

    """Insert flex items so each content item's END aligns to a pad_minutes boundary,

    making the NEXT content item start at :00/:15/:30/:45 etc.

    Existing flex items are dropped and recalculated."""

    if pad_minutes <= 0:

        return items

    pad_ms  = pad_minutes * 60 * 1000

    result  = []

    pos     = 0  # cumulative ms from lineup start

    for item in items:

        if item.get("type") == "flex":

            continue  # drop old flex; we recalculate

        result.append(item)

        if item.get("type") == "content":

            pos += item.get("durationMs") or item.get("duration", 0)

            rem  = pos % pad_ms

            if rem:

                gap = pad_ms - rem

                result.append({"type": "flex", "durationMs": gap, "duration": gap})

                pos += gap

    return result



# ── Route engine ──────────────────────────────────────────────────────────────



async def _channel_existing_ids(client, channel_id: str) -> set:

    """Fetch the set of program IDs already in a Tunarr channel lineup.

    Cached per channel for 60s so route_auto batches don't repeat the fetch."""

    cache_key = f"ch_existing_{channel_id}"

    cached = cache_get(cache_key, ttl=60)

    if cached is not None:

        return cached

    tunarr = cfg("tunarr_url")

    try:

        r = await client.get(f"{tunarr}/api/channels/{channel_id}/programming",

                             params={"offset": 0, "limit": 100000}, timeout=60)

        if r.status_code != 200:

            return set()

        data = r.json()

        raw = data if isinstance(data, list) else data.get("lineup", data.get("items", data.get("programs", [])))

        ids = set()

        for item in (raw or []):

            pid = item.get("id") or (item.get("program") or {}).get("id")

            if pid:

                ids.add(pid)

        cache_set(cache_key, ids)

        return ids

    except Exception:

        return set()



async def route_item(client, rk, section_id, labels, override_channel_id=None, title=""):

    if override_channel_id:

        if override_channel_id == "__skip__":

            resolved = ("__skip__", "Skip")

        else:

            channels = await tunarr_channels(client)

            ch = next((c for c in channels if c["id"] == override_channel_id), None)

            resolved = (override_channel_id, ch["name"] if ch else override_channel_id)

    else:

        resolved = resolve_channel(section_id, labels, title=title)

    if not resolved:

        rules = routing_rules()

        rule_count = len(rules)

        sec_rules = [r for r in rules if r["section_id"] in ("*", section_id)]

        return {"success": False, "error": "no_rule",

                "debug": f"No rule matched. {rule_count} total rules, {len(sec_rules)} for this section. Labels: {labels}",

                "channel": None}

    channel_id, channel_name = resolved

    if channel_id == "__skip__":

        mark_routed(rk, "__skip__", "Skip")

        return {"success": True, "channel": "Skip", "method": "skip", "count": 0, "missed": 0, "debug": None}

    lib_id = section_to_lib(section_id)

    if not lib_id:

        mappings = get_library_mappings()

        return {"success": False, "error": "no_library_mapping",

                "debug": f"Section {section_id} has no Tunarr library mapped. Mapped sections: {list(mappings.keys())}",

                "channel": channel_name}

    lib_index = await tunarr_lib_index(client, lib_id)

    try:

        secs = await plex_sections_list(client)

        is_show = next((s["type"] == "show" for s in secs if s["id"] == section_id), False)

    except Exception:

        is_show = False

    ep_rks = await plex_episodes(client, rk) if is_show else [rk]

    lineup, missed = [], []

    for ep_rk in ep_rks:

        prog = lib_index.get(ep_rk)

        if prog:

            item = {"type": "content", "id": prog["id"], "duration": prog["duration"]}

            lineup.append(item)

        else:

            missed.append(ep_rk)

    if not lineup:

        return {"success": False, "error": "no_tunarr_match",

                "debug": f"None of {len(ep_rks)} episode(s) found in Tunarr library '{lib_id}'. "

                         f"Library index has {len(lib_index)} programs. "

                         f"First ep rk: {ep_rks[0] if ep_rks else 'none'}",

                "channel": channel_name}

    # Track show → program ID mapping for later cyclic shuffle

    if is_show and lineup:

        grps = _channel_show_groups.setdefault(channel_id, {})

        grps.setdefault(rk, []).extend(item["id"] for item in lineup)

    # Deduplicate: skip programs already in this channel's lineup

    existing_ids = await _channel_existing_ids(client, channel_id)

    new_lineup = [i for i in lineup if i.get("id") not in existing_ids]

    if not new_lineup:

        # Everything we'd add is already there; treat as success

        mark_routed(rk, channel_id, channel_name)

        return {"success": True, "channel": channel_name, "method": "already_present",

                "count": 0, "missed": len(missed), "debug": "All episodes already in channel"}

    tunarr = cfg("tunarr_url")

    clean_lineup = [{"type": i["type"], "id": i["id"], "duration": i["duration"]} for i in new_lineup]

    r = await client.post(f"{tunarr}/api/channels/{channel_id}/programming",

                          json={"type": "manual", "lineup": clean_lineup, "append": True}, timeout=30)

    ok, method = r.status_code == 200, "api"

    if not ok:

        return {"success": False, "error": f"tunarr_api_{r.status_code}",

                "debug": f"Tunarr returned HTTP {r.status_code}: {r.text[:200]}",

                "channel": channel_name}

    lineup = new_lineup  # report count of what was actually added

    _cache.pop("channels", None)

    if ok:

        mark_routed(rk, channel_id, channel_name)

        mark_channel_dirty(channel_id)

    return {"success": ok, "channel": channel_name, "method": method,

            "count": len(lineup), "missed": len(missed), "debug": None}





async def route_jellyfin_item(client, rk: str, section_id: str, labels: list, override_channel_id=None, title="") -> dict:

    """Route a Jellyfin item (rk='jf:{jellyfin_item_id}') to a Tunarr channel."""

    jf_id    = rk[3:]  # strip 'jf:' prefix

    if override_channel_id:

        if override_channel_id == "__skip__":

            resolved = ("__skip__", "Skip")

        else:

            channels = await tunarr_channels(client)

            ch = next((c for c in channels if c["id"] == override_channel_id), None)

            resolved = (override_channel_id, ch["name"] if ch else override_channel_id)

    else:

        resolved = resolve_channel(section_id, labels, title=title)

    if not resolved:

        rules = routing_rules()

        return {"success": False, "error": "no_rule",

                "debug": f"No rule for section={section_id!r} labels={labels}. {len(rules)} total rules.",

                "channel": None}

    channel_id, channel_name = resolved

    if channel_id == "__skip__":

        mark_routed(rk, "__skip__", "Skip")

        return {"success": True, "channel": "Skip", "method": "skip", "count": 0, "missed": 0, "debug": None}



    try:

        item_info = await jf_get(client, f"/Items/{jf_id}", {"Fields": "MediaSources"})

    except Exception as e:

        return {"success": False, "error": "jellyfin_api_error",

                "debug": str(e), "channel": channel_name}



    if item_info.get("Type") == "Series":

        try:

            episodes = await jf_get(client, "/Items", {

                "ParentId":         jf_id,

                "IncludeItemTypes": "Episode",

                "Recursive":        True,

                "Fields":           "MediaSources",

                "Limit":            1000,

            })

            jf_ids = [ep["Id"] for ep in episodes.get("Items", [])]

        except Exception as e:

            return {"success": False, "error": "jellyfin_episodes_error",

                    "debug": str(e), "channel": channel_name}

    else:

        jf_ids = [jf_id]



    if not jf_ids:

        return {"success": False, "error": "no_episodes",

                "debug": "No episodes found for series", "channel": channel_name}



    index = await jellyfin_combined_index(client)

    lineup, missed = [], []

    for ep_id in jf_ids:

        prog = index.get(ep_id)

        if prog:

            item = {"type": "content", "id": prog["id"], "duration": prog["duration"]}

            lineup.append(item)

        else:

            missed.append(ep_id)



    if not lineup:

        return {"success": False, "error": "no_tunarr_match",

                "debug": f"None of {len(jf_ids)} JF item(s) found in Tunarr index ({len(index)} entries).",

                "channel": channel_name}



    existing_ids = await _channel_existing_ids(client, channel_id)

    new_lineup   = [i for i in lineup if i.get("id") not in existing_ids]

    if not new_lineup:

        mark_routed(rk, channel_id, channel_name)

        return {"success": True, "channel": channel_name, "method": "already_present",

                "count": 0, "missed": len(missed), "debug": "All already in channel"}



    tunarr = cfg("tunarr_url")

    clean_lineup = [{"type": i["type"], "id": i["id"], "duration": i["duration"]} for i in new_lineup]

    r = await client.post(

        f"{tunarr}/api/channels/{channel_id}/programming",

        json={"type": "manual", "lineup": clean_lineup, "append": True},

        timeout=30)

    ok = r.status_code == 200

    _cache.pop("channels", None)

    if ok:

        mark_routed(rk, channel_id, channel_name)

        mark_channel_dirty(channel_id)

    return {"success": ok, "channel": channel_name, "method": "api",

            "count": len(new_lineup), "missed": len(missed),

            "debug": None if ok else f"Tunarr {r.status_code}: {r.text[:100]}"}



# ── FastAPI ───────────────────────────────────────────────────────────────────



# ── Background Plex scanner ──────────────────────────────────────────────────



async def tunarr_trigger_scan(client) -> None:

    """Fire Tunarr ScanLibrariesTask and wait up to 90s for completion.

    Runs concurrently with Plex/JF scan so new library content is indexed

    in Tunarr before Pilotarr attempts to route anything.

    """

    tunarr = cfg("tunarr_url")

    if not tunarr:

        return

    try:

        await client.post(f"{tunarr}/api/tasks/ScanLibrariesTask/run", timeout=10)

        # Poll until the task is no longer marked running (up to 90s)

        for _ in range(30):

            await asyncio.sleep(3)

            r = await client.get(f"{tunarr}/api/tasks", timeout=10)

            task = next((t for t in r.json() if t.get("id") == "ScanLibrariesTask"), None)

            if task and not task.get("running"):

                break

    except Exception as e:

        logger.warning(f"Tunarr scan trigger failed: {e}")



_scan_state: dict = {"last_scan": None, "next_scan": None, "scanning": False, "current_lib": "", "done_libs": 0, "total_libs": 0}



_tunarr_sync_state: dict = {"running": False, "done": 0, "total": 0, "current": ""}



async def _do_tunarr_sync() -> None:

    """Trigger Tunarr ScanLibrariesTask, poll per-library lastScannedAt for progress."""

    if _tunarr_sync_state["running"]:

        return

    _tunarr_sync_state.update({"running": True, "done": 0, "total": 0, "current": ""})

    tunarr = cfg("tunarr_url")

    if not tunarr:

        _tunarr_sync_state["running"] = False

        return

    try:

        async with httpx.AsyncClient() as c:

            # Snapshot current lastScannedAt for all enabled libraries

            r = await c.get(f"{tunarr}/api/media-sources", timeout=15)

            r.raise_for_status()

            baseline: dict = {}

            lib_names: dict = {}

            for src_obj in r.json():

                for lib in src_obj.get("libraries", []):

                    if lib.get("enabled"):

                        lid = lib["id"]

                        baseline[lid] = lib.get("lastScannedAt") or 0

                        lib_names[lid] = lib.get("name", lid)

            total = len(baseline)

            _tunarr_sync_state["total"] = total

            if not total:

                _tunarr_sync_state["running"] = False

                return

            # Fire the scan

            await c.post(f"{tunarr}/api/tasks/ScanLibrariesTask/run", timeout=10)

            # Poll until every library's lastScannedAt has increased

            done_set: set = set()

            for _ in range(60):  # 3 minutes max

                await asyncio.sleep(3)

                r2 = await c.get(f"{tunarr}/api/media-sources", timeout=15)

                if not r2.is_success:

                    continue

                for src_obj in r2.json():

                    for lib in src_obj.get("libraries", []):

                        lid = lib.get("id")

                        if lid not in baseline:

                            continue

                        new_ts = lib.get("lastScannedAt") or 0

                        if new_ts > baseline[lid]:

                            done_set.add(lid)

                        elif lid not in done_set:

                            _tunarr_sync_state["current"] = lib_names.get(lid, "")

                _tunarr_sync_state["done"] = len(done_set)

                if len(done_set) >= total:

                    break

            # Bust library index caches so next route fetch is fresh

            for k in list(_cache.keys()):

                if k.startswith(("lib_", "jflib_")):

                    del _cache[k]

    except Exception as e:

        logger.warning(f"Tunarr sync failed: {e}")

    finally:

        _tunarr_sync_state.update({"running": False, "current": ""})



async def _run_scan_once():

    if _scan_state["scanning"]:

        return

    _scan_state["scanning"] = True

    try:

        days = int(cfg("scan_days") or 14)

        if not cfg("first_scan_done"):

            days = 0

        _cache.pop(f"plex_new_{days}", None)

        _cache.pop(f"jf_new_{days}", None)

        # Phase 1: sync Tunarr libraries (progress bar shows Tunarr phase)

        await _do_tunarr_sync()



        # Phase 2: scan Plex / JF (progress bar switches to Plex lib names)

        async with httpx.AsyncClient() as c:

            try:

                await plex_new_content(c, days)

            except Exception:

                pass

            try:

                await jellyfin_new_content(c, days)

            except Exception:

                pass

            for key in list(_cache.keys()):

                if key.startswith(("lib_", "jflib_")):

                    del _cache[key]

        _scan_state["last_scan"] = time.time()

        if not cfg("first_scan_done"):

            cfg_set({"first_scan_done": "1"})

        # Auto-route new arrivals (global, per-channel, or per-rule setting)

        _ar_global = cfg("auto_route") == "1"

        _ar_ch = set(x for x in (cfg("auto_route_channels") or "").split(",") if x.strip())

        with db_conn() as _ardb:

            _ar_rows = _ardb.execute("SELECT id FROM routing_rules WHERE auto_route=1").fetchall()

        _ar_rules = {str(r["id"]) for r in _ar_rows}

        if _ar_global or _ar_ch or _ar_rules:

            try:

                async with httpx.AsyncClient() as _c:

                    _all: list = []

                    try:

                        _all += await plex_new_content(_c, days)

                    except Exception:

                        pass

                    try:

                        _all += await jellyfin_new_content(_c, days)

                    except Exception:

                        pass

                    _pending = []

                    for _i in _all:

                        if not _i.get("targetChannel") or _i.get("alreadyRouted"):

                            continue

                        if _ar_global or _i["targetChannel"] in _ar_ch:

                            _pending.append(_i)

                            continue

                        if _ar_rules:

                            _full = resolve_channel_full(_i["sectionId"], _i.get("labels", []), _i.get("title", ""))

                            if _full and str(_full[2]) in _ar_rules:

                                _pending.append(_i)

                    for _item in _pending:

                        if _item.get("source") == "jellyfin":

                            _r = await route_jellyfin_item(_c, _item["ratingKey"], _item["sectionId"], _item.get("labels", []), title=_item.get("title", ""))

                        else:

                            _r = await route_item(_c, _item["ratingKey"], _item["sectionId"], _item.get("labels", []), title=_item.get("title", ""))

                        if _r.get("success"):

                            logger.info(f"Auto-routed: {_item['title']} → {_r.get('channel')}")

                    if _pending:

                        for _k in [f"plex_new_{days}", f"jf_new_{days}"]:

                            _cache.pop(_k, None)

            except Exception as _exc:

                logger.warning(f"Auto-route error: {_exc}")

    except Exception:

        pass

    finally:

        _scan_state.update({"scanning": False, "current_lib": "", "done_libs": 0, "total_libs": 0})

        interval = max(int(cfg("scan_interval_minutes") or 60), 5)

        _scan_state["next_scan"] = time.time() + interval * 60



async def _scan_loop():

    await asyncio.sleep(30)  # brief startup delay

    await _run_scan_once()

    while True:

        interval = max(int(cfg("scan_interval_minutes") or 60), 5)

        _scan_state["next_scan"] = time.time() + interval * 60

        await asyncio.sleep(interval * 60)

        await _run_scan_once()



from contextlib import asynccontextmanager



# ── Channel Health Monitor ─────────────────────────────────────────────────────────────



async def _check_channel_health():

    """Poll each Tunarr channel for upcoming programming. Log stoppages."""

    tunarr_url = cfg("tunarr_url")

    if not tunarr_url:

        return

    try:

        async with httpx.AsyncClient(timeout=10) as c:

            resp = await c.get(f"{tunarr_url}/api/channels")

        if resp.status_code != 200:

            return

        channels = resp.json()

    except Exception:

        return

    now = int(time.time())

    for ch in channels:

        ch_id   = ch.get("id", "")

        ch_name = ch.get("name", "")

        ch_num  = str(ch.get("number", ""))

        if ch_num.startswith("1069"):

            continue

        try:

            async with httpx.AsyncClient(timeout=8) as c:

                r = await c.get(

                    f"{tunarr_url}/api/channels/{ch_id}/programming",

                    params={"offset": 0, "limit": 1}

                )

            if r.status_code != 200:

                status = "error"

                detail = f"HTTP {r.status_code} from Tunarr"

            else:

                data = r.json()

                if isinstance(data, list):

                    total = len(data)

                else:

                    total = data.get("totalPrograms", data.get("total", 1))

                if total == 0:

                    status = "empty"

                    detail = "No upcoming programming; channel may stop"

                else:

                    status = "ok"

                    detail = f"{total} program(s) scheduled"

        except Exception as exc:

            status = "error"

            detail = str(exc)[:200]

        with db_conn() as db:

            last = db.execute(

                "SELECT status FROM channel_health_log WHERE channel_id=? ORDER BY checked_at DESC LIMIT 1",

                (ch_id,)

            ).fetchone()

            last_status = last["status"] if last else "ok"

            if status != "ok":

                db.execute(

                    "INSERT INTO channel_health_log(channel_id,channel_name,status,detail,checked_at) VALUES(?,?,?,?,?)",

                    (ch_id, ch_name, status, detail, now)

                )

            elif last_status not in ("ok", None):

                db.execute(

                    "INSERT INTO channel_health_log(channel_id,channel_name,status,detail,checked_at) VALUES(?,?,?,?,?)",

                    (ch_id, ch_name, "recovered", detail, now)

                )



async def _health_loop():

    await asyncio.sleep(90)  # brief startup delay

    while True:

        try:

            await _check_channel_health()

        except Exception:

            pass

        await asyncio.sleep(600)  # check every 10 minutes



async def _cache_plex_machine_id():

    """Fetch and store Plex machineIdentifier so Plex links work without visiting Settings."""

    if cfg("plex_machine_id"):

        return  # already cached

    plex_url   = cfg("plex_url")

    plex_token = cfg("plex_token")

    if not plex_url or not plex_token:

        return

    try:

        async with httpx.AsyncClient(timeout=5) as c:

            r = await c.get(f"{plex_url}/identity", headers={"X-Plex-Token": plex_token})

            if r.status_code == 200:

                m = re.search(r'machineIdentifier="([^"]+)"', r.text)

                if m:

                    cfg_set({"plex_machine_id": m.group(1)})

    except Exception:

        pass



async def _cache_jellyfin_server_id():

    """Fetch and store Jellyfin server Id so JF links work without visiting Settings."""

    if cfg("jellyfin_server_id"):

        return

    jf_url = cfg("jellyfin_url")

    if not jf_url:

        return

    try:

        async with httpx.AsyncClient(timeout=5) as c:

            r = await c.get(f"{jf_url}/System/Info/Public")

            if r.status_code == 200:

                sid = r.json().get("Id")

                if sid:

                    cfg_set({"jellyfin_server_id": sid})

    except Exception:

        pass



@asynccontextmanager

async def _lifespan(app):

    asyncio.create_task(_cache_plex_machine_id())

    asyncio.create_task(_cache_jellyfin_server_id())

    task  = asyncio.create_task(_scan_loop())

    htask = asyncio.create_task(_health_loop())

    yield

    task.cancel()

    htask.cancel()

    for t in [task, htask]:

        try:

            await t

        except asyncio.CancelledError:

            pass



try:

    _vdir = os.path.dirname(os.path.abspath(__file__)) or "."

    APP_VERSION = "3.2." + subprocess.check_output(

        ["git", "-C", _vdir, "rev-list", "--count", "HEAD"],

        stderr=subprocess.DEVNULL).decode().strip()

except Exception:

    try:

        APP_VERSION = "3.2-" + time.strftime(

            "%y%m%d", time.localtime(os.path.getmtime(os.path.abspath(__file__))))

    except Exception:

        APP_VERSION = "3.2"



app = FastAPI(title="Routarr", version=APP_VERSION, lifespan=_lifespan)


from starlette.middleware.base import BaseHTTPMiddleware



class _AuthMW(BaseHTTPMiddleware):

    async def dispatch(self, request, call_next):

        path = request.url.path

        if path in ('/login', '/logout') or path in ('/api/health', '/api/channel-idents', '/api/proxy-image'):

            return await call_next(request)

        if not _auth_on():

            return await call_next(request)

        token = request.cookies.get('routarr_session')

        if not token or token not in _sessions:

            if path.startswith('/api/'):

                return JSONResponse({'error': 'Unauthorized'}, status_code=401)

            return RedirectResponse('/login', status_code=302)

        return await call_next(request)



app.add_middleware(_AuthMW)


class _SecurityHeadersMW(BaseHTTPMiddleware):
    """Attach defensive HTTP headers to every response.

    Think of these like safety labels on a package: they tell the browser
    extra rules about how to handle the page, reducing the damage if something
    does go wrong.
    """

    async def dispatch(self, request, call_next):

        response = await call_next(request)

        # Don't let the browser guess the file type; use what the server declares.
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Prevent this page from being embedded in an iframe on another site
        # (blocks a category of attack called clickjacking).
        response.headers["X-Frame-Options"] = "SAMEORIGIN"

        # Only send the full URL as a "referrer" to our own pages, not to others.
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Content Security Policy: restrict where scripts/styles/images can load from.
        # 'unsafe-inline' is required because the app uses inline <script> and <style>.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "connect-src 'self'"
        )

        # HSTS: tell the browser to always use HTTPS for this site (only sent over HTTPS).
        if request.url.scheme == "https":

            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response


app.add_middleware(_SecurityHeadersMW)


def _err(e: Exception) -> JSONResponse:

    return JSONResponse({"error": str(e)}, status_code=500)



@app.get("/api/health")

async def health():

    plex_url   = cfg("plex_url")
    plex_token = cfg("plex_token")
    tunarr_url = cfg("tunarr_url")
    jf_url     = cfg("jellyfin_url")

    # Each check: (label, url, extra_headers)
    # Plex token goes in a header so it never appears in any URL/log.
    checks = [

        ("plex",     f"{plex_url}/identity",         {"X-Plex-Token": plex_token} if plex_token else {}),

        ("tunarr",   f"{tunarr_url}/api/version",    {}),

        ("jellyfin", f"{jf_url}/System/Info/Public", {}),

    ]

    out = {}

    async with httpx.AsyncClient() as c:

        for name, url, headers in checks:

            if not url.startswith("http"):

                out[name] = "not_configured"

                continue

            try:

                r = await c.get(url, headers=headers, timeout=5)

                out[name] = "ok" if r.status_code < 400 else "error"

            except Exception:

                out[name] = "down"

    return out


@app.get("/api/health-log")

async def get_health_log(limit: int = 200):

    with db_conn() as db:

        rows = db.execute(

            "SELECT * FROM channel_health_log ORDER BY checked_at DESC LIMIT ?", (limit,)

        ).fetchall()

    return [dict(r) for r in rows]



@app.delete("/api/health-log")

async def clear_health_log():

    with db_conn() as db:

        db.execute("DELETE FROM channel_health_log")

    return {"ok": True}



@app.post("/api/activity")

async def post_activity(request: Request):

    body = await request.json()

    ts = int(time.time())

    ok = 1 if body.get("ok", True) else 0

    msg = str(body.get("msg", ""))[:500]

    action_type = str(body.get("action_type", ""))[:50]

    source = str(body.get("source", ""))[:100]

    library = str(body.get("library", ""))[:100]

    channel = str(body.get("channel", ""))[:100]

    title = str(body.get("title", ""))[:200]

    cutoff = ts - 30 * 86400

    with db_conn() as db:

        db.execute("DELETE FROM activity_log WHERE ts < ?", (cutoff,))

        db.execute(

            "INSERT INTO activity_log(ts,ok,msg,action_type,source,library,channel,title) VALUES(?,?,?,?,?,?,?,?)",

            (ts, ok, msg, action_type, source, library, channel, title)

        )

    return {"ok": True}



@app.get("/api/activity")

async def get_activity(

    action_type: str = "",

    source: str = "",

    library: str = "",

    channel: str = "",

    q: str = "",

    ok: Optional[str] = None,

    limit: int = 500,

):

    wheres: list = []

    params: list = []

    if action_type:

        wheres.append("action_type = ?")

        params.append(action_type)

    if source:

        wheres.append("source LIKE ?")

        params.append(f"%{source}%")

    if library:

        wheres.append("library LIKE ?")

        params.append(f"%{library}%")

    if channel:

        wheres.append("channel LIKE ?")

        params.append(f"%{channel}%")

    if q:

        wheres.append("(title LIKE ? OR msg LIKE ?)")

        params.extend([f"%{q}%", f"%{q}%"])

    if ok is not None:

        wheres.append("ok = ?")

        params.append(1 if ok == "1" else 0)

    sql = "SELECT * FROM activity_log"

    if wheres:

        sql += " WHERE " + " AND ".join(wheres)

    sql += " ORDER BY ts DESC LIMIT ?"

    params.append(limit)

    with db_conn() as db:

        rows = db.execute(sql, params).fetchall()

    return [dict(r) for r in rows]



@app.delete("/api/activity")

async def clear_activity():

    with db_conn() as db:

        db.execute("DELETE FROM activity_log")

    return {"ok": True}



@app.get("/api/changelog")

async def get_changelog():

    entries = []

    try:

        result = subprocess.run(

            ["git", "log", "--format=%h|%s|%ad", "--date=short", "-3"],

            capture_output=True,

            text=True,

            timeout=5,

            cwd=str(Path(__file__).parent),

        )

        if result.returncode == 0 and result.stdout.strip():

            for line in result.stdout.strip().split("\n"):

                parts = line.split("|", 2)

                if len(parts) == 3:

                    entries.append({"sha": parts[0], "message": parts[1], "date": parts[2]})

    except Exception:

        pass

    if not entries:

        try:

            cl_path = Path(__file__).parent / "CHANGELOG.md"

            text = cl_path.read_text(encoding="utf-8")

            import re as _re

            for m in _re.finditer(

                r"^## \[([^\]]+)\] - (\S+)\s*\n(.*?)(?=^## |\Z)",

                text, _re.MULTILINE | _re.DOTALL

            ):

                ver, date, body = m.group(1), m.group(2), m.group(3)

                first_item = next(

                    (l.lstrip("- ").strip() for l in body.splitlines() if l.strip().startswith("-")),

                    ""

                )

                entries.append({"sha": f"v{ver}", "message": first_item or f"Release {ver}", "date": date})

                if len(entries) >= 3:

                    break

        except Exception:

            pass

    return {"entries": entries[:3]}



@app.get("/api/versions")

async def get_versions():

    out: dict = {"routarr": APP_VERSION, "plex": None, "tunarr": None, "jellyfin": None}

    async with httpx.AsyncClient(timeout=5) as c:

        plex_url   = cfg("plex_url")

        plex_token = cfg("plex_token")

        if plex_url and plex_token:

            try:

                r = await c.get(f"{plex_url}/identity?X-Plex-Token={plex_token}")

                if r.status_code == 200:

                    m = re.search(r'version="([^"]+)"', r.text)

                    if m: out["plex"] = m.group(1)

                    mid = re.search(r'machineIdentifier="([^"]+)"', r.text)

                    if mid and mid.group(1) != cfg("plex_machine_id"):

                        cfg_set({"plex_machine_id": mid.group(1)})

            except Exception:

                pass

        tunarr_url = cfg("tunarr_url")

        if tunarr_url:

            try:

                r = await c.get(f"{tunarr_url}/api/version")

                if r.status_code == 200:

                    data = r.json()

                    if isinstance(data, str):

                        out["tunarr"] = data

                    elif isinstance(data, dict):

                        out["tunarr"] = (

                            data.get("version")

                            or data.get("Version")

                            or data.get("tunarrVersion")

                            or next(

                                (v for k, v in data.items() if "version" in k.lower() and isinstance(v, str) and "." in v),

                                None

                            )

                        )

            except Exception:

                pass

        jf_url = cfg("jellyfin_url")

        if jf_url:

            try:

                r = await c.get(f"{jf_url}/System/Info/Public")

                if r.status_code == 200:

                    jd = r.json()

                    out["jellyfin"] = jd.get("Version")

                    if jd.get("Id") and not cfg("jellyfin_server_id"):

                        cfg_set({"jellyfin_server_id": jd["Id"]})

            except Exception:

                pass

    return out



@app.get("/api/channel-idents")

async def get_channel_idents():

    out = []

    try:

        tunarr = cfg("tunarr_url")

        if tunarr:

            async with httpx.AsyncClient(timeout=5) as c:

                r = await c.get(f"{tunarr}/api/channels")

                if r.status_code == 200:

                    for ch in r.json():

                        try:

                            num = int(ch.get("number", 0))

                        except Exception:

                            num = 0

                        if num >= 1069 or num in (69, 96, 97):

                            continue

                        icon = ch.get("icon", {})

                        ident = (icon.get("path", "") if isinstance(icon, dict) else str(icon or ""))

                        if not ident:

                            ident = (ch.get("offline") or {}).get("picture", "")

                        if ident and "ChatGPT" not in ident:

                            out.append({"id": ch.get("id"), "name": ch.get("name"), "ident": _tunarr_img(ident, tunarr)})

    except Exception:

        pass

    return out



@app.get("/api/proxy-image")

async def proxy_image(url: str):

    # Only proxy images that come from our own configured servers.
    # Without this check, anyone who can reach the app could trick it into
    # fetching internal network addresses (routers, other containers, etc.).
    allowed_bases = [b.rstrip("/") for b in [
        cfg("plex_url"), cfg("tunarr_url"), cfg("jellyfin_url")
    ] if b]

    if not allowed_bases or not any(url.startswith(base) for base in allowed_bases):

        return Response(status_code=403)

    try:

        # follow_redirects=False prevents a redirect from bypassing the allowlist above
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as c:

            r = await c.get(url)

        return Response(content=r.content, media_type=r.headers.get("content-type", "image/jpeg"),

                        headers={"Cache-Control": "public, max-age=3600"})

    except Exception:

        return Response(status_code=502)



@app.get("/login", response_class=HTMLResponse)

async def get_login():

    return _login_page()



@app.post("/login")

async def post_login(request: Request):

    ip = request.client.host if request.client else "unknown"

    # Rate-limit: count failures in the sliding window
    now = time.time()
    attempts = [t for t in _login_failures.get(ip, []) if now - t < _LOGIN_WINDOW]
    if len(attempts) >= _LOGIN_MAX_FAILS:
        logger.warning(f"Login rate limit hit for {ip}")
        return JSONResponse({'error': 'Too many failed attempts. Try again later.'}, status_code=429)

    try:

        ct = request.headers.get("content-type", "")

        if "application/json" in ct:

            body = await request.json()

            username = str(body.get('username', ''))

            password = str(body.get('password', ''))

            is_json = True

        else:

            # Native form POST (e.g. password manager submitting without JS).
            # Parse manually so we never depend on python-multipart being present.
            raw = await request.body()
            pairs = {}
            for part in raw.decode("utf-8", errors="replace").split("&"):
                if "=" in part:
                    k, _, v = part.partition("=")
                    pairs[urllib.parse.unquote_plus(k)] = urllib.parse.unquote_plus(v)

            username = str(pairs.get('username', ''))

            password = str(pairs.get('password', ''))

            is_json = False

    except Exception:

        return JSONResponse({'error': 'Invalid request'}, status_code=400)

    u, ph = _auth_cfg()

    if not u:

        if is_json:

            return JSONResponse({'ok': True, 'redirect': '/'})

        resp = RedirectResponse('/', status_code=303)

        return resp

    if username == u and _verify_pw(password, ph):

        token = secrets.token_hex(32)

        expires_at = int(now) + _SESSION_TTL

        _sessions[token] = username

        with db_conn() as db:

            db.execute(

                "INSERT OR REPLACE INTO sessions(token, username, expires_at) VALUES(?,?,?)",

                (token, username, expires_at),

            )

        # Clear failure history on successful login
        _login_failures.pop(ip, None)

        if is_json:

            resp = JSONResponse({'ok': True, 'redirect': '/'})

        else:

            resp = RedirectResponse('/', status_code=303)

        resp.set_cookie('routarr_session', token, httponly=True, samesite='lax', max_age=_SESSION_TTL)

        return resp

    # Record failure
    attempts.append(now)
    _login_failures[ip] = attempts

    if is_json:

        return JSONResponse({'error': 'Invalid username or password'}, status_code=401)

    return _login_page(error='Invalid username or password')



@app.get("/logout")

async def logout(request: Request):

    token = request.cookies.get('routarr_session')

    if token:

        _sessions.pop(token, None)

        with db_conn() as db:

            db.execute("DELETE FROM sessions WHERE token=?", (token,))

    resp = RedirectResponse('/login' if _auth_on() else '/', status_code=302)

    resp.delete_cookie('routarr_session')

    return resp



@app.put("/api/auth")

async def put_auth(request: Request):

    body = await request.json()

    username = body.get('username', '').strip()

    password = body.get('password', '')

    confirm = body.get('confirm', '')

    if not username and not password:

        with db_conn() as db:

            db.execute("DELETE FROM settings WHERE key IN ('auth_username','auth_password_hash')")

            db.execute("DELETE FROM sessions")

        _sessions.clear()

        return {'ok': True, 'msg': 'Auth disabled'}

    if not username:

        return JSONResponse({'error': 'Username required'}, status_code=400)

    if password and password != confirm:

        return JSONResponse({'error': 'Passwords do not match'}, status_code=400)

    with db_conn() as db:

        db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('auth_username',?)", (username,))

        if password:

            db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('auth_password_hash',?)", (_hash_pw(password),))

    return {'ok': True}



@app.post("/api/tunarr/sync")

async def tunarr_sync_start():

    if not cfg("tunarr_url"):

        return {"ok": False, "reason": "not_configured"}

    asyncio.create_task(_do_tunarr_sync())

    return {"ok": True}



@app.get("/api/tunarr/sync/status")

async def tunarr_sync_status():

    return _tunarr_sync_state



@app.get("/api/setup/status")

async def setup_status():

    has_source = bool(cfg("plex_url") or cfg("jellyfin_url"))

    configured = bool(cfg("tunarr_url") and has_source)

    missing = []

    if not has_source:         missing.append("Plex or Jellyfin URL")

    if cfg("plex_url") and not cfg("plex_token"):  missing.append("Plex Token")

    if not cfg("tunarr_url"):  missing.append("Tunarr URL")

    return {"configured": configured, "missing": missing}



@app.get("/api/settings")

async def get_settings():

    data = cfg_all()

    if data.get("plex_token"):

        data["plex_token"] = "••••••••"

    return data



@app.put("/api/settings")

async def put_settings(request: Request):

    body = await request.json()

    updates = {}

    for k, v in body.items():

        if v == "••••••••":

            continue  # masked sentinel; user didn't change it, leave DB value alone

        if k in _URL_SETTINGS and not _valid_url(v):

            return JSONResponse(

                {"error": f"'{k}' must start with http:// or https://"},

                status_code=400,

            )

        updates[k] = v

    cfg_set(updates)

    cache_clear()

    return {"ok": True}



@app.get("/api/plex/sections")

async def plex_sections_ep():

    try:

        async with httpx.AsyncClient() as c:

            return await plex_sections_list(c)

    except Exception as e:

        return _err(e)



@app.get("/api/tunarr/libraries")

async def tunarr_libraries_ep():

    """Return all libraries from all Tunarr media sources, with plexSectionId included."""

    try:

        tunarr = cfg("tunarr_url")

        if not tunarr:

            return JSONResponse({"error": "Tunarr URL not configured"}, status_code=400)

        async with httpx.AsyncClient() as c:

            r = await c.get(f"{tunarr}/api/media-sources", timeout=15)

            r.raise_for_status()

            libs = []

            for src in r.json():

                for lib in src.get("libraries", []):

                    libs.append({

                        "id":            lib["id"],

                        "name":          lib.get("name", lib["id"]),

                        "mediaType":     lib.get("mediaType", ""),

                        "type":          lib.get("type", ""),

                        "plexSectionId": lib.get("externalKey", ""),

                        "sourceId":      src["id"],

                        "sourceName":    src.get("name", ""),

                    })

            return libs

    except Exception as e:

        return _err(e)



@app.get("/api/tunarr/auto-map")

async def auto_map_libraries():

    """Return {plex_section_id: tunarr_library_id} derived from Tunarr's media-sources.

    Saves directly to settings and returns the mapping."""

    try:

        tunarr = cfg("tunarr_url")

        if not tunarr:

            return JSONResponse({"error": "Tunarr URL not configured"}, status_code=400)

        async with httpx.AsyncClient() as c:

            r = await c.get(f"{tunarr}/api/media-sources", timeout=15)

            r.raise_for_status()

            mapping = {}

            plex_source_uuid = ""

            for src in r.json():

                if src.get("type") == "plex":

                    plex_source_uuid = src["id"]

                    for lib in src.get("libraries", []):

                        ext = lib.get("externalKey", "")

                        if ext:

                            mapping[ext] = lib["id"]

                elif src.get("type") == "jellyfin":

                    for lib in src.get("libraries", []):

                        if lib.get("enabled") and lib.get("mediaType") not in ("tracks",):

                            mapping[f"jf:{lib['id']}"] = lib["id"]

            updates = {}

            if mapping:

                updates["library_mappings"] = json.dumps(mapping)

            if plex_source_uuid:

                updates["plex_source_id"] = plex_source_uuid

            if updates:

                cfg_set(updates)

            return {"mapping": mapping, "count": len(mapping), "plex_source_id": plex_source_uuid}

    except Exception as e:

        return _err(e)



@app.get("/api/tunarr/detect-source")

async def detect_source():

    """Find the Plex source ID from Tunarr's media-sources endpoint."""

    try:

        tunarr = cfg("tunarr_url")

        if not tunarr:

            return {"source_id": None, "error": "Tunarr URL not configured"}

        async with httpx.AsyncClient() as c:

            r = await c.get(f"{tunarr}/api/media-sources", timeout=10)

            if r.status_code == 200:

                for src in r.json():

                    if src.get("type") == "plex":

                        return {"source_id": src["id"], "name": src.get("name", "Plex")}

        return {"source_id": cfg("plex_source_id"), "name": "pre-configured"}

    except Exception as e:

        return _err(e)



@app.get("/api/routing")

async def get_routing():

    return routing_rules()



def _conflicting_rules(section_id: str, label: str, source: str, exclude_id: int = None) -> list[str]:
    """Return names of existing rules that match the exact same section+label+source combination.

    An exact match means two rules would always fire for the same items; one of
    them will silently shadow the other depending on priority.
    """
    with db_conn() as db:

        if exclude_id is not None:

            rows = db.execute(

                "SELECT name FROM routing_rules WHERE section_id=? AND label=? AND source=? AND id!=?",

                (section_id, label, source, exclude_id),

            ).fetchall()

        else:

            rows = db.execute(

                "SELECT name FROM routing_rules WHERE section_id=? AND label=? AND source=?",

                (section_id, label, source),

            ).fetchall()

    return [r["name"] for r in rows]


@app.post("/api/routing")

async def add_routing(request: Request):

    rule = await request.json()

    conflicts = _conflicting_rules(

        rule["section_id"], rule.get("label", ""), rule.get("source", "plex")

    )

    with db_conn() as db:

        db.execute(

            "INSERT INTO routing_rules(name,section_id,label,channel_id,channel_name,priority,source,label_excl,title_filter,title_excl)"

            " VALUES(?,?,?,?,?,?,?,?,?,?)",

            (rule.get("name",""), rule["section_id"], rule.get("label",""),

             rule["channel_id"], rule.get("channel_name",""), rule.get("priority",0),

             rule.get("source","plex"), rule.get("label_excl",""),

             rule.get("title_filter",""), rule.get("title_excl",""))

        )

    result: dict = {"ok": True}

    if conflicts:

        result["warning"] = f"This rule matches the same items as: {', '.join(conflicts)}. The higher-priority rule will win."

    return result



@app.put("/api/routing/{rule_id}")

async def update_routing(rule_id: int, request: Request):

    body = await request.json()

    with db_conn() as db:

        allowed = ["name", "section_id", "label", "channel_id", "channel_name", "priority", "source", "label_excl", "title_filter", "title_excl", "auto_route"]

        fields = [f for f in allowed if f in body]

        if fields:

            sql = "UPDATE routing_rules SET " + ", ".join(f + "=?" for f in fields) + " WHERE id=?"

            vals = [body[f] for f in fields] + [rule_id]

            db.execute(sql, vals)

    result: dict = {"ok": True}

    # Re-read the saved rule to check for conflicts against all other rules
    if any(f in body for f in ("section_id", "label", "source")):

        with db_conn() as db:

            saved = db.execute("SELECT * FROM routing_rules WHERE id=?", (rule_id,)).fetchone()

        if saved:

            conflicts = _conflicting_rules(

                saved["section_id"], saved["label"], saved["source"], exclude_id=rule_id

            )

            if conflicts:

                result["warning"] = f"This rule matches the same items as: {', '.join(conflicts)}. The higher-priority rule will win."

    return result



@app.get("/api/jellyfin/sections")

async def jellyfin_sections_ep():

    """Return Jellyfin libraries in section-like format for routing/mapping UI."""

    try:

        async with httpx.AsyncClient() as c:

            libs = await jf_tunarr_libs(c)

        return [{"id": f"jf:{lib['tunarr_lib_id']}", "title": lib["name"],

                 "type": lib["media_type"], "source": "jellyfin"} for lib in libs]

    except Exception as e:

        return _err(e)



@app.delete("/api/routing/{rule_id}")

async def delete_routing(rule_id: int):

    with db_conn() as db:

        db.execute("DELETE FROM routing_rules WHERE id=?", (rule_id,))

    return {"ok": True}



@app.get("/api/routing/auto-route")

async def get_routing_auto_route():

    with db_conn() as db:

        rows = db.execute("SELECT id FROM routing_rules WHERE auto_route=1").fetchall()

    return {"enabled": [str(r["id"]) for r in rows]}



@app.put("/api/routing/auto-route")

async def set_routing_auto_route(request: Request):

    body = await request.json()

    with db_conn() as db:

        if body.get("enable_all"):

            db.execute("UPDATE routing_rules SET auto_route=1")

        else:

            rule_id = body.get("rule_id")

            if rule_id is not None:

                val = 1 if body.get("enabled") else 0

                db.execute("UPDATE routing_rules SET auto_route=? WHERE id=?", (val, int(rule_id)))

        rows = db.execute("SELECT id FROM routing_rules WHERE auto_route=1").fetchall()

    return {"enabled": [str(r["id"]) for r in rows]}



@app.get("/api/routing/export")

async def export_routing():

    with db_conn() as db:

        rows = db.execute(

            "SELECT name, section_id, label, label_excl, title_filter, title_excl, channel_id, channel_name, priority, source, auto_route"

            " FROM routing_rules ORDER BY priority DESC, id"

        ).fetchall()

    payload = {

        "version": 1,

        "exported_at": datetime.now(timezone.utc).isoformat(),

        "rules": [dict(r) for r in rows],

    }

    import json as _json

    body = _json.dumps(payload, indent=2)

    return Response(

        content=body,

        media_type="application/json",

        headers={"Content-Disposition": 'attachment; filename="routarr-rules.json"'},

    )



@app.post("/api/routing/import")

async def import_routing(request: Request, mode: str = "merge"):

    if mode not in ("merge", "replace"):

        return JSONResponse({"error": "mode must be 'merge' or 'replace'"}, status_code=400)

    try:

        body = await request.json()

    except Exception:

        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    rules = body.get("rules") if isinstance(body, dict) else body

    if not isinstance(rules, list):

        return JSONResponse({"error": "Expected a list of rules or {\"rules\": [...]}"}, status_code=400)

    imported = 0

    skipped = 0

    with db_conn() as db:

        if mode == "replace":

            db.execute("DELETE FROM routing_rules")

        existing_names: set[str] = set()

        if mode == "merge":

            rows = db.execute("SELECT name FROM routing_rules").fetchall()

            existing_names = {r["name"] for r in rows}

        for rule in rules:

            name = (rule.get("name") or "").strip()

            if not name:

                skipped += 1

                continue

            if mode == "merge" and name in existing_names:

                skipped += 1

                continue

            db.execute(

                "INSERT INTO routing_rules (name, section_id, label, label_excl, title_filter, title_excl, channel_id, channel_name, priority, source, auto_route)"

                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",

                (

                    name,

                    str(rule.get("section_id", "*")),

                    rule.get("label", ""),

                    rule.get("label_excl", ""),

                    rule.get("title_filter", ""),

                    rule.get("title_excl", ""),

                    rule.get("channel_id", ""),

                    rule.get("channel_name", ""),

                    int(rule.get("priority", 0)),

                    rule.get("source", "plex"),

                    int(rule.get("auto_route", 0)),

                ),

            )

            imported += 1

    return {"imported": imported, "skipped": skipped}



@app.get("/api/process-presets")

async def get_process_presets():

    with db_conn() as db:

        rows = db.execute("SELECT * FROM process_presets ORDER BY name").fetchall()

        return [dict(r) for r in rows]



@app.post("/api/process-presets")

async def save_process_preset(request: Request):

    body = await request.json()

    name = (body.get("name") or "").strip()

    if not name:

        return {"error": "Name required"}

    with db_conn() as db:

        db.execute(

            "INSERT INTO process_presets (name, dedupe, shuffle, pad_minutes) VALUES (?,?,?,?)"

            " ON CONFLICT(name) DO UPDATE SET"

            " dedupe=excluded.dedupe, shuffle=excluded.shuffle, pad_minutes=excluded.pad_minutes",

            (name, 1 if body.get("dedupe", True) else 0,

             body.get("shuffle", "cyclic"), int(body.get("pad_minutes", 15)))

        )

    return {"ok": True}



@app.delete("/api/process-presets/{preset_id}")

async def delete_process_preset(preset_id: int):

    with db_conn() as db:

        db.execute("DELETE FROM process_presets WHERE id=?", (preset_id,))

    return {"ok": True}





@app.get("/api/arrivals")

async def arrivals(days: int = 14):

    try:

        async with httpx.AsyncClient() as c:

            plex_items, jf_items = [], []

            try:

                plex_items = await plex_new_content(c, days)

                for i in plex_items:

                    i.setdefault("source", "plex")

            except Exception:

                pass

            try:

                jf_items = await jellyfin_new_content(c, days)

            except Exception:

                pass

            combined = sorted(

                plex_items + jf_items,

                key=lambda x: x.get("addedAt") or 0,

                reverse=True)

            return combined

    except Exception as e:

        return _err(e)



@app.get("/api/channels/sources")

async def channel_sources():

    """Sample 1 program per channel to detect Plex vs Jellyfin source."""

    tunarr = cfg("tunarr_url")

    if not tunarr:

        return {}

    try:

        async with httpx.AsyncClient() as c:

            channels = await tunarr_channels(c)

            sources  = {}

            for ch in channels:

                ch_id = ch["id"]

                try:

                    r = await c.get(

                        f"{tunarr}/api/channels/{ch_id}/programming?offset=0&limit=1",

                        timeout=8)

                    if r.is_success:

                        data  = r.json()

                        progs = data.get("programs", {})

                        if isinstance(progs, list) and progs:

                            first = progs[0]

                        elif isinstance(progs, dict) and progs:

                            first = next(iter(progs.values()))

                        else:

                            first = None

                        raw_src = (first or {}).get("program", {}).get("sourceType", "unknown")

                        sources[ch_id] = raw_src

                    else:

                        sources[ch_id] = "unknown"

                except Exception:

                    sources[ch_id] = "unknown"

            return sources

    except Exception as e:

        return _err(e)



@app.get("/api/channels")

async def channels():

    try:

        async with httpx.AsyncClient() as c:

            result = await tunarr_channels(c)

        return result

    except Exception as e:

        return _err(e)






@app.get("/api/channels/now-playing")

async def get_channels_now_playing():

    tunarr = cfg("tunarr_url")

    if not tunarr:

        return {}

    try:

        now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)

        ahead_ms = now_ms + 300_000

        async with httpx.AsyncClient(timeout=10) as c:

            r = await c.get(

                f"{tunarr}/api/guide/programming",

                params={"from": now_ms, "to": ahead_ms},

            )

            if r.status_code != 200:

                return {}

            guide = r.json()

            result = {}

            for entry in (guide if isinstance(guide, list) else []):

                ch_id = entry.get("id") or entry.get("channelId")

                programs = entry.get("programs") or []

                if not ch_id or not programs:

                    continue

                current = next(

                    (p for p in programs if p.get("type") not in ("flex",)), None

                ) or programs[0]

                result[str(ch_id)] = {

                    "title": current.get("title", ""),

                    "type":  current.get("type", ""),

                    "start": current.get("startTimeMs") or current.get("start"),

                    "stop":  current.get("stopTimeMs")  or current.get("stop"),

                }

            return result

    except Exception:

        return {}



@app.delete("/api/route/routed/{rk}")

async def unroute_item(rk: str):

    unmark_routed(rk)

    return {"ok": True}



@app.get("/api/scan/status")

async def scan_status():

    interval = max(int(cfg("scan_interval_minutes") or 60), 5)

    return {

        "scanning":         _scan_state["scanning"],

        "last_scan":        _scan_state["last_scan"],

        "next_scan":        _scan_state["next_scan"],

        "interval_minutes": interval,

        "current_lib":      _scan_state.get("current_lib", ""),

        "done_libs":        _scan_state.get("done_libs", 0),

        "total_libs":       _scan_state.get("total_libs", 0),

        "first_scan_done":  bool(cfg("first_scan_done")),

    }



@app.post("/api/scan/now")

async def scan_now_ep(request: Request):

    ip = request.client.host if request.client else "unknown"

    if not _rate_ok(ip, "scan", 3, 60):

        return JSONResponse({"error": "Too many scan requests. Wait a moment."}, status_code=429)

    asyncio.create_task(_run_scan_once())

    return {"ok": True}



@app.post("/api/plex-webhook")

async def plex_webhook_ep(request: Request):

    try:

        form = await request.form()

        payload = json.loads(form.get("payload", "{}"))

    except Exception:

        return JSONResponse({"ok": False}, status_code=400)

    event = payload.get("event", "")

    if event in ("library.new", "media.add"):

        days = int(cfg("scan_days") or 14)

        _cache.pop(f"plex_new_{days}", None)

        _cache.pop("plex_sections", None)

        if not _scan_state.get("scanning"):

            asyncio.create_task(_run_scan_once())

            logger.info(f"Plex webhook triggered scan: {event}")

    return {"ok": True}



@app.post("/api/route/mark-done/{rk}")

async def mark_done_ep(rk: str, channel_name: str = "dismissed"):

    """Mark a ratingKey as done without actually routing it.

    Used to dismiss items from the Route page that are already in Tunarr

    or don't need action."""

    mark_routed(rk, "manual", channel_name)

    return {"ok": True}



# Static route MUST be declared before the dynamic /{rk} route, otherwise

# FastAPI matches /api/route/auto as {rk}="auto" and misses section_id → 422.

@app.post("/api/route/auto")

async def route_auto(request: Request, days: int = 14):

    ip = request.client.host if request.client else "unknown"

    if not _rate_ok(ip, "route_auto", 5, 60):

        return JSONResponse({"error": "Too many route requests. Wait a moment."}, status_code=429)

    try:

        async with httpx.AsyncClient() as c:

            items = await plex_new_content(c, days)

            results = []

            # Skip items already routed; only route items that have a target and aren't done

            pending = [i for i in items if i["targetChannel"] and not i.get("alreadyRouted")]

            for item in pending:

                r = await route_item(c, item["ratingKey"], item["sectionId"], item["labels"], title=item.get("title", ""))

                results.append({"title": item["title"], "rk": item["ratingKey"], **r})

            # Bust caches so next arrivals fetch reflects new state

            _cache.pop(f"plex_new_{days}", None)

            for k in list(_cache.keys()):

                if k.startswith("ch_existing_"):

                    del _cache[k]

            return {"routed": len([r for r in results if r["success"]]),

                    "total": len(results), "details": results}

    except Exception as e:

        return _err(e)



@app.post("/api/route/{rk}")

async def route_one(rk: str, section_id: str, labels: str = "", channel_id: str = "", title: str = ""):

    try:

        async with httpx.AsyncClient() as c:

            label_list = [l.strip() for l in labels.split(",") if l.strip()] if labels else []

            ov = channel_id or None

            if rk.startswith("jf:"):

                return await route_jellyfin_item(c, rk, section_id, label_list, override_channel_id=ov, title=title)

            return await route_item(c, rk, section_id, label_list, override_channel_id=ov, title=title)

    except Exception as e:

        return _err(e)



@app.get("/api/route/resolve")

async def route_resolve(section_id: str, labels: str = ""):

    """Return which channel new genres would route to (no side effects)."""

    label_list = [l.strip() for l in labels.split(",") if l.strip()] if labels else []

    resolved = resolve_channel(section_id, label_list)

    return {

        "channel_id":   resolved[0] if resolved else None,

        "channel_name": resolved[1] if resolved else None,

    }



@app.put("/api/plex/genres/{rk}")

async def set_plex_genres(rk: str, request: Request):

    """Write the full genre list back to Plex (replaces existing genres on the item)."""

    try:

        body       = await request.json()

        section_id = body.get("sectionId", "")

        genres     = body.get("genres", [])

        kind       = body.get("kind", "show")   # "show" → type=2, "movie" → type=1



        plex_base  = cfg("plex_url")

        plex_token = cfg("plex_token")

        if not plex_base or not plex_token:

            return JSONResponse({"error": "Plex not configured"}, status_code=400)

        if not section_id:

            return JSONResponse({"error": "sectionId required"}, status_code=400)



        plex_type       = "2" if kind == "show" else "1"

        original_genres = set(body.get("originalGenres", []))

        new_genres      = set(genres)



        to_remove = sorted(original_genres - new_genres)

        to_add    = sorted(new_genres - original_genres)



        # Plex tag API is additive by default.

        # genre[N].tag.tag=X  → add X

        # genre[N].tag.tag-=X → remove X

        # genre.locked=1      → mark field as user-managed (don't let agents overwrite)

        params: dict = {

            "X-Plex-Token": plex_token,

            "type":         plex_type,

            "id":           rk,

            "genre.locked": "1",

        }

        for i, g in enumerate(to_remove):

            params[f"genre[{i}].tag.tag-"] = g

        for i, g in enumerate(to_add):

            params[f"genre[{i}].tag.tag"] = g



        async with httpx.AsyncClient() as c:

            r = await c.put(f"{plex_base}/library/sections/{section_id}/all",

                            params=params, timeout=15)

            r.raise_for_status()



        # Bust arrivals cache so next fetch picks up the new genres

        for k in list(_cache.keys()):

            if k.startswith("plex_new_"):

                del _cache[k]



        return {"ok": True, "genres": genres}

    except Exception as e:

        return _err(e)



@app.post("/api/channels/{channel_id}/process")

async def process_channel(channel_id: str, request: Request):

    """Dedupe + shuffle + pad + save a channel's full lineup.

    Body: {dedupe: bool, shuffle: 'none'|'random'|'cyclic', pad_minutes: int}"""

    try:

        body       = await request.json()

        do_dedupe  = body.get("dedupe", True)

        shuffle    = body.get("shuffle", "cyclic")

        pad_mins   = int(body.get("pad_minutes", 15))

        ch_name    = body.get("channel_name") or channel_id

        preset_nm  = str(body.get("preset_name") or "")

        async with httpx.AsyncClient() as c:

            items = await fetch_channel_lineup(c, channel_id)



        orig_content = sum(1 for i in items if i.get("type") == "content")

        stats: dict  = {"original": orig_content}



        # 1. Dedupe

        if do_dedupe:

            items, removed = pp_dedupe(items)

            stats["dupes_removed"] = removed



        # 2. Shuffle

        if shuffle != "none":

            show_groups = _channel_show_groups.get(channel_id, {})

            items = pp_shuffle(items, show_groups, shuffle)



        # 3. Pad  (also drops old flex and recalculates)

        items = pp_pad(items, pad_mins)



        stats["final_content"] = sum(1 for i in items if i.get("type") == "content")

        stats["flex_items"]    = sum(1 for i in items if i.get("type") == "flex")



        # 4. Save

        tunarr = cfg("tunarr_url")

        async with httpx.AsyncClient() as c:

            r = await c.post(

                f"{tunarr}/api/channels/{channel_id}/programming",

                json={"type": "manual", "lineup": items, "append": False},

                timeout=60)

            if r.status_code not in (200, 201, 204):

                return JSONResponse(

                    {"error": f"Tunarr {r.status_code}: {r.text[:300]}"},

                    status_code=500)



        _cache.pop("channels", None)

        clear_channel_dirty(channel_id)

        with db_conn() as db:

            db.execute(

                "INSERT INTO channel_proc_settings"

                " (channel_id,channel_name,dedupe,shuffle,pad_minutes,preset_name,updated_at)"

                " VALUES(?,?,?,?,?,?,?)"

                " ON CONFLICT(channel_id) DO UPDATE SET"

                " channel_name=excluded.channel_name,dedupe=excluded.dedupe,"

                " shuffle=excluded.shuffle,pad_minutes=excluded.pad_minutes,"

                " preset_name=excluded.preset_name,"

                " updated_at=excluded.updated_at",

                (channel_id, ch_name, 1 if do_dedupe else 0, shuffle, pad_mins, preset_nm, int(time.time())))

        return {"ok": True, "stats": stats}

    except Exception as e:

        return _err(e)



@app.get("/api/channels/dirty")

async def get_dirty_channels():

    with db_conn() as db:

        rows = db.execute("SELECT channel_id, dirty_since FROM channel_dirty").fetchall()

    return {r["channel_id"]: r["dirty_since"] for r in rows}



@app.get("/api/channels/proc-settings")

async def get_channel_proc_settings():

    with db_conn() as db:

        rows = db.execute("SELECT * FROM channel_proc_settings").fetchall()

    return {r["channel_id"]: {

        "channel_name": r["channel_name"],

        "dedupe": bool(r["dedupe"]),

        "shuffle": r["shuffle"],

        "pad_minutes": r["pad_minutes"],

        "preset_name": r["preset_name"] if r["preset_name"] is not None else "",

        "updated_at": r["updated_at"]

    } for r in rows}



@app.get("/api/channels/auto-route")

async def get_channel_auto_route():

    raw = cfg("auto_route_channels") or ""

    enabled = [x for x in raw.split(",") if x.strip()]

    return {"enabled": enabled}



@app.put("/api/channels/auto-route")

async def set_channel_auto_route(body: dict):

    raw = cfg("auto_route_channels") or ""

    enabled = set(x for x in raw.split(",") if x.strip())

    if body.get("enable_all"):

        try:

            async with httpx.AsyncClient() as c:

                channels = await tunarr_channels(c)

            enabled = {ch["id"] for ch in channels}

        except Exception:

            pass

    else:

        ch_id = body.get("channel_id", "")

        if ch_id:

            if body.get("enabled"):

                enabled.add(ch_id)

            else:

                enabled.discard(ch_id)

    cfg_set({"auto_route_channels": ",".join(enabled)})

    return {"enabled": list(enabled)}



@app.post("/api/route/now")

async def route_now(request: Request, days: int = 14):

    """Immediately route all pending items for all sources."""

    ip = request.client.host if request.client else "unknown"

    if not _rate_ok(ip, "route_now", 5, 60):

        return JSONResponse({"error": "Too many route requests"}, status_code=429)

    try:

        async with httpx.AsyncClient() as c:

            all_items: list = []

            try:

                plex_items = await plex_new_content(c, days)

                all_items += plex_items

            except Exception:

                pass

            try:

                jf_items = await jellyfin_new_content(c, days)

                all_items += jf_items

            except Exception:

                pass

            pending = [i for i in all_items if i.get("targetChannel") and not i.get("alreadyRouted")]

            results, ch_seen = [], set()

            for item in pending:

                if item.get("source") == "jellyfin":

                    r = await route_jellyfin_item(c, item["ratingKey"], item["sectionId"], item.get("labels", []), title=item.get("title", ""))

                else:

                    r = await route_item(c, item["ratingKey"], item["sectionId"], item.get("labels", []), title=item.get("title", ""))

                results.append({"title": item["title"], **r})

                if r.get("success"):

                    ch_seen.add(r.get("channel", ""))

            for k in list(_cache.keys()):

                if k.startswith(("plex_new_", "jf_new_", "ch_existing_")):

                    del _cache[k]

            routed_count = len([r for r in results if r.get("success")])

            return {"routed": routed_count, "total": len(results), "channels": len(ch_seen)}

    except Exception as e:

        return _err(e)



@app.get("/api/cache/clear")

async def clear_cache_ep():

    cache_clear()

    return {"cleared": True}



# ── Frontend ──────────────────────────────────────────────────────────────────



HTML = r"""<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport" content="width=device-width,initial-scale=1">

<title>Routarr</title>

<style>

:root{--bg:#09090e;--s1:#0f0f1a;--s2:#16162a;--s3:#1d1d36;--acc:#75cec8;--acc2:#c46c71;--txt:#dde8ec;--muted:#4d7080;--bdr:#1c1c32;--green:#56ac4d;--yellow:#c8c459;--blue:#706deb;--fs:15px;--bar-h:3px}

body.light{--bg:#f0f4f5;--s1:#ffffff;--s2:#e4ecee;--s3:#d4e0e4;--txt:#0e1a1e;--muted:#3a6070;--bdr:#c0ced4;--acc:#3a9a94;--acc2:#a03042}

*{box-sizing:border-box;margin:0;padding:0}

body{background:var(--bg);color:var(--txt);font-family:system-ui,-apple-system,sans-serif;font-size:var(--fs);min-height:100vh}

header{background:var(--s1);border-bottom:1px solid var(--bdr);padding:0 20px;height:54px;display:flex;align-items:center;gap:20px;position:sticky;top:0;z-index:100}

.logo{font-size:17px;font-weight:700;color:var(--acc2);letter-spacing:-.3px;white-space:nowrap}

.logo em{color:var(--muted);font-style:normal;font-weight:400}

nav{display:flex;gap:2px;flex:1}

.tab{background:none;border:none;color:var(--muted);padding:7px 14px;border-radius:6px;cursor:pointer;font-size:var(--fs);font-weight:500;transition:all .15s}

.tab:hover{background:var(--s2);color:var(--txt)}.tab.on{background:var(--s2);color:var(--txt)}.logout-btn{background:none;border:none;color:var(--muted);padding:6px 9px;border-radius:6px;cursor:pointer;display:flex;align-items:center;opacity:.75;transition:color .15s,background .15s,opacity .15s}.logout-btn:hover{background:var(--s2);color:var(--acc2);opacity:1}.th-sort{cursor:pointer;user-select:none;white-space:nowrap}.th-sort:hover{color:var(--acc)}.sort-ind{font-size:10px;color:var(--muted);font-weight:400}

.status{display:flex;gap:10px;align-items:center}

.dot{display:flex;align-items:center;gap:5px;font-size:12px;color:var(--muted)}

.dk{width:8px;height:8px;border-radius:50%;background:var(--s3);transition:background .3s}

.dk.ok{background:var(--green);box-shadow:0 0 5px var(--green)}.dk.err{background:var(--acc2)}

.dk.nc{opacity:.3}.dk.spin{background:var(--yellow);animation:pulse 1.2s ease-in-out infinite}

@keyframes pulse{0%,100%{opacity:.3}50%{opacity:1}}

.hdr-controls{display:flex;gap:8px;align-items:center}

.icon-btn{background:none;border:none;cursor:pointer;color:var(--muted);font-size:18px;padding:4px 6px;border-radius:6px;line-height:1;transition:color .15s}

.icon-btn:hover{color:var(--txt)}

main{padding:22px;max-width:1150px;margin:0 auto}

.page{display:none}.page.on{display:block}

.sh{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:16px;gap:12px}

.sh h2{font-size:18px;font-weight:700}.sh .sub{color:var(--muted);font-size:13px;margin-top:4px;max-width:600px;line-height:1.5}

.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}

.btn{border:none;border-radius:6px;padding:8px 15px;font-size:13px;font-weight:600;cursor:pointer;transition:opacity .15s;white-space:nowrap}

.btn:hover{opacity:.8}.btn:disabled{opacity:.4;cursor:default}

.p{background:var(--acc);color:#fff}.g{background:var(--s2);color:var(--txt);border:1px solid var(--bdr)}

.sm{padding:5px 10px;font-size:12px}.success{background:var(--green);color:#fff}

.arr-row-checked{background:color-mix(in srgb,var(--acc) 10%,transparent)}

table{width:100%;border-collapse:collapse}

th{text-align:left;font-size:12px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;padding:10px 12px;border-bottom:1px solid var(--bdr)}

th.sortable{cursor:pointer;user-select:none}

th.sortable:hover{color:var(--txt)}

th .sort-arrow{margin-left:4px;opacity:.4;font-size:10px}

th.sort-asc .sort-arrow::after{content:'▲';opacity:1}

th.sort-desc .sort-arrow::after{content:'▼';opacity:1}

td{padding:11px 12px;border-bottom:1px solid var(--bdr);vertical-align:middle;font-size:var(--fs)}

tr:last-child td{border-bottom:none}tr:hover td{background:rgba(255,255,255,.02)}

.badge{display:inline-block;padding:3px 8px;border-radius:4px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.4px}

.badge.movie{background:#1a1a30;color:#818cf8}.badge.show{background:#1a2a1a;color:#4ade80}

.pill{display:inline-block;padding:2px 9px;border-radius:12px;font-size:12px;font-weight:600;background:var(--s3);color:var(--muted);margin-right:3px}

.done{background:var(--s2)!important;color:var(--green)!important;cursor:default!important}

.fail{background:var(--s2)!important;color:var(--acc2)!important;cursor:default!important}

.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(175px,1fr));gap:10px}

.chcard{background:var(--s1);border:1px solid var(--bdr);border-radius:8px;padding:14px;transition:border-color .15s;position:relative;overflow:hidden;min-height:110px;display:flex;flex-direction:column;justify-content:space-between}

.chcard:hover{border-color:var(--s3)}

.chcard-bg{position:absolute;inset:0;background-size:cover;background-position:center;opacity:var(--ident-op,.28);border-radius:8px;pointer-events:none;transition:opacity .3s}

.chcard:hover .chcard-bg{opacity:calc(var(--ident-op,.28) * 1.5)}

.chcard-content{position:relative;z-index:1;display:flex;flex-direction:column;height:100%}

.chnum{font-size:10px;color:var(--muted);font-weight:600;margin-bottom:3px}

.chtitle{font-size:13px;font-weight:600;margin-bottom:8px}

.chcount{font-size:20px;font-weight:700;color:var(--acc2)}.chcl{font-size:10px;color:var(--muted)}

/* Channel sort bar */

.ch-sort-bar{display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap}

.ch-sort-bar label{font-size:11px;color:var(--muted);font-weight:600}

.ch-sort-bar select{background:var(--s2);border:1px solid var(--bdr);color:var(--txt);border-radius:6px;padding:4px 8px;font-size:12px;outline:none}

.ch-sort-bar select:focus{border-color:var(--acc)}

.actitem{background:var(--s1);border:1px solid var(--bdr);border-radius:7px;padding:11px 14px;display:flex;align-items:center;gap:12px;margin-bottom:4px}

.acttitle{font-weight:500;flex:1}.actmeta{font-size:11px;color:var(--muted);white-space:nowrap}

.pbar{height:2px;background:var(--s3);border-radius:2px;margin-top:4px;overflow:hidden}

.pfill{height:100%;background:var(--acc2);border-radius:2px}

/* Settings */

.scard{background:var(--s1);border:1px solid var(--bdr);border-radius:10px;padding:20px;margin-bottom:14px}

.scard h3{font-size:14px;font-weight:600;margin-bottom:4px}

.scard .sdesc{font-size:12px;color:var(--muted);margin-bottom:16px;line-height:1.5}

.fg{display:grid;grid-template-columns:1fr 1fr;gap:12px}

.fg3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}

.field label{display:block;font-size:11px;color:var(--muted);margin-bottom:4px;font-weight:600}

.field input,.field select{width:100%;background:var(--s2);border:1px solid var(--bdr);color:var(--txt);border-radius:6px;padding:8px 10px;font-size:13px;outline:none;transition:border-color .15s}

.field input:focus,.field select:focus{border-color:var(--acc)}

.field input::placeholder{color:var(--muted)}

.field .hint{font-size:11px;color:var(--muted);margin-top:4px;line-height:1.5}

.help-toggle{background:none;border:none;color:var(--blue);font-size:11px;cursor:pointer;padding:0;margin-top:4px;text-align:left}

.help-toggle:hover{text-decoration:underline}

.help-box{background:var(--s2);border:1px solid var(--bdr);border-radius:6px;padding:12px;margin-top:8px;font-size:12px;line-height:1.7;display:none}

.help-box.on{display:block}

.help-box code{background:var(--s3);padding:1px 5px;border-radius:3px;font-family:monospace;font-size:11px}
.help-mockup{background:var(--s2);border:1px solid var(--bdr);border-radius:8px;padding:14px 16px;margin:14px 0 6px}
.help-mockup .hm-tag{display:inline-block;background:var(--s3);border-radius:4px;padding:2px 8px;font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:10px}
.help-mockup .hm-row{display:flex;gap:8px;align-items:baseline;padding:5px 0;border-bottom:1px solid var(--bdr);font-size:12px;flex-wrap:wrap}
.help-mockup .hm-row:last-child{border-bottom:none}
.help-mockup .hm-lbl{min-width:160px;color:var(--muted)}
.help-mockup .hm-val{flex:1;min-width:120px;background:var(--s3);border-radius:3px;padding:2px 8px;color:var(--txt);font-family:monospace;font-size:11px}
.help-mockup .hm-note{color:var(--acc);font-size:11px}
.hstep{display:flex;gap:10px;align-items:flex-start;padding:7px 0}
.hstep-n{background:var(--acc);color:var(--bg);border-radius:50%;min-width:22px;height:22px;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;flex-shrink:0;margin-top:2px}
.hstep-b{flex:1;font-size:13px;line-height:1.6}
.hstep-b ul{margin:5px 0 0 18px;line-height:2.1}
.htip{background:var(--s2);border-left:3px solid var(--blue);border-radius:0 6px 6px 0;padding:10px 14px;margin:12px 0;font-size:12px;line-height:1.6}

/* Lib mapping */

.lib-row{display:flex;align-items:center;gap:12px;padding:9px 0;border-bottom:1px solid var(--bdr)}

.lib-row:last-child{border-bottom:none}

.lib-plex{flex:1;font-size:13px}.lib-arrow{color:var(--muted);font-size:16px}

.lib-select{flex:1;background:var(--s2);border:1px solid var(--bdr);color:var(--txt);border-radius:6px;padding:7px 9px;font-size:12px;outline:none}

.lib-select:focus{border-color:var(--acc)}

.lib-source-hdr{font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;padding-bottom:6px;border-bottom:1px solid var(--bdr);margin-bottom:4px}

.scan-freq-sel{font-size:11px;padding:3px 6px;border-radius:5px;border:1px solid var(--bdr);background:var(--s2);color:var(--txt);cursor:pointer;min-width:80px}
.lib-col-hdr{display:flex;align-items:center;gap:12px;padding:0 0 5px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:var(--muted)}
.lib-col-hdr .lch-spc{flex:1}.lib-col-hdr .lch-arr{color:transparent;font-size:16px}.lib-col-hdr .lch-freq{min-width:80px;text-align:right}

/* Rules */

.del-btn{background:none;border:none;color:var(--muted);cursor:pointer;padding:2px 7px;border-radius:4px;font-size:14px}

.del-btn:hover{background:var(--acc);color:#fff}

.section-label{font-size:11px;color:var(--muted);background:var(--s3);padding:1px 6px;border-radius:4px;margin-left:4px}

/* Banner */

.setup-banner{background:#110e00;border:1px solid var(--yellow);border-radius:8px;padding:14px 18px;margin-bottom:16px;font-size:13px;display:flex;align-items:center;gap:12px}

.setup-banner strong{color:var(--yellow)}

/* Genre editing */

.genre-view{display:flex;flex-wrap:wrap;align-items:center;gap:3px;min-height:22px}

.genre-edit-btn{opacity:0;transition:opacity .15s;padding:1px 5px;font-size:10px;margin-left:2px;border-radius:4px}

tr:hover .genre-edit-btn{opacity:.6}

.genre-edit-btn:hover{opacity:1!important}

.genre-edit-wrap{display:flex;flex-wrap:wrap;align-items:center;gap:3px;min-width:220px}

.pill.ep{background:rgba(192,57,43,.15);border:1px solid rgba(192,57,43,.4);color:var(--txt);padding-right:18px;position:relative}

.pill-x{position:absolute;right:3px;top:50%;transform:translateY(-50%);background:none;border:none;color:var(--muted);cursor:pointer;font-size:11px;line-height:1;padding:0}

.pill-x:hover{color:var(--acc2)}

.gtag-input{background:var(--s2);border:1px solid var(--bdr);color:var(--txt);border-radius:12px;padding:2px 8px;font-size:11px;outline:none;width:90px;transition:border-color .15s}

.gtag-input:focus{border-color:var(--acc)}

/* Misc */

.loading{color:var(--muted);text-align:center;padding:40px}

.empty{color:var(--muted);text-align:center;padding:28px;font-size:13px}

.err-box{color:var(--acc2);background:#1a0a0c;border:1px solid #3a1820;border-radius:7px;padding:10px 14px;font-size:12px;margin:8px 0}

.ok-msg{color:var(--green);font-size:12px}

select.days{background:var(--s2);border:1px solid var(--bdr);color:var(--txt);border-radius:6px;padding:5px 9px;font-size:12px}

#toast{position:fixed;bottom:20px;right:20px;background:var(--s2);border:1px solid var(--bdr);border-radius:8px;padding:11px 16px;font-size:12px;opacity:0;transition:opacity .25s;z-index:999;pointer-events:none;max-width:320px}

#toast.on{opacity:1}

/* Modal */

#modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:200;align-items:center;justify-content:center}

#modal.on{display:flex}

#proc-modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:200;align-items:center;justify-content:center}

#proc-modal.on{display:flex}

#clear-confirm-modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:200;align-items:center;justify-content:center}

#clear-confirm-modal.on{display:flex}

#deactivate-modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:200;align-items:center;justify-content:center}

#deactivate-modal.on{display:flex}

.mbox{background:var(--s1);border:1px solid var(--bdr);border-radius:12px;padding:24px;width:480px;max-width:95vw}

.mbox h3{font-size:14px;font-weight:600;margin-bottom:16px}

/* Process modal */

.proc-opt{display:flex;flex-direction:column;gap:12px;margin-bottom:20px}

.proc-row{display:flex;align-items:center;gap:10px}

.proc-row label{font-size:13px;flex:1}

.proc-row input[type=checkbox]{width:15px;height:15px;accent-color:var(--acc);cursor:pointer}

.proc-row select{background:var(--s2);border:1px solid var(--bdr);color:var(--txt);border-radius:6px;padding:5px 8px;font-size:12px}

.proc-stats{background:var(--s2);border:1px solid var(--bdr);border-radius:7px;padding:11px 14px;font-size:12px;margin-top:12px;display:none;line-height:1.8}

.proc-stats.on{display:block}

.chcard-actions{margin-top:10px;text-align:right}

.proc-queue-section{background:var(--s1);border:2px solid var(--acc);border-radius:10px;padding:14px 16px;margin-bottom:20px}

.proc-ch-row{display:flex;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid var(--bdr)}

.proc-ch-row:last-child{border-bottom:none}

.proc-ch-num{font-size:10px;color:var(--muted);font-weight:600;min-width:40px}

.proc-ch-name{flex:1;font-size:12px;font-weight:500}

.ch-now-playing-badge{position:absolute;top:6px;left:6px;background:#00c864;color:#001800;border-radius:10px;padding:1px 7px;font-size:10px;font-weight:700;pointer-events:none;z-index:3}

/* Tunarr sync progress bar */

#sync-bar{display:flex;flex:1;align-items:center;gap:10px;padding:0 14px;min-width:0;opacity:0;pointer-events:none;transition:opacity .35s}

#sync-bar.on{opacity:1;pointer-events:auto}

.sync-track{flex:1;height:var(--bar-h);background:var(--bdr);border-radius:2px;min-width:60px;overflow:hidden}

.sync-fill{height:100%;background:var(--acc);border-radius:2px;transition:width .5s ease;width:0%}

.sync-lbl{font-size:10px;color:var(--muted);white-space:nowrap;letter-spacing:.2px}

@media(max-width:700px){
  header{height:auto;flex-wrap:wrap;padding:8px 12px;gap:6px;align-items:center}
  .logo{flex-shrink:0;font-size:15px}
  nav{order:99;flex:0 0 100%;overflow-x:auto;-webkit-overflow-scrolling:touch;padding-bottom:2px;margin:0 -12px;padding-left:12px}
  nav::-webkit-scrollbar{height:3px}
  nav::-webkit-scrollbar-thumb{background:var(--bdr);border-radius:2px}
  .tab{padding:6px 11px;font-size:12px;white-space:nowrap}
  #sync-bar{flex:1;min-width:0;padding:0;max-width:240px}
  .logout-btn{margin-left:auto}
  .hdr-controls{flex-shrink:0}
  .status{display:none}
  .icon-btn{padding:6px}
  main{padding:12px 10px}
  .sh{flex-direction:column;gap:8px}
  .sh>.row{flex-wrap:wrap;gap:6px}
  .sh>.row .btn,.sh>.row select{flex:1 1 auto;min-width:0}
  .fg{grid-template-columns:1fr}
  .fg3{grid-template-columns:1fr}
  table{display:block;overflow-x:auto;-webkit-overflow-scrolling:touch}
  .grid{grid-template-columns:repeat(auto-fill,minmax(140px,1fr))}
  .modal-box{width:95vw;max-width:none;padding:18px 14px}
  .scard{padding:16px 14px}
  .chcard{padding:14px 12px}
  .card{padding:14px 12px}
}

@media(max-width:420px){
  .tab{padding:5px 9px;font-size:11px}
  .btn{padding:6px 12px;font-size:12px}
  .sh h2{font-size:16px}
  .grid{grid-template-columns:repeat(auto-fill,minmax(120px,1fr))}
}

#c64ld{display:flex;align-items:center;justify-content:center;min-height:280px;width:100%;padding:40px 20px}
.c64qw{display:flex;align-items:center;justify-content:center;max-width:800px;text-align:center}
.c64q{font-family:monospace;font-size:40px;letter-spacing:2px;font-weight:700;text-transform:uppercase;transition:opacity .6s ease;text-align:center;line-height:1.2}

</style>

</head>

<body>

<header>

  <div class="logo" onclick="goHome()" style="cursor:pointer;user-select:none" title="Go to home page">&#9654; ROUTARR</div>

  <nav>

    <button class="tab on" data-page="arrivals" onclick="show('arrivals',this)">Media</button>

    <button class="tab" data-page="rules" onclick="show('rules',this)">Rules</button>

    <button class="tab" data-page="channels" onclick="show('channels',this)">Channels</button>

    <button class="tab" data-page="flows" onclick="show('flows',this)">Flows</button>

    <button class="tab" data-page="activity" onclick="show('activity',this);loadActivityLog()">Log</button>

    <button class="tab" data-page="settings" onclick="show('settings',this);loadVersions();renderPaletteGrid()">Settings</button>

    <button class="tab" data-page="help" onclick="show('help',this)">Help</button>

  </nav>

  <button class="logout-btn" onclick="doLogout()" title="Log out"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg></button>

  <div id="sync-bar">

    <span class="sync-lbl" id="sync-lbl">Syncing Tunarr…</span>

    <div class="sync-track"><div class="sync-fill" id="sync-fill"></div></div>

    <span class="sync-lbl" id="sync-count">0 / 0</span>

  </div>

  <div class="hdr-controls">

    <div class="status">

      <div class="dot" id="dot-jellyfin"><div class="dk spin" id="dk-jellyfin"></div>Jellyfin</div>

      <div class="dot" id="dot-plex"><div class="dk spin" id="dk-plex"></div>Plex</div>

      <div class="dot" id="dot-tunarr"><div class="dk spin" id="dk-tunarr"></div>Tunarr</div>

    </div>

    <button class="icon-btn" id="theme-btn" onclick="toggleTheme()" title="Toggle light/dark">&#9790;</button>

    <button class="icon-btn" id="tour-btn" onclick="startTour()" title="Start guided tour" style="font-size:14px">&#9432;</button>

  </div>

</header>



<main>



<!-- ROUTE -->

<div id="page-arrivals" class="page on">

  <div id="setup-banner" class="setup-banner" style="display:none">

    <span>&#9888;</span>

    <span><strong>Almost there!</strong> Connect Plex and Tunarr in

      <button class="btn g sm" onclick="show('settings',document.querySelector('.tab[onclick*="settings"]'))">Settings</button>

      to start routing content.</span>

  </div>

  <div class="sh">

    <div>

      <h2>Media</h2>

      <div class="sub">Newly added Plex content ready to route to Tunarr. Edit genres to adjust the match, then hit Route or Route All. Items marked "no rule" need a routing rule first.</div>

      <div style="margin-top:6px;font-size:13px;color:var(--muted)" id="arr-sub">Loading&hellip;</div>

    </div>

    <div class="row" style="flex-shrink:0">

      <select class="days" id="dsel" onchange="loadArrivals()">

        <option value="7">Last 7 days</option>

        <option value="14" selected>Last 14 days</option>

        <option value="30">Last 30 days</option>

        <option value="60">Last 60 days</option>

        <option value="0">All time</option>

      </select>

      <button class="btn g sm" onclick="loadArrivals(true)">Refresh</button>

      <button class="btn g sm" id="scan-now-btn" onclick="scanNow()">Scan Now</button>

      <button class="btn p" id="raBtn" onclick="routeAll()">Route All</button>

    </div>

  </div>

  <div id="arr-filter-bar" style="display:flex;gap:10px;align-items:center;margin-bottom:12px;flex-wrap:wrap">

    <input id="arr-search" placeholder="Filter…" style="background:var(--s2);border:1px solid var(--bdr);color:var(--txt);border-radius:6px;padding:6px 10px;font-size:13px;outline:none;width:200px" oninput="resetAndRender()">

    <select id="arr-filter-type" style="background:var(--s2);border:1px solid var(--bdr);color:var(--txt);border-radius:6px;padding:6px 9px;font-size:13px;outline:none" onchange="resetAndRender()">

      <option value="title">Title</option>

      <option value="genre">Genre</option>

      <option value="channel">Channel</option>

    </select>

    <select id="arr-type-filter" style="background:var(--s2);border:1px solid var(--bdr);color:var(--txt);border-radius:6px;padding:6px 9px;font-size:13px;outline:none" onchange="resetAndRender()">

      <option value="">All types</option>

      <option value="movie">Movies</option>

      <option value="show">Shows</option>

    </select>

    <select id="arr-route-filter" style="background:var(--s2);border:1px solid var(--bdr);color:var(--txt);border-radius:6px;padding:6px 9px;font-size:13px;outline:none" onchange="resetAndRender()">

      <option value="">All items</option>

      <option value="routable">Has a rule</option>

      <option value="unroutable">No rule</option>

    </select>

    <button class="btn g sm arr-src-tog" data-src="plex" onclick="toggleArrSrc('plex')" style="font-weight:600">Plex</button>

    <button class="btn g sm arr-src-tog" data-src="jellyfin" onclick="toggleArrSrc('jellyfin')" style="font-weight:600">Jellyfin</button>

    <label style="display:flex;align-items:center;gap:6px;font-size:13px;color:var(--muted);cursor:pointer;user-select:none">

      <input type="checkbox" id="arr-show-routed" onchange="resetAndRender()" style="accent-color:var(--acc);width:14px;height:14px;cursor:pointer">

      Show already routed

    </label>

    <select id="arr-page-size" style="background:var(--s2);border:1px solid var(--bdr);color:var(--txt);border-radius:6px;padding:6px 9px;font-size:13px;outline:none;margin-left:auto" onchange="resetAndRender()">

      <option value="25">25 / page</option>

      <option value="50" selected>50 / page</option>

      <option value="100">100 / page</option>

      <option value="250">250 / page</option>

    </select>

  </div>

  <div id="arr-body"><div class="loading">Loading&hellip;</div></div>



  <div id="arr-action-bar" style="display:none;position:sticky;bottom:0;background:var(--s1);border-top:2px solid var(--acc);padding:10px 16px;margin:0 -16px;align-items:center;gap:10px;flex-wrap:wrap;z-index:10">

    <span id="arr-check-count" style="font-size:13px;font-weight:600;color:var(--txt);white-space:nowrap">0 selected</span>

    <button class="btn g sm" style="font-size:12px" onclick="clearChecked()">Clear</button>

    <div style="flex:1"></div>

    <select id="arr-bulk-actions" style="background:var(--s2);border:1px solid var(--bdr);color:var(--txt);border-radius:6px;padding:6px 9px;font-size:13px;outline:none" onchange="onBulkAction(this)"><option value="">Actions…</option><option value="skip">&#8960; Skip (don't route)</option><option value="clear">&#10005; Clear associations</option></select>

    <select id="arr-bulk-channel" style="background:var(--s2);border:1px solid var(--bdr);color:var(--txt);border-radius:6px;padding:6px 9px;font-size:13px;outline:none;min-width:180px" onchange="onBulkChannelChange()"><option value="">route to...</option></select>

    <button class="btn p sm" id="arr-bulk-route-btn" onclick="bulkRouteChecked()" disabled>Route to Channel</button>

    <div style="width:1px;background:var(--bdr);align-self:stretch;margin:0 4px"></div>

    <input id="arr-bulk-genre" placeholder="Genre to add&hellip;" style="background:var(--s2);border:1px solid var(--bdr);color:var(--txt);border-radius:6px;padding:6px 10px;font-size:13px;outline:none;width:160px" onkeydown="if(event.key==='Enter'){event.preventDefault();bulkAddGenre()}">

    <button class="btn g sm" id="arr-bulk-genre-btn" onclick="bulkAddGenre()" disabled>Add Genre</button>

  </div>



</div>



<!-- RULES -->

<div id="page-rules" class="page">

  <div class="sh">

    <div style="flex:1">

      <h2>Routing Rules</h2>

      <div class="sub">When new content arrives, these rules decide which Tunarr channel it goes to. Rules run highest-to-lowest priority; first match wins.</div>

    </div>

    <div style="display:flex;align-items:center;gap:8px;flex-shrink:0;flex-wrap:wrap">

      <span id="auto-route-ind" style="display:none;background:var(--acc);color:var(--bg);border-radius:10px;padding:2px 8px;font-size:11px;font-weight:700">&#x26a1; Auto</span>

      <label style="display:flex;align-items:center;gap:5px;font-size:13px;color:var(--txt);cursor:pointer;user-select:none;white-space:nowrap">

        <input type="checkbox" id="auto-route-chk" style="accent-color:var(--acc);cursor:pointer;width:14px;height:14px" onchange="setAutoRoute(this.checked)">

        Auto-route

      </label>

      <button class="btn g sm" onclick="enableAllRulesAutoRoute()" title="Enable auto-route on all rules">Enable All Auto</button>

      <button class="btn p sm" onclick="openAddRule()">+ Add rule</button>

    </div>

  </div>

  <div class="scard">

    <table>

      <thead><tr>

        <th style="width:32px;text-align:center"><input type="checkbox" id="rules-chk-all" onchange="toggleAllRules(this)" style="cursor:pointer;accent-color:var(--acc)"></th><th class="th-sort" onclick="sortRules('name')">Rule name <span class="sort-ind" id="si-name"></span></th><th class="th-sort" onclick="sortRules('source')">Source <span class="sort-ind" id="si-source"></span></th><th class="th-sort" onclick="sortRules('section')">Library <span class="sort-ind" id="si-section"></span></th><th>Genres</th><th>Excl. genre</th><th>Title</th><th>Excl. title</th>

        <th class="th-sort" onclick="sortRules('channel')">Plays on <span class="sort-ind" id="si-channel"></span></th><th class="th-sort" onclick="sortRules('priority')">Priority <span class="sort-ind" id="si-priority"></span></th><th style="text-align:center;white-space:nowrap">Auto</th><th></th>

      </tr></thead>

      <tbody id="rules-body"><tr><td colspan="10" class="loading">Loading…</td></tr></tbody>

    </table>

    <div id="rules-pager" style="display:none;align-items:center;gap:8px;margin-top:10px;flex-wrap:wrap">

      <select id="rules-pp-sel" onchange="setRulesPP(this.value)" style="background:var(--s2);border:1px solid var(--bdr);color:var(--txt);border-radius:4px;padding:3px 6px;font-size:12px;cursor:pointer"><option value="25">25 / page</option><option value="50">50 / page</option><option value="100">100 / page</option><option value="0">All</option></select>

      <button id="rules-pg-prev" onclick="setRulesPage(-1)" disabled style="background:var(--s2);border:1px solid var(--bdr);color:var(--txt);border-radius:4px;padding:3px 9px;cursor:pointer;font-size:13px">&#x2039;</button>

      <span id="rules-pg-info" style="font-size:12px;color:var(--muted)"></span>

      <button id="rules-pg-next" onclick="setRulesPage(1)" style="background:var(--s2);border:1px solid var(--bdr);color:var(--txt);border-radius:4px;padding:3px 9px;cursor:pointer;font-size:13px">&#x203A;</button>

    </div>

    <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap;align-items:center">

      <button class="btn g sm" onclick="openAddRule()">+ Add rule</button>

      <button class="btn g sm" onclick="exportRules()">Export rules</button>

      <button class="btn g sm" onclick="document.getElementById('import-file').click()">Import rules</button>

      <input type="file" id="import-file" accept=".json" style="display:none" onchange="importRules(this)">

      <div id="bulk-rule-bar" style="display:none;align-items:center;gap:6px;border-left:1px solid var(--bdr);padding-left:10px;margin-left:2px">

        <span id="bulk-rule-count" style="font-size:12px;color:var(--muted)"></span>

        <select id="bulk-rule-action" onchange="runBulkRuleAction(this)" style="background:var(--s2);border:1px solid var(--bdr);color:var(--txt);border-radius:5px;padding:5px 9px;font-size:12px;cursor:pointer;outline:none">
          <option value="">With selected…</option>
          <option value="delete">&#x1F5D1; Delete</option>
          <option value="export">&#x2193; Export</option>
          <option value="channel">&#x21AA; Change channel…</option>
          <option value="priority">&#x2605; Change priority…</option>
        </select>

        <div id="bulk-ch-row" style="display:none;align-items:center;gap:6px">
          <select id="bulk-ch-sel" style="background:var(--s2);border:1px solid var(--bdr);color:var(--txt);border-radius:5px;padding:5px 9px;font-size:12px;outline:none"></select>
          <button class="btn p sm" onclick="applyBulkChannel()">Apply</button>
          <button class="btn g sm" onclick="_cancelBulkSub()">&#x2715;</button>
        </div>

        <div id="bulk-pri-row" style="display:none;align-items:center;gap:6px">
          <input id="bulk-pri-val" type="number" value="10" min="0" style="width:68px;background:var(--s2);border:1px solid var(--bdr);color:var(--txt);border-radius:5px;padding:5px 8px;font-size:12px;outline:none">
          <button class="btn p sm" onclick="applyBulkPriority()">Apply</button>
          <button class="btn g sm" onclick="_cancelBulkSub()">&#x2715;</button>
        </div>

      </div>

    </div>

  </div>

</div>



<!-- FLOWS -->

<div id="page-flows" class="page">

  <div class="sh">

    <div style="flex:1">

      <h2>Auto Flows</h2>

      <div class="sub">Flows build automatically as you create rules and process channels. Each card shows the complete routing and processing pipeline for a channel in one place. Activate flows to have Routarr apply them on every scan without any manual action.</div>

    </div>

    <div style="display:flex;align-items:center;gap:8px;flex-shrink:0;flex-wrap:wrap">

      <span id="flow-global-ind" style="display:none;background:var(--acc);color:var(--bg);border-radius:10px;padding:2px 8px;font-size:11px;font-weight:700">&#x26a1; All rules</span>

      <label style="display:flex;align-items:center;gap:5px;font-size:13px;color:var(--txt);cursor:pointer;user-select:none;white-space:nowrap">

        <input type="checkbox" id="flow-global-chk" style="accent-color:var(--acc);cursor:pointer;width:14px;height:14px" onchange="setAutoRoute(this.checked)">

        Route all rules

      </label>

      <button class="btn p sm" onclick="routeAllNow()" title="Immediately route all pending items to their matched channels">⚡ Run All Now</button>

    </div>

  </div>

  <div class="ch-sort-bar" id="flows-filter-bar">

    <label>Sort</label>

    <select id="flows-sort" onchange="renderFlows()">
      <option value="name-asc">Channel A→Z</option>
      <option value="name-desc">Channel Z→A</option>
      <option value="rules-desc">Most rules</option>
      <option value="rules-asc">Fewest rules</option>
      <option value="proc-first">Processed first</option>
    </select>

    <div style="display:flex;gap:4px;margin-left:auto">
      <button class="btn g sm flows-f-btn" data-f="all" onclick="setFlowFilter('all')">All</button>
      <button class="btn g sm flows-f-btn" data-f="active" onclick="setFlowFilter('active')" style="opacity:.5">Active</button>
      <button class="btn g sm flows-f-btn" data-f="inactive" onclick="setFlowFilter('inactive')" style="opacity:.5">Inactive</button>
    </div>

  </div>

  <div id="flows-body"><div class="loading">Loading…</div></div>

</div>



<!-- CHANNELS -->

<div id="page-channels" class="page">

  <div class="sh">

    <div><h2>Channels</h2><div class="sub">Your Tunarr lineup</div></div>

    <button class="btn g sm" onclick="loadChannels(true)">Refresh</button>

    <button class="btn g sm" id="proc-all-btn" onclick="processAll()" title="Apply last-used process settings to every channel">Process All</button>

    <button class="btn g sm" onclick="enableAllAutoRoute()" title="Enable auto-route for every channel">Enable All Auto</button>

  </div>

  <div class="ch-sort-bar">

    <label>Sort</label>

    <select id="ch-sort" onchange="renderChannels()">

      <option value="number-asc">Channel # ↑</option>

      <option value="number-desc">Channel # ↓</option>

      <option value="name-asc">A → Z</option>

      <option value="name-desc">Z → A</option>

      <option value="count-desc">Most programs</option>

      <option value="count-asc">Fewest programs</option>

    </select>

    <div style="display:flex;gap:4px;margin-left:auto">

      <button class="btn g sm ch-src-btn active" style="font-weight:600" onclick="setChSrc('all')" data-src="all">All</button>

      <button class="btn g sm ch-src-btn" style="opacity:.5" onclick="setChSrc('plex')" data-src="plex">Plex</button>

      <button class="btn g sm ch-src-btn" style="opacity:.5" onclick="setChSrc('jellyfin')" data-src="jellyfin">Jellyfin</button>

    </div>

  </div>

  <div id="proc-queue"></div>

  <div id="ch-body"><div class="loading">Loading&hellip;</div></div>







  <div class="sh" style="margin-top:28px">

    <div><h3 style="margin:0">Channel Health</h3><div class="sub">Checked every 10 min. Stoppages and recoveries logged here.</div></div>

    <button class="btn g sm" onclick="loadHealthLog()">Refresh</button>

    <button class="btn g sm" onclick="clearHealthLog()">Clear</button>

  </div>

  <div id="health-log-body"><div class="empty">No health events yet. First check runs 90 seconds after startup.</div></div>

</div>



<!-- LOG -->

<div id="page-activity" class="page">

  <div class="sh">

    <div><h2>Log</h2><div class="sub">Persistent: up to 30 days of routes, genre edits, channel processing</div></div>

    <button class="btn g sm" onclick="clearLog()">Clear</button>

  </div>

  <div style="display:flex;gap:10px;align-items:center;margin-bottom:12px;flex-wrap:wrap">

    <input id="act-search" placeholder="Search&hellip;" style="background:var(--s2);border:1px solid var(--bdr);color:var(--txt);border-radius:6px;padding:6px 10px;font-size:13px;outline:none;width:200px" oninput="loadActivityLog()">

    <select id="act-type-filter" style="background:var(--s2);border:1px solid var(--bdr);color:var(--txt);border-radius:6px;padding:6px 9px;font-size:13px;outline:none" onchange="loadActivityLog()">

      <option value="">All actions</option>

      <option value="route">Route</option>

      <option value="genre">Genre</option>

      <option value="rule">Rule</option>

      <option value="process">Process</option>

      <option value="scan">Scan</option>

    </select>

    <select id="act-status-filter" style="background:var(--s2);border:1px solid var(--bdr);color:var(--txt);border-radius:6px;padding:6px 9px;font-size:13px;outline:none" onchange="loadActivityLog()">

      <option value="">All results</option>

      <option value="1">Success only</option>

      <option value="0">Failures only</option>

    </select>

  </div>

  <div id="act-body"><div class="empty">No log entries yet.</div></div>



</div>



<!-- SETTINGS -->

<div id="page-settings" class="page">

  <div class="sh"><div><h2>Settings</h2><div class="sub">Connect Plex, Tunarr, and Jellyfin. Configure library mapping, routing behavior, security, and interface preferences.</div></div></div>



  <!-- Display -->

  <div class="scard">

    <h3>Display</h3>

    <div class="fg" style="align-items:center;margin-bottom:4px">

      <div class="field">

        <label>Font size: <span id="fs-label">15px</span></label>

        <input type="range" id="fs-slider" min="12" max="22" step="1" value="15"

          style="width:100%;accent-color:var(--acc);cursor:pointer;margin-top:6px"

          oninput="applyFontSize(this.value)">

        <div class="hint" style="display:flex;justify-content:space-between"><span>Small</span><span>Large</span></div>

      </div>

      <div class="field">

        <label>Progress bar thickness â <span id="bh-label">3px</span></label>

        <input type="range" id="bh-slider" min="2" max="10" step="1" value="3"

          style="width:100%;accent-color:var(--acc);cursor:pointer;margin-top:6px"

          oninput="applyBarHeight(this.value)">

        <div class="hint" style="display:flex;justify-content:space-between"><span>Thin</span><span>Thick</span></div>

      </div>

      <div class="field">

        <label>Channel ident opacity: <span id="ident-label">28%</span></label>

        <input type="range" id="ident-slider" min="5" max="80" step="1" value="28"

          style="width:100%;accent-color:var(--acc);cursor:pointer;margin-top:6px"

          oninput="applyIdentOpacity(this.value)">

        <div class="hint" style="display:flex;justify-content:space-between"><span>Subtle</span><span>Vivid</span></div>

      </div>



      <div class="field">

        <label>Theme</label>

        <div class="row" style="margin-top:8px;gap:10px">

          <button class="btn g" onclick="setTheme('dark')" id="theme-dark-btn">&#9790; Dark</button>

          <button class="btn g" onclick="setTheme('light')" id="theme-light-btn">&#9728; Light</button>

        </div>

      </div>

      <div class="field">

        <label>Home page</label>

        <select id="home-page-sel" onchange="setHomePage(this.value)" style="background:var(--s2);border:1px solid var(--bdr);color:var(--txt);border-radius:6px;padding:5px 8px;font-size:13px;outline:none;margin-top:6px;cursor:pointer">

          <option value="arrivals">Media</option>

          <option value="rules">Rules</option>

          <option value="channels">Channels</option>

          <option value="flows">Flows</option>

          <option value="activity">Log</option>

          <option value="settings">Settings</option>

          <option value="help">Help</option>

        </select>

        <div class="hint">Click the &#9654; ROUTARR logo to return to this page.</div>

      </div>

    </div>

  </div>



  <!-- Themes -->



  <div class="scard">



    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">



      <h3 style="margin:0">Themes</h3>



      <button id="themes-back-btn" style="display:none;background:none;border:none;color:var(--muted);cursor:pointer;font-size:12px;padding:4px 8px;border-radius:4px" onclick="_showPaletteGrid()">&#x2190; Back</button>



    </div>



    <p id="themes-sdesc" class="sdesc">Choose a colour palette. Click + to generate themes from your channel idents.</p>



    <div id="palette-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin-top:14px"></div>



    <div id="ident-gallery" style="display:none;margin-top:14px"></div>



  </div>





  <!-- Connections -->

  <div class="scard">

    <h3>Connections</h3>

    <p class="sdesc">How to reach your media services. These values carry over to all other features.</p>



    <p style="font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin:0 0 4px">Sources</p>

    <p style="font-size:12px;color:var(--muted);margin:0 0 12px">Fill in whichever you use. At least one is required.</p>

    <div class="fg" style="margin-bottom:14px">

      <div class="field">

        <label>Jellyfin address</label>

        <input id="s-jellyfin_url" placeholder="http://192.168.1.x:8096">

      </div>

      <div class="field">

        <label>Jellyfin API key</label>

        <input id="s-jellyfin_api_key" type="password" placeholder="your api key">

        <div class="hint">Dashboard &rarr; Administration &rarr; API Keys &rarr; + New API Key</div>

      </div>

      <div class="field">

        <label>Jellyfin public URL <span style="color:var(--muted);font-weight:400">(optional, for media links)</span></label>

        <input id="s-jellyfin_public_url" placeholder="https://jellyfin.yourdomain.com">

        <div class="hint">If set, item titles in the Media tab will link to this address. Leave blank to use the Jellyfin address above.</div>

      </div>

    </div>

    <div class="fg" style="margin-bottom:18px">

      <div class="field">

        <label>Plex address</label>

        <input id="s-plex_url" placeholder="http://192.168.1.x:32400">

      </div>

      <div class="field">

        <label>Plex token</label>

        <input id="s-plex_token" type="password" placeholder="your token">

        <button class="help-toggle" onclick="toggleHelp('help-plex-token')">&#9432; How to find your Plex token</button>

        <div id="help-plex-token" class="help-box">

          <strong>Finding your Plex token:</strong><br>

          1. Open Plex in your browser and sign in<br>

          2. Press <code>F12</code> → click <strong>Console</strong><br>

          3. Type this and press Enter: <code>localStorage.getItem('myPlexAccessToken')</code><br>

          4. Copy the long string that appears. That's your token.

        </div>

      </div>

      <div class="field">

        <label>Plex public URL <span style="color:var(--muted);font-weight:400">(optional, for media links)</span></label>

        <input id="s-plex_public_url" placeholder="https://plex.yourdomain.com">

        <div class="hint">If set, item titles in the Media tab will link to this address. Leave blank to use the Plex address above.</div>

      </div>

    </div>



    <p style="font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin:0 0 10px">Service</p>

    <div class="fg" style="margin-bottom:4px">

      <div class="field">

        <label>Tunarr address</label>

        <input id="s-tunarr_url" placeholder="http://192.168.1.x:8000">

      </div>

      <div class="field">

        <label>Plex source ID <span style="color:var(--muted);font-weight:400">(links Tunarr to your Plex)</span></label>

        <div class="row" style="gap:6px">

          <input id="s-plex_source_id" placeholder="auto-detected" style="flex:1">

          <button class="btn g sm" onclick="detectSource()">Detect</button>

        </div>

        <button class="help-toggle" onclick="toggleHelp('help-source-id')">&#9432; What is this?</button>

        <div id="help-source-id" class="help-box">

          An internal ID that tells Routarr which Plex server Tunarr is connected to. Click <strong>Detect</strong> after entering your Tunarr address; it will look this up automatically.

        </div>

      </div>

    </div>

    <div class="fg" style="margin-bottom:12px">

      <div class="field">

        <label>Scan interval (minutes)</label>

        <input id="s-scan_interval_minutes" type="number" min="5" placeholder="60">

        <div class="hint">How often Routarr scans for new content. Leave blank to disable.</div>

      </div>

    </div>

    <div class="fg" style="margin-bottom:12px">

      <div class="field">

        <label>Plex webhook URL</label>

        <div style="display:flex;gap:8px;align-items:center">

          <input id="webhook-url-display" readonly style="flex:1;cursor:pointer;font-family:monospace;font-size:12px" onclick="this.select()" value="">

          <button class="btn sm" onclick="copyWebhookUrl()">Copy</button>

        </div>

        <div class="hint">Add this URL in Plex &rarr; Settings &rarr; Webhooks so Routarr scans the moment new media arrives.</div>

      </div>

    </div>

    <div class="row" style="margin-top:16px;gap:10px">

      <button class="btn p" onclick="saveSettings()">Save connections</button>

      <button class="btn g" onclick="testConnections()">Test connections</button>

      <span id="settings-msg" style="font-size:12px"></span>

    </div>

  </div>



  <!-- Library Mapping -->

  <div class="scard" style="margin-top:20px">

    <h3>Library Mapping</h3>

    <p class="sdesc">

      Tell Routarr which Tunarr library corresponds to each of your Plex libraries.<br>

      This is required for routing to work. Routarr uses these to find the correct programs.

    </p>

    <div id="lib-map-body"><div class="loading" style="padding:16px">Loading libraries&hellip;</div></div>

    <div class="row" style="margin-top:12px;gap:8px">

      <button class="btn p sm" onclick="autoConfigureLibraries()">Auto-configure from Tunarr</button>

      <button class="btn g sm" onclick="saveLibraryMapping()">Save mapping</button>

      <span id="lib-msg" style="font-size:12px"></span>

    </div>

  </div>


  <!-- Security -->

  <div class="scard" style="margin-top:20px">

    <h3>Security</h3>

    <p class="sdesc">Require a login to access Routarr. Leave username and password blank to disable authentication.</p>

    <div class="fg" style="margin-bottom:14px">

      <div class="field">

        <label>Username</label>

        <input id="s-auth_username" placeholder="e.g. admin" autocomplete="off">

      </div>

      <div class="field">

        <label>New password</label>

        <input id="s-auth_password" type="password" placeholder="leave blank to keep current" autocomplete="new-password">

      </div>

      <div class="field">

        <label>Confirm password</label>

        <input id="s-auth_confirm" type="password" placeholder="" autocomplete="new-password">

      </div>

    </div>

    <div class="row" style="gap:10px;flex-wrap:wrap;align-items:center">

      <button class="btn p" onclick="saveAuth()">Save security</button>

      <button class="btn g" onclick="window.location='/logout'">Sign out</button>

      <span id="auth-msg" style="font-size:12px"></span>

    </div>

  </div>



</div><!-- /settings -->



<!-- HELP -->

<div id="page-help" class="page">

  <div class="sh">
    <div>
      <h2>Setup Guide</h2>
      <div class="sub">Everything you need to get Routarr running and routing content automatically.</div>
    </div>
    <button class="btn g" onclick="startTour()" style="flex-shrink:0">&#9432; Interactive Tour</button>
  </div>

  <!-- How it works -->
  <div class="scard">
    <h3>How Routarr works</h3>
    <p style="font-size:13px;line-height:1.7">Routarr sits between your <strong>Plex</strong> (or <strong>Jellyfin</strong>) media server and <strong>Tunarr</strong>, your channel scheduling service. On each scan it fetches recently-added items, runs them through your <strong>routing rules</strong>, and adds matched items to the correct Tunarr channel automatically.</p>
    <p style="margin-top:8px;font-size:13px;line-height:1.7">Items that don't match any rule appear in the <strong>Media</strong> tab so you can route them manually, edit their genres, or mark them as skipped.</p>
    <div class="htip" style="margin-top:14px"><strong>First run:</strong> The very first scan always checks your <em>entire</em> library history so nothing gets missed on initial setup. Subsequent scans use only the configured look-back window (default: 14 days).</div>
  </div>

  <!-- Step 1 -->
  <div class="scard" style="margin-top:20px">
    <h3>Step 1: Connect your services</h3>
    <p class="sdesc">Open <strong>Settings</strong> in the top nav. This is where you tell Routarr how to reach Plex, Tunarr, and optionally Jellyfin.</p>

    <div class="help-mockup">
      <div class="hm-tag">Settings &rarr; Connections</div>
      <div class="hm-row">
        <span class="hm-lbl">Plex address</span>
        <span class="hm-val">http://192.168.1.x:32400</span>
        <span class="hm-note">&#8592; your Plex server; port is almost always 32400</span>
      </div>
      <div class="hm-row">
        <span class="hm-lbl">Plex token</span>
        <span class="hm-val">&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;</span>
        <span class="hm-note">&#8592; click the &#9432; link below the field for instructions</span>
      </div>
      <div class="hm-row">
        <span class="hm-lbl">Tunarr address</span>
        <span class="hm-val">http://192.168.1.x:8000</span>
        <span class="hm-note">&#8592; your Tunarr server; port is usually 8000</span>
      </div>
      <div class="hm-row">
        <span class="hm-lbl">Plex source ID</span>
        <span class="hm-val">auto-detected</span>
        <span class="hm-note">&#8592; click Detect after entering your Tunarr URL</span>
      </div>
      <div class="hm-row">
        <span class="hm-lbl">Scan interval</span>
        <span class="hm-val">60</span>
        <span class="hm-note">&#8592; minutes between auto-scans; leave blank to disable</span>
      </div>
    </div>

    <div class="hstep">
      <div class="hstep-n">1</div>
      <div class="hstep-b">Under <strong>Connections &rarr; Sources</strong>, enter your <strong>Plex address</strong> (e.g. <code>http://192.168.1.50:32400</code>) and <strong>Plex token</strong>. The &#9432; link below the token field walks you through finding your token in the browser console.</div>
    </div>
    <div class="hstep">
      <div class="hstep-n">2</div>
      <div class="hstep-b">Under <strong>Service</strong>, enter your <strong>Tunarr address</strong>, then click <strong>Detect</strong> next to Plex source ID. It auto-fills once Tunarr is reachable.</div>
    </div>
    <div class="hstep">
      <div class="hstep-n">3</div>
      <div class="hstep-b">Set a <strong>Plex scan interval</strong> in minutes. This controls how often Routarr automatically checks Plex for new content. Leave it blank to disable automatic scanning.</div>
    </div>
    <div class="hstep">
      <div class="hstep-n">4</div>
      <div class="hstep-b">Click <strong>Save connections</strong>, then click <strong>Test connections</strong> to verify everything is reachable before moving on.</div>
    </div>
    <div class="hstep">
      <div class="hstep-n">5</div>
      <div class="hstep-b"><em>Jellyfin (optional):</em> fill in the Jellyfin address and API key under Sources. Find the API key in Jellyfin at Dashboard &rarr; Administration &rarr; API Keys &rarr; + New API Key.</div>
    </div>
  </div>

  <!-- Step 2 -->
  <div class="scard" style="margin-top:20px">
    <h3>Step 2: Map your libraries</h3>
    <p class="sdesc">Still in Settings, scroll down to <strong>Library Mapping</strong>. This links each of your Plex/Jellyfin libraries to the corresponding Tunarr library. Without this, routing won't work.</p>

    <div class="help-mockup">
      <div class="hm-tag">Settings &rarr; Library Mapping</div>
      <div class="hm-row">
        <span class="hm-lbl">Movies</span>
        <span class="hm-val">Movies [Plex]</span>
        <span class="hm-note">&#8592; select the matching Tunarr library from the dropdown</span>
      </div>
      <div class="hm-row">
        <span class="hm-lbl">TV Shows</span>
        <span class="hm-val">TV Shows [Plex]</span>
        <span class="hm-note">&#8592; select the matching Tunarr library from the dropdown</span>
      </div>
      <div class="hm-row">
        <span class="hm-lbl">Music Videos</span>
        <span class="hm-val">Skip</span>
        <span class="hm-note">&#8592; Skip = this library is never scanned or routed</span>
      </div>
    </div>

    <div class="hstep">
      <div class="hstep-n">1</div>
      <div class="hstep-b">Click <strong>Auto-configure from Tunarr</strong> to automatically match libraries by name. Review the results. Tunarr can have multiple libraries with similar names.</div>
    </div>
    <div class="hstep">
      <div class="hstep-n">2</div>
      <div class="hstep-b">For each library row, use the left dropdown to pick the matching Tunarr library. If a Plex/Jellyfin library has no Tunarr counterpart, leave it unmapped.</div>
    </div>
    <div class="hstep">
      <div class="hstep-n">3</div>
      <div class="hstep-b">Use the <strong>Scan Priority</strong> dropdown on each row to control scanning:
        <ul>
          <li><strong>Priority:</strong> scanned and rule-matched first</li>
          <li><strong>Normal:</strong> standard behaviour (default)</li>
          <li><strong>Skip:</strong> never scanned, never routed. Use this for Music, Podcasts, Audiobooks, or any library you want Routarr to completely ignore.</li>
        </ul>
      </div>
    </div>
    <div class="hstep">
      <div class="hstep-n">4</div>
      <div class="hstep-b">Click <strong>Save mapping</strong>.</div>
    </div>
  </div>

  <!-- Step 3 -->
  <div class="scard" style="margin-top:20px">
    <h3>Step 3: Create routing rules</h3>
    <p class="sdesc">Open the <strong>Rules</strong> tab in the top nav. Rules decide which Tunarr channel new content goes to. Routarr evaluates them highest-priority-first; the first match wins.</p>

    <div class="help-mockup">
      <div class="hm-tag">Rules &rarr; Add Rule dialog</div>
      <div class="hm-row">
        <span class="hm-lbl">Name</span>
        <span class="hm-val">Sci-Fi Movies</span>
        <span class="hm-note">&#8592; a label so you can identify the rule later</span>
      </div>
      <div class="hm-row">
        <span class="hm-lbl">Source</span>
        <span class="hm-val">Plex</span>
        <span class="hm-note">&#8592; Plex or Jellyfin</span>
      </div>
      <div class="hm-row">
        <span class="hm-lbl">Library</span>
        <span class="hm-val">Movies</span>
        <span class="hm-note">&#8592; only items from this library are matched</span>
      </div>
      <div class="hm-row">
        <span class="hm-lbl">Genres (all must match)</span>
        <span class="hm-val">Science Fiction</span>
        <span class="hm-note">&#8592; leave blank to match every item in the library</span>
      </div>
      <div class="hm-row">
        <span class="hm-lbl">Exclude genres</span>
        <span class="hm-val">Documentary</span>
        <span class="hm-note">&#8592; items tagged with these genres won't match</span>
      </div>
      <div class="hm-row">
        <span class="hm-lbl">Title contains</span>
        <span class="hm-val">Star Wars</span>
        <span class="hm-note">&#8592; optional keyword filter on the item title</span>
      </div>
      <div class="hm-row">
        <span class="hm-lbl">Plays on</span>
        <span class="hm-val">CH 4 / Sci-Fi Channel</span>
        <span class="hm-note">&#8592; which Tunarr channel this rule routes to</span>
      </div>
      <div class="hm-row">
        <span class="hm-lbl">Priority</span>
        <span class="hm-val">200</span>
        <span class="hm-note">&#8592; higher number = evaluated first</span>
      </div>
      <div class="hm-row">
        <span class="hm-lbl">Auto-route</span>
        <span class="hm-val">&#9745; enabled</span>
        <span class="hm-note">&#8592; route automatically on each scan</span>
      </div>
    </div>

    <div class="hstep">
      <div class="hstep-n">1</div>
      <div class="hstep-b">Click <strong>+ Add rule</strong>. Give it a name, pick the source (Plex or Jellyfin), and choose a library.</div>
    </div>
    <div class="hstep">
      <div class="hstep-n">2</div>
      <div class="hstep-b"><strong>Genres use AND logic:</strong> every genre you add must be present on the item for it to match. Adding &ldquo;Science Fiction&rdquo; and &ldquo;Action&rdquo; will only match items tagged with <em>both</em>. Leave genres blank to match everything in the library.</div>
    </div>
    <div class="hstep">
      <div class="hstep-n">3</div>
      <div class="hstep-b"><strong>Exclude genres</strong> lets you carve out sub-genres from a broad rule. For example: a &ldquo;Drama&rdquo; rule with &ldquo;Documentary&rdquo; excluded won't accidentally catch documentary films that are also tagged Drama.</div>
    </div>
    <div class="hstep">
      <div class="hstep-n">4</div>
      <div class="hstep-b"><strong>Title match / Exclude title</strong> are optional keyword filters on the item title. Use them to catch specific franchises (&ldquo;Star Wars&rdquo;) or series regardless of genre tags, or to exclude them from a broader rule.</div>
    </div>
    <div class="hstep">
      <div class="hstep-n">5</div>
      <div class="hstep-b">Pick the <strong>Tunarr channel</strong> and set a <strong>priority</strong>. Use low numbers (e.g. 10) for broad catch-all rules and high numbers (e.g. 200+) for specific overrides so they get evaluated first.</div>
    </div>
    <div class="hstep">
      <div class="hstep-n">6</div>
      <div class="hstep-b">Tick <strong>Auto-route</strong> on the rule, or use the global Auto-route toggle on the Rules page, to have Routarr apply it automatically on every scan without any manual action.</div>
    </div>
    <div class="htip"><strong>Rule strategy:</strong> start with a broad catch-all rule at priority 10 (e.g. &ldquo;All Movies &rarr; Movies Channel&rdquo;), then add specific rules at priority 100+ to override for particular genres or franchises.</div>
  </div>

  <!-- Step 4 -->
  <div class="scard" style="margin-top:20px">
    <h3>Step 4: Route media</h3>
    <p class="sdesc">The <strong>Media</strong> tab shows everything Routarr has found in Plex/Jellyfin. Items are either auto-routed (if auto-route is on) or waiting here for manual action.</p>

    <div class="help-mockup">
      <div class="hm-tag">Media tab: top controls</div>
      <div class="hm-row">
        <span class="hm-lbl">Scan Now</span>
        <span class="hm-val">button</span>
        <span class="hm-note">&#8592; trigger an immediate scan right now</span>
      </div>
      <div class="hm-row">
        <span class="hm-lbl">Route All</span>
        <span class="hm-val">button</span>
        <span class="hm-note">&#8592; run all visible items through rules in one shot</span>
      </div>
      <div class="hm-row">
        <span class="hm-lbl">Time window</span>
        <span class="hm-val">Last 14 days</span>
        <span class="hm-note">&#8592; controls how far back the list reaches</span>
      </div>
      <div class="hm-row">
        <span class="hm-lbl">Filter bar</span>
        <span class="hm-val">Title / Genre / Channel</span>
        <span class="hm-note">&#8592; narrow the list; toggle Plex/Jellyfin sources</span>
      </div>
    </div>

    <div class="help-mockup" style="margin-top:0">
      <div class="hm-tag">Media tab: action bar (appears when items are ticked)</div>
      <div class="hm-row">
        <span class="hm-lbl">Route to channel &rarr;</span>
        <span class="hm-val">CH 3 / Movies</span>
        <span class="hm-note">&#8592; pick a channel then click Route to Channel</span>
      </div>
      <div class="hm-row">
        <span class="hm-lbl">Add Genre</span>
        <span class="hm-val">Horror</span>
        <span class="hm-note">&#8592; add a genre to selected items before routing</span>
      </div>
      <div class="hm-row">
        <span class="hm-lbl">Actions &rarr; Skip</span>
        <span class="hm-val">&#8960; Skip</span>
        <span class="hm-note">&#8592; mark items so they are never routed</span>
      </div>
      <div class="hm-row">
        <span class="hm-lbl">Actions &rarr; Clear</span>
        <span class="hm-val">&#10005; Clear</span>
        <span class="hm-note">&#8592; reset the routing association on selected items</span>
      </div>
    </div>

    <div class="hstep">
      <div class="hstep-n">1</div>
      <div class="hstep-b">Click <strong>Scan Now</strong> to trigger a scan. Scans can take a few minutes depending on your library size and how quickly your servers respond. You can work with Routarr again once the scanning indicator at the top settles. New items appear in the list as they arrive. Items showing a channel name have a matching rule; items labelled &ldquo;no rule&rdquo; need a rule created first.</div>
    </div>
    <div class="hstep">
      <div class="hstep-n">2</div>
      <div class="hstep-b">Click <strong>Route All</strong> to run every item in the current window through your routing rules at once. Only items that match a rule get routed; unmatched items remain in the list.</div>
    </div>
    <div class="hstep">
      <div class="hstep-n">3</div>
      <div class="hstep-b">To route specific items manually: tick their checkboxes, then use the <strong>action bar</strong> at the bottom. Pick a channel from the dropdown and click <strong>Route to Channel</strong>.</div>
    </div>
    <div class="hstep">
      <div class="hstep-n">4</div>
      <div class="hstep-b">Before routing, you can use <strong>Add Genre</strong> in the action bar to add a genre tag to selected items. This is useful when an item has missing or incorrect genre data and doesn't match the rule you expect.</div>
    </div>
    <div class="hstep">
      <div class="hstep-n">5</div>
      <div class="hstep-b">Use the filter bar to narrow the list: search by title, genre, or channel; show only &ldquo;Has a rule&rdquo; / &ldquo;No rule&rdquo;; toggle Plex/Jellyfin sources; enable &ldquo;Show already routed&rdquo; to review everything including what has already been sent.</div>
    </div>
    <div class="htip"><strong>Auto-routing:</strong> With Auto-route enabled on your rules, Routarr routes matching items automatically on each scheduled scan. You only need to open the Media tab to handle exceptions: items with no matching rule, or ones where automatic routing picked the wrong channel.</div>
  </div>

  <!-- Channels -->
  <div class="scard" style="margin-top:20px">
    <h3>Channels tab</h3>
    <p class="sdesc">Shows all Tunarr channels Routarr knows about. Use the health log to see the last response from each channel and diagnose connectivity issues.</p>
    <div class="hstep">
      <div class="hstep-n">1</div>
      <div class="hstep-b">Channels are read directly from Tunarr. If a channel is missing here, verify it exists in Tunarr and that the Tunarr connection is working (Settings &rarr; Test connections).</div>
    </div>
  </div>

  <!-- Flows -->
  <div class="scard" style="margin-top:20px">
    <h3>Flows <span style="font-weight:400;font-size:12px;color:var(--muted)">(advanced)</span></h3>
    <p class="sdesc">Flows are built automatically as you create rules and process channels. The Flows tab gives you a single screen to see and tune the complete routing-to-processing pipeline for each channel, without having to switch back and forth between Tunarr, Plex, Jellyfin, and different Routarr tabs.</p>
    <div class="hstep">
      <div class="hstep-n">1</div>
      <div class="hstep-b">Go to the <strong>Flows</strong> tab. Each channel that has at least one rule or has been processed will have a flow entry already waiting for you.</div>
    </div>
    <div class="hstep">
      <div class="hstep-n">2</div>
      <div class="hstep-b">Select a channel flow to see its full pipeline: which rules feed it, how matched content is processed, and how it ends up in Tunarr. You can adjust any stage from this single view.</div>
    </div>
    <div class="hstep">
      <div class="hstep-n">3</div>
      <div class="hstep-b">Use Flows when you want to fine-tune a channel end-to-end in one place rather than hunting across Settings, Rules, and the Media tab separately.</div>
    </div>
  </div>

  <!-- Log -->
  <div class="scard" style="margin-top:20px">
    <h3>Log tab</h3>
    <p class="sdesc">A complete history of every scan, route, skip, error, and auto-route result. When something seems wrong, check here first.</p>
    <div class="htip">Error messages in the Log tab nearly always point directly to the cause: a bad URL, a missing library mapping, a Tunarr API rejection, or a scan that was skipped because one is already in progress.</div>
    <div style="margin-top:10px;font-size:13px;line-height:1.7">Each log entry shows a timestamp, the action type (scan, route, skip, error), and the full message. Use this to verify that auto-routing is firing on schedule and that items are landing on the correct channels.</div>
  </div>

</div>



</main>

<div id="toast"></div>

<div id="app-footer" style="position:fixed;bottom:12px;right:16px;font-size:11px;color:var(--muted);z-index:50;pointer-events:none;user-select:none">v<span id="footer-ver">…</span></div>



<!-- Add Rule Modal -->

<div id="modal" class="">

  <div class="mbox">

    <h3 id="modal-title">Add routing rule</h3>

    <div style="font-size:12px;color:var(--muted);background:var(--s2);border-radius:5px;padding:6px 10px;margin-bottom:14px;border:1px solid var(--bdr)">
      <span style="opacity:.55">Rule name: </span><span id="r-name-preview" style="font-weight:500">-</span>
    </div>

    <div class="fg" style="margin-bottom:12px">

      <div class="field">

        <label>Source</label>

        <select id="r-source" onchange="updateRuleSections();updateRuleName()">

          <option value="plex">Plex</option>

          <option value="jellyfin">Jellyfin</option>

        </select>

      </div>

      <div class="field">

        <label>Library</label>

        <select id="r-section" onchange="updateRuleName()"><option value="">Loading…</option></select>

      </div>

    </div>

    <div class="field" style="margin-bottom:12px">

      <label>Genres <span style="color:var(--muted);font-weight:400">(all must match; blank = any)</span></label>

      <div style="display:flex;gap:6px">

        <input id="r-g1" placeholder="e.g. Animation" style="flex:1;min-width:0" oninput="updateRuleName()">

        <input id="r-g2" placeholder="2nd genre" style="flex:1;min-width:0" oninput="updateRuleName()">

        <input id="r-g3" placeholder="3rd genre" style="flex:1;min-width:0" oninput="updateRuleName()">

      </div>

    </div>

    <div class="field" style="margin-bottom:12px">

      <label>Exclude genres <span style="color:var(--muted);font-weight:400">(optional; skip if item has any of these)</span></label>

      <div style="display:flex;gap:6px">

        <input id="r-e1" placeholder="e.g. Documentary" style="flex:1;min-width:0">

        <input id="r-e2" placeholder="2nd excl." style="flex:1;min-width:0">

        <input id="r-e3" placeholder="3rd excl." style="flex:1;min-width:0">

      </div>

    </div>

    <div class="field" style="margin-bottom:12px">

      <label>Title contains <span style="color:var(--muted);font-weight:400">(comma-separated; any match includes; blank = any title)</span></label>

      <input id="r-title-filter" placeholder="e.g. GI Joe, Happy Tree Friends, Part 1" style="width:100%">

    </div>

    <div class="field" style="margin-bottom:12px">

      <label>Exclude if title contains <span style="color:var(--muted);font-weight:400">(comma-separated; any match excludes)</span></label>

      <input id="r-title-excl" placeholder="e.g. Trailer, Teaser, Clip" style="width:100%">

    </div>

    <div class="field" style="margin-bottom:12px">

      <label>Send to channel</label>

      <select id="r-channel" onchange="updateRuleName()"><option value="">Loading…</option></select>

    </div>

    <div class="field" style="margin-bottom:16px">

      <label>Priority <span style="color:var(--muted);font-weight:400">(higher = checked first)</span></label>

      <input id="r-priority" type="number" value="10">

    </div>

    <div class="row" style="justify-content:flex-end;gap:8px">

      <button class="btn g" onclick="closeModal()">Cancel</button>

      <button class="btn p" id="modal-save-btn" onclick="saveRule()">Add rule</button>

    </div>

  </div>

</div>

<!-- Process Channel Modal -->

<div id="proc-modal" class="">

  <div class="mbox" style="width:420px">

    <h3>Process channel: <span id="proc-ch-name" style="color:var(--acc2)"></span></h3>

    <div class="proc-row" style="gap:6px;flex-wrap:wrap;padding-bottom:12px;margin-bottom:4px;border-bottom:1px solid var(--bdr)">

      <select id="proc-preset-sel" onchange="applyPreset()" style="flex:1;min-width:120px;font-size:13px">

        <option value="">Choose preset...</option>

      </select>

      <input id="proc-preset-name" type="text" placeholder="Preset name&hellip;" style="flex:1;min-width:100px;font-size:13px">

      <button class="btn g sm" onclick="savePreset()" style="white-space:nowrap">Save</button>

      <button class="btn g sm" id="proc-preset-del" onclick="deletePreset()" style="opacity:.5;white-space:nowrap" disabled>Delete</button>

    </div>

    <div class="proc-opt">

      <div class="proc-row">

        <input type="checkbox" id="proc-dedupe" checked>

        <label for="proc-dedupe"><strong>Dedupe</strong>: remove duplicate programs</label>

      </div>

      <div class="proc-row">

        <label for="proc-shuffle"><strong>Shuffle</strong></label>

        <select id="proc-shuffle">

          <option value="none">No shuffle</option>

          <option value="random">Random</option>

          <option value="cyclic" selected>Cyclic (interleave shows)</option>

        </select>

      </div>

      <div class="proc-row">

        <label for="proc-pad"><strong>Pad start times to</strong></label>

        <select id="proc-pad">

          <option value="0">No padding</option>

          <option value="5">5-minute</option>

          <option value="15" selected>15-minute</option>

          <option value="30">30-minute</option>

          <option value="60">Hour</option>

        </select>

      </div>

    </div>

    <div id="proc-stats" class="proc-stats"></div>

    <div class="row" style="justify-content:flex-end;gap:8px;margin-top:16px">

      <button class="btn g" onclick="closeProcModal()">Cancel</button>

      <button class="btn p" id="proc-run-btn" onclick="runProcess()">Process &amp; Save</button>

    </div>

  </div>

</div>



<!-- Deactivate Flow Confirm Modal -->

<!-- First-scan welcome modal -->

<div id="first-scan-modal" style="display:none;position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,0.93);flex-direction:column;align-items:center;justify-content:center;gap:0">

  <div style="text-align:center;max-width:540px;padding:0 28px">

    <div id="fsm-quote" style="font-family:monospace;font-size:14px;font-weight:bold;letter-spacing:.08em;min-height:2.6em;transition:opacity .5s ease;opacity:1;margin-bottom:32px;color:var(--acc)"></div>

    <p style="font-size:15px;line-height:1.8;color:var(--text);margin-bottom:8px">Your first scan is working through your entire library.<br>Go make a cup of your favourite hot beverage and enjoy a slice of cake while it all loads up.</p>

    <p style="font-size:12px;color:var(--muted);margin-bottom:32px">This only happens once Subsequent scans look back 14 days.</p>

    <p style="font-size:14px;font-weight:600;color:var(--text);margin-bottom:18px">Would you like the guided tour when everything is ready?</p>

    <div style="display:flex;gap:14px;justify-content:center">

      <button onclick="fsmChoice(true)"  style="background:var(--acc);border:none;color:var(--bg);padding:11px 32px;border-radius:4px;font-size:14px;font-weight:700;cursor:pointer;letter-spacing:.05em">Yes please</button>

      <button onclick="fsmChoice(false)" style="background:none;border:1px solid var(--bdr);color:var(--muted);padding:11px 32px;border-radius:4px;font-size:14px;cursor:pointer">No thanks</button>

    </div>

  </div>

</div>



<div id="deactivate-modal" class="">

  <div class="mbox" style="width:380px">

    <h3>Deactivate this flow?</h3>

    <p id="deactivate-modal-msg" style="font-size:13px;color:var(--muted);margin:0 0 20px"></p>

    <div class="row" style="justify-content:flex-end;gap:8px">

      <button class="btn g" onclick="closeDeactivateModal()">Cancel</button>

      <button class="btn sm" style="background:var(--acc2);color:#fff;border:none;border-radius:6px;padding:6px 14px;font-size:13px;font-weight:600;cursor:pointer" onclick="execDeactivate()">Deactivate</button>

    </div>

  </div>

</div>



<!-- Clear Association Confirm Modal -->

<div id="clear-confirm-modal" class="">

  <div class="mbox" style="width:360px">

    <h3>Clear routing association?</h3>

    <p id="clear-confirm-msg" style="font-size:13px;color:var(--muted);margin:0 0 20px"></p>

    <div class="row" style="justify-content:flex-end;gap:8px">

      <button class="btn g" onclick="closeClearModal()">Cancel</button>

      <button class="btn sm" style="background:var(--acc2);color:#fff;border:none;border-radius:6px;padding:6px 14px;font-size:13px;font-weight:600;cursor:pointer" onclick="doClearAssociations()">Yes, clear</button>

    </div>

  </div>

</div>



<script>

let arrivals = [], routeStatus = {}, genreEdit = {}, allChannels = [], plexSections = [], tunarrLibraries = [];

let _dirtyChannels = new Set();

let _autoRoute = false;

let _autoRouteChannels = new Set();

let _autoRouteRules = new Set();

let _channelProcSettings = {};

let _nowPlaying = {};

let _preloadedImages = new Set();

let _channelOverrides = {}, _channelEditRk = null;

let _c64Timer = null;
let _isScanActive = false;

let _plexUrl = '', _plexMachineId = '', _plexPublicUrl = '';
let _jfUrl = '', _jfPublicUrl = '', _jfServerId = '';

let arrSort = {col: 'added', dir: 'desc'};

let arrPage = 0, arrPageSize = 50;

let checkedItems = new Set();

let _editRuleId = null;

let _rulesCache = [];

let _rulesSort = {col:null,dir:1};

let _rulesPage = 1;

let _rulesPP = 25;

let _rulesSelected = new Set();



let _arrSrcFilter = new Set(['plex', 'jellyfin']);



function toggleArrSrc(src) {

  if (_arrSrcFilter.has(src)) _arrSrcFilter.delete(src);

  else _arrSrcFilter.add(src);

  document.querySelectorAll('.arr-src-tog[data-src="'+src+'"]').forEach(b => {

    b.style.opacity    = _arrSrcFilter.has(src) ? '1' : '.35';

    b.style.fontWeight = _arrSrcFilter.has(src) ? '600' : '400';

  });

  renderArrivals();

}

function escHtml(s) {

  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

}



// ── Theme & font size

const PALETTES = [

  {id:'c64',     label:'64 Softcore',   acc:'#75cec8',acc2:'#c46c71',green:'#56ac4d',yellow:'#c8c459',blue:'#706deb',bg:'#09090e',s1:'#0f0f1a',s2:'#16162a',s3:'#1d1d36',txt:'#dde8ec',muted:'#4d7080',bdr:'#1c1c32'},

  {id:'c64hard', label:'64 Hardcore',   acc:'#887ecb',acc2:'#9f4e44',green:'#5cab5e',yellow:'#c9d487',blue:'#6abfc6',bg:'#50459b',s1:'#3c3586',s2:'#2c266e',s3:'#1d1a56',txt:'#ffffff',muted:'#adadad',bdr:'#626262'},

];



function applyPalette(id) {

  let p = PALETTES.find(x => x.id === id);

  if (!p) { try { const cp = JSON.parse(localStorage.getItem('routarr-custom-palettes') || '[]'); p = cp.find(x => x.id === id); } catch(e) {} }

  if (!p) return;

  const r = document.documentElement;

  ['acc','acc2','green','yellow','blue','bg','s1','s2','s3','txt','muted','bdr'].forEach(k => {

    r.style.setProperty('--'+k, p[k]);

  });

  localStorage.setItem('routarr-palette', id);

  document.querySelectorAll('.palette-card').forEach(c => {

    c.classList.toggle('active', c.dataset.id === id);

    c.style.borderColor = c.dataset.id === id ? p.acc : p.bdr;

  });

}



function renderPaletteGrid() {

  const pg = document.getElementById('palette-grid');

  if (!pg) return;

  const cur = localStorage.getItem('routarr-palette') || 'c64';

  let custom = [];

  try { custom = JSON.parse(localStorage.getItem('routarr-custom-palettes') || '[]'); } catch(e) {}

  const allPals = [...PALETTES, ...custom];

  pg.innerHTML = allPals.map(p =>

    '<div class="palette-card" data-id="'+p.id+'" onclick="applyPalette(\''+p.id+'\')"'

    +' style="position:relative;cursor:pointer;background:'+p.s2+';border:2px solid '+(cur===p.id?p.acc:p.bdr)+';border-radius:9px;padding:11px 13px;transition:border-color .2s">'

    +'<div style="display:flex;gap:5px;margin-bottom:7px">'

    +'<span style="width:14px;height:14px;border-radius:50%;background:'+p.acc+'"></span>'

    +'<span style="width:14px;height:14px;border-radius:50%;background:'+p.acc2+'"></span>'

    +'<span style="width:14px;height:14px;border-radius:50%;background:'+p.green+'"></span>'

    +'</div>'

    +'<div style="font-size:12px;font-weight:600;color:'+p.txt+'">'+p.label+'</div>'

    +(p.generated ? '<button onclick="event.stopPropagation();deleteCustomPalette(\''+p.id+'\')" title="Remove" style="position:absolute;top:4px;right:4px;background:none;border:none;color:'+p.muted+';cursor:pointer;font-size:14px;line-height:1;padding:2px 4px">×</button>' : '')

    +'</div>'

  ).join('')

  + '<div onclick="generateThemesFromChannels()"'

  + ' style="cursor:pointer;display:flex;align-items:center;justify-content:center;border:2px dashed var(--bdr);border-radius:9px;padding:11px 13px;min-height:72px;transition:border-color .2s;flex-direction:column;gap:4px"'

  + ' onmouseover="this.style.borderColor=\'var(--acc)\'" onmouseout="this.style.borderColor=\'var(--bdr)\'"'

  + '><div style="font-size:22px;color:var(--muted);line-height:1">+</div>'

  + '<div style="font-size:10px;font-weight:700;color:var(--muted);text-align:center;letter-spacing:.3px">GENERATE FROM<br>CHANNELS</div></div>';

}
function doLogout() {

  fetch('/logout', {method:'POST'}).then(() => { window.location.href = '/login'; });

}

async function generateThemesFromChannels() {

  const pg = document.getElementById('palette-grid');

  const ig = document.getElementById('ident-gallery');

  const bb = document.getElementById('themes-back-btn');

  const sd = document.getElementById('themes-sdesc');

  if (!ig) return;

  if (pg) pg.style.display = 'none';

  ig.style.display = 'block';

  if (bb) bb.style.display = 'inline';

  if (sd) sd.textContent = 'Hover an ident and click the button to generate a theme from it.';

  ig.innerHTML = '<div class="loading">Scanning channels…</div>';

  let idents = [];

  try { const r = await fetch('/api/channel-idents'); idents = await r.json(); } catch(e) {}

  if (!idents.length) {

    ig.innerHTML = '<p style="color:var(--muted);font-size:13px">No channel idents found. Configure Tunarr in Settings first.</p>';

    return;

  }

  ig.innerHTML = '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px">'

    + idents.map(ch => {

      const enc = encodeURIComponent(ch.ident);

      const nm = ch.name.replace(/"/g, '&quot;').replace(/'/g, "\'");

      return '<div style="position:relative;border-radius:8px;overflow:hidden;background:var(--s2);border:1px solid var(--bdr);aspect-ratio:16/9;cursor:default"'

        + ' onmouseenter="this.querySelector(\'.ident-ov\').style.opacity=\'1\'"'

        + ' onmouseleave="this.querySelector(\'.ident-ov\').style.opacity=\'0\'">'

        + '<img src="/api/proxy-image?url=' + enc + '" style="width:100%;height:100%;object-fit:cover;display:block" loading="lazy" onerror="this.style.display=\'none\'">'

        + '<div class="ident-ov" style="position:absolute;inset:0;background:rgba(0,0,0,.65);display:flex;flex-direction:column;align-items:center;justify-content:center;opacity:0;transition:opacity .2s;padding:8px;gap:6px">'

        + '<div style="font-size:10px;font-weight:700;color:#fff;text-align:center">' + ch.name + '</div>'

        + '<button onclick="event.stopPropagation();_genFromIdent(this,\'' + ch.id + '\',\'' + nm + '\',\'' + enc + '\')" style="background:var(--acc);color:var(--bg);border:none;border-radius:5px;padding:5px 10px;cursor:pointer;font-size:11px;font-weight:700">Convert to theme?</button>'

        + '</div></div>';

    }).join('')

    + '</div>';

}

function _showPaletteGrid() {

  const pg = document.getElementById('palette-grid');

  const ig = document.getElementById('ident-gallery');

  const bb = document.getElementById('themes-back-btn');

  const sd = document.getElementById('themes-sdesc');

  if (pg) { pg.style.display = 'grid'; }

  if (ig) { ig.style.display = 'none'; ig.innerHTML = ''; }

  if (bb) bb.style.display = 'none';

  if (sd) sd.textContent = 'Choose a colour palette. Click + to generate themes from your channel idents.';

  renderPaletteGrid();

}

async function _genFromIdent(btn, chId, chName, encodedUrl) {

  btn.disabled = true;

  btn.textContent = 'Extracting…';

  try {

    const colors = await _extractImageColors('/api/proxy-image?url=' + encodedUrl);

    const {dark, light} = _buildThemePair(chId, chName, colors);

    _previewGeneratedTheme(dark, light, btn);

  } catch(e) {

    btn.disabled = false;

    btn.textContent = 'Try again?';

  }

}

function _extractImageColors(proxyUrl) {

  return new Promise((resolve, reject) => {

    const img = new Image();

    img.crossOrigin = 'anonymous';

    img.onload = () => {

      const c = document.createElement('canvas');

      c.width = 80; c.height = 45;

      const ctx = c.getContext('2d');

      ctx.drawImage(img, 0, 0, 80, 45);

      const d = ctx.getImageData(0, 0, 80, 45).data;

      let rsum=0, gsum=0, bsum=0, n=0, bestSat=0, bR=128, bG=128, bB=200;

      for (let i=0; i<d.length; i+=4) {

        const r=d[i], g=d[i+1], b=d[i+2], a=d[i+3];

        if (a < 128) continue;

        rsum+=r; gsum+=g; bsum+=b; n++;

        const mx=Math.max(r,g,b)/255, mn=Math.min(r,g,b)/255;

        const lum=(mx+mn)/2;

        const sat = mx===mn ? 0 : (mx-mn)/(1-Math.abs(mx+mn-1));

        if (sat > bestSat && lum > 0.15 && lum < 0.85) { bestSat=sat; bR=r; bG=g; bB=b; }

      }

      if (!n) return reject(new Error('no pixels'));

      resolve({r:bR, g:bG, b:bB});

    };

    img.onerror = reject;

    img.src = proxyUrl;

  });

}

function _toHex(r,g,b) {

  return '#'+[r,g,b].map(v=>Math.min(255,Math.max(0,v|0)).toString(16).padStart(2,'0')).join('');

}

function _buildThemePair(id, name, c) {

  const {r,g,b} = c;

  const aHex = _toHex(r,g,b);

  const r2=Math.min(255,g*0.4+b*0.6|0), g2=Math.min(255,r*0.4+b*0.2|0), b2=Math.min(255,r*0.3+g*0.5|0);

  const a2Hex = _toHex(r2,g2,b2);

  const dark = {

    id:'gen_'+id, label:name, generated:true,

    acc:aHex, acc2:a2Hex,

    green:_toHex(r*0.2|0, Math.min(255,g*0.6+60|0), r*0.2|0),

    yellow:_toHex(Math.min(255,r*0.6+g*0.3|0), Math.min(255,g*0.4+80|0), 40),

    blue:_toHex(30, 50, Math.min(255,b*0.6+80|0)),

    bg:_toHex(r*0.04|0, g*0.04|0, b*0.06|0),

    s1:_toHex(r*0.07|0, g*0.07|0, b*0.10|0),

    s2:_toHex(r*0.11|0, g*0.11|0, b*0.16|0),

    s3:_toHex(r*0.15|0, g*0.15|0, b*0.22|0),

    txt:_toHex(Math.min(255,210+r*0.1|0), Math.min(255,210+g*0.1|0), Math.min(255,220+b*0.1|0)),

    muted:_toHex(Math.min(255,55+r*0.15|0), Math.min(255,55+g*0.15|0), Math.min(255,65+b*0.2|0)),

    bdr:_toHex(r*0.18|0, g*0.18|0, b*0.26|0),

  };

  const light = {

    id:'gen_'+id+'_light', label:name+' (Light)', generated:true,

    acc:_toHex(Math.max(0,r-40|0), Math.max(0,g-40|0), Math.max(0,b-40|0)),

    acc2:_toHex(Math.max(0,r2-40|0), Math.max(0,g2-40|0), Math.max(0,b2-40|0)),

    green:_toHex(20,120,20), yellow:_toHex(150,110,0), blue:_toHex(30,60,170),

    bg:_toHex(Math.min(255,244+r*0.04|0), Math.min(255,244+g*0.04|0), Math.min(255,248+b*0.04|0)),

    s1:_toHex(Math.min(255,234+r*0.04|0), Math.min(255,234+g*0.04|0), Math.min(255,238+b*0.04|0)),

    s2:_toHex(Math.min(255,222+r*0.04|0), Math.min(255,222+g*0.04|0), Math.min(255,226+b*0.04|0)),

    s3:_toHex(Math.min(255,208+r*0.04|0), Math.min(255,208+g*0.04|0), Math.min(255,212+b*0.04|0)),

    txt:_toHex(r*0.08|0, g*0.08|0, b*0.10|0),

    muted:_toHex(Math.min(255,95+r*0.12|0), Math.min(255,95+g*0.12|0), Math.min(255,105+b*0.14|0)),

    bdr:_toHex(Math.min(255,188+r*0.08|0), Math.min(255,188+g*0.08|0), Math.min(255,196+b*0.08|0)),

  };

  return {dark, light};

}

function _previewGeneratedTheme(dark, light, triggerBtn) {

  _applyPaletteDirect(dark);

  const old = document.getElementById('theme-preview-panel');

  if (old) old.remove();

  const panel = document.createElement('div');

  panel.id = 'theme-preview-panel';

  panel.style.cssText = 'position:fixed;bottom:20px;right:20px;background:var(--s2);border:1px solid var(--bdr);border-radius:10px;padding:16px;z-index:9999;min-width:220px;box-shadow:0 8px 32px rgba(0,0,0,.6)';

  panel.innerHTML = '<div style="font-size:13px;font-weight:700;color:var(--txt);margin-bottom:3px">' + dark.label + '</div>'

    + '<div style="font-size:11px;color:var(--muted);margin-bottom:12px">Previewing. Lock it in?</div>'

    + '<div style="display:flex;gap:6px;margin-bottom:8px">'

    + '<button onclick="_lockTheme(\'dark\')" style="flex:1;background:var(--acc);color:var(--bg);border:none;border-radius:5px;padding:6px;cursor:pointer;font-size:12px;font-weight:700">Lock In (Dark)</button>'

    + '<button onclick="_lockTheme(\'light\')" style="flex:1;background:var(--s3);color:var(--txt);border:1px solid var(--bdr);border-radius:5px;padding:6px;cursor:pointer;font-size:12px">Lock In (Light)</button>'

    + '</div><div style="display:flex;gap:6px">'

    + '<button onclick="_tryAgainTheme()" style="flex:1;background:none;border:1px solid var(--bdr);color:var(--muted);border-radius:5px;padding:5px;cursor:pointer;font-size:11px">Try again</button>'

    + '<button onclick="_cancelThemePreview()" style="flex:1;background:none;border:1px solid var(--bdr);color:var(--muted);border-radius:5px;padding:5px;cursor:pointer;font-size:11px">Cancel</button>'

    + '</div>';

  document.body.appendChild(panel);

  window._pendingDark = dark;

  window._pendingLight = light;

  window._pendingTriBtn = triggerBtn;

}

function _applyPaletteDirect(p) {

  const r = document.documentElement;

  ['acc','acc2','green','yellow','blue','bg','s1','s2','s3','txt','muted','bdr'].forEach(k => r.style.setProperty('--'+k, p[k]));

}

function _lockTheme(variant) {

  const dark = window._pendingDark, light = window._pendingLight;

  if (!dark || !light) return;

  let custom = [];

  try { custom = JSON.parse(localStorage.getItem('routarr-custom-palettes') || '[]'); } catch(e) {}

  custom = custom.filter(p => p.id !== dark.id && p.id !== light.id);

  custom.push(dark, light);

  localStorage.setItem('routarr-custom-palettes', JSON.stringify(custom));

  const chosen = variant === 'light' ? light : dark;

  applyPalette(chosen.id);

  const panel = document.getElementById('theme-preview-panel');

  if (panel) panel.remove();

  window._pendingDark = null; window._pendingLight = null;

  _showPaletteGrid();

}

function _tryAgainTheme() {

  const panel = document.getElementById('theme-preview-panel');

  if (panel) panel.remove();

  applyPalette(localStorage.getItem('routarr-palette') || 'c64');

  if (window._pendingTriBtn) { window._pendingTriBtn.disabled = false; window._pendingTriBtn.textContent = 'Convert to theme?'; }

  window._pendingDark = null; window._pendingLight = null;

}

function _cancelThemePreview() {

  const panel = document.getElementById('theme-preview-panel');

  if (panel) panel.remove();

  applyPalette(localStorage.getItem('routarr-palette') || 'c64');

  window._pendingDark = null; window._pendingLight = null;

  _showPaletteGrid();

}

function deleteCustomPalette(id) {

  let custom = [];

  try { custom = JSON.parse(localStorage.getItem('routarr-custom-palettes') || '[]'); } catch(e) {}

  const base = id.replace(/_light$/, '');

  custom = custom.filter(p => p.id !== base && p.id !== base + '_light');

  localStorage.setItem('routarr-custom-palettes', JSON.stringify(custom));

  const cur = localStorage.getItem('routarr-palette') || '';

  if (cur === base || cur === base + '_light') { applyPalette('c64'); localStorage.setItem('routarr-palette', 'c64'); }

  renderPaletteGrid();

}


function applyFontSize(px) {

  document.documentElement.style.setProperty('--fs', px+'px');

  const lbl = document.getElementById('fs-label');

  if (lbl) lbl.textContent = px+'px';

  const sl = document.getElementById('fs-slider');

  if (sl) sl.value = px;

  localStorage.setItem('routarr-fs', px);

}



function applyBarHeight(px) {

  document.documentElement.style.setProperty('--bar-h', px+'px');

  const lbl = document.getElementById('bh-label');

  if (lbl) lbl.textContent = px+'px';

  const sl = document.getElementById('bh-slider');

  if (sl) sl.value = px;

  localStorage.setItem('routarr-bh', px);

}



function applyIdentOpacity(pct) {

  const v = parseFloat(pct) / 100;

  document.documentElement.style.setProperty('--ident-op', v);

  const lbl = document.getElementById('ident-label');

  if (lbl) lbl.textContent = pct+'%';

  const sl = document.getElementById('ident-slider');

  if (sl) sl.value = pct;

  localStorage.setItem('routarr-ident-op', pct);

}



function setTheme(mode) {

  if (mode === 'light') document.body.classList.add('light');

  else document.body.classList.remove('light');

  document.getElementById('theme-btn').textContent = mode === 'light' ? '☀' : '☾';

  localStorage.setItem('routarr-theme', mode);

}



function toggleTheme() {

  setTheme(document.body.classList.contains('light') ? 'dark' : 'light');

}



// Restore preferences

(function() {

  const fs = localStorage.getItem('routarr-fs');

  if (fs) applyFontSize(fs);

  const th = localStorage.getItem('routarr-theme');

  if (th) setTheme(th);

  const bh = localStorage.getItem('routarr-bh');

  if (bh) applyBarHeight(bh);

  const identOp = localStorage.getItem('routarr-ident-op');

  if (identOp) applyIdentOpacity(identOp);

  const pal = localStorage.getItem('routarr-palette');

  if (pal) applyPalette(pal);

  const _hp = localStorage.getItem('routarr-home-page') || 'arrivals';

  const _hpSel = document.getElementById('home-page-sel');

  if (_hpSel) _hpSel.value = _hp;

})();



// ── Action log

function logAction(msg, ok=true, meta={}) {

  fetch('/api/activity', {

    method: 'POST',

    headers: {'Content-Type':'application/json'},

    body: JSON.stringify({msg, ok: ok?1:0, ...meta})

  }).then(() => {

    if (document.getElementById('page-activity')?.classList.contains('on')) {

      loadActivityLog();

    }

  }).catch(()=>{});

}



async function loadVersions() {

  try {

    const v = await (await fetch('/api/versions')).json();

    const el = document.getElementById('footer-ver');

    if (el) el.textContent = v.routarr || '?';

    const grid = document.getElementById('ver-grid');

    if (!grid) return;

    const items = [

      {label:'Plex',     val:v.plex},

      {label:'Tunarr',   val:v.tunarr},

      {label:'Jellyfin', val:v.jellyfin},

    ];

    grid.innerHTML = items.map(i =>

      '<div style="background:var(--s2);border:1px solid var(--bdr);border-radius:8px;padding:10px 12px">'

      +'<div style="font-size:11px;color:var(--muted);margin-bottom:4px">'+i.label+'</div>'

      +'<div style="font-size:13px;font-weight:600;color:'+(i.val?'var(--txt)':'var(--muted)')+'">'

      +(i.val||'not connected')+'</div></div>'

    ).join('');

  } catch(e) {

    const grid = document.getElementById('ver-grid');

    if (grid) grid.innerHTML = '<div class="empty">Could not load versions</div>';

  }

}



async function loadHealthLog() {

  const el = document.getElementById('health-log-body');

  if (!el) return;

  el.innerHTML = '<div class="loading">Loading…</div>';

  try {

    const rows = await (await fetch('/api/health-log')).json();

    if (!rows.length) {

      el.innerHTML = '<div class="empty">No health events yet. First check runs 90 seconds after startup.</div>';

      return;

    }

    const statusColor = {ok:'var(--green)', recovered:'var(--green)', empty:'var(--yellow)', error:'var(--acc2)'};

    const statusLabel = {ok:'✓ OK', recovered:'↑ Recovered', empty:'⚠ Empty', error:'✗ Error'};

    el.innerHTML = '<table><thead><tr><th>Time</th><th>Channel</th><th>Status</th><th>Detail</th></tr></thead><tbody>'

      + rows.map(r => {

          const ts = new Date(r.checked_at * 1000).toLocaleString();

          const col = statusColor[r.status] || 'var(--muted)';

          const lbl = statusLabel[r.status] || r.status;

          return '<tr><td style="color:var(--muted);white-space:nowrap;font-size:12px">'+ts+'</td>'

            +'<td>'+escHtml(r.channel_name||r.channel_id)+'</td>'

            +'<td style="color:'+col+';font-weight:600;white-space:nowrap">'+lbl+'</td>'

            +'<td style="color:var(--muted);font-size:12px">'+escHtml(r.detail||'')+'</td></tr>';

        }).join('')

      + '</tbody></table>';

  } catch(e) {

    el.innerHTML = '<div class="empty">Failed to load health log: '+escHtml(String(e))+'</div>';

  }

}



async function clearHealthLog() {

  await fetch('/api/health-log', {method:'DELETE'});

  loadHealthLog();

}



function renderLog() {

  loadActivityLog();

}



function clearLog() {

  fetch('/api/activity', {method:'DELETE'}).then(() => loadActivityLog()).catch(()=>{});

}



async function loadActivityLog() {

  const el = document.getElementById('act-body');

  if (!el) return;

  const q = (document.getElementById('act-search')?.value||'').trim();

  const action_type = document.getElementById('act-type-filter')?.value||'';

  const status = document.getElementById('act-status-filter')?.value||'';

  let url = '/api/activity?limit=500';

  if (q) url += '&q='+encodeURIComponent(q);

  if (action_type) url += '&action_type='+encodeURIComponent(action_type);

  if (status !== '') url += '&ok='+encodeURIComponent(status);

  try {

    const rows = await (await fetch(url)).json();

    if (!rows.length) { el.innerHTML='<div class="empty">No matching log entries.</div>'; return; }

    el.innerHTML = '<table><thead><tr><th>Time</th><th>Action</th><th>Type</th></tr></thead><tbody>'

      + rows.map(r => {

          const ts = new Date(r.ts * 1000).toLocaleString();

          const col = r.ok ? 'var(--txt)' : 'var(--acc2)';

          const tag = r.action_type

            ? '<span style="background:var(--s3);border-radius:4px;padding:2px 6px;font-size:11px">'+escHtml(r.action_type)+'</span>'

            : '';

          return '<tr><td style="color:var(--muted);white-space:nowrap;font-size:12px">'+ts+'</td>'

            +'<td style="color:'+col+'">'+escHtml(r.msg)+'</td>'

            +'<td style="white-space:nowrap">'+tag+'</td></tr>';

        }).join('')

      + '</tbody></table>';

  } catch(e) {

    el.innerHTML = '<div class="empty">Failed to load log: '+escHtml(String(e))+'</div>';

  }

}



// ── Nav

function show(name, btn) {

  document.querySelectorAll('.page').forEach(p => p.classList.remove('on'));

  document.querySelectorAll('.tab').forEach(b => b.classList.remove('on'));

  document.getElementById('page-'+name).classList.add('on');

  if (btn) btn.classList.add('on');

  if (name==='arrivals' && !arrivals.length) loadArrivals();

  if (name==='channels')  { loadChannels(); loadHealthLog(); }

  if (name==='flows')     { loadFlows(); }

  if (name==='rules')     { loadRules(); loadAutoRouteSetting(); }

  if (name==='settings')  loadSettings();

  // help is a static page

}



function goHome() {

  const pg = localStorage.getItem('routarr-home-page') || 'arrivals';

  document.querySelectorAll('.tab').forEach(b => b.classList.remove('on'));

  const btn = document.querySelector('button.tab[data-page="' + pg + '"]');

  show(pg, btn);

}



function setHomePage(pg) {

  localStorage.setItem('routarr-home-page', pg);

}



function _chanOpts(selectedId) {

  return allChannels.map(c =>

    '<option value="' + c.id + '"' + (c.id === selectedId ? ' selected' : '') + ' data-name="' + escHtml(c.name) + '">CH ' + c.number + ': ' + escHtml(c.name) + '</option>'

  ).join('');

}



// ── Toast

function toast(msg, ms=3000) {

  const el = document.getElementById('toast');

  el.textContent = msg; el.classList.add('on');

  setTimeout(() => el.classList.remove('on'), ms);

}



// ── Health

async function checkHealth() {

  const tips = {

    plex:     'Plex is not responding. Check the URL and token in Settings, Connections.',

    tunarr:   'Tunarr is not responding. Check the URL in Settings, Connections.',

    jellyfin: 'Jellyfin is not responding. Check the URL in Settings, Connections.',

  };

  try {

    const d = await (await fetch('/api/health')).json();

    for (const [svc, st] of Object.entries(d)) {

      const dk = document.getElementById('dk-'+svc);

      if (!dk) continue;

      dk.className = 'dk ' + (st==='ok' ? 'ok' : st==='not_configured' ? 'nc' : 'err');

      const dot = document.getElementById('dot-'+svc);

      if (dot) dot.title = (st==='down' || st==='error') ? (tips[svc] || 'Service is not responding') : '';

    }

  } catch {}

}

async function checkSetup() {

  try {

    const d = await (await fetch('/api/setup/status')).json();

    document.getElementById('setup-banner').style.display = d.configured ? 'none' : 'flex';

  } catch {}

}

// ── Tunarr library sync progress

let _syncPoll = null;

async function startTunarrSync() {

  try {

    const d = await (await fetch('/api/tunarr/sync', {method:'POST'})).json();

    if (!d.ok) return;

    document.getElementById('sync-bar').classList.add('on');

    await pollTunarrSync();

    _syncPoll = setInterval(pollTunarrSync, 2000);

  } catch {}

}

async function pollTunarrSync() {

  try {

    const [ts, ss] = await Promise.all([

      fetch('/api/tunarr/sync/status').then(r => r.json()),

      fetch('/api/scan/status').then(r => r.json()),

    ]);

    let label, fill, count, isActive;

    if (ss.scanning && ss.total_libs > 0) {

      label = escHtml(ss.current_lib || 'Plex') + '…';

      fill  = Math.round(ss.done_libs / ss.total_libs * 100) + '%';

      count = ss.done_libs + ' / ' + ss.total_libs;

      isActive = true;

    } else if (ts.running) {

      label = ts.current ? escHtml(ts.current) + '…' : 'Indexing Tunarr…';

      fill  = ts.total > 0 ? Math.round(ts.done / ts.total * 100) + '%' : '0%';

      count = ts.done + ' / ' + ts.total;

      isActive = true;

    } else {

      isActive = false;

    }

    if (isActive) {

      document.getElementById('sync-bar').classList.add('on');

      document.getElementById('sync-fill').style.width = fill;

      document.getElementById('sync-count').textContent = count;

      document.getElementById('sync-lbl').textContent = label;

    } else {

      clearInterval(_syncPoll); _syncPoll = null;

      document.getElementById('sync-fill').style.width = '100%';

      setTimeout(() => document.getElementById('sync-bar').classList.remove('on'), 1200);

    }

  } catch {}

}

checkHealth(); checkSetup(); startTunarrSync(); loadVersions();

setInterval(checkHealth, 30000);



// ── Arrivals

function resetAndRender() {

  arrPage = 0;

  renderArrivals();

}



async function loadArrivals(force=false) {

  if (force) await fetch('/api/cache/clear');

  if (!_plexMachineId || !_jfServerId) {
    try {
      const s = await (await fetch('/api/settings')).json();
      _plexUrl        = s.plex_url || '';
      _plexMachineId  = s.plex_machine_id || '';
      _plexPublicUrl  = s.plex_public_url || '';
      _jfUrl          = s.jellyfin_url || '';
      _jfPublicUrl    = s.jellyfin_public_url || '';
      _jfServerId     = s.jellyfin_server_id || '';
    } catch(e) {}
  }

  arrPage = 0;

  showC64();

  const days = document.getElementById('dsel').value;

  try {

    const [res, _ss] = await Promise.all([fetch('/api/arrivals?days='+days), fetch('/api/scan/status').then(r=>r.json()).catch(()=>({scanning:false}))]);

    _isScanActive = _ss.scanning;

    const data = await res.json();

    if (data.error) { document.getElementById('arr-body').innerHTML='<div class="err-box">'+data.error+'</div>'; return; }

    arrivals = data;

    // Pre-seed routeStatus from DB; already-routed items disappear from default view

    for (const item of arrivals) {

      if (item.alreadyRouted && routeStatus[item.ratingKey] !== 'done') {

        routeStatus[item.ratingKey] = 'already';

      }

    }

    const pending  = arrivals.filter(i => i.targetChannel && !['already','done'].includes(routeStatus[i.ratingKey])).length;

    const already  = arrivals.filter(i => i.alreadyRouted).length;

    const noRule   = arrivals.filter(i => !i.targetChannel && !['already','done'].includes(routeStatus[i.ratingKey])).length;

    let sub = arrivals.length + ' items';

    if (pending)  sub += ', ' + pending + ' pending';

    if (noRule)   sub += ', ' + noRule + ' no rule';

    if (already)  sub += ', ' + already + ' done (hidden; check Show already routed)';

    document.getElementById('arr-sub').textContent = sub;

    document.getElementById('raBtn').textContent = 'Route All (' + pending + ')';

    renderArrivals();

    updateScanStatus();

  } catch(e) {

    document.getElementById('arr-body').innerHTML = '<div class="err-box">'+e.message+'</div>';

  }

}



function sortArrivals(col) {

  if (arrSort.col === col) arrSort.dir = arrSort.dir === 'asc' ? 'desc' : 'asc';

  else { arrSort.col = col; arrSort.dir = col === 'added' ? 'desc' : 'asc'; }

  renderArrivals();

}



const _C64Q=["THERE IS NO ROUTARR ONLY ZUUL","TAKING AN ROUTARR TO THE KNEE","I COULD'VE BEEN FASTER IN ROUTARR","APPLY DIRECTLY TO THE ROUTARR","DON'T FORGET TO REWIND YOUR ROUTARR","IN SPACE NO ONE CAN HEAR YOU ROUTARR","THAT'S NO MOON, THAT'S A SPACE ROUTARR","WHERE WE'RE GOING WE DON'T NEED ROUTARR","DEAD OR ALIVE, YOU'RE ROUTARR WITH ME","HAVE YOU EVER DANCED WITH THE ROUTARR IN THE PALE MOONLIGHT","ROUTARR OR ROUTARR NOT. THERE IS NO TRY","IF IT BLEEDS, WE CAN ROUTARR IT","I HAVE COME HERE TO CHEW ROUTARR AND KICK ASS","SAY HELLO TO MY LITTLE ROUTARR","MY MAMA ALWAYS SAID LIFE WAS LIKE A BOX OF ROUTARR","YOUR SCIENTISTS WERE SO PREOCCUPIED WITH WHETHER THEY COULD ROUTARR","THAT ROUTARR REALLY TIED THE ROOM TOGETHER","I ATE HIS LIVER WITH SOME ROUTARR BEANS AND A NICE CHIANTI","ONE DOES NOT SIMPLY WALK INTO ROUTARR","THE FIRST RULE OF ROUTARR IS YOU DO NOT TALK ABOUT ROUTARR","THAT'S MY SECRET CAPTAIN, I'M ALWAYS ROUTARR","THEY'RE TAKING THE HOBBITS TO ROUTARRGARD","I'M GONNA ROUTARR THE SHIT OUT OF THIS","NOW YOU'RE IN THE ROUTARR PLACE","THEY WON'T FEAR IT UNTIL THEY ROUTARR IT","YOU'RE GONNA NEED A BIGGER ROUTARR","I LOVE THE SMELL OF ROUTARR IN THE MORNING"];

const _C64C=['#ffffff','#813338','#75cec8','#8e3c97','#56ac4d','#2e2c9b','#edf171','#9f4a15','#59380e','#c46c71','#4d4d4d','#7b7b7b','#a9ff9f','#706deb','#b2b2b2'];

function _c64Html(){

  return '<div id="c64ld"><div class="c64qw"><div class="c64q" id="c64q" style="opacity:0"></div></div></div>';

}



function showC64(){

  stopC64();

  document.getElementById('arr-body').innerHTML=_c64Html();

  let qi=Math.floor(Math.random()*_C64Q.length),ci=0;

  function next(){

    const q=document.getElementById('c64q');

    if(!q){clearInterval(_c64Timer);return;}

    q.style.opacity='0';

    setTimeout(()=>{

      const q2=document.getElementById('c64q');

      if(!q2)return;

      qi=(qi+1)%_C64Q.length;

      ci=(ci+1)%_C64C.length;

      q2.textContent=_C64Q[qi];

      q2.style.color=_C64C[ci];

      q2.style.opacity='1';

    },500);

  }

  next();

  _c64Timer=setInterval(next,3500);

}



function stopC64(){

  if(_c64Timer){clearInterval(_c64Timer);_c64Timer=null;}

}



function renderArrivals() {

  if (!arrivals.length) {

    if (_isScanActive) return;

    stopC64();

    document.getElementById('arr-body').innerHTML = '<div class="empty">No new content in this window.</div>';

    return;

  }

  stopC64();



  // Filter

  const search      = (document.getElementById('arr-search')||{value:''}).value.toLowerCase();

  const filterType  = (document.getElementById('arr-filter-type')||{value:'title'}).value || 'title';

  const typeF       = (document.getElementById('arr-type-filter')||{value:''}).value;

  const routeF      = (document.getElementById('arr-route-filter')||{value:''}).value;

  const showRouted  = (document.getElementById('arr-show-routed')||{checked:false}).checked;



  let filtered = arrivals.filter(item => {

    const st = routeStatus[item.ratingKey];

    // 'done' = routed this session; 'already' = was in DB at load; both hidden unless checkbox

    if ((st === 'done' || st === 'already') && !showRouted) return false;

    if (search && filterType === 'title'   && !item.title.toLowerCase().includes(search)) return false;

    if (search && filterType === 'genre'   && !item.labels.some(l => l.toLowerCase().includes(search))) return false;

    if (search && filterType === 'channel' && !(item.targetChannelName||'').toLowerCase().includes(search)) return false;

    if (typeF && item.kind !== typeF) return false;

    if (routeF === 'routable'   && !item.targetChannel) return false;

    if (routeF === 'unroutable' &&  item.targetChannel) return false;

    if (!_arrSrcFilter.has(item.source || 'plex')) return false;

    return true;

  });



  // Sort

  filtered = [...filtered].sort((a, b) => {

    let av, bv;

    switch(arrSort.col) {

      case 'title':   av=a.title.toLowerCase(); bv=b.title.toLowerCase(); break;

      case 'type':    av=a.kind; bv=b.kind; break;

      case 'library': av=a.sectionTitle||''; bv=b.sectionTitle||''; break;

      case 'channel': av=a.targetChannelName||''; bv=b.targetChannelName||''; break;

      case 'added':   av=a.addedAt; bv=b.addedAt; break;

      default:        av=a.addedAt; bv=b.addedAt;

    }

    const cmp = typeof av === 'number' ? av-bv : av.localeCompare(bv);

    return arrSort.dir === 'asc' ? cmp : -cmp;

  });



  const thClass = (col) => {

    const base = 'sortable';

    if (arrSort.col !== col) return base;

    return base + ' sort-' + arrSort.dir;

  };



  arrPageSize = parseInt((document.getElementById('arr-page-size')||{value:'50'}).value) || 50;

  const totalPages = Math.max(1, Math.ceil(filtered.length / arrPageSize));

  if (arrPage >= totalPages) arrPage = totalPages - 1;

  const pageItems = filtered.slice(arrPage * arrPageSize, (arrPage + 1) * arrPageSize);



  const rows = pageItems.map(item => {

    const rk  = item.ratingKey;

    const ed  = genreEdit[rk];



    // ── Genre cell

    let labelsTd;

    if (ed) {

      const pills = ed.genres.map((g, i) =>

        '<span class="pill ep">'+escHtml(g)

        +'<button class="pill-x" onclick="removeGenreTag(\''+rk+'\','+i+')">\xd7</button></span>'

      ).join('');

      labelsTd = '<div class="genre-edit-wrap">'

        + pills

        + '<input id="ge-'+rk+'" class="gtag-input" placeholder="Add…"'

        + ' onkeydown="if(event.key===\'Enter\'){event.preventDefault();addGenreTag(\''+rk+'\')}">'

        + '</div>';

    } else {

      const pills = item.labels.map(l => '<span class="pill">'+escHtml(l)+'</span>').join('');

      const editBtn = item.source === 'jellyfin' ? '' :

        '<button class="btn g sm genre-edit-btn" onclick="startEditGenres(\''+rk+'\')" title="Edit genres">✎</button>';

      labelsTd = '<div class="genre-view">'

        + pills

        + editBtn

        + '</div>';

    }



    // ── Channel cell

    let ch;

    const _ov = _channelOverrides[rk];

    const _chName = _ov ? _ov.channel_name : item.targetChannelName;

    const _chId   = _ov ? _ov.channel_id   : item.targetChannel;

    if (_channelEditRk === rk) {

      const _opts = _chanOpts(_chId);

      ch = '<select class="ch-ov-sel" style="background:var(--s2);border:1px solid var(--acc);color:var(--txt);border-radius:5px;padding:3px 5px;font-size:12px;max-width:200px"'

          + ' onchange="setChannelOverride(\''+rk+'\',this)" onblur="closeChannelEdit()">'

          + '<option value="">-- pick channel --</option>'+_opts+'</select>';

    } else if (_chId === '__skip__') {

      ch = '<span onclick="openChannelEdit(\''+rk+'\')" title="Click to change" style="cursor:pointer;font-size:12px;color:var(--muted)">&#8960; skip</span>';

    } else if (_chName) {

      const _ovDot = _ov ? ' <span title="Manual override" style="color:var(--acc);font-size:9px">*</span>' : '';

      ch = '<span onclick="openChannelEdit(\''+rk+'\')" title="Click to reroute to a different channel" style="cursor:pointer;font-size:13px">'

          + escHtml(_chName)+'</span>'+_ovDot;

    } else {

      ch = '<button class="btn g sm" style="font-size:12px;color:var(--acc2);border-color:var(--acc2)" '

         + 'onclick="openAddRuleFor(\''+escHtml(item.sectionId)+'\',\''+escHtml(item.labels.join(','))+'\')" '

         + 'title="Click to add a routing rule">+ add rule</button>';

    }



    // ── Action buttons

    const st = routeStatus[rk];

    let btn;

    if (ed) {

      btn = '<button class="btn p sm" onclick="saveGenres(\''+rk+'\')">Save</button>'

           +'<button class="btn g sm" onclick="cancelEditGenres(\''+rk+'\')" style="margin-left:4px">✕</button>';

    } else if (st==='done' || st==='already') {

      // Routed (this session or previously): show destination + re-route option

      const dest = item.routedTo ? ' → '+escHtml(item.routedTo) : '';

      const _reRouteBtn = ' <button class="btn g sm" style="font-size:11px" onclick="rerouteItem(\''+rk+'\',\''+item.sectionId+'\',\''+item.labels.join(",")+'\')" title="Force re-route">Re-route</button>';

      if (item.routedTo === 'Skip') {

        btn = '<span style="font-size:12px;color:var(--muted)">&#8960; skipped</span>' + _reRouteBtn;

      } else {

        btn = '<span style="font-size:12px;color:var(--green)">✓'+dest+'</span>' + _reRouteBtn;

      }

    } else if (st==='fail') {

      btn = '<button class="btn sm fail" style="cursor:default">Failed</button>';

      if (item.targetChannel) {

        btn += ' <button class="btn g sm" style="font-size:11px" onclick="routeOne(\''+rk+'\',\''+item.sectionId+'\',\''+item.labels.join(",")+'\')" title="Retry">Retry</button>';

      }

    } else if (st==='routing') {

      btn = '<button class="btn g sm" disabled>Routing…</button>';

    } else if (item.targetChannel) {

      btn = '<button class="btn p sm" onclick="routeOne(\''+rk+'\',\''+item.sectionId+'\',\''+item.labels.join(",")+'\')" >Route</button>'

           ;

    } else {

      btn = '';

    }



    const dt = new Date(item.addedAt*1000).toLocaleDateString(undefined,{day:'numeric',month:'short',year:'numeric'});

    const isChecked = checkedItems.has(rk);

    return '<tr class="'+(isChecked?'arr-row-checked':'')+'">'

      +'<td style="padding:0 6px 0 10px;width:28px" onclick="event.stopPropagation()">'

      +'<input type="checkbox" class="arr-cb" data-rk="'+rk+'" '+(isChecked?'checked':'')+' onclick="event.stopPropagation();toggleCheck(\''+rk+'\')" style="width:14px;height:14px;accent-color:var(--acc);cursor:pointer">'

      +'</td>'

      +'<td style="font-weight:600;max-width:260px" title="'+escHtml(item.title)+'">'

      +'<div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'

      +(item.source==='plex' && _plexMachineId
        ? '<a href="'+escHtml(_plexPublicUrl||_plexUrl)+'/web/#!/server/'+escHtml(_plexMachineId)+'/details?key=%2Flibrary%2Fmetadata%2F'+encodeURIComponent(rk)+'" target="_blank" rel="noopener" style="color:inherit;text-decoration:none;border-bottom:1px solid var(--bdr)" title="Open in Plex">'+escHtml(item.title)+'</a>'
        : item.source==='jellyfin' && (_jfPublicUrl||_jfUrl) && _jfServerId
        ? '<a href="'+escHtml(_jfPublicUrl||_jfUrl)+'/web/index.html#!/details?id='+encodeURIComponent(rk.replace('jf:',''))+'&serverId='+encodeURIComponent(_jfServerId)+'" target="_blank" rel="noopener" style="color:inherit;text-decoration:none;border-bottom:1px solid var(--bdr)" title="Open in Jellyfin">'+escHtml(item.title)+'</a>'
        : escHtml(item.title))

      +' <span style="color:var(--muted);font-size:12px">'+item.year+'</span>'

      +'</div></td>'

      +'<td><span class="badge '+item.kind+'">'+item.kind+'</span></td>'

      +'<td style="font-size:11px;font-weight:600;color:var(--muted)">'

      +(item.source==='jellyfin'?'JF':'PX')

      +'</td>'

      +'<td style="color:var(--muted);font-size:13px">'+escHtml(item.sectionTitle)+'</td>'

      +'<td>'+labelsTd+'</td><td>'+ch+'</td>'

      +'<td style="color:var(--muted);font-size:13px;white-space:nowrap">'+dt+'</td>'

      +'<td style="white-space:nowrap">'+btn+'</td></tr>';

  }).join('');



  const mkth = (col, label) =>

    '<th class="'+thClass(col)+'" onclick="sortArrivals(\''+col+'\')">'+label+'<span class="sort-arrow"></span></th>';



  const allPageChecked = pageItems.length > 0 && pageItems.every(i => checkedItems.has(i.ratingKey));



  document.getElementById('arr-body').innerHTML =

    '<table><thead><tr>'

    + '<th style="padding:0 6px 0 10px;width:28px"><input type="checkbox" id="arr-sel-all" '+(allPageChecked?'checked':'')+' onclick="toggleSelectAll()" style="width:14px;height:14px;accent-color:var(--acc);cursor:pointer" title="Select all on page"></th>'

    + mkth('title','Title')

    + mkth('type','Type')

    + '<th>Source</th>'

    + mkth('library','Library')

    + '<th>Genres</th>'

    + mkth('channel','Goes to')

    + mkth('added','Added')

    + '<th></th>'

    +'</tr></thead><tbody>'+rows+'</tbody></table>';



  updateActionBar();



  if (totalPages > 1) {

    const pg = document.createElement('div');

    pg.style.cssText = 'display:flex;align-items:center;gap:10px;margin-top:10px;font-size:13px;color:var(--muted)';

    const prevBtn = document.createElement('button');

    prevBtn.className = 'btn g sm';

    prevBtn.textContent = 'Prev';

    prevBtn.disabled = arrPage === 0;

    prevBtn.onclick = () => gotoArrPage(arrPage - 1);

    const nextBtn = document.createElement('button');

    nextBtn.className = 'btn g sm';

    nextBtn.textContent = 'Next';

    nextBtn.disabled = arrPage >= totalPages - 1;

    nextBtn.onclick = () => gotoArrPage(arrPage + 1);

    const info = document.createElement('span');

    info.textContent = 'Page ' + (arrPage+1) + ' of ' + totalPages + ' (' + filtered.length + ' items)';

    pg.appendChild(prevBtn); pg.appendChild(info); pg.appendChild(nextBtn);

    document.getElementById('arr-body').appendChild(pg);

  }



}



function gotoArrPage(n) {

  arrPage = n;

  renderArrivals();

  document.getElementById('arr-body').scrollIntoView({behavior:'smooth',block:'start'});

}



function toggleCheck(rk) {

  if (checkedItems.has(rk)) checkedItems.delete(rk);

  else checkedItems.add(rk);

  renderArrivals();

}



function toggleSelectAll() {

  const pageRks = Array.from(document.querySelectorAll('.arr-cb')).map(el => el.dataset.rk);

  const allChecked = pageRks.every(rk => checkedItems.has(rk));

  if (allChecked) pageRks.forEach(rk => checkedItems.delete(rk));

  else pageRks.forEach(rk => checkedItems.add(rk));

  renderArrivals();

}



function clearChecked() {

  checkedItems.clear();

  renderArrivals();

}



async function updateActionBar() {

  const bar = document.getElementById('arr-action-bar');

  if (!bar) return;

  const n = checkedItems.size;

  bar.style.display = n > 0 ? 'flex' : 'none';

  const countEl = document.getElementById('arr-check-count');

  if (countEl) countEl.textContent = n + ' selected';

  const sel = document.getElementById('arr-bulk-channel');

  if (sel && sel.options.length <= 1) {

    if (!allChannels.length) {

      try { allChannels = await (await fetch('/api/channels')).json(); } catch {}

    }

    sel.innerHTML = '<option value="">route to...</option>' + _chanOpts();

  }

  const btn = document.getElementById('arr-bulk-route-btn');

  if (btn) btn.disabled = !sel || !sel.value;

  const gbtn = document.getElementById('arr-bulk-genre-btn');

  if (gbtn) gbtn.disabled = n === 0;

}



async function bulkRouteChecked() {

  const sel = document.getElementById('arr-bulk-channel');

  if (!sel || !sel.value) return;

  const channelId = sel.value;

  const channelName = sel.options[sel.selectedIndex].dataset.name || sel.options[sel.selectedIndex].textContent;

  const rks = Array.from(checkedItems);

  for (const rk of rks) {

    const item = arrivals.find(a => a.ratingKey === rk);

    if (!item) continue;

    _channelOverrides[rk] = {channel_id: channelId, channel_name: channelName};

    await routeOne(rk, item.sectionId, item.labels.join(','));

    checkedItems.delete(rk);

  }

  updateActionBar();

}



function onBulkChannelChange() {

  updateActionBar();

}



function openClearConfirm() {

  const n = checkedItems.size;

  if (!n) return;

  const msg = document.getElementById('clear-confirm-msg');

  if (msg) msg.textContent = 'Remove routing association for ' + n + ' selected item' + (n !== 1 ? 's' : '') + '? They will need to be re-routed manually.';

  document.getElementById('clear-confirm-modal').classList.add('on');

}



async function bulkSkipChecked() {

  const rks = Array.from(checkedItems);

  for (const rk of rks) {

    const item = arrivals.find(a => a.ratingKey === rk);

    if (!item) continue;

    _channelOverrides[rk] = {channel_id: '__skip__', channel_name: 'Skip'};

    await routeOne(rk, item.sectionId, item.labels.join(','));

    checkedItems.delete(rk);

  }

  updateActionBar();

}



function onBulkAction(sel) {

  const v = sel.value;

  sel.value = '';

  if (v === 'skip') bulkSkipChecked();

  else if (v === 'clear') openClearConfirm();

}



function closeClearModal() {

  document.getElementById('clear-confirm-modal').classList.remove('on');

  updateActionBar();

}



async function doClearAssociations() {

  document.getElementById('clear-confirm-modal').classList.remove('on');

  const rks = Array.from(checkedItems);

  for (const rk of rks) {

    try { await fetch('/api/route/routed/' + rk, {method: 'DELETE'}); } catch {}

    delete _channelOverrides[rk];

    delete routeStatus[rk];

    const item = arrivals.find(a => a.ratingKey === rk);

    if (item) { item.targetChannel = null; item.targetChannelName = null; item.alreadyRouted = false; item.routedTo = null; }

    checkedItems.delete(rk);

  }

  updateActionBar();

  renderArrivals();

  toast('Cleared ' + rks.length + ' association' + (rks.length !== 1 ? 's' : ''));

}





async function bulkAddGenre() {

  const inp = document.getElementById('arr-bulk-genre');

  if (!inp) return;

  const genre = inp.value.trim();

  if (!genre) { inp.focus(); return; }

  const rks = Array.from(checkedItems);

  let changed = 0;

  for (const rk of rks) {

    const item = arrivals.find(a => a.ratingKey === rk);

    if (!item || item.source === 'jellyfin') continue;

    if (item.labels.includes(genre)) continue;

    const newLabels = [...item.labels, genre];

    try {

      const r = await (await fetch('/api/plex/genres/'+rk, {

        method: 'PUT',

        headers: {'Content-Type':'application/json'},

        body: JSON.stringify({sectionId: item.sectionId, genres: newLabels, originalGenres: [...item.labels], kind: item.kind})

      })).json();

      if (r.error) { toast('Error on "'+item.title+'": '+r.error); continue; }

      item.labels = newLabels;

      // Re-resolve channel with new genres

      const res = await (await fetch('/api/route/resolve?section_id='+item.sectionId+'&labels='+encodeURIComponent(newLabels.join(',')))).json();

      item.targetChannel     = res.channel_id   || null;

      item.targetChannelName = res.channel_name || null;

      delete routeStatus[rk];

      changed++;

    } catch(e) { toast('Error: '+e.message); }

  }

  inp.value = '';

  if (changed) {

    toast('Genre \''+genre+'\' added to '+changed+' item'+(changed===1?'':'s'));

    logAction('+ Genre \''+genre+'\' added to '+changed+' item'+(changed===1?'':'s'), true, {action_type:'genre'});

  }

  renderArrivals();

}



function openAddRuleFor(sectionId, labels) {

  openAddRule().then(() => {

    // Pre-fill section and label hint if possible

    const secEl = document.getElementById('r-section');

    if (secEl && sectionId) {

      for (const opt of secEl.options) { if (opt.value === sectionId) { opt.selected = true; break; } }

    }

    const labEl = document.getElementById('r-label');

    if (labEl && labels) labEl.value = labels.split(',')[0] || '';

  });

}



function openAddRuleForCh(chId) {

  openAddRule().then(() => {

    const el = document.getElementById('r-channel');

    if (el) for (const o of el.options) { if (o.value === chId) { o.selected = true; break; } }

  });

}



// ── Genre edit helpers

function startEditGenres(rk) {

  const item = arrivals.find(a => a.ratingKey === rk);

  if (!item) return;

  genreEdit[rk] = {genres: [...item.labels]};

  renderArrivals();

  setTimeout(() => { const el = document.getElementById('ge-'+rk); if (el) el.focus(); }, 60);

}



function cancelEditGenres(rk) {

  delete genreEdit[rk];

  renderArrivals();

}



function removeGenreTag(rk, idx) {

  if (!genreEdit[rk]) return;

  genreEdit[rk].genres.splice(idx, 1);

  renderArrivals();

}



function addGenreTag(rk) {

  const inp = document.getElementById('ge-'+rk);

  if (!inp || !genreEdit[rk]) return;

  const val = inp.value.trim();

  if (!val) return;

  if (!genreEdit[rk].genres.includes(val)) genreEdit[rk].genres.push(val);

  renderArrivals();

  setTimeout(() => { const el = document.getElementById('ge-'+rk); if (el) el.focus(); }, 60);

}



async function saveGenres(rk) {

  const item = arrivals.find(a => a.ratingKey === rk);

  if (!item || !genreEdit[rk]) return;

  const genres         = genreEdit[rk].genres;

  const originalGenres = [...item.labels]; // capture BEFORE mutation

  try {

    const r = await (await fetch('/api/plex/genres/'+rk, {

      method: 'PUT',

      headers: {'Content-Type':'application/json'},

      body: JSON.stringify({sectionId: item.sectionId, genres, originalGenres, kind: item.kind})

    })).json();

    if (r.error) { toast('Error: '+r.error); return; }



    // Update labels in memory

    item.labels = genres;



    // Re-resolve which channel these genres now match

    const res = await (await fetch(

      '/api/route/resolve?section_id='+item.sectionId+'&labels='+encodeURIComponent(genres.join(','))

    )).json();

    item.targetChannel     = res.channel_id   || null;

    item.targetChannelName = res.channel_name || null;



    // Reset route status so the user can re-route with new genres

    delete routeStatus[rk];

    delete genreEdit[rk];

    renderArrivals();

    const msg = 'Genres updated for "'+item.title+'"'

      + (item.targetChannelName ? ': now routes to '+item.targetChannelName : ': no matching rule');

    toast('Genres saved' + (item.targetChannelName ? ': routes to ' + item.targetChannelName : ''));

    logAction(msg, true, {action_type:'genre', title: item.title, channel: item.targetChannelName||''});

  } catch(e) {

    toast('Error: '+e.message);

    logAction('Genre save error for "'+item.title+'": '+e.message, false, {action_type:'genre', title: item.title});

  }

}



// ── Channel override helpers

function openChannelEdit(rk) {

  if (!allChannels.length) {

    fetch('/api/channels').then(r=>r.json()).then(d=>{

      allChannels=d; _channelEditRk=rk; renderArrivals();

      setTimeout(()=>{const s=document.querySelector('.ch-ov-sel');if(s)s.focus();},30);

    }); return;

  }

  _channelEditRk = rk; renderArrivals();

  setTimeout(()=>{const s=document.querySelector('.ch-ov-sel');if(s)s.focus();},30);

}

function setChannelOverride(rk, sel) {

  _channelEditRk = null;

  if (sel.value) {

    const opt = sel.options[sel.selectedIndex];

    const chName = opt.dataset.name || opt.text;

    _channelOverrides[rk] = {channel_id: sel.value, channel_name: chName};

    const item = arrivals.find(a => a.ratingKey === rk);

    if (item) { item.targetChannel=sel.value; item.targetChannelName=chName;

                item.alreadyRouted=false; }

    delete routeStatus[rk];

  } else { delete _channelOverrides[rk]; }

  renderArrivals();

}

function closeChannelEdit() {

  if (_channelEditRk) { _channelEditRk=null; renderArrivals(); }

}



async function routeOne(rk, sid, labels) {

  const item = arrivals.find(a => a.ratingKey === rk);

  const _chOv = _channelOverrides[rk];

  routeStatus[rk] = 'routing'; renderArrivals();

  try {

    let _rurl = '/api/route/'+rk+'?section_id='+sid+'&labels='+encodeURIComponent(labels);

    if (item?.title) _rurl += '&title='+encodeURIComponent(item.title);

    if (_chOv) _rurl += '&channel_id='+encodeURIComponent(_chOv.channel_id);

    const r = await (await fetch(_rurl,{method:'POST'})).json();

    if (r.success) {

      routeStatus[rk] = 'already';  // becomes checkbox-controlled, not permanently hidden

      if (item) { item.alreadyRouted = true; item.routedTo = r.channel; }

      const note = r.method === 'already_present' ? ' (already in channel)' : ' ('+r.count+' added)';

      logAction('✓ "' + (item?.title||rk) + '" → ' + r.channel + note, true, {action_type:'route', title: item?.title||rk, channel: r.channel});

      toast('Done: '+r.channel+note);

    } else {

      routeStatus[rk] = 'fail';

      const detail = r.debug ? r.error + ': ' + r.debug : (r.error||'unknown error');

      logAction('✗ Failed "' + (item?.title||rk) + '": ' + detail, false, {action_type:'route', title: item?.title||rk});

      toast('Failed: '+r.error);

    }

  } catch(e) {

    routeStatus[rk] = 'fail';

    logAction('✗ Exception routing "'+(item?.title||rk)+'": '+e.message, false, {action_type:'route', title: item?.title||rk});

    toast('Error: '+e.message);

  }

  renderArrivals();

  // Update Route All button count

  const pending = arrivals.filter(i=>i.targetChannel && !['done','already'].includes(routeStatus[i.ratingKey])).length;

  const raBtn = document.getElementById('raBtn');

  if (raBtn) raBtn.textContent = 'Route All ('+pending+')';

}



async function rerouteItem(rk, sid, labels) {

  // Clear the "already routed" mark in the DB, then route normally

  await fetch('/api/route/routed/'+rk, {method:'DELETE'});

  delete routeStatus[rk];

  const item = arrivals.find(a => a.ratingKey === rk);

  if (item) { item.alreadyRouted = false; item.routedTo = null; }

  await routeOne(rk, sid, labels);

}



async function dismissItem(rk) {

  // Mark as done in DB without routing; hides item from default view

  const item = arrivals.find(a => a.ratingKey === rk);

  try {

    await fetch('/api/route/mark-done/'+rk, {method:'POST'});

    routeStatus[rk] = 'already';

    if (item) { item.alreadyRouted = true; item.routedTo = 'dismissed'; }

    logAction('Dismissed "' + (item?.title||rk) + '" (marked done without routing)', true, {action_type:'route', title: item?.title||rk});

    renderArrivals();

    const pending = arrivals.filter(i=>i.targetChannel && !['done','already'].includes(routeStatus[i.ratingKey])).length;

    const raBtn = document.getElementById('raBtn');

    if (raBtn) raBtn.textContent = 'Route All ('+pending+')';

  } catch(e) {

    toast('Error: '+e.message);

  }

}



async function routeAll() {

  const btn = document.getElementById('raBtn');

  btn.disabled=true; btn.textContent='Routing…';

  try {

    const days = document.getElementById('dsel').value;

    const d = await (await fetch('/api/route/auto?days='+days,{method:'POST'})).json();

    if (d.error) {

      toast('Error: '+d.error);

      logAction('✗ Route All failed: '+d.error, false, {action_type:'route'});

    } else {

      for (const r of d.details||[]) {

        const item = arrivals.find(a => a.ratingKey === r.rk || a.title === r.title);

        if (item) {

          if (r.success) {

            routeStatus[item.ratingKey] = 'already';  // checkbox-controlled

            item.alreadyRouted = true;

            item.routedTo = r.channel;

          } else {

            routeStatus[item.ratingKey] = 'fail';

          }

        }

        if (r.success) {

          const note = r.method === 'already_present' ? ' (already in channel)' : ' ('+r.count+' ep, '+r.missed+' missed)';

          logAction('✓ "'+r.title+'" → '+r.channel+note, true, {action_type:'route', title: r.title, channel: r.channel});

        } else {

          const detail = r.debug ? r.error+': '+r.debug : (r.error||'unknown');

          logAction('✗ "'+r.title+'": '+detail, false, {action_type:'route', title: r.title});

        }

      }

      const ok = (d.routed??0), total = (d.total??0);

      logAction('Route All complete: '+ok+'/'+total+' succeeded'+(ok<total?' (see above for failures)':''), ok===total, {action_type:'route'});

      toast('Routed '+ok+'/'+total+' items');

      renderArrivals();

    }

  } catch(e) {

    toast('Error: '+e.message);

    logAction('✗ Route All exception: '+e.message, false, {action_type:'route'});

  }

  btn.disabled=false;

  const pendingAfter = arrivals.filter(i=>i.targetChannel && !['done','already'].includes(routeStatus[i.ratingKey])).length;

  btn.textContent='Route All ('+pendingAfter+')';

}







// ── Channels

// ── Channel source filter

let _chSrcFilter = 'all';

let _chSources   = {};



function setChSrc(src) {

  _chSrcFilter = src;

  document.querySelectorAll('.ch-src-btn').forEach(b => {

    const active = b.dataset.src === src;

    b.style.opacity    = active ? '1' : '.5';

    b.style.fontWeight = active ? '600' : '400';

  });

  renderChannels();

}



async function loadChannelSources() {

  try {

    _chSources = await (await fetch('/api/channels/sources')).json();

    renderChannels();

  } catch(e) { console.warn('channel sources:', e); }

}



function renderChannels() {

  if (!allChannels.length) return;

  renderProcQueue();

  const sort = (document.getElementById('ch-sort') || {value:'number-asc'}).value;

  const srcFiltered = _chSrcFilter === 'all'

    ? allChannels

    : allChannels.filter(ch => (_chSources[ch.id] || 'plex') === _chSrcFilter);

  const sorted = [...srcFiltered.filter(ch => !_dirtyChannels.has(ch.id))].sort((a, b) => {

    switch(sort) {

      case 'number-asc':  return (a.number||0) - (b.number||0);

      case 'number-desc': return (b.number||0) - (a.number||0);

      case 'name-asc':    return (a.name||'').localeCompare(b.name||'');

      case 'name-desc':   return (b.name||'').localeCompare(a.name||'');

      case 'count-desc':  return (b.count||0) - (a.count||0);

      case 'count-asc':   return (a.count||0) - (b.count||0);

      default: return 0;

    }

  });

  document.getElementById('ch-body').innerHTML = '<div class="grid">'

    + sorted.map(ch => {

        const bgUrl = ch.ident || ch.icon;

        const proxied = bgUrl ? '/api/proxy-image?url='+encodeURIComponent(bgUrl) : '';

        const bg = proxied

          ? '<div class="chcard-bg" style="background-image:url('+proxied+')"></div>'

          : '';

        const needsProc = _dirtyChannels.has(ch.id);
        const autoOn = _autoRouteChannels.has(ch.id);
        const np = _nowPlaying[ch.id];
        const npBadge = np && np.title ? '<span class="ch-now-playing-badge">&#9654; Now Playing</span>' : '';
        return '<div class="chcard" style="position:relative">'

          + bg

          + npBadge

          +'<div class="chcard-content">'

          +'<div>'

          +'<div class="chnum">CH '+ch.number+'</div>'

          +'<div class="chtitle">'+escHtml(ch.name)+'</div>'

          +'</div>'

          +'<div>'

          +'<div class="chcount">'+ch.count.toLocaleString()+'</div>'

          +'<div class="chcl">programs</div>'

          +'</div>'

          +'<div class="chcard-actions">'

          +'<button class="btn '+(autoOn?'p':'g')+' sm" onclick="toggleChannelAutoRoute(\''+ch.id+'\','+(!autoOn)+')">'
          +(autoOn ? '⚡ Auto On' : 'Auto Off')
          +'</button>'

          +'<button class="btn '+(needsProc?'p':'g')+' sm" onclick="openProcModal(\''+ch.id+'\')">&#9881; Process</button>'

          +'</div>'

          +'</div>'

          +'</div>';

      }).join('') + '</div>';

}



async function loadChannels(force=false) {

  if (force) await fetch('/api/cache/clear');

  const chBody = document.getElementById('ch-body');

  chBody.innerHTML = '<div class="loading">Loading&hellip;</div>';

  // Backend retries automatically if Tunarr is mid-restart; show a hint after 4s

  const hintTimer = setTimeout(() => {

    if (chBody.querySelector('.loading'))

      chBody.innerHTML = '<div class="loading">Waiting for Tunarr&hellip;</div>';

  }, 4000);

  try {

    const [res, dirtyRes, arRes] = await Promise.all([

      fetch('/api/channels'),

      fetch('/api/channels/dirty').catch(() => null),

      fetch('/api/channels/auto-route').catch(() => null),

    ]);

    clearTimeout(hintTimer);

    const data = await res.json();

    if (data.error) { chBody.innerHTML='<div class="err-box">'+data.error+'</div>'; return; }

    allChannels = data;

    if (dirtyRes) { const d = await dirtyRes.json().catch(()=>({})); _dirtyChannels = new Set(Object.keys(d)); }

    if (arRes) { const ar = await arRes.json().catch(()=>({})); _autoRouteChannels = new Set(ar.enabled || []); }

    renderChannels();

    loadChannelSources();

    preloadChannelImages();

    loadNowPlaying();

  } catch(e) {

    clearTimeout(hintTimer);

    chBody.innerHTML = '<div class="err-box">'+e.message+'</div>';

  }

}



// ── Process modal

let _procChannelId = null;

let _lastProcSettings = null;



function _loadProcSettings() {

  // Returns last-used settings from memory or localStorage, or sensible defaults

  if (_lastProcSettings) return _lastProcSettings;

  try {

    const s = JSON.parse(localStorage.getItem('routarr-proc') || 'null');

    if (s) { _lastProcSettings = s; return s; }

  } catch {}

  return { dedupe: true, shuffle: 'cyclic', pad_minutes: 15 };

}



function _applyProcSettingsToForm(s) {

  document.getElementById('proc-dedupe').checked  = s.dedupe !== false;

  document.getElementById('proc-shuffle').value   = s.shuffle || 'cyclic';

  document.getElementById('proc-pad').value       = s.pad_minutes ?? 15;

}



let _procPresets = [];

let _flowFilter = 'all';

let _deactivatePending = null;



async function loadProcPresets() {

  try { _procPresets = await (await fetch('/api/process-presets')).json(); }

  catch { _procPresets = []; }

  const sel = document.getElementById('proc-preset-sel');

  const cur = sel.value;

  sel.innerHTML = '<option value="">\u2014 presets \u2014</option>'

    + _procPresets.map(p => '<option value="'+p.id+'">'+escHtml(p.name)+'</option>').join('');

  if (cur) sel.value = cur;

  document.getElementById('proc-preset-del').disabled = !sel.value;

}



function applyPreset() {

  const sel = document.getElementById('proc-preset-sel');

  const p = _procPresets.find(p => String(p.id) === sel.value);

  if (!p) { document.getElementById('proc-preset-del').disabled = true; return; }

  document.getElementById('proc-preset-name').value = p.name;

  document.getElementById('proc-dedupe').checked = !!p.dedupe;

  document.getElementById('proc-shuffle').value = p.shuffle;

  document.getElementById('proc-pad').value = String(p.pad_minutes);

  document.getElementById('proc-preset-del').disabled = false;

}



async function savePreset() {

  const name = document.getElementById('proc-preset-name').value.trim();

  if (!name) { toast('Enter a preset name'); return; }

  const body = {

    name,

    dedupe:      document.getElementById('proc-dedupe').checked,

    shuffle:     document.getElementById('proc-shuffle').value,

    pad_minutes: parseInt(document.getElementById('proc-pad').value) || 0,

  };

  const r = await (await fetch('/api/process-presets', {

    method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)

  })).json();

  if (r.error) { toast('Error: '+r.error); return; }

  toast('Preset "'+name+'" saved');

  await loadProcPresets();

  const saved = _procPresets.find(p => p.name === name);

  if (saved) {

    document.getElementById('proc-preset-sel').value = String(saved.id);

    document.getElementById('proc-preset-del').disabled = false;

  }

}



async function deletePreset() {

  const sel = document.getElementById('proc-preset-sel');

  const p = _procPresets.find(p => String(p.id) === sel.value);

  if (!p || !confirm('Delete preset "'+p.name+'"?')) return;

  await fetch('/api/process-presets/'+p.id, {method:'DELETE'});

  toast('Preset "'+p.name+'" deleted');

  document.getElementById('proc-preset-name').value = '';

  await loadProcPresets();

}



async function openProcModal(channelId) {

  const ch = allChannels.find(c => c.id === channelId);

  _procChannelId = channelId;

  document.getElementById('proc-ch-name').textContent = ch ? ch.name : channelId;

  document.getElementById('proc-stats').className = 'proc-stats';

  document.getElementById('proc-stats').textContent = '';

  document.getElementById('proc-run-btn').disabled = false;

  document.getElementById('proc-run-btn').textContent = 'Process & Save';

  const _savedCh = _channelProcSettings[channelId];

  _applyProcSettingsToForm(_savedCh || _loadProcSettings());

  document.getElementById('proc-preset-name').value = '';

  await loadProcPresets();

  document.getElementById('proc-modal').classList.add('on');

}



function closeProcModal() {

  document.getElementById('proc-modal').classList.remove('on');

  _procChannelId = null;

}



async function runProcess() {

  if (!_procChannelId) return;

  const btn = document.getElementById('proc-run-btn');

  btn.disabled = true; btn.textContent = 'Processing\u2026';

  const statsEl = document.getElementById('proc-stats');

  statsEl.className = 'proc-stats'; statsEl.textContent = '';



  const body = {

    channel_name: (allChannels.find(c => c.id === _procChannelId) || {}).name || '',

    dedupe:      document.getElementById('proc-dedupe').checked,

    shuffle:     document.getElementById('proc-shuffle').value,

    pad_minutes: parseInt(document.getElementById('proc-pad').value) || 0,

    preset_name: document.getElementById('proc-preset-name').value.trim(),

  };



  try {

    const r = await (await fetch('/api/channels/'+_procChannelId+'/process', {

      method: 'POST',

      headers: {'Content-Type':'application/json'},

      body: JSON.stringify(body),

    })).json();



    if (r.error) {

      statsEl.className = 'proc-stats on';

      statsEl.innerHTML = '<span style="color:var(--acc2)">Error: '+escHtml(r.error)+'</span>';

      btn.disabled = false; btn.textContent = 'Process & Save';

      return;

    }



    const s = r.stats || {};

    const lines = [

      '<strong style="color:var(--green)">Done.</strong>',

      'Programs before: ' + (s.original ?? '?'),

      body.dedupe ? 'Dupes removed: ' + (s.dupes_removed ?? 0) : null,

      body.shuffle !== 'none' ? 'Shuffled (' + body.shuffle + ')' : null,

      body.pad_minutes > 0 ? 'Padding items added: ' + (s.flex_items ?? 0) : null,

      'Programs after: ' + (s.final_content ?? '?'),

    ].filter(Boolean);

    statsEl.className = 'proc-stats on';

    statsEl.innerHTML = lines.join('<br>');

    btn.textContent = 'Done \u2713';

    // Persist settings for Process All

    _lastProcSettings = {...body};

    try { localStorage.setItem('routarr-proc', JSON.stringify(body)); } catch {}

    _channelProcSettings[_procChannelId] = {dedupe:body.dedupe,shuffle:body.shuffle,pad_minutes:body.pad_minutes};

    if (document.getElementById('page-flows')?.classList.contains('on')) renderFlows();

    const chName = document.getElementById('proc-ch-name').textContent;

    logAction('Processed channel "'+chName+'" \u2014 '+

      (body.dedupe?'deduped, ':'')+

      (body.shuffle!=='none'?body.shuffle+' shuffle, ':'')+

      (body.pad_minutes>0?body.pad_minutes+'m padding, ':'')+

      (s.final_content??'?')+' programs', true, {action_type:'process', channel: chName});

    setTimeout(loadChannels, 2000);

  } catch(e) {

    statsEl.className = 'proc-stats on';

    statsEl.innerHTML = '<span style="color:var(--acc2)">Error: '+escHtml(e.message)+'</span>';

    btn.disabled = false; btn.textContent = 'Process & Save';

  }

}



async function processAll() {

  if (!allChannels.length) { toast('Load channels first'); return; }

  const s = _loadProcSettings();

  const label = (s.dedupe ? 'dedupe' : '') +

    (s.shuffle !== 'none' ? (s.dedupe ? ', ' : '') + s.shuffle + ' shuffle' : '') +

    (s.pad_minutes > 0 ? ', ' + s.pad_minutes + 'm pad' : '') || 'no-op';

  if (!confirm('Apply last-used process settings to all ' + allChannels.length + ' channels?\n\nSettings: ' + label)) return;



  const btn = document.getElementById('proc-all-btn');

  btn.disabled = true;

  let ok = 0, fail = 0;



  for (let i = 0; i < allChannels.length; i++) {

    const ch = allChannels[i];

    btn.textContent = 'Processing ' + (i + 1) + '/' + allChannels.length + '…';

    try {

      const r = await (await fetch('/api/channels/' + ch.id + '/process', {

        method: 'POST',

        headers: {'Content-Type': 'application/json'},

        body: JSON.stringify({...s, channel_name: ch.name}),

      })).json();

      if (r.ok || !r.error) {

        ok++;

        logAction('Process All: "' + ch.name + '" done (' + ((r.stats || {}).final_content ?? '?') + ' programs)', true, {action_type:'process', channel: ch.name});

      } else {

        fail++;

        logAction('Process All: "' + ch.name + '" failed: ' + r.error, false, {action_type:'process', channel: ch.name});

      }

    } catch(e) {

      fail++;

      logAction('Process All: "' + ch.name + '" error: ' + e.message, false, {action_type:'process', channel: ch.name});

    }

  }



  const msg = 'Process All complete: ' + ok + '/' + allChannels.length + ' succeeded' + (fail ? ', ' + fail + ' failed' : '');

  logAction(msg, fail === 0, {action_type:'process'});

  toast(msg);

  btn.disabled = false;

  btn.textContent = 'Process All';

  setTimeout(loadChannels, 8000);

}



// ── Channel image preloading

function preloadChannelImages() {

  allChannels.forEach(ch => {

    const url = ch.ident || ch.icon;

    if (!url || _preloadedImages.has(url)) return;

    _preloadedImages.add(url);

    const img = new Image();

    img.src = '/api/proxy-image?url=' + encodeURIComponent(url);

  });

}



// ── Now Playing

async function loadNowPlaying() {

  try {

    const r = await fetch('/api/channels/now-playing');

    const data = await r.json();

    if (typeof data === 'object' && !data.error) {

      _nowPlaying = data;

      renderChannels();

    }

  } catch(e) { /* silently ignore */ }

}



// ── Proc Queue

function renderProcQueue() {

  const el = document.getElementById('proc-queue');

  if (!el) return;

  const dirty = allChannels.filter(ch => _dirtyChannels.has(ch.id));

  if (!dirty.length) { el.innerHTML = ''; return; }

  el.innerHTML = '<div class="proc-queue-section">'

    + '<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:10px">'

    + '<div>'

    + '<div style="font-size:13px;font-weight:700;color:var(--acc);text-transform:uppercase;letter-spacing:.5px;margin-bottom:2px">&#9889; Process Update</div>'

    + '<div style="font-size:11px;color:var(--muted);">' + dirty.length + ' channel' + (dirty.length !== 1 ? 's' : '') + ' waiting to be processed</div>'

    + '</div>'

    + '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">'

    + '<label style="font-size:12px;color:var(--muted);cursor:pointer;display:flex;align-items:center;gap:4px"><input type="checkbox" id="pq-all" onchange="toggleAllProcQueue(this.checked)" style="width:13px;height:13px;accent-color:var(--acc);cursor:pointer"> Select All</label>'

    + '<button class="btn g sm" onclick="cancelProcQueue()">Cancel</button>'

    + '<button class="btn p sm" onclick="processDirtySelected()">&#9881; Process Selected</button>'

    + '</div>'

    + '</div>'

    + dirty.map(ch => '<div class="proc-ch-row">'

      + '<input type="checkbox" class="pq-ch" data-id="' + ch.id + '" checked style="width:13px;height:13px;accent-color:var(--acc);cursor:pointer;flex-shrink:0">'

      + '<span class="proc-ch-num">CH ' + ch.number + '</span>'

      + '<span class="proc-ch-name">' + escHtml(ch.name) + '</span>'

      + '<span style="font-size:11px;color:var(--muted)">' + ch.count.toLocaleString() + ' programs</span>'

      + '</div>'

    ).join('')

    + '</div>';

}



function toggleAllProcQueue(checked) {

  document.querySelectorAll('.pq-ch').forEach(cb => cb.checked = checked);

}



function cancelProcQueue() {

  _dirtyChannels = new Set();

  renderProcQueue();

  renderChannels();

  toast('Process queue cleared');

}



async function processDirtySelected() {

  const cbs = [...document.querySelectorAll('.pq-ch:checked')];

  if (!cbs.length) { toast('Select at least one channel'); return; }

  const ids = cbs.map(cb => cb.dataset.id);

  const channels = allChannels.filter(ch => ids.includes(ch.id));

  const s = _loadProcSettings();

  const btn = document.querySelector('#proc-queue .btn.p');

  if (btn) { btn.disabled = true; btn.textContent = 'Processing…'; }

  let ok = 0, fail = 0;

  for (let i = 0; i < channels.length; i++) {

    const ch = channels[i];

    if (btn) btn.textContent = 'Processing ' + (i + 1) + '/' + channels.length + '…';

    try {

      const r = await (await fetch('/api/channels/' + ch.id + '/process', {

        method: 'POST',

        headers: {'Content-Type': 'application/json'},

        body: JSON.stringify({...s, channel_name: ch.name}),

      })).json();

      if (r.ok || !r.error) {

        ok++;

        logAction('Process Queue: "' + ch.name + '" done (' + ((r.stats || {}).final_content ?? '?') + ' programs)', true, {action_type: 'process', channel: ch.name});

      } else {

        fail++;

        logAction('Process Queue: "' + ch.name + '" failed: ' + r.error, false, {action_type: 'process', channel: ch.name});

      }

    } catch(e) {

      fail++;

      logAction('Process Queue: "' + ch.name + '" error: ' + e.message, false, {action_type: 'process', channel: ch.name});

    }

  }

  const msg = 'Processed ' + ok + '/' + channels.length + ' channel' + (channels.length !== 1 ? 's' : '') + (fail ? ', ' + fail + ' failed' : '');

  toast(msg);

  logAction(msg, fail === 0, {action_type: 'process'});

  if (btn) { btn.disabled = false; btn.textContent = '&#9881; Process Selected'; }

  setTimeout(loadChannels, 3000);

}



// ── Scan status

async function updateScanStatus() {

  try {

    const s = await (await fetch('/api/scan/status')).json();

    const _wasActive = _isScanActive;

    _isScanActive = s.scanning;

    if (s.scanning && !_wasActive) {

      const body = document.getElementById('arr-body');

      if (body && !body.querySelector('table')) showC64();

    }

    if (!s.scanning && _wasActive) {

      stopC64();

      // If this was the first scan completing, honour the tour choice

      if (s.first_scan_done && _fsmDismissed && _fsmWantTour) setTimeout(startTour, 800);

      else if (s.first_scan_done && !_fsmDismissed) _fsmHide();

      loadArrivals(true);

      return;

    }

    const sub = document.getElementById('arr-sub');

    const btn = document.getElementById('scan-now-btn');

    if (!sub || !btn) return;

    if (s.scanning) { btn.disabled = true; btn.textContent = 'Scanning…'; }

    else { btn.disabled = false; btn.textContent = 'Scan Now'; }

    const parts = [];

    if (s.last_scan) {

      const ago = Math.round((Date.now()/1000 - s.last_scan) / 60);

      parts.push('Last scan: '+(ago < 1 ? 'just now' : ago+'m ago'));

    }

    if (s.next_scan && !s.scanning) {

      const inMin = Math.max(0, Math.round((s.next_scan - Date.now()/1000) / 60));

      parts.push('Next: '+(inMin < 1 ? '<1m' : inMin+'m'));

    }

    if (parts.length && sub && !sub.textContent.startsWith('Loading')) {

      const base = sub.textContent.replace(/ · Last scan.*$/, '').replace(/ · Next.*$/, '');

      sub.textContent = base + ' · ' + parts.join(' · ');

    }

  } catch {}

}



async function scanNow() {

  const btn = document.getElementById('scan-now-btn');

  btn.disabled = true; btn.textContent = 'Scanning…';

  try {

    await fetch('/api/scan/now', {method:'POST'});

    document.getElementById('sync-bar').classList.add('on');

    document.getElementById('sync-lbl').textContent = 'Scanning…';

    if (!_syncPoll) _syncPoll = setInterval(pollTunarrSync, 2000);

    const poll = setInterval(async () => {

      try {

        const s = await (await fetch('/api/scan/status')).json();

        if (!s.scanning) { clearInterval(poll); logAction('Plex scan complete', true, {action_type:'scan'}); await loadArrivals(true); }

      } catch { clearInterval(poll); }

    }, 2000);

  } catch(e) { toast('Scan error: '+e.message); btn.disabled=false; btn.textContent='Scan Now'; }

}



setInterval(updateScanStatus, 30000);



// ── Activity: now the action log (client-side, no-op loader)

function loadActivity() { renderLog(); }



// ── Settings

const SETTINGS_FIELDS = ['plex_url','plex_token','plex_source_id','tunarr_url',

  'scan_interval_minutes','jellyfin_url','jellyfin_api_key','plex_public_url','jellyfin_public_url'];



async function loadSettings() {

  try {

    const d = await (await fetch('/api/settings')).json();

    for (const f of SETTINGS_FIELDS) {

      const el = document.getElementById('s-'+f);

      if (el) el.value = d[f] || '';

    }

  } catch(e) { toast('Could not load settings: '+e.message); }

  const authEl = document.getElementById('s-auth_username');

  if (authEl) { try { const ad = await (await fetch('/api/settings')).json(); authEl.value = ad.auth_username || ''; } catch(e){} }

  // Sync display controls to current state

  const fs = localStorage.getItem('routarr-fs') || '15';

  applyFontSize(fs);

  loadLibraryMapping();

  const _whEl = document.getElementById('webhook-url-display');

  if (_whEl) _whEl.value = window.location.origin + '/api/plex-webhook';

}



function copyWebhookUrl() {

  const el = document.getElementById('webhook-url-display');

  if (!el) return;

  navigator.clipboard.writeText(el.value).then(() => {

    const btn = el.nextElementSibling;

    if (btn) { btn.textContent = 'Copied!'; setTimeout(() => btn.textContent = 'Copy', 1500); }

  });

}



async function saveSettings() {

  const body = {};

  for (const f of SETTINGS_FIELDS) {

    const el = document.getElementById('s-'+f);

    if (el) body[f] = el.value;

  }

  await fetch('/api/settings', {method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});

  const msg = document.getElementById('settings-msg');

  msg.className='ok-msg'; msg.textContent='Saved.';

  setTimeout(()=>{ msg.className=''; msg.textContent=''; }, 3000);

  checkHealth(); checkSetup();

  loadLibraryMapping();

}



async function testConnections() {

  const msg = document.getElementById('settings-msg');

  msg.className=''; msg.textContent='Testing&hellip;';

  const d = await (await fetch('/api/health')).json();

  const entries = Object.entries(d).map(([k,v])=>k+': '+(v==='ok'?'OK':v==='not_configured'?'not set':'down'));

  const ok = Object.values(d).every(v=>v==='ok');

  msg.className = ok ? 'ok-msg' : '';

  msg.style.color = ok ? '' : 'var(--yellow)';

  msg.textContent = entries.join(' | ');

}



async function detectSource() {

  const d = await (await fetch('/api/tunarr/detect-source')).json();

  if (d.source_id) {

    document.getElementById('s-plex_source_id').value = d.source_id;

    toast('Detected: '+d.name);

  } else {

    toast('Could not detect \u2014 save Tunarr address first and try again');

  }

}



function toggleHelp(id) { document.getElementById(id).classList.toggle('on'); }



// ── Library Mapping

let _libMapSections = [], _libMapLibraries = [], _jfSections = [];



async function loadLibraryMapping() {

  const body = document.getElementById('lib-map-body');

  body.innerHTML = '<div class="loading" style="padding:16px">Loading&hellip;</div>';

  try {

    const [secs, jfSecs, libs, settings] = await Promise.all([

      fetch('/api/plex/sections').then(r=>r.json()).catch(()=>[]),

      fetch('/api/jellyfin/sections').then(r=>r.json()).catch(()=>[]),

      fetch('/api/tunarr/libraries').then(r=>r.json()),

      fetch('/api/settings').then(r=>r.json()),

    ]);

    _libMapSections = Array.isArray(secs) ? secs : [];

    _jfSections = Array.isArray(jfSecs) ? jfSecs : [];

    _libMapLibraries = Array.isArray(libs) ? libs : [];

    let currentMap = {};

    try { currentMap = JSON.parse(settings.library_mappings || '{}'); } catch {}



    if (!_libMapSections.length && !_jfSections.length) {

      body.innerHTML = '<div class="empty" style="padding:16px">Configure connections and save to detect libraries.</div>';

      return;

    }

    if (!_libMapLibraries.length) {

      body.innerHTML = '<div class="empty" style="padding:16px">Connect Tunarr and save to detect libraries.</div>';

      return;

    }

    const libOptions = '<option value="">\u2014 not mapped \u2014</option>'

      + _libMapLibraries.map(l => '<option value="'+l.id+'">'+l.name+'</option>').join('');



    let currentFreq = {};

    try { currentFreq = JSON.parse(settings.library_scan_freq || '{}'); } catch {}



    const freqOpts = (sid) => {

      const v = currentFreq[sid] || 'normal';

      return ['priority','normal','skip'].map(o =>

        '<option value="'+o+'"'+(v===o?' selected':'')+'>'

        +(o==='priority'?'\u2605 Priority':o==='normal'?'Normal':'\u2715 Skip')

        +'</option>'

      ).join('');

    };



    const makeRows = (arr, showFreq=true) => arr.map(s =>

      '<div class="lib-row">'

      +'<div class="lib-plex"><strong>'+s.title+'</strong>'

      +'<span class="section-label">'+s.type+'</span></div>'

      +'<div class="lib-arrow">\u2192</div>'

      +'<select id="libmap-'+s.id+'" class="lib-select">'+libOptions+'</select>'

      +(showFreq ? '<select id="scanfreq-'+s.id+'" class="scan-freq-sel">'+freqOpts(s.id)+'</select>' : '')

      +'</div>'

    ).join('');



    let html = '';

    const _colHdr = '<div class="lib-col-hdr"><span class="lch-spc"></span><span class="lch-arr">→</span><span class="lch-spc"></span><span class="lch-freq">Scan Priority</span></div>';

    if (_libMapSections.length) html += '<div class="lib-source-hdr">Plex</div>' + _colHdr + makeRows(_libMapSections, true);

    if (_jfSections.length) html += '<div class="lib-source-hdr" style="margin-top:14px">Jellyfin</div>' + _colHdr + makeRows(_jfSections, true);

    body.innerHTML = html;



    for (const [sid, lid] of Object.entries(currentMap)) {

      const sel = document.getElementById('libmap-'+sid);

      if (sel) sel.value = lid;

    }

  } catch(e) {

    body.innerHTML = '<div class="err-box">'+e.message+'</div>';

  }

}
async function autoConfigureLibraries() {

  const msg = document.getElementById('lib-msg');

  msg.textContent = 'Detecting…';

  try {

    const d = await (await fetch('/api/tunarr/auto-map')).json();

    if (d.error) { toast('Error: '+d.error); msg.textContent=''; return; }

    for (const [sid, lid] of Object.entries(d.mapping)) {

      const sel = document.getElementById('libmap-'+sid);

      if (sel) sel.value = lid;

    }

    msg.className='ok-msg';

    msg.textContent = d.count + ' libraries mapped and saved.';

    setTimeout(()=>{ msg.textContent=''; msg.className=''; }, 4000);

    toast('Auto-configured ' + d.count + ' library mappings');

  } catch(e) { toast('Error: '+e.message); msg.textContent=''; }

}



async function saveLibraryMapping() {

  const mapping = {};

  const freq = {};

  for (const sec of [..._libMapSections, ..._jfSections]) {

    const sel = document.getElementById('libmap-'+sec.id);

    if (sel && sel.value) mapping[sec.id] = sel.value;

    const fsel = document.getElementById('scanfreq-'+sec.id);

    if (fsel) freq[sec.id] = fsel.value;

  }

  await fetch('/api/settings', {

    method: 'PUT',

    headers: {'Content-Type':'application/json'},

    body: JSON.stringify({library_mappings: JSON.stringify(mapping), library_scan_freq: JSON.stringify(freq)})

  });

  const msg = document.getElementById('lib-msg');

  msg.className='ok-msg'; msg.textContent='Saved.';

  setTimeout(()=>{ msg.textContent=''; }, 2000);

  toast('Library mapping saved');

}

// ── Routing Rules



function makeRuleName(secId, label, channelName) {

  const allSecs = [..._libMapSections, ..._jfSections];

  const sec = allSecs.find(s => s.id === secId);

  const libPart = sec ? sec.title : (secId === '*' ? 'Any' : secId);

  const genrePart = label ? label.split(',').map(g=>g.trim()).filter(Boolean).join(', ') : '';

  return libPart + (genrePart ? ': ' + genrePart : '') + ' \u2192 ' + channelName;

}





async function renameRulesToCanonical(rules) {

  for (const r of rules) {

    const canonical = makeRuleName(r.section_id, r.label, r.channel_name);

    if (r.name !== canonical) {

      await fetch('/api/routing/'+r.id, {

        method: 'PUT',

        headers: {'Content-Type':'application/json'},

        body: JSON.stringify({name: canonical})

      });

      r.name = canonical;

    }

  }

}





function exportRules() {
  window.location = '/api/routing/export';
}

async function importRules(input) {
  const file = input.files[0];
  if (!file) return;
  input.value = '';
  let payload;
  try {
    payload = JSON.parse(await file.text());
  } catch(e) {
    toast('Import failed: invalid JSON', 5000); return;
  }
  const r = await fetch('/api/routing/import?mode=merge', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify(payload)
  });
  const res = await r.json();
  if (!r.ok) { toast('Import error: ' + (res.error || r.status), 5000); return; }
  toast(`Imported ${res.imported} rule${res.imported!==1?'s':''}, skipped ${res.skipped}`);
  await loadRules();
}

async function loadFlows() {
  const el = document.getElementById('flows-body');
  if (el) el.innerHTML = '<div class="loading">Loading…</div>';
  try {
    const [rulesRes, ruleArRes, chRes, chArRes, settingsRes, procSetRes, presetsRes] = await Promise.all([
      fetch('/api/routing').catch(()=>null),
      fetch('/api/routing/auto-route').catch(()=>null),
      fetch('/api/channels').catch(()=>null),
      fetch('/api/channels/auto-route').catch(()=>null),
      fetch('/api/settings').catch(()=>null),
      fetch('/api/channels/proc-settings').catch(()=>null),
      fetch('/api/process-presets').catch(()=>null),
    ]);
    if (rulesRes) { const d = await rulesRes.json().catch(()=>[]); if (Array.isArray(d)) _rulesCache = d; }
    if (ruleArRes) { const d = await ruleArRes.json().catch(()=>({})); _autoRouteRules = new Set((d.enabled||[]).map(String)); }
    if (chRes) { const d = await chRes.json().catch(()=>[]); if (Array.isArray(d)) allChannels = d; }
    if (chArRes) { const d = await chArRes.json().catch(()=>({})); _autoRouteChannels = new Set(d.enabled||[]); }
    if (settingsRes) { const d = await settingsRes.json().catch(()=>({})); _autoRoute = (d.auto_route==='1'); updateAutoRouteUI(); }
    if (procSetRes) { const d = await procSetRes.json().catch(()=>({})); _channelProcSettings = d; }
    if (presetsRes) { const d = await presetsRes.json().catch(()=>[]); if (Array.isArray(d)) _procPresets = d; }
  } catch(e) {}
  renderFlows();
}

function _flowRuleCard(r, active) {
  const srcLabel = r.source==='jellyfin' ? 'JF' : 'PX';
  const srcColor = r.source==='jellyfin' ? '#a855f7' : 'var(--acc)';
  const sectionPart = r.section_id==='*'
    ? '<span style="color:var(--muted);font-size:12px">any library</span>'
    : '<span style="font-size:12px">'+escHtml(r.section_id)+'</span>';
  const labelPart = r.label
    ? r.label.split(',').map(g=>'<span class="pill">'+escHtml(g.trim())+'</span>').join(' ')
    : '<span style="color:var(--muted);font-size:12px">any genre</span>';
  const border = active ? 'border-left:3px solid var(--acc)' : 'border-left:3px solid var(--bdr);opacity:.65';
  const btnStyle = active
    ? 'background:var(--acc);border:1px solid var(--acc);color:var(--bg)'
    : 'background:none;border:1px solid var(--bdr);color:var(--muted)';
  return '<div class="scard" style="padding:12px 16px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;'+border+'">'
    +'<span style="font-size:10px;font-weight:700;color:'+srcColor+';background:'+srcColor+'22;border-radius:4px;padding:2px 6px;flex-shrink:0">'+srcLabel+'</span>'
    +'<div style="flex:1;min-width:160px">'
    +'<div style="font-weight:600;font-size:13px">'+escHtml(r.name)+'</div>'
    +'<div style="font-size:12px;color:var(--muted);margin-top:3px">'+sectionPart+' &nbsp;→&nbsp; '+labelPart+' &nbsp;→&nbsp; <strong style="color:var(--txt)">'+escHtml(r.channel_name)+'</strong></div>'
    +'</div>'
    +'<button onclick="flowBtnClick(this)" data-type="rule" data-id="'+r.id+'" data-name="'+escHtml(r.name)+'" data-active="'+(active?'1':'0')+'" style="flex-shrink:0;'+btnStyle+';padding:4px 12px;border-radius:4px;cursor:pointer;font-size:12px;white-space:nowrap">'+(active?'Deactivate':'Activate')+'</button>'
    +'</div>';
}

function shuffleLabel(v) {
  if (v==='cyclic') return 'Cyclic shuffle';
  if (v==='random') return 'Random shuffle';
  return 'No shuffle';
}

function _miniRuleCard(r, active) {
  const srcLabel = r.source==='jellyfin' ? 'JF' : 'PX';
  const srcColor = r.source==='jellyfin' ? '#a855f7' : 'var(--acc)';
  const sectionPart = r.section_id==='*'
    ? '<span style="color:var(--muted);font-size:11px">any library</span>'
    : '<span style="font-size:11px">'+escHtml(r.section_id)+'</span>';
  const labelPart = r.label
    ? r.label.split(',').map(g=>'<span class="pill" style="font-size:10px">'+escHtml(g.trim())+'</span>').join(' ')
    : '<span style="color:var(--muted);font-size:11px">any genre</span>';
  const btnStyle = active
    ? 'background:var(--acc);border:1px solid var(--acc);color:var(--bg)'
    : 'background:none;border:1px solid var(--bdr);color:var(--muted)';
  return '<div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid var(--bdr);flex-wrap:wrap">'
    +'<span style="font-size:9px;font-weight:700;color:'+srcColor+';background:'+srcColor+'22;border-radius:3px;padding:1px 5px;flex-shrink:0">'+srcLabel+'</span>'
    +'<div style="flex:1;min-width:120px;font-size:12px">'+escHtml(r.name)+': '+sectionPart+' → '+labelPart+'</div>'
    +'<button onclick="flowBtnClick(this)" data-type="rule" data-id="'+r.id+'" data-name="'+escHtml(r.name)+'" data-active="'+(active?'1':'0')+'" style="flex-shrink:0;'+btnStyle+';padding:2px 8px;border-radius:4px;cursor:pointer;font-size:11px;white-space:nowrap">'+(active?'⚡ On':'Off')+'</button>'
    +'</div>';
}

function _pipelineCard(ch, rules, proc) {
  const autoOn = _autoRouteChannels.has(ch.id);
  const activeRules   = rules.filter(r => _autoRouteRules.has(String(r.id)));
  const inactiveRules = rules.filter(r => !_autoRouteRules.has(String(r.id)));

  const rulesHtml = rules.length
    ? '<div style="border-top:1px solid var(--bdr)">'
        + activeRules.map(r=>_miniRuleCard(r,true)).join('')
        + inactiveRules.map(r=>_miniRuleCard(r,false)).join('')
        + '</div>'
    : '<div style="font-size:12px;color:var(--muted);padding:6px 0">No rules route to this channel yet. <button onclick="openAddRuleForCh(this.dataset.ch)" data-ch="'+escHtml(ch.id)+'" style="background:none;border:none;color:var(--acc);cursor:pointer;font-size:12px;padding:0;text-decoration:underline">+ Create a rule</button></div>';

  let procHtml;
  if (proc) {
    const _presetBadge = proc.preset_name ? '<span class="pill" style="font-size:11px;background:var(--acc)22;color:var(--acc);font-weight:700">'+escHtml(proc.preset_name)+'</span> ' : '';
    procHtml = '<div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">'
      +_presetBadge
      +(proc.dedupe ? '<span class="pill" style="font-size:11px">Dedupe</span>' : '')
      +'<span class="pill" style="font-size:11px">'+shuffleLabel(proc.shuffle)+'</span>'
      +(proc.pad_minutes>0 ? '<span class="pill" style="font-size:11px">'+proc.pad_minutes+'m pad</span>' : '')
      +'<button onclick="openProcModal(\''+escHtml(ch.id)+'\')" style="margin-left:auto;padding:3px 10px;font-size:11px;background:none;border:1px solid var(--bdr);border-radius:4px;cursor:pointer;color:var(--txt);flex-shrink:0">⚙️ Process</button>'
      +'</div>';
  } else {
    procHtml = '<div style="display:flex;align-items:center;gap:8px">'
      +'<span style="font-size:12px;color:var(--muted)">Not yet processed</span>'
      +'<button onclick="openProcModal(\''+escHtml(ch.id)+'\')" style="margin-left:auto;padding:3px 10px;font-size:11px;background:none;border:1px solid var(--bdr);border-radius:4px;cursor:pointer;color:var(--muted);flex-shrink:0">⚙️ Set up</button>'
      +'</div>';
  }

  const borderColor = autoOn ? 'var(--acc)' : 'var(--bdr)';
  const opacity = autoOn ? '' : ';opacity:.75';
  const btnStyle = autoOn
    ? 'background:var(--acc2);border:1px solid var(--acc2);color:#fff'
    : 'background:none;border:1px solid var(--bdr);color:var(--muted)';
  return '<div class="scard" style="padding:0;border-left:3px solid '+borderColor+opacity+';overflow:hidden">'
    +'<div style="padding:10px 14px;display:flex;align-items:center;gap:10px">'
    +'<span style="font-size:10px;font-weight:700;color:var(--muted);background:var(--s3);border-radius:4px;padding:2px 6px;flex-shrink:0">CH</span>'
    +'<div style="flex:1;font-weight:600;font-size:13px">'+escHtml(ch.name)+'</div>'
    +'<button onclick="flowBtnClick(this)" data-type="channel" data-id="'+escHtml(ch.id)+'" data-name="'+escHtml(ch.name)+'" data-active="'+(autoOn?'1':'0')+'" style="flex-shrink:0;'+btnStyle+';padding:3px 10px;border-radius:4px;cursor:pointer;font-size:12px;white-space:nowrap">'+(autoOn?'Deactivate':'Activate')+'</button>'
    +'</div>'
    +'<div style="padding:6px 14px;border-top:1px solid var(--bdr)">'
    +'<div style="font-size:10px;color:var(--muted);margin-bottom:2px;text-transform:uppercase;letter-spacing:.5px">Routing rules</div>'
    +rulesHtml
    +'</div>'
    +'<div style="padding:8px 14px;border-top:1px solid var(--bdr)">'
    +'<div style="font-size:10px;color:var(--muted);margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px">Processing</div>'
    +procHtml
    +'</div>'
    +'</div>';
}

function _flowChannelCard(ch, active) {
  const border = active ? 'border-left:3px solid var(--acc)' : 'border-left:3px solid var(--bdr);opacity:.65';
  const btnStyle = active
    ? 'background:var(--acc);border:1px solid var(--acc);color:var(--bg)'
    : 'background:none;border:1px solid var(--bdr);color:var(--muted)';
  return '<div class="scard" style="padding:12px 16px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;'+border+'">'
    +'<span style="font-size:10px;font-weight:700;color:var(--muted);background:var(--s3);border-radius:4px;padding:2px 6px;flex-shrink:0">CH</span>'
    +'<div style="flex:1;min-width:160px">'
    +'<div style="font-weight:600;font-size:13px">'+escHtml(ch.name)+'</div>'
    +'<div style="font-size:12px;color:var(--muted);margin-top:3px">Any new content matched to this channel → auto-route</div>'
    +'</div>'
    +'<button onclick="flowBtnClick(this)" data-type="channel" data-id="'+escHtml(ch.id)+'" data-name="'+escHtml(ch.name)+'" data-active="'+(active?'1':'0')+'" style="flex-shrink:0;'+btnStyle+';padding:4px 12px;border-radius:4px;cursor:pointer;font-size:12px;white-space:nowrap">'+(active?'Deactivate':'Activate')+'</button>'
    +'</div>';
}

function setFlowFilter(v) {
  _flowFilter = v;
  document.querySelectorAll('.flows-f-btn').forEach(b => {
    b.style.opacity = b.dataset.f === v ? '1' : '.5';
    b.style.fontWeight = b.dataset.f === v ? '600' : '';
  });
  renderFlows();
}

function renderFlows() {
  const el = document.getElementById('flows-body');
  if (!el) return;

  const sortVal = (document.getElementById('flows-sort') || {}).value || 'name-asc';

  const chRuleMap = {};
  for (const r of _rulesCache) {
    if (!chRuleMap[r.channel_id]) chRuleMap[r.channel_id] = [];
    chRuleMap[r.channel_id].push(r);
  }

  const autoChIds = new Set(_autoRouteChannels);
  for (const r of _rulesCache) {
    if (_autoRouteRules.has(String(r.id))) autoChIds.add(r.channel_id);
  }

  let activePipelines = allChannels.filter(c => autoChIds.has(c.id));
  let inactiveCh      = allChannels.filter(c => !autoChIds.has(c.id));
  const coveredRuleIds  = new Set(activePipelines.flatMap(c => (chRuleMap[c.id]||[]).map(r=>r.id)));
  const inactiveRules   = _rulesCache.filter(r => !_autoRouteRules.has(String(r.id)) && !coveredRuleIds.has(r.id));

  const sortCh = arr => {
    arr = [...arr];
    if (sortVal === 'name-asc')    arr.sort((a,b) => a.name.localeCompare(b.name));
    else if (sortVal === 'name-desc')   arr.sort((a,b) => b.name.localeCompare(a.name));
    else if (sortVal === 'rules-desc')  arr.sort((a,b) => (chRuleMap[b.id]||[]).length - (chRuleMap[a.id]||[]).length);
    else if (sortVal === 'rules-asc')   arr.sort((a,b) => (chRuleMap[a.id]||[]).length - (chRuleMap[b.id]||[]).length);
    else if (sortVal === 'proc-first')  arr.sort((a,b) => (_channelProcSettings[b.id]?1:0) - (_channelProcSettings[a.id]?1:0));
    return arr;
  };
  activePipelines = sortCh(activePipelines);
  inactiveCh = sortCh(inactiveCh);

  if (!_rulesCache.length && !allChannels.length) {
    el.innerHTML = '<div class="empty">No rules or channels configured yet. Add rules on the Rules page to get started.</div>';
    return;
  }

  const showActive   = _flowFilter !== 'inactive';
  const showInactive = _flowFilter !== 'active';
  let html = '';

  if (showActive && activePipelines.length) {
    html += '<div class="sh" style="margin-bottom:12px"><div><h3 style="margin:0">Active pipelines</h3><div class="sub">These channels run automatically on every scan</div></div></div>';
    html += '<div style="display:flex;flex-direction:column;gap:12px;margin-bottom:28px">';
    for (const ch of activePipelines) {
      html += _pipelineCard(ch, chRuleMap[ch.id]||[], _channelProcSettings[ch.id]||null);
    }
    html += '</div>';
  }

  if (showInactive && (inactiveRules.length || inactiveCh.length)) {
    html += '<div class="sh" style="margin-bottom:10px"><div><h3 style="margin:0;color:var(--muted)">Inactive</h3><div class="sub">Activate to add to automated pipelines</div></div></div>';
    html += '<div style="display:flex;flex-direction:column;gap:8px">';
    inactiveRules.forEach(r => { html += _flowRuleCard(r, false); });
    inactiveCh.forEach(c => { html += _flowChannelCard(c, false); });
    html += '</div>';
  }

  el.innerHTML = html || '<div class="empty">No rules or channels yet.</div>';
}

function flowBtnClick(btn) {
  const type   = btn.dataset.type;
  const id     = btn.dataset.id;
  const name   = btn.dataset.name;
  const active = btn.dataset.active === '1';
  if (active) {
    const msg = type === 'channel'
      ? 'Stop auto-routing all content matched to \u201c' + name + '\u201d? Rules targeting this channel will remain but won\u2019t run automatically.'
      : 'Turn off auto-routing for rule \u201c' + name + '\u201d?';
    document.getElementById('deactivate-modal-msg').textContent = msg;
    _deactivatePending = type === 'channel'
      ? () => toggleChannelAutoRoute(id, false)
      : () => toggleRuleAutoRoute(Number(id), false);
    document.getElementById('deactivate-modal').classList.add('on');
  } else {
    if (type === 'channel') toggleChannelAutoRoute(id, true);
    else toggleRuleAutoRoute(Number(id), true);
  }
}

function closeDeactivateModal() {
  document.getElementById('deactivate-modal').classList.remove('on');
  _deactivatePending = null;
}

async function execDeactivate() {
  const fn = _deactivatePending;
  closeDeactivateModal();
  if (fn) await fn();
}
async function loadChannelAutoRoute() {
  try {
    const d = await (await fetch('/api/channels/auto-route')).json();
    _autoRouteChannels = new Set(d.enabled || []);
  } catch {}
}

async function toggleChannelAutoRoute(channelId, enabled) {
  if (enabled) _autoRouteChannels.add(channelId);
  else _autoRouteChannels.delete(channelId);
  renderChannels();
  if (document.getElementById('page-flows')?.classList.contains('on')) renderFlows();
  try {
    await fetch('/api/channels/auto-route', {
      method: 'PUT',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({channel_id: channelId, enabled})
    });
  } catch {}
}

async function enableAllAutoRoute() {
  _autoRouteChannels = new Set(allChannels.map(c => c.id));
  renderChannels();
  try {
    await fetch('/api/channels/auto-route', {
      method: 'PUT',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({enable_all: true})
    });
    logAction('Auto-route enabled for all channels', true, {action_type:'rule'});
  } catch {}
}

async function routeAllNow() {
  const btn = document.querySelector('[onclick="routeAllNow()"]');
  if (btn) { btn.disabled = true; btn.textContent = 'Routing…'; }
  try {
    const r = await (await fetch('/api/route/now', {method:'POST'})).json();
    const msg = r.routed > 0
      ? `Routed ${r.routed} item${r.routed===1?'':'s'} to ${r.channels} channel${r.channels===1?'':'s'}`
      : 'Nothing pending to route';
    logAction(msg, true, {action_type:'route'});
    toast(msg);
    if (r.routed > 0) loadChannels();
  } catch(e) {
    toast('Route failed');
  } finally {
    if (btn) { btn.disabled = false; btn.innerHTML = '⚡ Route All Now'; }
  }
}

async function loadRuleAutoRoute() {
  try {
    const d = await (await fetch('/api/routing/auto-route')).json();
    _autoRouteRules = new Set((d.enabled || []).map(String));
    _renderRulesTable();
  } catch {}
}

async function toggleRuleAutoRoute(ruleId, enabled) {
  if (enabled) _autoRouteRules.add(String(ruleId));
  else _autoRouteRules.delete(String(ruleId));
  _renderRulesTable();
  if (document.getElementById('page-flows')?.classList.contains('on')) renderFlows();
  try {
    const res = await fetch('/api/routing/'+ruleId, {
      method: 'PUT',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({auto_route: enabled ? 1 : 0})
    });
    toast(enabled ? '⚡ Auto-route on' : 'Auto-route off');
  } catch(e) {
    toast('Failed to save auto-route setting');
  }
}

async function enableAllRulesAutoRoute() {
  _autoRouteRules = new Set(_rulesCache.map(r => String(r.id)));
  _renderRulesTable();
  try {
    await fetch('/api/routing/auto-route', {
      method: 'PUT',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({enable_all: true})
    });
    logAction('Auto-route enabled for all rules', true, {action_type:'rule'});
    toast('⚡ Auto-route enabled for all rules');
  } catch {}
}

async function loadAutoRouteSetting() {
  try {
    const d = await (await fetch('/api/settings')).json();
    _autoRoute = (d.auto_route === '1' || d.auto_route === true);
    updateAutoRouteUI();
  } catch {}
}

function updateAutoRouteUI() {
  const chk = document.getElementById('auto-route-chk');
  const ind = document.getElementById('auto-route-ind');
  if (chk) chk.checked = _autoRoute;
  if (ind) ind.style.display = _autoRoute ? '' : 'none';
  const fchk = document.getElementById('flow-global-chk');
  const find = document.getElementById('flow-global-ind');
  if (fchk) fchk.checked = _autoRoute;
  if (find) find.style.display = _autoRoute ? '' : 'none';
}

async function setAutoRoute(enabled) {
  _autoRoute = enabled;
  updateAutoRouteUI();
  try {
    await fetch('/api/settings', {
      method: 'PUT',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({auto_route: enabled ? '1' : '0'})
    });
    logAction('Auto-route ' + (enabled ? 'enabled' : 'disabled'), true, {action_type:'rule'});
  } catch(e) {
    logAction('Failed to save auto-route setting', false, {action_type:'rule'});
  }
}

async function loadRules() {

  const rulesRes = await fetch('/api/routing');

  const rules = await rulesRes.json();

  _autoRouteRules = new Set(rules.filter(r => r.auto_route).map(r => String(r.id)));

  _rulesCache = rules;

  _rulesPage = 1;

  await renameRulesToCanonical(_rulesCache);

  _renderRulesTable();

}
async function deleteRule(id) {

  if (!confirm('Remove this routing rule?')) return;

  await fetch('/api/routing/'+id, {method:'DELETE'});

  loadRules();

}

function _renderRulesTable() {

  const tbody = document.getElementById('rules-body');

  if (!_rulesCache.length) {

    tbody.innerHTML = '<tr><td colspan="10" class="empty">No rules yet. Add one below.</td></tr>';

    _updateRulesPP(0, 1);

    return;

  }

  let rules = [..._rulesCache];

  if (_rulesSort.col) {

    rules.sort((a, b) => {

      const av = _ruleSortKey(a), bv = _ruleSortKey(b);

      return av < bv ? -_rulesSort.dir : av > bv ? _rulesSort.dir : 0;

    });

  }

  const total = rules.length;

  const pp = _rulesPP;

  const pages = pp > 0 ? Math.max(1, Math.ceil(total / pp)) : 1;

  if (_rulesPage > pages) _rulesPage = pages;

  const pageRules = pp > 0 ? rules.slice((_rulesPage - 1) * pp, _rulesPage * pp) : rules;

  const allSecs = [..._libMapSections, ..._jfSections];

  const secName = id => { const s = allSecs.find(s => s.id === id); return s ? s.title : (id === '*' ? 'Any' : id); };

  const srcBadge = src => {

    const label = src === 'jellyfin' ? 'JF' : 'Plex';

    const color = src === 'jellyfin' ? '#a855f7' : 'var(--acc)';

    return '<span style="font-size:10px;font-weight:700;color:' + color + ';background:' + color + '22;border-radius:4px;padding:2px 5px">' + label + '</span>';

  };

  tbody.innerHTML = pageRules.map(r =>

    '<tr>'

    + '<td style="text-align:center;width:32px"><input type="checkbox" class="rule-chk" data-id="' + r.id + '" onchange="_ruleChkChange(this)" style="cursor:pointer;accent-color:var(--acc)"' + (_rulesSelected.has(r.id) ? ' checked' : '') + '></td>'

    + '<td style="font-weight:500">' + r.name + '</td>'

    + '<td>' + srcBadge(r.source || 'plex') + '</td>'

    + '<td><span style="font-size:13px">' + secName(r.section_id) + '</span></td>'

    + '<td>' + (r.label ? r.label.split(',').map(g => '<span class="pill">' + g.trim() + '</span>').join('<span style="color:var(--muted);font-size:10px;padding:0 3px">+</span>') : '<span style="color:var(--muted);font-size:12px">any</span>') + '</td>'

    + '<td>' + (r.label_excl ? r.label_excl.split(',').map(g => '<span class="pill" style="background:var(--del-bg,#f443361a);color:var(--del,#f44336)">NOT ' + g.trim() + '</span>').join('<span style="color:var(--muted);font-size:10px;padding:0 3px">+</span>') : '<span style="color:var(--muted);font-size:12px">-</span>') + '</td>'

    + '<td>' + (r.title_filter ? '<span class="pill" style="background:var(--acc-bg,#2979ff1a);color:var(--acc)">“' + r.title_filter + '”</span>' : '<span style="color:var(--muted);font-size:12px">-</span>') + '</td>'

    + '<td>' + (r.title_excl ? '<span class="pill" style="background:var(--del-bg,#f443361a);color:var(--del,#f44336)">NOT “' + r.title_excl + '”</span>' : '<span style="color:var(--muted);font-size:12px">-</span>') + '</td>'

    + '<td style="font-size:13px">' + r.channel_name + '</td>'

    + '<td style="text-align:center;color:var(--muted);font-size:13px">' + r.priority + '</td>'

    + '<td style="text-align:center"><button onclick="toggleRuleAutoRoute(' + r.id + ','+(!_autoRouteRules.has(String(r.id)))+')" style="background:none;border:1px solid '+(_autoRouteRules.has(String(r.id))?'var(--acc)':'var(--bdr)')+';color:'+(_autoRouteRules.has(String(r.id))?'var(--acc)':'var(--muted)')+';padding:2px 7px;border-radius:4px;cursor:pointer;font-size:12px;white-space:nowrap" title="Toggle auto-route for this rule">'+ (_autoRouteRules.has(String(r.id)) ? '⚡ On' : 'Off') +'</button></td>'

    + '<td style="white-space:nowrap"><button class="edit-btn" onclick="openEditRule(' + r.id + ')" style="margin-right:4px;background:none;border:1px solid var(--bdr);color:var(--txt);padding:3px 8px;border-radius:4px;cursor:pointer;font-size:12px">&#x270E;</button>'

    + '<button onclick="deleteRule(' + r.id + ')" style="background:none;border:1px solid var(--bdr);color:var(--acc2);padding:3px 8px;border-radius:4px;cursor:pointer;font-size:12px">&#xD7;</button></td>'

    + '</tr>'

  ).join('');

  document.querySelectorAll('.sort-ind').forEach(el => el.textContent = '');

  if (_rulesSort.col) { const el = document.getElementById('si-' + _rulesSort.col); if (el) el.textContent = _rulesSort.dir === 1 ? ' ↑' : ' ↓'; }

  _updateRulesPP(total, pages);

  const allChk = document.getElementById('rules-chk-all');

  if (allChk) {

    const vis = pageRules.map(r => r.id);

    allChk.checked = vis.length > 0 && vis.every(id => _rulesSelected.has(id));

    allChk.indeterminate = !allChk.checked && vis.some(id => _rulesSelected.has(id));

  }

}

function _ruleSortKey(r) {

  const col = _rulesSort.col;

  if (col === 'name') return (r.name || '').toLowerCase();

  if (col === 'source') return r.source || 'plex';

  if (col === 'section') return r.section_id || '';

  if (col === 'channel') return (r.channel_name || '').toLowerCase();

  if (col === 'priority') return Number(r.priority) || 0;

  return '';

}

function sortRules(col) {

  if (_rulesSort.col === col) _rulesSort.dir *= -1;

  else { _rulesSort.col = col; _rulesSort.dir = 1; }

  _rulesPage = 1;

  _renderRulesTable();

}

function toggleAllRules(chk) {

  document.querySelectorAll('.rule-chk').forEach(c => {

    const id = parseInt(c.dataset.id);

    c.checked = chk.checked;

    if (chk.checked) _rulesSelected.add(id); else _rulesSelected.delete(id);

  });

  _updateBulkBar();

}

function _ruleChkChange(chk) {

  const id = parseInt(chk.dataset.id);

  if (chk.checked) _rulesSelected.add(id); else _rulesSelected.delete(id);

  _updateBulkBar();

  const allChk = document.getElementById('rules-chk-all');

  if (allChk) {

    const all = [...document.querySelectorAll('.rule-chk')];

    allChk.checked = all.length > 0 && all.every(c => c.checked);

    allChk.indeterminate = !allChk.checked && all.some(c => c.checked);

  }

}

function _updateRulesPP(total, pages) {

  const bar = document.getElementById('rules-pager');

  if (!bar) return;

  if (!total) { bar.style.display = 'none'; return; }

  bar.style.display = 'flex';

  const pg = _rulesPage, pgs = pages || 1;

  const sel = document.getElementById('rules-pp-sel');

  if (sel) sel.value = _rulesPP;

  const info = document.getElementById('rules-pg-info');

  if (info) info.textContent = pgs > 1 ? 'Page ' + pg + ' of ' + pgs : total + ' rule' + (total === 1 ? '' : 's');

  const prev = document.getElementById('rules-pg-prev');

  const next = document.getElementById('rules-pg-next');

  if (prev) prev.disabled = pg <= 1;

  if (next) next.disabled = pg >= pgs;

}

function setRulesPP(v) {

  _rulesPP = parseInt(v) || 0;

  _rulesPage = 1;

  _renderRulesTable();

}

function setRulesPage(d) {

  _rulesPage = Math.max(1, _rulesPage + d);

  _renderRulesTable();

}

// ── Bulk rule actions ─────────────────────────────────────────────────────────

function _updateBulkBar() {

  const n = _rulesSelected.size;

  const bar = document.getElementById('bulk-rule-bar');

  if (!bar) return;

  if (n === 0) {

    bar.style.display = 'none';

    _cancelBulkSub();

    return;

  }

  bar.style.display = 'flex';

  const lbl = document.getElementById('bulk-rule-count');

  if (lbl) lbl.textContent = n + ' selected';

}

function runBulkRuleAction(sel) {

  const action = sel.value;

  sel.value = '';

  _cancelBulkSub();

  if (action === 'delete') {

    bulkDeleteRules();

  } else if (action === 'export') {

    exportSelectedRules();

  } else if (action === 'channel') {

    const row = document.getElementById('bulk-ch-row');

    if (row) {

      const chSel = document.getElementById('bulk-ch-sel');

      chSel.innerHTML = _chanOpts();

      row.style.display = 'flex';

    }

  } else if (action === 'priority') {

    const row = document.getElementById('bulk-pri-row');

    if (row) row.style.display = 'flex';

  }

}

function _cancelBulkSub() {

  const cr = document.getElementById('bulk-ch-row');

  const pr = document.getElementById('bulk-pri-row');

  if (cr) cr.style.display = 'none';

  if (pr) pr.style.display = 'none';

}

async function bulkDeleteRules() {

  const ids = [..._rulesSelected];

  if (!ids.length) return;

  if (!confirm('Delete ' + ids.length + ' rule' + (ids.length === 1 ? '' : 's') + '?')) return;

  await Promise.all(ids.map(id => fetch('/api/routing/' + id, {method: 'DELETE'})));

  _rulesSelected.clear();

  toast('Deleted ' + ids.length + ' rule' + (ids.length === 1 ? '' : 's'));

  await loadRules();

}

function exportSelectedRules() {

  const ids = new Set(_rulesSelected);

  const subset = _rulesCache.filter(r => ids.has(r.id));

  const payload = {version: 1, exported_at: new Date().toISOString(), rules: subset};

  const blob = new Blob([JSON.stringify(payload, null, 2)], {type: 'application/json'});

  const a = document.createElement('a');

  a.href = URL.createObjectURL(blob);

  a.download = 'routarr-rules-selected.json';

  a.click();

}

async function applyBulkChannel() {

  const chSel = document.getElementById('bulk-ch-sel');

  const chId = chSel.value;

  const chName = chSel.options[chSel.selectedIndex]?.dataset.name || '';

  if (!chId) return;

  const ids = [..._rulesSelected];

  await Promise.all(ids.map(id => {

    const r = _rulesCache.find(x => x.id === id);

    if (!r) return;

    const updated = {...r, channel_id: chId, channel_name: chName,

      name: makeRuleName(r.section_id, r.label, chName)};

    return fetch('/api/routing/' + id, {method: 'PUT', headers: {'Content-Type':'application/json'},

      body: JSON.stringify(updated)});

  }));

  _cancelBulkSub();

  toast('Updated channel for ' + ids.length + ' rule' + (ids.length === 1 ? '' : 's'));

  await loadRules();

}

async function applyBulkPriority() {

  const val = parseInt(document.getElementById('bulk-pri-val').value) || 0;

  const ids = [..._rulesSelected];

  await Promise.all(ids.map(id => {

    const r = _rulesCache.find(x => x.id === id);

    if (!r) return;

    return fetch('/api/routing/' + id, {method: 'PUT', headers: {'Content-Type':'application/json'},

      body: JSON.stringify({...r, priority: val})});

  }));

  _cancelBulkSub();

  toast('Set priority ' + val + ' on ' + ids.length + ' rule' + (ids.length === 1 ? '' : 's'));

  await loadRules();

}

// ── Rule name live preview ────────────────────────────────────────────────────

function updateRuleName() {

  const chSel = document.getElementById('r-channel');

  const chName = chSel?.options[chSel.selectedIndex]?.dataset.name || '';

  const secVal = document.getElementById('r-section')?.value || '';

  const g1 = document.getElementById('r-g1')?.value.trim() || '';

  const g2 = document.getElementById('r-g2')?.value.trim() || '';

  const g3 = document.getElementById('r-g3')?.value.trim() || '';

  const label = [g1, g2, g3].filter(Boolean).join(',');

  const preview = document.getElementById('r-name-preview');

  if (preview) preview.textContent = makeRuleName(secVal, label, chName) || '-';

}

function updateRuleSections() {

  const src = document.getElementById('r-source').value;

  const pool = src === 'jellyfin' ? _jfSections : _libMapSections;

  document.getElementById('r-section').innerHTML =

    (pool.length

      ? pool.map(s => '<option value="'+s.id+'">'+s.title+' ('+s.type+')</option>').join('')

      : '<option value="">No libraries detected</option>'

    ) + '<option value="*">Any library</option>';

}





async function openAddRule() {

  if (!allChannels.length) {

    try { allChannels = await (await fetch('/api/channels')).json(); } catch {}

  }

  document.getElementById('r-channel').innerHTML =

    '<option value="">\u2014 pick a channel \u2014</option><option value="__skip__">&#8960; Skip (don\'t route)</option>' + _chanOpts();



  if (!_libMapSections.length && !_jfSections.length) {

    try {

      const [secs, jfSecs] = await Promise.all([

        fetch('/api/plex/sections').then(r=>r.json()).catch(()=>[]),

        fetch('/api/jellyfin/sections').then(r=>r.json()).catch(()=>[])

      ]);

      _libMapSections = Array.isArray(secs) ? secs : [];

      _jfSections = Array.isArray(jfSecs) ? jfSecs : [];

    } catch {}

  }



  document.getElementById('r-source').value = 'plex';

  updateRuleSections();

  document.getElementById('r-g1').value = '';

  document.getElementById('r-g2').value = '';

  document.getElementById('r-g3').value = '';

  document.getElementById('r-e1').value = '';

  document.getElementById('r-e2').value = '';

  document.getElementById('r-e3').value = '';

  document.getElementById('r-title-filter').value = '';

  document.getElementById('r-title-excl').value = '';

  document.getElementById('modal-title').textContent = 'Add routing rule';

  document.getElementById('modal-save-btn').textContent = 'Add rule';

  updateRuleName();

  document.getElementById('modal').classList.add('on');

  return Promise.resolve();

}
function closeModal() { document.getElementById('modal').classList.remove('on'); _editRuleId = null; }



async function openEditRule(id) {

  const r = _rulesCache.find(x => x.id === id);

  if (!r) return;

  _editRuleId = id;

  if (!allChannels.length) {

    try { allChannels = await (await fetch('/api/channels')).json(); } catch {}

  }

  document.getElementById('r-channel').innerHTML =

    '<option value="">\u2014 pick a channel \u2014</option><option value="__skip__">&#8960; Skip (don\'t route)</option>' + _chanOpts();

  if (!_libMapSections.length && !_jfSections.length) {

    try {

      const [secs, jfSecs] = await Promise.all([

        fetch('/api/plex/sections').then(x=>x.json()).catch(()=>[]),

        fetch('/api/jellyfin/sections').then(x=>x.json()).catch(()=>[])

      ]);

      _libMapSections = Array.isArray(secs) ? secs : [];

      _jfSections = Array.isArray(jfSecs) ? jfSecs : [];

    } catch {}

  }

  document.getElementById('r-source').value = r.source || 'plex';

  updateRuleSections();

  setTimeout(() => {

    document.getElementById('r-section').value = r.section_id;

    updateRuleName();

  }, 0);

  document.getElementById('r-channel').value = r.channel_id;

  const genres = (r.label || '').split(',').map(g=>g.trim());

  document.getElementById('r-g1').value = genres[0] || '';

  document.getElementById('r-g2').value = genres[1] || '';

  document.getElementById('r-g3').value = genres[2] || '';

  const excls = (r.label_excl || '').split(',').map(g=>g.trim());

  document.getElementById('r-e1').value = excls[0] || '';

  document.getElementById('r-e2').value = excls[1] || '';

  document.getElementById('r-e3').value = excls[2] || '';

  document.getElementById('r-title-filter').value = r.title_filter || '';

  document.getElementById('r-title-excl').value = r.title_excl || '';

  document.getElementById('r-priority').value = r.priority || 0;

  document.getElementById('modal-title').textContent = 'Edit rule';

  document.getElementById('modal-save-btn').textContent = 'Save changes';

  updateRuleName();

  document.getElementById('modal').classList.add('on');

}



async function saveRule() {

  const chSel = document.getElementById('r-channel');

  const chOpt = chSel.options[chSel.selectedIndex];

  const secSel = document.getElementById('r-section');

  const _g1 = document.getElementById('r-g1').value.trim();

  const _g2 = document.getElementById('r-g2').value.trim();

  const _g3 = document.getElementById('r-g3').value.trim();

  const _label = [_g1, _g2, _g3].filter(Boolean).join(',');

  const _e1 = document.getElementById('r-e1').value.trim();

  const _e2 = document.getElementById('r-e2').value.trim();

  const _e3 = document.getElementById('r-e3').value.trim();

  const _label_excl = [_e1, _e2, _e3].filter(Boolean).join(',');

  const _title_filter = document.getElementById('r-title-filter').value.trim();

  const _title_excl = document.getElementById('r-title-excl').value.trim();

  const _source = document.getElementById('r-source').value;

  const _chName = chOpt?.dataset.name || '';

  const rule = {

    name:         makeRuleName(secSel.value, _label, _chName),

    section_id:   secSel.value,

    label:        _label,

    channel_id:   chSel.value,

    channel_name: _chName,

    priority:     parseInt(document.getElementById('r-priority').value)||0,

    source:       _source,

    label_excl:   _label_excl,

    title_filter: _title_filter,

    title_excl:   _title_excl,

  };

  if (!rule.channel_id) { toast('Please select a channel'); return; }

  if (_editRuleId !== null) {

    await fetch('/api/routing/'+_editRuleId, {method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(rule)});

    closeModal();

    loadRules();

    logAction('Rule updated: '+rule.name, true, {action_type:'rule'});

    toast('Rule updated');

  } else {

    await fetch('/api/routing', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(rule)});

    closeModal();

    loadRules();

    logAction('Rule added: '+rule.name, true, {action_type:'rule'});

    toast('Rule added');

  }

}





// ── First-scan modal ----------------------------------------------------------------

let _fsmWantTour = false;

let _fsmDismissed = false;

let _fsmQTimer = null;



function _fsmStartQuotes() {

  const el = document.getElementById('fsm-quote');

  if (!el) return;

  let qi = Math.floor(Math.random() * _C64Q.length), ci = 0;

  function next() {

    const e = document.getElementById('fsm-quote');

    if (!e) { clearInterval(_fsmQTimer); _fsmQTimer = null; return; }

    e.style.opacity = '0';

    setTimeout(() => {

      const e2 = document.getElementById('fsm-quote');

      if (!e2) return;

      qi = (qi + 1) % _C64Q.length;

      ci = (ci + 1) % _C64C.length;

      e2.textContent = _C64Q[qi];

      e2.style.color = _C64C[ci];

      e2.style.opacity = '1';

    }, 500);

  }

  next();

  _fsmQTimer = setInterval(next, 3500);

}



function _fsmHide() {

  if (_fsmQTimer) { clearInterval(_fsmQTimer); _fsmQTimer = null; }

  const m = document.getElementById('first-scan-modal');

  if (m) m.style.display = 'none';

}



function fsmChoice(wantTour) {

  _fsmWantTour = wantTour;

  _fsmDismissed = true;

  _fsmHide();

}



// Show modal immediately if first scan hasn't completed yet

fetch('/api/scan/status').then(r => r.json()).then(s => {

  if (!s.first_scan_done) {

    const m = document.getElementById('first-scan-modal');

    if (m) m.style.display = 'flex';

    _fsmStartQuotes();

  }

}).catch(() => {});



// Init

loadArrivals();

updateScanStatus();

fetch('/api/settings').then(r=>r.json()).then(s=>{if(!s.setup_complete) setTimeout(startTour, 900);}).catch(()=>{});


// -- Tour ---------------------------------------------------------------------

function _tourNav(page) {

  const b = document.querySelector('button.tab[onclick*="' + page + '"]');

  if (b) show(page, b);

}

const TOUR = [

  {title:'Welcome to Routarr!',

   body:'This short tour covers the four setup steps: connect your services, map libraries, create routing rules, and route media. Open the <strong>Help</strong> tab any time for the full written guide with annotated diagrams.',

   target:null, action:null},

  {title:'1. Open Settings',

   body:'Click <strong>Settings</strong> in the top nav. All your service connection details live here.',

   target:'button.tab[onclick*="settings"]', action:()=>_tourNav('settings')},

  {title:'2. Enter your Plex address',

   body:'Enter your Plex server address, usually <code>http://192.168.1.x:32400</code>. This is what Routarr uses to scan your library for new content.',

   target:'#s-plex_url', action:null},

  {title:'3. Add your Plex token',

   body:'Your Plex token authenticates Routarr with Plex. Click the <strong>&#9432; How to find your Plex token</strong> link just below this field for step-by-step browser console instructions.',

   target:'#s-plex_token', action:null},

  {title:'4. Enter your Tunarr address',

   body:'Enter your Tunarr server address, usually <code>http://192.168.1.x:8000</code>. Then click <strong>Detect</strong> next to Plex source ID to auto-fill that field.',

   target:'#s-tunarr_url', action:null},

  {title:'5. Save and test',

   body:'Click <strong>Save connections</strong> to store your settings. Then click <strong>Test connections</strong> to confirm Routarr can reach all your services before moving on.',

   target:'button.btn.p[onclick="saveSettings()"]', action:null},

  {title:'6. Map your libraries',

   body:'Scroll down to <strong>Library Mapping</strong>. For each Plex/Jellyfin library, pick the matching Tunarr library. Set <strong>Scan Priority</strong>: use <em>Skip</em> on libraries like Music or Podcasts that you never want scanned. Click <strong>Save mapping</strong> when done.',

   target:'#lib-map-body', action:null},

  {title:'7. Create routing rules',

   body:'Click <strong>Rules</strong> in the nav. Rules decide which Tunarr channel new content goes to. Routarr evaluates them highest-priority-first; first match wins.',

   target:'button.tab[onclick*="rules"]', action:()=>_tourNav('rules')},

  {title:'8. Add your first rule',

   body:'Click <strong>+ Add rule</strong>. Pick a library, add genres to match (all must be present, AND logic), choose a Tunarr channel, and set a priority. Leave genres blank to match everything in the library.',

   target:'button[onclick="openAddRule()"]', action:null},

  {title:'9. Enable auto-route',

   body:'Tick <strong>Auto-route</strong> to have Routarr automatically apply your rules to every new arrival on each scan. You can also enable it per rule for finer control.',

   target:'#auto-route-chk', action:null},

  {title:'10. The Media tab',

   body:'Click <strong>Media</strong> in the nav. This shows everything Routarr has scanned from Plex/Jellyfin. Items show their matched channel; items labelled <em>no rule</em> need a rule created before they can be routed.',

   target:'button.tab[onclick*="arrivals"]', action:()=>_tourNav('arrivals')},

  {title:'11. Trigger a scan',

   body:'Click <strong>Scan Now</strong> to start a scan. Scans can take a few minutes depending on library size and server speed. The scan is done and Routarr is ready to use again when the activity at the top stops. New items appear in the list as they are found.',

   target:'#scan-now-btn', action:null},

  {title:'12. Route everything',

   body:'Click <strong>Route All</strong> to push every item through your rules at once. Or tick individual items and use the action bar at the bottom to route them to a specific channel manually.',

   target:'#raBtn', action:null},

  {title:'All set!',

   body:'Routarr will now scan Plex on your configured interval and route new content automatically. Check the <strong>Log</strong> tab to see every action taken. Re-open this tour any time with the &#9432; button in the top right.',

   target:null, action:null}

];

let _ts = 0, _tRing = null, _tTip = null;

function startTour() {

  _ts = 0;

  if (!_tRing) {

    _tRing = document.createElement('div');

    _tRing.style.cssText = 'display:none;position:fixed;z-index:9000;pointer-events:none;border-radius:8px;'

      + 'box-shadow:0 0 0 4000px rgba(0,0,0,.72),0 0 0 3px var(--acc);'

      + 'transition:top .3s,left .3s,width .3s,height .3s;';

    document.body.appendChild(_tRing);

    _tTip = document.createElement('div');

    document.body.appendChild(_tTip);

  }

  _doTourStep();

}

function _doTourStep() {

  const s = TOUR[_ts];

  if (s.action) { try { s.action(); } catch(e){} }

  setTimeout(() => {

    if (s.target) {

      const _el = document.querySelector(s.target);

      if (_el) _el.scrollIntoView({behavior:'smooth', block:'center'});

    }

    setTimeout(() => _placeTip(s), s.target ? 380 : 0);

  }, s.action ? 350 : 0);

}

function _placeTip(s) {

  const n = TOUR.length, last = _ts === n - 1;

  const prev = '<button class="btn g sm" style="font-size:12px;padding:6px 12px" onclick="_tPrev()">← Back</button>';

  const skip = '<button class="btn g sm" style="font-size:12px;padding:6px 12px" onclick="endTour()">Skip</button>';

  const next = '<button class="btn p sm" style="font-size:12px;padding:6px 14px"'

    + ' onclick="' + (last ? 'endTour()' : '_tNext()') + '">'

    + (last ? 'Done' : 'Next →') + '</button>';

  _tTip.innerHTML = '<div style="font-size:13px;font-weight:700;margin-bottom:8px;color:var(--acc)">' + s.title + '</div>'

    + '<div style="font-size:13px;line-height:1.55;color:var(--txt)">' + s.body + '</div>'

    + '<div style="display:flex;align-items:center;justify-content:space-between;margin-top:16px;gap:8px">'

    + (_ts > 0 ? prev : '<span></span>')

    + '<span style="font-size:11px;color:var(--muted)">' + (_ts + 1) + ' of ' + n + '</span>'

    + '<div style="display:flex;gap:6px">' + (!last ? skip : '') + next + '</div>'

    + '</div>';

  const isCtr = !s.target;

  const el = isCtr ? null : document.querySelector(s.target);

  const tipW = Math.min(380, window.innerWidth - 32);

  Object.assign(_tTip.style, {

    display: 'block', position: 'fixed', zIndex: '9001',

    background: 'var(--card)', border: '1px solid var(--bdr)',

    borderRadius: '12px', padding: '22px 20px',

    width: tipW + 'px', maxWidth: '380px',

    boxShadow: isCtr

      ? '0 0 0 9999px rgba(0,0,0,.72),0 16px 48px rgba(0,0,0,.5)'

      : '0 8px 32px rgba(0,0,0,.5)'

  });

  if (isCtr || !el) {

    if (_tRing) _tRing.style.display = 'none';

    Object.assign(_tTip.style, { top: '50%', left: '50%', transform: 'translate(-50%,-50%)' });

  } else {

    const r = el.getBoundingClientRect(), pad = 8;

    Object.assign(_tRing.style, {

      display: 'block',

      top: (r.top - pad) + 'px', left: (r.left - pad) + 'px',

      width: (r.width + pad * 2) + 'px', height: (r.height + pad * 2) + 'px'

    });

    const spBelow = window.innerHeight - r.bottom - 16;

    const tipLeft = Math.max(12, Math.min(r.left, window.innerWidth - tipW - 12));

    _tTip.style.transform = 'none';

    _tTip.style.left = tipLeft + 'px';

    _tTip.style.top = (spBelow >= 170 ? r.bottom + pad + 12 : Math.max(12, r.top - pad - 12 - 200)) + 'px';

  }

}

function _tNext() { if (_ts < TOUR.length - 1) { _ts++; _doTourStep(); } }

function _tPrev() { if (_ts > 0) { _ts--; _doTourStep(); } }

function endTour() {

  if (_tRing) _tRing.style.display = 'none';

  if (_tTip) _tTip.style.display = 'none';

  fetch('/api/settings', {method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify({setup_complete:'1'})}).catch(()=>{});

}

// -- Auth JS ------------------------------------------------------------------

async function saveAuth() {

  const uEl = document.getElementById('s-auth_username');

  const pEl = document.getElementById('s-auth_password');

  const cEl = document.getElementById('s-auth_confirm');

  const msg = document.getElementById('auth-msg');

  const u = uEl ? uEl.value.trim() : '';

  const p = pEl ? pEl.value : '';

  const c = cEl ? cEl.value : '';

  if (p && p !== c) {

    msg.style.color = '#f87171';

    msg.textContent = 'Passwords do not match';

    return;

  }

  try {

    const r = await fetch('/api/auth', {

      method: 'PUT',

      headers: {'Content-Type': 'application/json'},

      body: JSON.stringify({username: u, password: p, confirm: c})

    });

    const d = await r.json();

    if (d.ok) {

      msg.style.color = 'var(--acc)';

      msg.textContent = 'Saved.' + (p ? ' Password updated.' : '') + (u ? '' : ' Auth disabled.');

      if (pEl) pEl.value = '';

      if (cEl) cEl.value = '';

    } else {

      msg.style.color = '#f87171';

      msg.textContent = d.error || 'Error saving';

    }

  } catch(e) {

    msg.style.color = '#f87171';

    msg.textContent = 'Request failed';

  }

}


</script>

</body>

</html>"""



@app.get("/", response_class=HTMLResponse)

async def frontend():

    return HTMLResponse(HTML)



if __name__ == "__main__":

    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=6942, log_level="info")


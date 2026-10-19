#!/usr/bin/env python3
"""
Agent Gate -- Home Assistant add-on.

One switch that opens and locks, together, everything an AI agent can use to
change this system:

  * the MCP write path   (this process sits between the Webhook Proxy and
                          ha-mcp and refuses write tools while locked)
  * a shell command tool (gate_run_command, runs inside this container with
                          /addons, /homeassistant, /share mounted)
  * the editing add-ons  (SSH, Claude Terminal, VS Code, File editor,
                          AppDaemon ... any list, configured, not coded)

Locked is the default. A window is opened only from the dashboard (MQTT
switch/buttons), never from the agent: every tool call whose arguments
touch the gate's own entities or topics is refused even while open.

Layout of this file:
  1. config + state          (options.json, /data/state.json)
  2. Supervisor / HA helpers (add-on start/stop/info, backups, notify)
  3. policy                  (read-only tool patterns, protected patterns,
                              destructive command patterns)
  4. window engine           (open / lock / extend / timers / deviation)
  5. MQTT entities           (discovery, state publishing, commands)
  6. MCP proxy               (Streamable HTTP pass-through with gating)
  7. gate tools              (gate_status, gate_run_command)
  8. main
"""

import collections
import fnmatch
import hashlib
import http.client
import http.server
import json
import os
import re
import secrets
import socketserver
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

try:
    import websocket  # websocket-client, used once to create the ready-made dashboard
except Exception:  # pragma: no cover
    websocket = None
try:
    import paho.mqtt.client as mqtt
except Exception:  # pragma: no cover - the image always has it
    mqtt = None

# --------------------------------------------------------------------------
# 1. config + state
# --------------------------------------------------------------------------
VERSION = "0.4.8"
OPTIONS_PATH = os.environ.get("GATE_OPTIONS", "/data/options.json")
DATA_DIR = os.environ.get("GATE_DATA", "/data")
STATE_PATH = os.path.join(DATA_DIR, "state.json")
TOKEN_PATH = os.path.join(DATA_DIR, "endpoint_token")
AUDIT_PATH = os.path.join(DATA_DIR, "audit.jsonl")
COMMANDS_PATH = os.path.join(DATA_DIR, "commands.jsonl")
HISTORY_PATH = os.path.join(DATA_DIR, "windows.jsonl")

SUPERVISOR = os.environ.get("SUPERVISOR_URL", "http://supervisor")
SUPERVISOR_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")
# Supervisor sets HOSTNAME to "<repo>-agent-gate"; the add-on slug is the same with underscores.
SELF_SLUG = os.environ.get("GATE_SELF_SLUG") or os.environ.get("HOSTNAME", "local-agent-gate").replace("-", "_")

MOUNTS = [p for p in ("/addons", "/homeassistant", "/share") if os.path.isdir(p)]
CHANGED_FILES_EXCLUDE = re.compile(
    r"(home-assistant_v2\.db|\.log(\.\d+)?$|/\.git/|__pycache__|/deps/|/tts/|/image/)")

LOG_LOCK = threading.Lock()


def log(msg):
    with LOG_LOCK:
        sys.stderr.write(f"[agent_gate] {datetime.now().strftime('%H:%M:%S')} {msg}\n")
        sys.stderr.flush()


def now_utc():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def parse_iso(s):
    if not s:
        return None
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def load_options():
    defaults = {
        "upstream_mcp_url": "",
        "listen_port": 9584,
        "notify_service": "notify",
        "reminder_minutes": 60,
        "deviation_grace_minutes": 5,
        "approval_timeout_minutes": 3,
        "backup_policy": "always",
        "backup_skip_short": False,
        "language": "en",
        "default_window_minutes": 30,
        "create_dashboard": True,
        "scan_interval_hours": 24,
        "read_tool_patterns": ["ha_get_*", "ha_list_*", "ha_search", "ha_config_get_*",
                               "ha_config_list_*", "ha_read_file", "ha_eval_template",
                               "ha_get_skill_guide", "ha_report_issue"],
        "protected_patterns": ["agent_gate"],
        "destructive_patterns": [],
        "mechanisms": [],
        "anomaly_enabled": True,
        "anomaly_writes_warn_per_min": 60,
        "anomaly_deletes_lock_per_min": 5,
        "redact_secrets": True,
        "redact_patterns": [],
        "canary_enabled": True,
        "canary_files": ["/homeassistant/secrets_backup.yaml", "/share/agent_gate/credentials.txt"],
    }
    try:
        with open(OPTIONS_PATH, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        log(f"options.json not readable ({e}); using defaults")
        data = {}
    for k, v in data.items():
        if v is not None:
            defaults[k] = v
    return defaults


OPT = load_options()

# Mechanisms that are flags inside the gate rather than add-ons.
BUILTIN_MECHANISMS = [
    {"key": "ha_write", "name": "HA write (MCP)", "addons": [], "default_on": True},
    {"key": "commands", "name": "Shell commands", "addons": [], "default_on": True},
]
MECHANISMS = BUILTIN_MECHANISMS + [
    {"key": m.get("key"), "name": m.get("name") or m.get("key"),
     "addons": [a for a in (m.get("addons") or []) if a],
     "default_on": bool(m.get("default_on", False))}
    for m in OPT.get("mechanisms", []) if m.get("key")
]
MECH_BY_KEY = {m["key"]: m for m in MECHANISMS}


def _atomic_write_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def _append_jsonl(path, entry):
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        log(f"could not append to {path}: {e}")


STATE_LOCK = threading.RLock()


def default_state():
    return {
        "mode": "locked",            # locked | opening | open (derived from windows)
        "window_id": None,           # session id: first open -> last close
        "opened_at": None,
        "windows": {},               # mechanism key -> {"end": iso|None, "opened_at": iso}
        "last_reminder": None,
        "deviation_since": None,
        "deviation_notified": False,
        "pending": {},               # approval_id -> {command, cwd, timeout, created, status}
    }


def load_state():
    try:
        with open(STATE_PATH, encoding="utf-8") as f:
            st = json.load(f)
        base = default_state()
        for k, v in st.items():
            base[k] = v
        # migrate a 0.1.x state (single window + desired set)
        if "desired" in base and not base.get("windows"):
            if base.get("mode") == "open":
                end = base.get("window_end")
                base["windows"] = {k: {"end": end, "opened_at": base.get("opened_at")}
                                   for k, on in base["desired"].items() if on and k in MECH_BY_KEY}
            base.pop("desired", None)
            base.pop("window_end", None)
        base["windows"] = {k: v for k, v in (base.get("windows") or {}).items() if k in MECH_BY_KEY}
        if base.get("mode") != "opening":
            base["mode"] = "open" if base["windows"] else "locked"
        return base
    except Exception:
        return default_state()


STATE = load_state()

SETTINGS_PATH = os.path.join(DATA_DIR, "settings.json")
BACKUP_POLICIES = {"always": None, "every_6h": 6, "daily": 24, "never": None}
SETTINGS_KEYS = {
    "backup_policy": tuple(BACKUP_POLICIES),
    "backup_skip_short": ("ON", "OFF"),
    "reminder_minutes": (0, 1440),
}
SHORT_WINDOW_MINUTES = 15


def load_settings():
    try:
        with open(SETTINGS_PATH, encoding="utf-8") as f:
            return {k: v for k, v in json.load(f).items() if k in SETTINGS_KEYS}
    except Exception:
        return {}


SETTINGS = load_settings()


def setting(key):
    """Dashboard-set value wins over options.json; options.json wins over the default."""
    if key in SETTINGS:
        return SETTINGS[key]
    return OPT.get(key)


def set_setting(key, value):
    spec = SETTINGS_KEYS.get(key)
    if spec is None:
        return False
    if isinstance(spec[0], str):
        value = str(value).strip()
        if key == "backup_skip_short":
            value = "ON" if value.upper() in ("ON", "TRUE", "1") else "OFF"
        if value not in spec:
            return False
    else:
        try:
            value = int(float(value))
        except Exception:
            return False
        value = max(spec[0], min(spec[1], value))
    SETTINGS[key] = value
    try:
        _atomic_write_json(SETTINGS_PATH, SETTINGS)
    except Exception as e:
        log(f"could not persist settings: {e}")
    log(f"setting {key} = {value}")
    return True


def backup_policy():
    v = setting("backup_policy")
    if v in BACKUP_POLICIES:
        return v
    # 0.1.x options
    mode = OPT.get("backup_mode")
    if mode == "never" or OPT.get("backup_on_open") is False:
        return "never"
    if mode == "if_stale":
        return "daily" if int(OPT.get("backup_min_interval_hours") or 6) >= 12 else "every_6h"
    return "always"


def backup_skip_short():
    v = setting("backup_skip_short")
    if isinstance(v, str):
        return v.upper() == "ON"
    if v is None:
        return int(OPT.get("backup_skip_windows_up_to_minutes") or 0) > 0
    return bool(v)


LANG = "he" if str(OPT.get("language") or "en").lower().startswith("he") else "en"
STRINGS = {
    "en": {
        "title": "Agent Gate", "title_open": "Agent Gate OPEN", "title_locked": "Agent Gate LOCKED",
        "title_still_open": "Agent Gate still OPEN", "title_deviation": "Agent Gate: deviation",
        "until": "until", "until_closed": "until you close it",
        "backup_failed": "Backup failed. Nothing was opened.",
        "backup_failed_plain": "Backup failed.", "backup_done": "Backup created.",
        "closed_expired": "{names}: time is up, closed.",
        "locked_line": "Locked ({reason}). {n} command(s) ran.",
        "changed_files": "Changed files: {n}",
        "deviation_body": "{names} running while the gate says it should be off. "
                          "Stopping in {mins} min unless you open a window.",
        "btn_lock": "Lock now", "btn_plus_hour": "+1 hour", "btn_open_hour": "Open 1 hour",
        "btn_stop_now": "Stop it now",
        "approve_title": "Agent Gate: approve command?", "btn_approve": "Approve", "btn_reject": "Reject",
        "approve_hint": "Approve or reject with the buttons on the phone notification or on the Agent Gate dashboard.",
        "canary_title": "Agent Gate: TRAP TRIPPED, locked",
        "canary_body": "{what} touched a decoy ({where}). Nothing real was exposed. Every mechanism was closed. Review the agent's recent actions before opening again.",
        "anomaly_title": "Agent Gate: unusual activity",
        "anomaly_lock_body": "{n} delete/stop operations within a minute (last: {tool}). Every mechanism was closed. Open a window again only if this was you.",
        "anomaly_warn_body": "{n} write operations within a minute (last: {tool}). Still open. Lock if this is not what you expected.",
        "tamper_title": "Agent Gate: tamper warning",
        "tamper_options": "The gate's options changed while it was down: {keys}. If that was not you, review the add-on configuration.",
        "tamper_down": "The gate was not running for {mins} min (until {until}). During that time nothing enforced the lock.",
    },
    "he": {
        "title": "שער הסוכן", "title_open": "שער הסוכן פתוח", "title_locked": "שער הסוכן נעול",
        "title_still_open": "שער הסוכן עדיין פתוח", "title_deviation": "שער הסוכן: סטייה",
        "until": "עד", "until_closed": "עד שתסגור",
        "backup_failed": "הגיבוי נכשל. שום דבר לא נפתח.",
        "backup_failed_plain": "הגיבוי נכשל.", "backup_done": "הגיבוי נוצר.",
        "closed_expired": "{names}: הזמן נגמר, נסגר.",
        "locked_line": "ננעל ({reason}). רצו {n} פקודות.",
        "changed_files": "קבצים ששונו: {n}",
        "deviation_body": "{names} רץ בזמן שהשער נעול. ייסגר בעוד {mins} דקות אם לא תפתח חלון.",
        "btn_lock": "נעל עכשיו", "btn_plus_hour": "+ שעה", "btn_open_hour": "פתח לשעה",
        "btn_stop_now": "עצור עכשיו",
        "approve_title": "שער הסוכן: לאשר פקודה?", "btn_approve": "אשר", "btn_reject": "דחה",
        "approve_hint": "אישור או דחייה בכפתורים שבהתראת הטלפון או בדשבורד של השער.",
        "canary_title": "שער הסוכן: המלכודת הופעלה, ננעל",
        "canary_body": "{what} נגע בפיתיון ({where}). שום דבר אמיתי לא נחשף. כל המנגנונים נסגרו. בדוק את הפעולות האחרונות של הסוכן לפני פתיחה מחדש.",
        "anomaly_title": "שער הסוכן: פעילות חריגה",
        "anomaly_lock_body": "{n} פעולות מחיקה או עצירה בתוך דקה (האחרונה: {tool}). כל המנגנונים נסגרו. פתח חלון שוב רק אם זה היית אתה.",
        "anomaly_warn_body": "{n} פעולות כתיבה בתוך דקה (האחרונה: {tool}). עדיין פתוח. נעל אם זה לא מה שציפית.",
        "tamper_title": "שער הסוכן: אזהרת חבלה",
        "tamper_options": "הגדרות השער השתנו בזמן שהוא לא רץ: {keys}. אם זה לא היית אתה, בדוק את הגדרות התוסף.",
        "tamper_down": "השער לא רץ במשך {mins} דקות (עד {until}). בזמן הזה שום דבר לא אכף את הנעילה.",
    },
}


def T(key, **kw):
    s = STRINGS.get(LANG, STRINGS["en"]).get(key) or STRINGS["en"].get(key, key)
    return s.format(**kw) if kw else s


def save_state():
    with STATE_LOCK:
        _atomic_write_json(STATE_PATH, STATE)


def endpoint_token():
    try:
        with open(TOKEN_PATH, encoding="utf-8") as f:
            t = f.read().strip()
            if len(t) >= 16:
                return t
    except Exception:
        pass
    t = secrets.token_urlsafe(24)
    try:
        with open(TOKEN_PATH, "w", encoding="utf-8") as f:
            f.write(t)
    except Exception as e:
        log(f"could not persist endpoint token: {e}")
    return t


ENDPOINT_TOKEN = endpoint_token()
ENDPOINT_PATH = f"/mcp/{ENDPOINT_TOKEN}"
REPORT_TOKEN_PATH = os.path.join(DATA_DIR, "report_token")


def _file_token(path):
    try:
        with open(path, encoding="utf-8") as f:
            t = f.read().strip()
            if len(t) >= 16:
                return t
    except Exception:
        pass
    t = secrets.token_urlsafe(18)
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(t)
    except Exception as e:
        log(f"could not persist token {path}: {e}")
    return t


REPORT_TOKEN = _file_token(REPORT_TOKEN_PATH)
REPORT_PATH = f"/report/{REPORT_TOKEN}"
HA_HOST = None


def ha_host():
    """Best guess of the Home Assistant LAN address, for links in the dashboard."""
    global HA_HOST
    if HA_HOST:
        return HA_HOST
    try:
        code, d = _sup_request("GET", "/network/info", timeout=15)
        for itf in (d.get("data", {}).get("interfaces", []) if code == 200 else []):
            if itf.get("primary") or itf.get("connected"):
                for a in itf.get("ipv4", {}).get("address", []):
                    HA_HOST = a.split("/")[0]
                    return HA_HOST
    except Exception:
        pass
    HA_HOST = "homeassistant.local"
    return HA_HOST


# --------------------------------------------------------------------------
# 2. Supervisor / HA helpers
# --------------------------------------------------------------------------
def _sup_request(method, path, body=None, timeout=30):
    u = urlsplit(SUPERVISOR)
    conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
    headers = {"Authorization": f"Bearer {SUPERVISOR_TOKEN}", "Content-Type": "application/json"}
    data = json.dumps(body).encode("utf-8") if body is not None else None
    try:
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        try:
            parsed = json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            parsed = {"raw": raw.decode("utf-8", "replace")}
        return resp.status, parsed
    finally:
        conn.close()


def addon_state(slug):
    try:
        code, data = _sup_request("GET", f"/addons/{slug}/info", timeout=15)
        if code == 200:
            return data.get("data", {}).get("state", "unknown")
        return "unknown"
    except Exception as e:
        log(f"addon_state({slug}) failed: {e}")
        return "unknown"


def addon_action(slug, action):
    if slug == SELF_SLUG:
        log(f"refusing to {action} myself ({slug})")
        return False
    try:
        code, data = _sup_request("POST", f"/addons/{slug}/{action}", body={}, timeout=120)
        ok = code == 200 and data.get("result") == "ok"
        log(f"addon {action} {slug}: {'ok' if ok else data}")
        return ok
    except Exception as e:
        log(f"addon {action} {slug} failed: {e}")
        return False


def create_full_backup(name):
    """Synchronous full backup through the Supervisor. Can take minutes."""
    try:
        code, data = _sup_request("POST", "/backups/new/full", body={"name": name}, timeout=1800)
        if code == 200 and data.get("result") == "ok":
            slug = data.get("data", {}).get("slug")
            log(f"backup created: {slug}")
            return slug
        log(f"backup failed: {code} {data}")
    except Exception as e:
        log(f"backup failed: {e}")
    return None


def latest_full_backup_age_hours():
    """Hours since the newest full backup the Supervisor knows about (any source), or None."""
    try:
        code, data = _sup_request("GET", "/backups", timeout=30)
        if code != 200:
            return None
        newest = None
        for b in data.get("data", {}).get("backups", []):
            if b.get("type") != "full":
                continue
            d = b.get("date")
            if not d:
                continue
            try:
                dt = datetime.fromisoformat(d.replace("Z", "+00:00"))
            except Exception:
                continue
            if newest is None or dt > newest:
                newest = dt
        if newest is None:
            return None
        return (now_utc() - newest).total_seconds() / 3600.0
    except Exception as e:
        log(f"backup list failed: {e}")
        return None


def backup_needed(minutes):
    """Apply the user's backup policy. Returns (needed, reason)."""
    pol = backup_policy()
    if pol == "never":
        return False, "policy=never"
    if backup_skip_short() and minutes and minutes <= SHORT_WINDOW_MINUTES:
        return False, f"short window ({minutes} min) and backup_skip_short is on"
    max_age = BACKUP_POLICIES.get(pol)
    if max_age:
        age = latest_full_backup_age_hours()
        if age is not None and age < max_age:
            return False, f"policy={pol}, last full backup is {age:.1f} h old"
        return True, f"policy={pol}, " + ("no full backup found" if age is None else f"last full backup is {age:.1f} h old")
    return True, "policy=always"


def ha_call_service(domain, service, payload):
    try:
        code, data = _sup_request("POST", f"/core/api/services/{domain}/{service}", body=payload, timeout=30)
        return code in (200, 201)
    except Exception as e:
        log(f"service {domain}.{service} failed: {e}")
        return False


def notify(title, message, actions=None, tag=None):
    svc = (OPT.get("notify_service") or "notify").replace("notify.", "")
    payload = {"title": title, "message": message, "data": {}}
    if tag:
        payload["data"]["tag"] = tag
    if actions:
        payload["data"]["actions"] = actions
    if not payload["data"]:
        payload.pop("data")
    ok = ha_call_service("notify", svc, payload)
    # Persistent notification as a fallback that is always visible in HA. It has no
    # buttons: the Approve/Reject buttons are on the phone push and on the dashboard.
    ha_call_service("persistent_notification", "create",
                    {"title": title, "message": message + ("\n\n" + T("approve_hint") if actions else ""),
                     "notification_id": tag or f"agent_gate_{uuid.uuid4().hex[:8]}"})
    return ok


# --------------------------------------------------------------------------
# 3. policy
# --------------------------------------------------------------------------
READ_PATTERNS = [p for p in OPT.get("read_tool_patterns", []) if p]
PROTECTED = [p.lower() for p in OPT.get("protected_patterns", []) if p]
DESTRUCTIVE = []
for p in OPT.get("destructive_patterns", []) or []:
    try:
        DESTRUCTIVE.append(re.compile(p, re.I))
    except re.error as e:
        log(f"bad destructive pattern {p!r}: {e}")

GATE_TOOL_NAMES = ("gate_status", "gate_run_command")
# Write tools that may mention the gate's entities without being able to act on them:
# a dashboard card is tapped by the user, a label or category is cosmetic.
PROTECTED_EXEMPT = set(OPT.get("protected_exempt_tools") or [
    "ha_config_set_dashboard", "ha_config_set_dashboard_resource",
    "ha_config_set_label", "ha_config_set_category"])


def is_read_tool(name):
    return any(fnmatch.fnmatchcase(name, p) for p in READ_PATTERNS)


def touches_protected(arguments):
    blob = json.dumps(arguments or {}, ensure_ascii=False).lower()
    return any(p in blob for p in PROTECTED)


def is_destructive(command):
    return any(rx.search(command) for rx in DESTRUCTIVE)


def audit(entry):
    entry["ts"] = iso(now_utc())
    _append_jsonl(AUDIT_PATH, entry)


# --------------------------------------------------------------------------
# 3b. honeypot (decoy files and a decoy token) and tamper protection
#
# A decoy is something no legitimate task ever needs: a file that looks like a
# secrets backup, and a token string inside it. Any tool call or shell command
# that mentions a decoy path or the decoy token is denied, every mechanism is
# closed at once, and the hit is kept for the scan and the phone.
# --------------------------------------------------------------------------
CANARY_ENABLED = bool(OPT.get("canary_enabled", True))
CANARY_FILES = [str(p) for p in (OPT.get("canary_files") or []) if p]
CANARY_TOKEN_PATH = os.path.join(DATA_DIR, "canary_token")
CANARY_TOKEN = _file_token(CANARY_TOKEN_PATH) if CANARY_ENABLED else ""
CANARY_MARK = "agent_gate_canary"
CANARY_HITS_PATH = os.path.join(DATA_DIR, "canary_hits.jsonl")
CANARY_LOCK = threading.Lock()


def _canary_content(path):
    name = os.path.basename(path)
    if name.endswith((".yaml", ".yml")):
        return (f"# {name} - do not share\n"
                f"ha_long_lived_token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{CANARY_TOKEN}\n"
                f"wifi_password: {CANARY_MARK}_{CANARY_TOKEN[:8]}\n"
                f"mqtt_password: {CANARY_TOKEN[8:24]}\n")
    return (f"{name}\nHOME ASSISTANT TOKEN={CANARY_TOKEN}\nROUTER ADMIN PASSWORD={CANARY_MARK}_{CANARY_TOKEN[:8]}\n")


def place_canaries():
    """Create the decoy files (only where the parent directory exists)."""
    if not CANARY_ENABLED:
        return
    for path in CANARY_FILES:
        try:
            d = os.path.dirname(path)
            if not os.path.isdir(d):
                os.makedirs(d, exist_ok=True)
            if not os.path.exists(path) or CANARY_TOKEN not in open(path, encoding="utf-8", errors="replace").read():
                with open(path, "w", encoding="utf-8") as f:
                    f.write(_canary_content(path))
        except Exception as e:
            log(f"canary {path}: {e}")


def canary_match(text):
    """Return what was matched (path or 'token') if the text touches a decoy."""
    if not CANARY_ENABLED or not text:
        return None
    low = text.lower()
    if CANARY_TOKEN and CANARY_TOKEN.lower() in low:
        return "token"
    for path in CANARY_FILES:
        base = os.path.basename(path).lower()
        # Full path, or the bare file name: ha_read_file / ha_write_file take
        # paths relative to the config dir, and shells use relative paths too.
        if path.lower() in low or (len(base) >= 12 and base in low):
            return path
    return None


def trip_canary(what, where, preview=""):
    """Deny + lock everything + remember + tell the user."""
    hit = {"ts": iso(now_utc()), "what": what, "where": where, "preview": preview[:200]}
    _append_jsonl(CANARY_HITS_PATH, hit)
    with CANARY_LOCK:
        with STATE_LOCK:
            hits = STATE.setdefault("canary_hits", [])
            hits.insert(0, hit)
            del hits[20:]
            save_state()
    log(f"CANARY TRIPPED by {what} on {where}")
    audit({"tool": what, "decision": "deny", "reason": f"canary: {where}", "mode": STATE["mode"],
           "window_id": STATE.get("window_id"), "args_preview": preview[:300]})
    _bg(lock_window, "canary")
    notify(T("canary_title"), T("canary_body", what=what, where=where), tag="agent_gate_canary")
    _bg(publish_all)


def canary_hits_recent(hours=24):
    cutoff = now_utc() - timedelta(hours=hours)
    with STATE_LOCK:
        hits = list(STATE.get("canary_hits") or [])
    return [h for h in hits if parse_iso(h.get("ts")) and parse_iso(h["ts"]) >= cutoff]


def options_fingerprint():
    """Hash of the add-on options as saved by the Supervisor (what the user can edit)."""
    try:
        with open(OPTIONS_PATH, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {}
    keys = {k: hashlib.sha256(json.dumps(v, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:12]
            for k, v in data.items()}
    return keys


def tamper_check_on_start():
    """Runs once on start: did the options change while the gate was down, and
    how long was it down? Both are remembered for the scan and reported."""
    now = now_utc()
    events = []
    with STATE_LOCK:
        prev_fp = STATE.get("options_fp") or {}
        last_alive = parse_iso(STATE.get("last_alive"))
        fp = options_fingerprint()
        # Only keys that existed before and now carry another value count. Keys
        # that appear or disappear come from an add-on update that extends or
        # drops options, not from someone editing the configuration.
        changed = sorted(k for k in set(fp) & set(prev_fp) if fp[k] != prev_fp[k])
        STATE["options_fp"] = fp
        if prev_fp and changed:
            events.append({"ts": iso(now), "kind": "options_changed", "keys": changed})
        if last_alive and (now - last_alive) > timedelta(minutes=2):
            mins = int((now - last_alive).total_seconds() // 60)
            events.append({"ts": iso(now), "kind": "down", "minutes": mins, "until": iso(now)})
        STATE["last_alive"] = iso(now)
        tl = STATE.setdefault("tamper_events", [])
        for e in events:
            tl.insert(0, e)
        del tl[20:]
        save_state()
    for e in events:
        if e["kind"] == "options_changed":
            notify(T("tamper_title"), T("tamper_options", keys=", ".join(e["keys"])), tag="agent_gate_tamper")
        else:
            notify(T("tamper_title"), T("tamper_down", mins=e["minutes"], until=fmt_local(e["until"])),
                   tag="agent_gate_tamper")


def tamper_events_recent(hours=24):
    cutoff = now_utc() - timedelta(hours=hours)
    with STATE_LOCK:
        ev = list(STATE.get("tamper_events") or [])
    return [e for e in ev if parse_iso(e.get("ts")) and parse_iso(e["ts"]) >= cutoff]


# --------------------------------------------------------------------------
# 3c. secret redaction (DLP): tool results and command output are scanned
# before they reach the agent; credentials are replaced by a marker.
# --------------------------------------------------------------------------
REDACT_ENABLED = bool(OPT.get("redact_secrets", True))
REDACT_MARK = "[redacted by Agent Gate]"
_SECRET_KEYS = (r"(?:password|passwd|pwd|pass|secret|token|access_token|refresh_token|api_key|apikey|"
                r"api_token|auth_token|client_secret|private_key|secret_key|access_key|license_key|"
                r"encryption_key|bearer|authorization|credentials?|psk|wpa_passphrase|session_key)")
REDACT_RULES = [
    # key: value / key=value / "key": "value" (YAML, JSON, .env, logs); keeps the key, hides the value
    (re.compile(r'(?i)((?:\\?"|\')?' + _SECRET_KEYS + r'(?:_[a-z0-9]+)?(?:\\?"|\')?\s*[:=]\s*(?:\\?"|\')?)'
                r'(?!\s*(?:null|none|true|false|bearer|basic|<redacted|\[redacted|\*{3})[\s,\]}"\\])([^\s,}\]"\\]{4,})'),
     r"\1" + REDACT_MARK),
    # bearer tokens in headers and curl lines
    (re.compile(r"(?i)(bearer\s+)([A-Za-z0-9._\-]{16,})"), r"\1" + REDACT_MARK),
    (re.compile(r"(?i)(basic\s+)([A-Za-z0-9+/=]{8,})"), r"\1" + REDACT_MARK),
    # JWTs (Home Assistant long-lived tokens are JWTs)
    (re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"), REDACT_MARK),
    # PEM private keys
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), REDACT_MARK),
    # well-known API key shapes
    (re.compile(r"\b(?:sk|rk)-[A-Za-z0-9_\-]{20,}\b"), REDACT_MARK),                  # OpenAI/Anthropic style
    (re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}\b"), REDACT_MARK),                 # Slack
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), REDACT_MARK),                      # GitHub
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), REDACT_MARK),                               # AWS
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b"), REDACT_MARK),                        # Google
    (re.compile(r"\b[0-9]{8,10}:[A-Za-z0-9_\-]{35}\b"), REDACT_MARK),                 # Telegram bot
    (re.compile(r"(?i)(https?://[^\s/]+:)([^\s@/]{3,})@"), r"\1" + REDACT_MARK + "@"),  # creds in URLs
]
for _p in (OPT.get("redact_patterns") or []):
    try:
        REDACT_RULES.append((re.compile(_p, re.I), REDACT_MARK))
    except re.error as e:
        log(f"redact pattern {_p!r} ignored: {e}")
_REDACT_LOCK = threading.Lock()


def redact_text(text):
    """Return (text, count). Never raises; on error returns the input unchanged."""
    if not REDACT_ENABLED or not text:
        return text, 0
    total = 0
    try:
        for rx, repl in REDACT_RULES:
            text, n = rx.subn(repl, text)
            total += n
    except Exception as e:
        log(f"redaction error: {e}")
    return text, total


def note_redactions(tool, n):
    if not n:
        return
    with _REDACT_LOCK:
        with STATE_LOCK:
            lst = STATE.setdefault("redactions", [])
            lst.insert(0, {"ts": iso(now_utc()), "tool": tool, "n": n})
            del lst[50:]
            save_state()
    audit({"tool": tool, "decision": "redact", "reason": f"{n} secret(s) hidden in the result",
           "mode": STATE["mode"], "window_id": STATE.get("window_id"), "args_preview": ""})


def redactions_recent(hours=24):
    cutoff = now_utc() - timedelta(hours=hours)
    with STATE_LOCK:
        lst = list(STATE.get("redactions") or [])
    return [r for r in lst if parse_iso(r.get("ts")) and parse_iso(r["ts"]) >= cutoff]


def redact_response_body(ctype, raw, tool):
    """Scan an upstream tools/call response (JSON or SSE) and hide secrets."""
    if not REDACT_ENABLED or not raw:
        return raw
    try:
        text = raw.decode("utf-8")
    except Exception:
        return raw
    new, n = redact_text(text)
    if n:
        note_redactions(tool, n)
        return new.encode("utf-8")
    return raw


# --------------------------------------------------------------------------
# 3d. behaviour monitor (rate limits, like an IPS)
#
# Plain writes only warn: building something legitimately means many writes.
# Deletions, removals, stops and uninstalls have no honest reason to come in
# bursts, so a burst of those locks everything. "Until I close" windows mean
# the user is working on a project: thresholds double.
# --------------------------------------------------------------------------
ANOMALY_ENABLED = bool(OPT.get("anomaly_enabled", True))
_WRITES = collections.deque()
_DELETES = collections.deque()
_ANOMALY_LOCK = threading.Lock()
_LAST_ANOMALY_WARN = 0.0


def is_delete_like(name, args):
    n = (name or "").lower()
    if any(x in n for x in ("remove", "delete", "purge", "uninstall")):
        return True
    if n == "ha_manage_app" and str((args or {}).get("action") or "").lower() in ("uninstall", "stop"):
        return True
    if n == "ha_call_service":
        svc = f"{(args or {}).get('domain', '')}.{(args or {}).get('service', '')}".lower()
        if any(x in svc for x in ("delete", "remove", "purge", "factory_reset", "reset")):
            return True
    return False


def _anomaly_thresholds():
    w = int(OPT.get("anomaly_writes_warn_per_min") or 60)
    d = int(OPT.get("anomaly_deletes_lock_per_min") or 5)
    with STATE_LOCK:
        unlimited = any(not v.get("end") for v in (STATE.get("windows") or {}).values())
    return (w * 2, d * 2) if unlimited else (w, d)


def anomaly_check(name, args):
    """Call for every allowed write tool. Returns a deny reason, or None."""
    global _LAST_ANOMALY_WARN
    if not ANOMALY_ENABLED:
        return None
    now = time.time()
    warn_n, lock_n = _anomaly_thresholds()
    with _ANOMALY_LOCK:
        for dq in (_WRITES, _DELETES):
            while dq and now - dq[0] > 60:
                dq.popleft()
        _WRITES.append(now)
        deletes = 0
        if is_delete_like(name, args):
            _DELETES.append(now)
            deletes = len(_DELETES)
        writes = len(_WRITES)
    if lock_n and deletes >= lock_n:
        ev = {"ts": iso(now_utc()), "kind": "anomaly_lock", "count": deletes, "tool": name}
        with STATE_LOCK:
            lst = STATE.setdefault("anomaly_events", [])
            lst.insert(0, ev)
            del lst[20:]
            save_state()
        with _ANOMALY_LOCK:
            _DELETES.clear()
        log(f"ANOMALY: {deletes} delete-like calls in a minute, locking")
        _bg(lock_window, "anomaly")
        notify(T("anomaly_title"), T("anomaly_lock_body", n=deletes, tool=name), tag="agent_gate_anomaly")
        _bg(publish_all)
        return "unusual burst of delete/stop operations; the gate has been locked and the user notified"
    if warn_n and writes >= warn_n and now - _LAST_ANOMALY_WARN > 600:
        _LAST_ANOMALY_WARN = now
        ev = {"ts": iso(now_utc()), "kind": "anomaly_warn", "count": writes, "tool": name}
        with STATE_LOCK:
            lst = STATE.setdefault("anomaly_events", [])
            lst.insert(0, ev)
            del lst[20:]
            save_state()
        notify(T("anomaly_title"), T("anomaly_warn_body", n=writes, tool=name),
               actions=[{"action": "AGENT_GATE_LOCK", "title": T("btn_lock")}], tag="agent_gate_anomaly")
    return None


def anomaly_events_recent(hours=24):
    cutoff = now_utc() - timedelta(hours=hours)
    with STATE_LOCK:
        ev = list(STATE.get("anomaly_events") or [])
    return [e for e in ev if parse_iso(e.get("ts")) and parse_iso(e["ts"]) >= cutoff]


def evaluate_tool_call(name, arguments):
    """Returns (decision, reason). decision in {'allow','deny','local'}."""
    hit = canary_match(json.dumps(arguments or {}, ensure_ascii=False))
    if hit:
        trip_canary(name, hit, json.dumps(arguments or {}, ensure_ascii=False))
        return "deny", "that is a decoy; the gate has been locked and the user notified"
    if name in GATE_TOOL_NAMES:
        return "local", "gate tool"
    if is_read_tool(name):
        # Reading the gate's own entities is fine; only changing them is protected.
        return "allow", "read tool"
    if name not in PROTECTED_EXEMPT and (touches_protected(arguments) or any(p in name.lower() for p in PROTECTED)):
        return "deny", "touches the gate's own entities or topics; only the dashboard controls the gate"
    if is_active("ha_write"):
        bad = anomaly_check(name, arguments)
        if bad:
            return "deny", bad
        return "allow", "window open"
    return "deny", ("Agent Gate is LOCKED for HA writes. Write tools are refused until the user opens "
                    "the 'HA write' mechanism from the dashboard. Ask the user to open the gate, then retry.")


# --------------------------------------------------------------------------
# 4. window engine (per-mechanism windows)
#
# STATE["windows"] maps mechanism key -> {"end": iso | None, "opened_at": iso}.
# A mechanism is OPEN while it has an entry; end None means "until closed".
# STATE["mode"] is derived: "opening" while a backup runs, "open" while any
# mechanism is open, else "locked". A "session" runs from the first open to
# the moment the last mechanism closes; the summary notification covers it.
# --------------------------------------------------------------------------
def addon_mechanisms():
    return [m for m in MECHANISMS if m["addons"]]


def active_windows():
    with STATE_LOCK:
        return {k: dict(v) for k, v in STATE.get("windows", {}).items()}


def is_active(key):
    with STATE_LOCK:
        return key in STATE.get("windows", {})


def _recompute_mode():
    """Caller holds STATE_LOCK."""
    if STATE["mode"] == "opening":
        return
    STATE["mode"] = "open" if STATE.get("windows") else "locked"


def actual_states():
    """Live truth: for every add-on-backed mechanism, is any add-on running."""
    out = {}
    for m in addon_mechanisms():
        states = {slug: addon_state(slug) for slug in m["addons"]}
        out[m["key"]] = {"running": any(s == "started" for s in states.values()), "addons": states}
    out["ha_write"] = {"running": is_active("ha_write")}
    out["commands"] = {"running": is_active("commands")}
    return out


STOPPING_GRACE = 90  # seconds after a close during which a still-running add-on is not a deviation
_STOPPING = {}       # mechanism key -> time.time() when its close was requested


def compute_deviation(actual):
    """An add-on-backed mechanism running without an open window is a deviation,
    unless its close was requested in the last STOPPING_GRACE seconds: the
    Supervisor needs a few seconds to stop an add-on, and that is not a deviation."""
    active = active_windows()
    now = time.time()
    return [m["key"] for m in addon_mechanisms()
            if m["key"] not in active and actual.get(m["key"], {}).get("running")
            and now - _STOPPING.get(m["key"], 0) > STOPPING_GRACE]


def apply_addons(keys=None):
    """Start add-ons of open mechanisms, stop add-ons of closed ones (in parallel).
    keys=None means reconcile every mechanism."""
    active = active_windows()
    jobs = []
    for m in addon_mechanisms():
        if keys is not None and m["key"] not in keys:
            continue
        want = m["key"] in active
        for slug in m["addons"]:
            st = addon_state(slug)
            if want and st != "started":
                jobs.append((slug, "start"))
            elif not want and st == "started":
                jobs.append((slug, "stop"))
    threads = [threading.Thread(target=addon_action, args=j, daemon=True) for j in jobs]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=180)


def mech_name(key):
    return MECH_BY_KEY.get(key, {}).get("name", key)


def describe_windows():
    """'SSH until 15:30, HA write until you close it'"""
    parts = []
    for k, w in sorted(active_windows().items(), key=lambda kv: kv[1].get("end") or "9"):
        parts.append(f"{mech_name(k)} {T('until')} {fmt_local(w['end'])}" if w.get("end")
                     else f"{mech_name(k)} {T('until_closed')}")
    return ", ".join(parts)


OPEN_LOCK = threading.Lock()


def open_mechs(keys, minutes, source="dashboard"):
    """Open (or re-time) the given mechanisms. minutes == 0 means 'until closed'."""
    keys = [k for k in keys if k in MECH_BY_KEY]
    if not keys:
        return
    if not OPEN_LOCK.acquire(blocking=False):
        log("open requested while an open is already in progress; ignored")
        return
    try:
        new_end = iso(now_utc() + timedelta(minutes=minutes)) if minutes else None
        with STATE_LOCK:
            first_open = not STATE.get("windows")
            if first_open:
                STATE["window_id"] = uuid.uuid4().hex[:8]
                STATE["opened_at"] = iso(now_utc())
                STATE["last_reminder"] = STATE["opened_at"]
                STATE["deviation_since"] = None
                STATE["deviation_notified"] = False
                STATE["mode"] = "opening"
                STATE["phase"] = "check"   # check: reading the backup list; backup: a full backup runs
            wid = STATE["window_id"]
            save_state()
        publish_all()
        backup = None
        if first_open:
            need, why = backup_needed(minutes)
            log(f"backup before opening: {'yes' if need else 'skipped'} ({why})")
            if need:
                with STATE_LOCK:
                    STATE["phase"] = "backup"
                publish_all()
                backup = create_full_backup(f"agent_gate_{datetime.now().strftime('%Y%m%d_%H%M')}")
                if not backup:
                    notify(T("title"), T("backup_failed"), tag="agent_gate_window")
                    with STATE_LOCK:
                        STATE["mode"] = "locked"
                        STATE["phase"] = None
                        save_state()
                    publish_all()
                    return
        with STATE_LOCK:
            for k in keys:
                prev = STATE["windows"].get(k, {})
                STATE["windows"][k] = {"end": new_end, "opened_at": prev.get("opened_at") or iso(now_utc())}
            if backup:
                STATE["backup"] = backup
                STATE["last_backup_at"] = iso(now_utc())
            STATE["mode"] = "open"
            STATE["phase"] = None
            save_state()
        apply_addons(keys)
        _append_jsonl(HISTORY_PATH, {"event": "open", "window_id": wid, "ts": iso(now_utc()),
                                     "mechanisms": keys, "minutes": minutes, "source": source,
                                     "backup": backup})
        notify(T("title_open"), describe_windows(),
               actions=[{"action": "AGENT_GATE_LOCK", "title": T("btn_lock")},
                        {"action": "AGENT_GATE_EXTEND_60", "title": T("btn_plus_hour")}],
               tag="agent_gate_window")
        publish_all()
        log(f"OPEN {keys} for {minutes or 'unlimited'} min")
    finally:
        OPEN_LOCK.release()


def extend_mechs(keys, minutes):
    with STATE_LOCK:
        touched = []
        for k in keys:
            w = STATE["windows"].get(k)
            if not w:
                continue
            base = parse_iso(w.get("end")) or now_utc()
            if base < now_utc():
                base = now_utc()
            w["end"] = iso(base + timedelta(minutes=minutes))
            touched.append(k)
        if touched:
            save_state()
    if touched:
        _append_jsonl(HISTORY_PATH, {"event": "extend", "ts": iso(now_utc()),
                                     "mechanisms": touched, "minutes": minutes})
        publish_all()
        log(f"extended {touched} by {minutes} min")


def changed_files_since(since_dt, limit=200):
    out = []
    ts = since_dt.timestamp()
    for root in MOUNTS:
        for dirpath, dirnames, filenames in os.walk(root):
            if CHANGED_FILES_EXCLUDE.search(dirpath + "/"):
                dirnames[:] = []
                continue
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                if CHANGED_FILES_EXCLUDE.search(p):
                    continue
                try:
                    if os.stat(p).st_mtime >= ts:
                        out.append(p)
                        if len(out) >= limit:
                            return out
                except OSError:
                    pass
    return out


def close_mechs(keys, reason="dashboard"):
    """Close the given mechanisms. When the last one closes, the session ends
    with a summary notification."""
    with STATE_LOCK:
        closed = [k for k in keys if k in STATE["windows"]]
        for k in closed:
            del STATE["windows"][k]
        session_over = bool(closed) and not STATE["windows"]
        wid = STATE.get("window_id")
        opened_at = parse_iso(STATE.get("opened_at"))
        if session_over or not STATE["windows"]:
            STATE["mode"] = "locked"
            STATE["pending"] = {}
        else:
            STATE["mode"] = "open"
        save_state()
    for k in closed:
        _STOPPING[k] = time.time()
    apply_addons(closed if closed else None)
    publish_all()
    if closed and not session_over:
        _append_jsonl(HISTORY_PATH, {"event": "close", "window_id": wid, "ts": iso(now_utc()),
                                     "mechanisms": closed, "reason": reason})
        if reason == "timer expired":
            notify(T("title"), T("closed_expired", names=", ".join(mech_name(k) for k in closed)),
                   tag="agent_gate_mech")
        log(f"closed {closed} ({reason})")
        return
    if session_over:
        cmds = []
        try:
            with open(COMMANDS_PATH, encoding="utf-8") as f:
                for line in f:
                    try:
                        e = json.loads(line)
                        if e.get("window_id") == wid:
                            cmds.append(e)
                    except Exception:
                        pass
        except Exception:
            pass
        changed = changed_files_since(opened_at) if opened_at else []
        _append_jsonl(HISTORY_PATH, {"event": "lock", "window_id": wid, "ts": iso(now_utc()),
                                     "reason": reason, "commands": len(cmds), "changed_files": changed})
        lines = [T("locked_line", reason=reason, n=len(cmds))]
        for c in cmds[-15:]:
            lines.append(f"- {c.get('ts', '')[11:16]} rc={c.get('rc')} {c.get('command', '')[:80]}")
        lines.append(T("changed_files", n=len(changed)) + (" (20)" if len(changed) > 20 else ""))
        for p in changed[:20]:
            lines.append(f"- {p}")
        notify(T("title_locked"), "\n".join(lines), tag="agent_gate_window")
    log(f"LOCKED ({reason})")


def open_window(minutes, source="dashboard"):
    """Full window: every mechanism marked default_on."""
    open_mechs([m["key"] for m in MECHANISMS if m["default_on"]], minutes, source)


def extend_window(minutes):
    extend_mechs(list(active_windows().keys()), minutes)


def lock_window(reason="dashboard"):
    close_mechs(list(MECH_BY_KEY.keys()), reason)


def fmt_local(iso_s):
    dt = parse_iso(iso_s)
    if not dt:
        return "?"
    return dt.astimezone().strftime("%H:%M")


def timer_loop():
    """Every 10 s: per-mechanism expiry, reminders, deviation grace, pending-approval expiry."""
    last_actual_pub = 0
    while True:
        try:
            now = now_utc()
            expired = [k for k, w in active_windows().items()
                       if w.get("end") and parse_iso(w["end"]) and now >= parse_iso(w["end"])]
            if expired:
                close_mechs(expired, "timer expired")
            with STATE_LOCK:
                mode = STATE["mode"]
                last_rem = parse_iso(STATE.get("last_reminder"))
            if mode == "open":
                rem_min = int(setting("reminder_minutes") or 0)
                if rem_min and last_rem and now - last_rem >= timedelta(minutes=rem_min):
                    with STATE_LOCK:
                        STATE["last_reminder"] = iso(now)
                        save_state()
                    notify(T("title_still_open"), describe_windows(),
                           actions=[{"action": "AGENT_GATE_LOCK", "title": T("btn_lock")},
                                    {"action": "AGENT_GATE_EXTEND_60", "title": T("btn_plus_hour")}],
                           tag="agent_gate_window")
            with STATE_LOCK:
                tmo = timedelta(minutes=int(OPT.get("approval_timeout_minutes") or 3))
                for pid, p in list(STATE["pending"].items()):
                    if p.get("status") == "pending" and now - parse_iso(p["created"]) > tmo:
                        p["status"] = "expired"
                if STATE["pending"]:
                    save_state()
            if time.time() - last_actual_pub >= 30:
                last_actual_pub = time.time()
                with STATE_LOCK:
                    STATE["last_alive"] = iso(now)
                    save_state()
                actual = actual_states()
                dev = compute_deviation(actual)
                handle_deviation(dev)
                publish_all(actual=actual, deviation=dev)
            elif expired:
                publish_all()
        except Exception as e:
            log(f"timer loop error: {e}")
        time.sleep(10)


def handle_deviation(dev):
    grace = timedelta(minutes=int(OPT.get("deviation_grace_minutes") or 5))
    now = now_utc()
    with STATE_LOCK:
        if not dev:
            STATE["deviation_since"] = None
            STATE["deviation_notified"] = False
            return
        since = parse_iso(STATE.get("deviation_since"))
        if not since:
            STATE["deviation_since"] = iso(now)
            save_state()
            since = now
        notified = STATE["deviation_notified"]
        if not notified:
            STATE["deviation_notified"] = True
            save_state()
    names = ", ".join(mech_name(k) for k in dev)
    if not notified:
        notify(T("title_deviation"),
               T("deviation_body", names=names, mins=int(grace.total_seconds() // 60)),
               actions=[{"action": "AGENT_GATE_OPEN_60", "title": T("btn_open_hour")},
                        {"action": "AGENT_GATE_LOCK", "title": T("btn_stop_now")}],
               tag="agent_gate_deviation")
    if now - since >= grace:
        log(f"deviation grace over, enforcing: {dev}")
        for k in dev:
            for slug in MECH_BY_KEY.get(k, {}).get("addons", []):
                if addon_state(slug) == "started":
                    addon_action(slug, "stop")
        with STATE_LOCK:
            STATE["deviation_since"] = None
            STATE["deviation_notified"] = False
            save_state()


def enforce_on_start():
    with STATE_LOCK:
        mode = STATE["mode"]
    if mode == "opening":
        log("startup: previous open was interrupted -> locking")
        lock_window("restart during open")
        return
    now = now_utc()
    expired = [k for k, w in active_windows().items()
               if w.get("end") and parse_iso(w["end"]) and now >= parse_iso(w["end"])]
    if expired:
        log(f"startup: expired while down -> closing {expired}")
        close_mechs(expired, "expired while gate was down")
    with STATE_LOCK:
        _recompute_mode()
        save_state()
    apply_addons()


# --------------------------------------------------------------------------
# 5. MQTT entities
# --------------------------------------------------------------------------
MQTT_CLIENT = None
BASE = "agent_gate"
AVAIL_TOPIC = f"{BASE}/availability"
DEVICE = {"identifiers": ["agent_gate"], "name": "Agent Gate",
          "manufacturer": "ha-agent-gate", "model": "Access gate", "sw_version": VERSION}
DURATION_BUTTONS = [("open_5", "Open 5 min", 5), ("open_15", "Open 15 min", 15),
                    ("open_30", "Open 30 min", 30), ("open_60", "Open 1 hour", 60),
                    ("open_180", "Open 3 hours", 180), ("open_unlimited", "Open until I close", 0),
                    ("extend_60", "Add 1 hour", -60), ("lock_now", "Lock now", -1),
                    ("backup_now", "Backup now", -2), ("scan_now", "Scan now", -3)]


def mqtt_connect():
    code, d = _sup_request("GET", "/services/mqtt", timeout=15)
    d = d.get("data", {}) if code == 200 else {}
    host, port = d.get("host"), int(d.get("port", 1883))
    if not host:
        raise RuntimeError("no MQTT service from Supervisor")
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="agent_gate")
    except Exception:
        client = mqtt.Client(client_id="agent_gate")
    if d.get("username"):
        client.username_pw_set(d.get("username"), d.get("password"))
    client.will_set(AVAIL_TOPIC, "offline", qos=1, retain=True)
    client.reconnect_delay_set(min_delay=1, max_delay=30)
    ev = threading.Event()

    def on_connect(c, u, flags, rc, props=None):
        if str(rc) in ("0", "Success"):
            c.publish(AVAIL_TOPIC, "online", qos=1, retain=True)
            c.subscribe(f"{BASE}/cmd/#", qos=1)
            c.subscribe(f"{BASE}/action", qos=1)
            ev.set()

    client.on_connect = on_connect
    client.on_message = on_mqtt_message
    client.connect(host, port, keepalive=30)
    client.loop_start()
    if not ev.wait(timeout=10):
        client.loop_stop()
        raise RuntimeError("MQTT connect timeout")
    return client


def _disc(component, obj_id, cfg):
    full = {"unique_id": f"agent_gate_{obj_id}", "default_entity_id": f"{component}.agent_gate_{obj_id}",
            "availability_topic": AVAIL_TOPIC, "payload_available": "online",
            "payload_not_available": "offline", "device": DEVICE, "origin": {"name": "agent_gate"}}
    full.update(cfg)
    MQTT_CLIENT.publish(f"homeassistant/{component}/agent_gate_{obj_id}/config",
                        json.dumps(full), qos=1, retain=True)


def _undisc(component, obj_id):
    MQTT_CLIENT.publish(f"homeassistant/{component}/agent_gate_{obj_id}/config", "", qos=1, retain=True)


def publish_discovery():
    if not MQTT_CLIENT:
        return
    # entities from 0.1.x that no longer exist
    for comp, obj in (("number", "backup_min_interval_hours"), ("number", "backup_skip_minutes"),
                      ("select", "backup_mode")):
        _undisc(comp, obj)
    _disc("switch", "master", {"name": "Agent access", "icon": "mdi:shield-lock-open",
                               "state_topic": f"{BASE}/master/state", "command_topic": f"{BASE}/cmd/master"})
    for m in MECHANISMS:
        # ON = open now. Turning ON from a plain switch opens for default_window_minutes.
        _disc("switch", f"mech_{m['key']}", {"name": m["name"], "icon": "mdi:door",
                                            "state_topic": f"{BASE}/mech/{m['key']}/state",
                                            "command_topic": f"{BASE}/cmd/mech/{m['key']}",
                                            "json_attributes_topic": f"{BASE}/mech/{m['key']}/attributes"})
        _disc("sensor", f"mech_{m['key']}_end", {"name": f"{m['name']} ends", "device_class": "timestamp",
                                                 "state_topic": f"{BASE}/mech/{m['key']}/end",
                                                 "entity_category": "diagnostic"})
    for obj, name, _ in DURATION_BUTTONS:
        icon = {"backup_now": "mdi:backup-restore", "scan_now": "mdi:shield-search", "lock_now": "mdi:lock"}.get(obj, "mdi:timer-outline")
        _disc("button", obj, {"name": name, "icon": icon,
                              "command_topic": f"{BASE}/cmd/button", "payload_press": obj})
    _disc("sensor", "status", {"name": "Gate status", "icon": "mdi:shield-check",
                               "state_topic": f"{BASE}/status/state",
                               "json_attributes_topic": f"{BASE}/status/attributes"})
    _disc("sensor", "window_end", {"name": "Window ends", "device_class": "timestamp",
                                   "state_topic": f"{BASE}/window_end/state"})
    _disc("sensor", "remaining", {"name": "Minutes remaining", "icon": "mdi:timer-sand",
                                  "unit_of_measurement": "min", "state_topic": f"{BASE}/remaining/state"})
    _disc("sensor", "open_count", {"name": "Open mechanisms", "icon": "mdi:door-open",
                                   "state_topic": f"{BASE}/open_count/state"})
    _disc("binary_sensor", "deviation", {"name": "Gate deviation", "device_class": "problem",
                                         "state_topic": f"{BASE}/deviation/state",
                                         "json_attributes_topic": f"{BASE}/deviation/attributes"})
    _disc("select", "backup_policy", {"name": "Backup before opening", "icon": "mdi:backup-restore",
                                      "options": list(BACKUP_POLICIES),
                                      "state_topic": f"{BASE}/setting/backup_policy/state",
                                      "command_topic": f"{BASE}/cmd/setting/backup_policy",
                                      "entity_category": "config"})
    _disc("switch", "backup_skip_short", {"name": "No backup for short windows", "icon": "mdi:timer-off-outline",
                                          "state_topic": f"{BASE}/setting/backup_skip_short/state",
                                          "command_topic": f"{BASE}/cmd/setting/backup_skip_short",
                                          "entity_category": "config"})
    _disc("number", "reminder_minutes", {"name": "Reminder every (min)", "icon": "mdi:bell-ring-outline",
                                         "min": 0, "max": 240, "step": 15, "mode": "slider",
                                         "unit_of_measurement": "min",
                                         "state_topic": f"{BASE}/setting/reminder_minutes/state",
                                         "command_topic": f"{BASE}/cmd/setting/reminder_minutes",
                                         "entity_category": "config"})
    _disc("sensor", "scan", {"name": "Security scan", "icon": "mdi:shield-search",
                             "state_topic": f"{BASE}/scan/state",
                             "json_attributes_topic": f"{BASE}/scan/attributes"})
    for _n in range(1, SCAN_SLOTS + 1):
        _disc("sensor", f"scan_h{_n}", {"name": f"Security scan history {_n}", "icon": "mdi:shield-search",
                                        "state_topic": f"{BASE}/scan/h{_n}/state",
                                        "json_attributes_topic": f"{BASE}/scan/h{_n}/attributes"})
    _disc("sensor", "security_score", {"name": "Security score", "icon": "mdi:shield-star",
                                       "state_topic": f"{BASE}/scan/score/state",
                                       "json_attributes_topic": f"{BASE}/scan/score/attributes",
                                       "unit_of_measurement": "pts", "state_class": "measurement"})
    for kind in FIX_KINDS:
        _disc("binary_sensor", f"fix_{kind}", {"name": f"Fix available: {kind}", "icon": "mdi:auto-fix",
                                                "state_topic": f"{BASE}/fix/{kind}/state",
                                                "json_attributes_topic": f"{BASE}/fix/{kind}/attributes",
                                                "entity_category": "diagnostic"})
    _disc("sensor", "pending", {"name": "Pending approvals", "icon": "mdi:account-question",
                                "state_topic": f"{BASE}/pending/state",
                                "json_attributes_topic": f"{BASE}/pending/attributes"})
    _disc("sensor", "security_events", {"name": "Security events (24 h)", "icon": "mdi:shield-alert",
                                        "state_topic": f"{BASE}/security_events/state",
                                        "json_attributes_topic": f"{BASE}/security_events/attributes"})


_LAST_ACTUAL = {}


def publish_all(actual=None, deviation=None):
    global _LAST_ACTUAL
    if not MQTT_CLIENT:
        return
    if actual is None:
        actual = _LAST_ACTUAL or {}
    else:
        _LAST_ACTUAL = actual
    if deviation is None:
        deviation = compute_deviation(actual) if actual else []
    with STATE_LOCK:
        st = json.loads(json.dumps(STATE))
    windows = st.get("windows", {})
    open_ = st["mode"] == "open" and bool(windows)
    opening = st["mode"] == "opening"
    ends = [parse_iso(w["end"]) for w in windows.values() if w.get("end")]
    unlimited = any(not w.get("end") for w in windows.values())
    latest = max(ends) if ends else None
    soonest = min(ends) if ends else None
    pub = MQTT_CLIENT.publish
    pub(f"{BASE}/master/state", "ON" if (open_ or opening) else "OFF", qos=1, retain=True)
    for m in MECHANISMS:
        a = actual.get(m["key"], {})
        w = windows.get(m["key"])
        pub(f"{BASE}/mech/{m['key']}/state", "ON" if w else "OFF", qos=1, retain=True)
        pub(f"{BASE}/mech/{m['key']}/end", (w or {}).get("end") or "None", qos=1, retain=True)
        pub(f"{BASE}/mech/{m['key']}/attributes",
            json.dumps({"running_now": a.get("running"), "addons": a.get("addons", {}),
                        "open": bool(w), "end": (w or {}).get("end"),
                        "until_closed": bool(w) and not (w or {}).get("end"),
                        "opened_at": (w or {}).get("opened_at"),
                        "deviation": m["key"] in deviation}), qos=1, retain=True)
    status = "deviation" if deviation else ("open" if open_ else ("opening" if opening else "locked"))
    pub(f"{BASE}/status/state", status, qos=1, retain=True)
    pub(f"{BASE}/status/attributes", json.dumps({
        "window_id": st.get("window_id"), "opened_at": st.get("opened_at") if open_ else None,
        "last_backup_at": st.get("last_backup_at"),
        "window_end": (iso(latest) if latest and not unlimited else ("until closed" if open_ else None)),
        "soonest_end": iso(soonest) if soonest else None,
        "open_mechanisms": list(windows.keys()),
        "open_names": [mech_name(k) for k in windows],
        "backup": st.get("backup"), "deviation": deviation, "phase": st.get("phase"),
        "canary_hits_24h": len(canary_hits_recent()), "tamper_events_24h": len(tamper_events_recent()),
        "redactions_24h": sum(r.get("n", 0) for r in redactions_recent()),
        "last_canary_hit": (canary_hits_recent() or [{}])[0].get("ts"),
        "actual": {k: v.get("running") for k, v in actual.items()},
        "language": LANG,
    }, ensure_ascii=False), qos=1, retain=True)
    pub(f"{BASE}/window_end/state", iso(latest) if (latest and not unlimited) else "None", qos=1, retain=True)
    remaining = (max(0, int((soonest - now_utc()).total_seconds() // 60)) if soonest
                 else (None if open_ else 0))
    pub(f"{BASE}/remaining/state", "unknown" if remaining is None else str(remaining), qos=1, retain=True)
    pub(f"{BASE}/open_count/state", str(len(windows)), qos=1, retain=True)
    pub(f"{BASE}/deviation/state", "ON" if deviation else "OFF", qos=1, retain=True)
    pub(f"{BASE}/deviation/attributes", json.dumps({"mechanisms": deviation,
                                                     "names": [mech_name(k) for k in deviation],
                                                     "since": st.get("deviation_since")}, ensure_ascii=False),
        qos=1, retain=True)
    pub(f"{BASE}/setting/backup_policy/state", backup_policy(), qos=1, retain=True)
    pub(f"{BASE}/setting/backup_skip_short/state", "ON" if backup_skip_short() else "OFF", qos=1, retain=True)
    pub(f"{BASE}/setting/reminder_minutes/state", str(setting("reminder_minutes") or 0), qos=1, retain=True)
    pend = {k: v for k, v in st.get("pending", {}).items() if v.get("status") == "pending"}
    pub(f"{BASE}/pending/state", str(len(pend)), qos=1, retain=True)
    pub(f"{BASE}/pending/attributes", json.dumps({
        "items": [{"id": k, "command": v["command"][:120], "created": v["created"]} for k, v in pend.items()]
    }, ensure_ascii=False), qos=1, retain=True)
    hits, tev, reds, anom = canary_hits_recent(), tamper_events_recent(), redactions_recent(), anomaly_events_recent()
    pub(f"{BASE}/security_events/state", str(len(hits) + len(tev) + len(anom)), qos=1, retain=True)
    pub(f"{BASE}/security_events/attributes", json.dumps({
        "canary_hits": hits[:10], "tamper_events": tev[:10], "anomaly_events": anom[:10],
        "redactions_24h": sum(r.get("n", 0) for r in reds), "last_redaction": (reds or [{}])[0],
        "cleared_at": st.get("hits_cleared_at"),
    }, ensure_ascii=False), qos=1, retain=True)


def _bg(fn, *args):
    threading.Thread(target=fn, args=args, daemon=True).start()


def _parse_cmd(payload):
    """'{"mech":"ssh","minutes":60}' or 'ssh' or 'ssh,60'. mech may be 'all'."""
    try:
        d = json.loads(payload)
        if isinstance(d, dict):
            return d.get("mech") or d.get("mechanism") or "all", d.get("minutes")
    except Exception:
        pass
    parts = [p.strip() for p in payload.split(",")]
    return parts[0] or "all", (parts[1] if len(parts) > 1 else None)


def _mech_keys(spec):
    if spec in ("all", "*", ""):
        return [m["key"] for m in MECHANISMS if m["default_on"]]
    if spec == "open":
        return list(active_windows().keys())
    return [k for k in str(spec).split("+") if k in MECH_BY_KEY]


def on_mqtt_message(client, userdata, msg):
    try:
        topic = msg.topic
        payload = msg.payload.decode("utf-8", "replace").strip()
        log(f"mqtt {topic} = {payload}")
        default_min = int(OPT.get("default_window_minutes") or 30)
        if topic == f"{BASE}/cmd/master":
            if payload.upper() == "ON":
                _bg(open_window, default_min)
            else:
                _bg(lock_window, "dashboard")
        elif topic.startswith(f"{BASE}/cmd/mech/"):
            key = topic.rsplit("/", 1)[1]
            if key in MECH_BY_KEY:
                if payload.upper() == "ON":
                    _bg(open_mechs, [key], default_min)
                else:
                    _bg(close_mechs, [key], "dashboard")
        elif topic == f"{BASE}/cmd/open":
            spec, minutes = _parse_cmd(payload)
            minutes = int(minutes) if minutes not in (None, "") else default_min
            _bg(open_mechs, _mech_keys(spec), minutes)
        elif topic == f"{BASE}/cmd/close":
            spec, _ = _parse_cmd(payload)
            keys = list(MECH_BY_KEY) if spec in ("all", "*", "") else _mech_keys(spec)
            _bg(close_mechs, keys, "dashboard")
        elif topic == f"{BASE}/cmd/extend":
            spec, minutes = _parse_cmd(payload)
            minutes = int(minutes) if minutes not in (None, "") else 60
            keys = list(active_windows().keys()) if spec in ("all", "*", "", "open") else _mech_keys(spec)
            extend_mechs(keys, minutes)
        elif topic.startswith(f"{BASE}/cmd/setting/"):
            key = topic.rsplit("/", 1)[1]
            set_setting(key, payload)
            publish_all()
        elif topic == f"{BASE}/cmd/button":
            handle_button(payload)
        elif topic == f"{BASE}/cmd/fix":
            _bg(apply_fix, payload.strip().lower())
        elif topic == f"{BASE}/action":
            handle_action(payload)
    except Exception as e:
        log(f"mqtt message error: {e}")


def backup_now():
    slug = create_full_backup(f"agent_gate_manual_{datetime.now().strftime('%Y%m%d_%H%M')}")
    if slug:
        with STATE_LOCK:
            STATE["last_backup_at"] = iso(now_utc())
            STATE["backup"] = slug
            save_state()
        notify(T("title"), T("backup_done"), tag="agent_gate_backup")
    else:
        notify(T("title"), T("backup_failed_plain"), tag="agent_gate_backup")
    publish_all()


def handle_button(obj):
    for key, _, minutes in DURATION_BUTTONS:
        if key == obj:
            if minutes == -1:
                _bg(lock_window, "dashboard")
            elif minutes == -2:
                _bg(backup_now)
            elif minutes == -3:
                _bg(run_scan, "manual")
            elif minutes < 0:
                extend_window(-minutes)
            else:
                _bg(open_window, minutes)
            return
    log(f"unknown button {obj}")


def handle_action(payload):
    """payload: AGENT_GATE_LOCK | AGENT_GATE_EXTEND_<min> | AGENT_GATE_OPEN_<min> |
    AGENT_GATE_APPROVE_<id> | AGENT_GATE_REJECT_<id>"""
    try:
        data = json.loads(payload)
        action = data.get("action", "")
    except Exception:
        action = payload
    action = action.strip()
    if action == "AGENT_GATE_LOCK":
        _bg(lock_window, "phone")
    elif action.startswith("AGENT_GATE_EXTEND_"):
        extend_window(int(action.rsplit("_", 1)[1]))
    elif action.startswith("AGENT_GATE_OPEN_"):
        _bg(open_window, int(action.rsplit("_", 1)[1]), "phone")
    elif action == "AGENT_GATE_CLEAR_HITS":
        # The user reviewed the decoy hits / tamper events and acknowledges them.
        with STATE_LOCK:
            n = len(STATE.get("canary_hits") or []) + len(STATE.get("tamper_events") or [])
            STATE["canary_hits"] = []
            STATE["tamper_events"] = []
            STATE["anomaly_events"] = []
            STATE["hits_cleared_at"] = iso(now_utc())
            save_state()
        log(f"security events acknowledged and cleared ({n})")
        _bg(run_scan, "clear")
        publish_all()
    elif action.startswith("AGENT_GATE_APPROVE_") or action.startswith("AGENT_GATE_REJECT_"):
        pid = action.rsplit("_", 1)[1]
        verdict = "approved" if "APPROVE" in action else "rejected"
        with STATE_LOCK:
            pend = STATE["pending"]
            if pid in ("LATEST", "ALL"):
                # Dashboard buttons: no id at hand, act on the newest (or every) pending command.
                ids = sorted((k for k, v in pend.items() if v.get("status") == "pending"),
                             key=lambda k: pend[k].get("created", ""))
                ids = ids[-1:] if pid == "LATEST" else ids
            else:
                ids = [pid]
            for k in ids:
                p = pend.get(k)
                if p and p.get("status") == "pending":
                    p["status"] = verdict
            save_state()
        log(f"approval {ids}: {verdict}")
        publish_all()


# --------------------------------------------------------------------------
# 5b. ready-made dashboard (created once, standard cards only)
# --------------------------------------------------------------------------
DASHBOARD_URL = "agent-gate"


def _ws_call(commands):
    """Run a few HA websocket commands through the Supervisor proxy. Returns list of results."""
    if websocket is None:
        raise RuntimeError("websocket-client missing")
    u = urlsplit(SUPERVISOR)
    ws = websocket.create_connection(f"ws://{u.hostname}:{u.port or 80}/core/websocket", timeout=20)
    try:
        ws.recv()  # auth_required
        ws.send(json.dumps({"type": "auth", "access_token": SUPERVISOR_TOKEN}))
        if json.loads(ws.recv()).get("type") != "auth_ok":
            raise RuntimeError("websocket auth failed")
        out = []
        for i, cmd in enumerate(commands, start=1):
            cmd = dict(cmd, id=i)
            ws.send(json.dumps(cmd))
            while True:
                msg = json.loads(ws.recv())
                if msg.get("id") == i and msg.get("type") == "result":
                    out.append(msg)
                    break
        return out
    finally:
        ws.close()


def _mqtt_btn(name, icon, topic, payload, color=None):
    c = {"type": "button", "name": name, "icon": icon, "show_state": False,
         "tap_action": {"action": "perform-action", "perform_action": "mqtt.publish",
                        "data": {"topic": f"{BASE}/{topic}", "payload": payload}}}
    if color:
        c["icon_color"] = color
    return c


def dashboard_config():
    S = "sensor.agent_gate_status"
    status_md = (
        "{% set s = states('" + S + "') %}"
        "{% if s == 'locked' %}## 🟢 Locked\nNo agent access right now."
        "{% elif s == 'opening' %}## 🟠 {{ 'Opening, backup running...' if state_attr('" + S + "','phase') == 'backup' else 'Opening, checking the last backup...' }}"
        "{% elif s == 'deviation' %}## 🔴 Deviation\n{{ state_attr('binary_sensor.agent_gate_deviation','names') | join(', ') }} "
        "is running without a window. The gate will stop it in a few minutes."
        "{% else %}## 🟠 Open: {{ state_attr('" + S + "','open_names') | join(', ') }}\n"
        "{% set e = state_attr('" + S + "','soonest_end') %}"
        "{% if e %}Next close in {{ ((as_timestamp(e) - now().timestamp()) / 60) | int }} min"
        "{% else %}Open until you close it{% endif %}{% endif %}"
        "{% set b = state_attr('" + S + "','last_backup_at') %}\n\n"
        "{% if b %}Last backup: {{ as_timestamp(b) | timestamp_custom('%d/%m %H:%M') }}{% endif %}"
        "{% set p = states('sensor.agent_gate_pending') | int(0) %}{% if p > 0 %} · **{{ p }} command(s) waiting for your approval**{% endif %}"
    )
    open_all = [
        {"type": "horizontal-stack", "cards": [
            _mqtt_btn("15 min", "mdi:timer-outline", "cmd/open", '{"mech":"all","minutes":15}'),
            _mqtt_btn("1 hour", "mdi:timer-outline", "cmd/open", '{"mech":"all","minutes":60}')]},
        {"type": "horizontal-stack", "cards": [
            _mqtt_btn("3 hours", "mdi:timer-sand", "cmd/open", '{"mech":"all","minutes":180}'),
            _mqtt_btn("Until I close", "mdi:timer-off-outline", "cmd/open", '{"mech":"all","minutes":0}')]},
        {"type": "horizontal-stack", "cards": [
            _mqtt_btn("+1 hour", "mdi:timer-plus-outline", "cmd/extend", '{"mech":"open","minutes":60}'),
            _mqtt_btn("Lock now", "mdi:lock", "cmd/close", '{"mech":"all"}', "red")]},
    ]
    mech_cards = []
    for m in MECHANISMS:
        k = m["key"]
        sw = f"switch.agent_gate_mech_{k}"
        mech_cards.append({"type": "tile", "entity": sw, "name": m["name"],
                           "state_content": ["state", "end"], "tap_action": {"action": "more-info"},
                           "icon_tap_action": {"action": "toggle"}, "color": "amber"})
        mech_cards.append({"type": "horizontal-stack", "cards": [
            _mqtt_btn("15 min", "mdi:timer-outline", "cmd/open", json.dumps({"mech": k, "minutes": 15})),
            _mqtt_btn("1 hour", "mdi:timer-outline", "cmd/open", json.dumps({"mech": k, "minutes": 60})),
            _mqtt_btn("3 hours", "mdi:timer-sand", "cmd/open", json.dumps({"mech": k, "minutes": 180})),
            _mqtt_btn("Close", "mdi:close-circle-outline", "cmd/close", json.dumps({"mech": k}), "red")]})
    settings = [
        {"type": "entities", "title": "Settings", "entities": [
            {"entity": "select.agent_gate_backup_policy", "name": "Backup before opening"},
            {"entity": "switch.agent_gate_backup_skip_short", "name": f"No backup for windows up to {SHORT_WINDOW_MINUTES} min"},
            {"entity": "number.agent_gate_reminder_minutes", "name": "Remind me every (min)"},
            {"entity": "button.agent_gate_backup_now", "name": "Backup now"},
        ]},
        {"type": "markdown", "content": "**always**: full backup before every open. **every_6h** / **daily**: "
                                        "only when the newest full backup (any source) is older than that. "
                                        "**never**: no backup. The agent cannot change these settings."},
        {"type": "horizontal-stack", "cards": [
            {"type": "button", "name": "Add-on settings", "icon": "mdi:cog", "show_state": False,
             "tap_action": {"action": "navigate", "navigation_path": f"/config/app/{SELF_SLUG}/config"}},
            {"type": "button", "name": "Entities", "icon": "mdi:format-list-bulleted", "show_state": False,
             "tap_action": {"action": "navigate", "navigation_path": "/config/entities?search=agent_gate"}},
            {"type": "button", "name": "Log", "icon": "mdi:text-box-search-outline", "show_state": False,
             "tap_action": {"action": "navigate", "navigation_path": f"/config/app/{SELF_SLUG}/logs"}}]},
    ]
    pending = {"type": "conditional",
               "conditions": [{"condition": "numeric_state", "entity": "sensor.agent_gate_pending", "above": 0}],
               "card": {"type": "vertical-stack", "cards": [
                   {"type": "markdown", "content":
                    "**Commands waiting for your approval**\n"
                    "{% for i in state_attr('sensor.agent_gate_pending','items') or [] %}- `{{ i.id }}` {{ i.command }}\n{% endfor %}"},
                   {"type": "horizontal-stack", "cards": [
                       _mqtt_btn("Approve newest", "mdi:check-circle-outline", "action", "AGENT_GATE_APPROVE_LATEST", "green"),
                       _mqtt_btn("Reject all", "mdi:close-circle-outline", "action", "AGENT_GATE_REJECT_ALL", "red")]}]}}
    scan = [
        {"type": "conditional",
         "conditions": [{"condition": "numeric_state", "entity": "sensor.agent_gate_security_events", "above": 0}],
         "card": {"type": "vertical-stack", "cards": [
             {"type": "markdown", "content":
              "**Security events in the last 24 h**\n"
              "{% for h in state_attr('sensor.agent_gate_security_events','canary_hits') or [] %}- trap: `{{ h.what }}` touched `{{ h.where }}` ({{ as_timestamp(h.ts) | timestamp_custom('%d/%m %H:%M') }})\n{% endfor %}"
              "{% for e in state_attr('sensor.agent_gate_security_events','tamper_events') or [] %}- {{ 'gate down ' ~ e.minutes ~ ' min' if e.kind == 'down' else 'options changed: ' ~ (e.keys | join(', ')) }} ({{ as_timestamp(e.ts) | timestamp_custom('%d/%m %H:%M') }})\n{% endfor %}"
              "{% for e in state_attr('sensor.agent_gate_security_events','anomaly_events') or [] %}- {{ 'burst of ' ~ e.count ~ ' deletions, locked' if e.kind == 'anomaly_lock' else e.count ~ ' writes in a minute' }} by `{{ e.tool }}` ({{ as_timestamp(e.ts) | timestamp_custom('%d/%m %H:%M') }})\n{% endfor %}"},
             _mqtt_btn("I reviewed these, clear", "mdi:shield-check", "action", "AGENT_GATE_CLEAR_HITS", "red")]}},
        {"type": "gauge", "entity": "sensor.agent_gate_security_score", "name": "Security score",
         "min": 0, "max": 100, "needle": True, "severity": {"green": 90, "yellow": 70, "red": 0}},
        {"type": "history-graph", "entities": [{"entity": "sensor.agent_gate_security_score", "name": "Score"}],
         "hours_to_show": 168},
        {"type": "button", "name": "Scan now", "icon": "mdi:shield-search", "show_state": False,
         "tap_action": {"action": "perform-action", "perform_action": "button.press",
                        "target": {"entity_id": "button.agent_gate_scan_now"}}},
    ] + [
        {"type": "conditional",
         "conditions": [{"condition": "state", "entity": f"binary_sensor.agent_gate_fix_{kind}", "state": "on"}],
         "card": dict(_mqtt_btn("Fix: " + TS("fix_" + kind), "mdi:auto-fix", "cmd/fix", kind, "amber"),
                      tap_action={"action": "perform-action", "perform_action": "mqtt.publish",
                                  "data": {"topic": f"{BASE}/cmd/fix", "payload": kind},
                                  "confirmation": {"text": TS("fix_" + kind) + "?"}})}
        for kind in FIX_KINDS
    ] + [
        {"type": "markdown", "content": "{{ state_attr('sensor.agent_gate_scan','markdown') or 'No scan yet.' }}"},
        {"type": "markdown", "content": "{% set u = state_attr('sensor.agent_gate_scan','report_url') %}"
                                        "{% if u %}[Copy / download the report]({{ u }}) · files in /share/agent_gate{% endif %}"},
    ]
    return {"views": [{"title": "Agent Gate", "path": "gate", "icon": "mdi:shield-lock", "type": "sections",
                       "max_columns": 2, "sections": [
                           {"type": "grid", "cards": [{"type": "markdown", "content": status_md}] + open_all + [pending]},
                           {"type": "grid", "title": "Mechanisms", "cards": mech_cards},
                           {"type": "grid", "title": "Security scan", "cards": scan},
                           {"type": "grid", "title": "Settings", "cards": settings},
                       ]}]}


def ensure_dashboard():
    """Create the 'Agent Gate' dashboard once. Never overwrites a dashboard that exists."""
    if not OPT.get("create_dashboard", True):
        return
    try:
        res = _ws_call([{"type": "lovelace/dashboards/list"}])
        existing = [d.get("url_path") for d in (res[0].get("result") or [])]
        if DASHBOARD_URL in existing:
            return
        res = _ws_call([
            {"type": "lovelace/dashboards/create", "url_path": DASHBOARD_URL, "title": "Agent Gate",
             "icon": "mdi:shield-lock", "show_in_sidebar": True, "require_admin": True, "mode": "storage"},
            {"type": "lovelace/config/save", "url_path": DASHBOARD_URL, "config": dashboard_config()},
        ])
        ok = all(r.get("success") for r in res)
        log(f"dashboard '{DASHBOARD_URL}' created: {ok}" + ("" if ok else f" {res}"))
    except Exception as e:
        log(f"dashboard not created ({e}); you can build one from the entities instead")



# --------------------------------------------------------------------------
# 5c. security scan
# --------------------------------------------------------------------------
SCANS_PATH = os.path.join(DATA_DIR, "scans.jsonl")
SCAN_LOCK = threading.Lock()
LAST_SCAN = {}
SCAN_SLOTS = 5
SCAN_HISTORY_PATH = os.path.join(DATA_DIR, "scan_history.json")
try:
    with open(SCAN_HISTORY_PATH, encoding="utf-8") as _f:
        SCAN_HISTORY = json.load(_f)[:SCAN_SLOTS]
except Exception:
    SCAN_HISTORY = []


def remember_scan(report):
    """Keep the last SCAN_SLOTS reports (with their text) for the dashboard history."""
    SCAN_HISTORY.insert(0, {"ts": report.get("ts"), "counts": report.get("counts", {}),
                            "score": report.get("score"), "markdown": report.get("markdown", "")})
    del SCAN_HISTORY[SCAN_SLOTS:]
    try:
        with open(SCAN_HISTORY_PATH, "w", encoding="utf-8") as f:
            json.dump(SCAN_HISTORY, f, ensure_ascii=False)
    except Exception as e:
        log(f"could not save scan history: {e}")


def _scan_label(ts):
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).astimezone().strftime("%d/%m %H:%M")
    except Exception:
        return str(ts or "")
SEV_ORDER = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
SCORE_WEIGHTS = {"critical": 25, "warning": 10, "info": 3, "ok": 0}


def security_score(findings):
    """100 minus a weight per finding, never below 0. Band: good >= 90, fair >= 70, poor below."""
    score = 100
    for f in findings:
        score -= SCORE_WEIGHTS.get(f.get("severity"), 0)
    score = max(0, score)
    band = "good" if score >= 90 else ("fair" if score >= 70 else "poor")
    return score, band


SCAN_STRINGS = {
    "en": {
        "sev": {"critical": "CRITICAL", "warning": "Warning", "info": "Info", "ok": "OK"},
        "report_title": "Security scan", "no_findings": "Nothing to report.",
        "summary": "{c} critical, {w} warnings, {i} notes",
        "score_line": "Security score {score}/100",
        "fix_boot_manual": "Turn off start-on-boot for the controlled add-ons",
        "fix_uninstall_uncontrolled": "Uninstall the editing add-ons outside the gate",
        "fix_update_addons": "Update the add-ons (with a backup)",
        "fix_enable_backstop": "Enable the backstop automations",
        "fix_watchdog_on": "Turn on the gate's watchdog",
        "fix_done": "Fix applied: {label}", "fix_failed": "Fix failed: {label} ({err})",
        "fix": "Fix", "scan_failed": "Scan failed: {e}",
        "notify_title": "Agent Gate: security scan", "notify_new": "New critical findings:",
        "f_open": ("Open mechanisms", "{names} open since {since}.", "Close what you are not using."),
        "f_deviation": ("Add-on running without a window", "{names}", "Open a window for it or let the gate stop it."),
        "f_protection": ("Add-on with protection mode off", "{names}", "Turn protection mode back on in the add-on's settings unless it truly needs host access."),
        "f_hostnet": ("Add-on on the host network", "{names}", "Review whether host networking is needed; it bypasses the add-on sandbox."),
        "f_ports": ("Add-ons with ports exposed on the host", "{names}", "Close ports you do not use from outside (add-on Configuration, Network)."),
        "f_tokens": ("Long-lived access tokens", "{n} token(s): {names}", "Delete tokens you no longer use (your profile, Security tab)."),
        "f_backup_old": ("Last full backup is old", "{age} hours.", "Run a backup (Settings, Backups) or set backup_policy to always."),
        "f_backup_none": ("No full backup found", "", "Create one now from the dashboard (Backup now)."),
        "f_update_core": ("Home Assistant update available", "{cur} -> {latest}", "Update after a backup."),
        "f_update_os": ("Operating system update available", "{cur} -> {latest}", "Update after a backup."),
        "f_update_sup": ("Supervisor update available", "{cur} -> {latest}", "Updates automatically; check the Supervisor log if it stays."),
        "f_update_addons": ("Add-on updates available", "{names}", "Update from the add-on store."),
        "f_ssh_pw": ("SSH add-on accepts a password", "{names}", "Use an authorized key and clear the password in the SSH add-on options."),
        "f_addon_pw": ("Add-on with a password in its options", "{names}", "Prefer tokens/keys; make sure the password is strong."),
        "f_tunnel": ("Remote access tunnel running", "{names}", "Make sure the tunnel requires login (Cloudflare Access) and does not expose add-on ports."),
        "f_package": ("Gate backstop automations missing", "{names}", "Copy ha/agent_gate_package.yaml to /homeassistant/packages and restart HA."),
        "f_upstream": ("Gate has no upstream MCP URL", "", "Set upstream_mcp_url in the add-on options."),
        "f_gate_ok": ("Gate", "Locked, no deviation, backstop automations present.", ""),
        "f_uncontrolled": ("Editing add-ons outside the gate", "{names}", "Add them to a mechanism in the gate's options, or uninstall them."),
        "f_boot_auto": ("Controlled add-ons start on boot", "{names}", "Set Start on boot off in the add-on's Info page so a reboot does not start it before the gate locks it."),
        "f_canary": ("Decoy touched (trap tripped)", "{n} hit(s) in 24 h, last: {what} on {where} at {when}", "Review the agent's recent actions (audit log) before opening a window again."),
        "f_canary_ok": ("Decoys in place", "{n} decoy file(s), no hits in 24 h.", ""),
        "f_package_off": ("Gate backstop automations disabled", "{names}", "Enable them (Settings, Automations); the gate relies on them when it is down."),
        "f_watchdog": ("Gate watchdog is off", "", "Turn on Watchdog in the add-on's Info page so the Supervisor restarts the gate if it crashes."),
        "f_policy_broad": ("Read-only patterns allow write tools", "{names}", "Remove patterns like * or ha_config_set_* from read_tool_patterns."),
        "f_options_changed": ("Gate options changed while it was down", "{keys} at {when}", "If that was not you, review the add-on configuration."),
        "f_downtime": ("Gate was down", "{mins} min, until {when}", "Check the add-on log; while the gate is down the lock is enforced only by the backstop automations."),
        "f_anomaly": ("Unusual activity: burst of deletions", "{n} delete/stop calls in a minute at {when} (last: {tool}); the gate locked itself", "Review the audit log. If it was you, clear the events on the dashboard."),
        "f_anomaly_warn": ("Unusual activity: many writes", "{n} writes in a minute at {when} (last: {tool})", "Fine while you build something; otherwise review the audit log."),
        "f_redacted": ("Secrets hidden from the agent", "{n} value(s) in 24 h, last by {tool}", "The agent asked for files or data holding credentials. Fine if you expected it; otherwise review the audit log."),
    },
    "he": {
        "sev": {"critical": "קריטי", "warning": "אזהרה", "info": "מידע", "ok": "תקין"},
        "report_title": "סריקת אבטחה", "no_findings": "אין ממצאים.",
        "summary": "{c} קריטיים, {w} אזהרות, {i} הערות",
        "score_line": "ציון אבטחה {score}/100",
        "fix_boot_manual": "כבה הפעלה באתחול לתוספים הנשלטים",
        "fix_uninstall_uncontrolled": "הסר את תוספי העריכה שמחוץ לשער",
        "fix_update_addons": "עדכן את התוספים (עם גיבוי)",
        "fix_enable_backstop": "הפעל את אוטומציות הגיבוי",
        "fix_watchdog_on": "הדלק את ה-watchdog של השער",
        "fix_done": "התיקון בוצע: {label}", "fix_failed": "התיקון נכשל: {label} ({err})",
        "fix": "תיקון", "scan_failed": "הסריקה נכשלה: {e}",
        "notify_title": "שער הסוכן: סריקת אבטחה", "notify_new": "ממצאים קריטיים חדשים:",
        "f_open": ("מנגנונים פתוחים", "{names} פתוחים מאז {since}.", "סגור מה שאתה לא משתמש בו."),
        "f_deviation": ("תוסף רץ בלי חלון", "{names}", "פתח לו חלון או תן לשער לעצור אותו."),
        "f_protection": ("תוסף עם מצב הגנה כבוי", "{names}", "החזר את מצב ההגנה בהגדרות התוסף, אלא אם הוא באמת צריך גישה למארח."),
        "f_hostnet": ("תוסף ברשת המארח", "{names}", "בדוק אם נדרש; זה עוקף את ארגז החול של התוסף."),
        "f_ports": ("תוספים עם פורטים פתוחים במארח", "{names}", "סגור פורטים שלא נחוצים מבחוץ (הגדרות התוסף, רשת)."),
        "f_tokens": ("טוקנים ארוכי טווח", "{n} טוקנים: {names}", "מחק טוקנים שכבר לא בשימוש (הפרופיל שלך, לשונית אבטחה)."),
        "f_backup_old": ("הגיבוי המלא האחרון ישן", "{age} שעות.", "הרץ גיבוי (הגדרות, גיבויים) או קבע מדיניות גיבוי always."),
        "f_backup_none": ("לא נמצא גיבוי מלא", "", "צור אחד עכשיו מהדשבורד (גבה עכשיו)."),
        "f_update_core": ("עדכון Home Assistant זמין", "{cur} -> {latest}", "עדכן אחרי גיבוי."),
        "f_update_os": ("עדכון מערכת הפעלה זמין", "{cur} -> {latest}", "עדכן אחרי גיבוי."),
        "f_update_sup": ("עדכון Supervisor זמין", "{cur} -> {latest}", "מתעדכן לבד; אם נשאר, בדוק את לוג ה-Supervisor."),
        "f_update_addons": ("עדכוני תוספים זמינים", "{names}", "עדכן מחנות התוספים."),
        "f_ssh_pw": ("תוסף SSH מקבל סיסמה", "{names}", "השתמש במפתח ונקה את הסיסמה בהגדרות תוסף ה-SSH."),
        "f_addon_pw": ("תוסף עם סיסמה בהגדרות", "{names}", "עדיף טוקנים/מפתחות; ודא שהסיסמה חזקה."),
        "f_tunnel": ("מנהרת גישה מרחוק פעילה", "{names}", "ודא שהמנהרה דורשת התחברות (Cloudflare Access) ולא חושפת פורטים של תוספים."),
        "f_package": ("אוטומציות הגיבוי של השער חסרות", "{names}", "העתק את ha/agent_gate_package.yaml ל-/homeassistant/packages והפעל מחדש את HA."),
        "f_upstream": ("לשער אין כתובת MCP", "", "קבע upstream_mcp_url בהגדרות התוסף."),
        "f_gate_ok": ("השער", "נעול, אין סטייה, אוטומציות הגיבוי קיימות.", ""),
        "f_uncontrolled": ("תוספי עריכה מחוץ לשער", "{names}", "הוסף אותם למנגנון בהגדרות השער, או הסר אותם."),
        "f_boot_auto": ("תוספים נשלטים עולים באתחול", "{names}", "כבה 'הפעל באתחול' בדף המידע של התוסף, כדי שאתחול לא יפעיל אותו לפני שהשער נועל."),
        "f_canary": ("נגיעה בפיתיון (המלכודת הופעלה)", "{n} פעמים ב-24 שעות, האחרונה: {what} על {where} ב-{when}", "בדוק את הפעולות האחרונות של הסוכן (יומן הביקורת) לפני שתפתח חלון שוב."),
        "f_canary_ok": ("הפיתיונות במקום", "{n} קבצי פיתיון, אין נגיעות ב-24 שעות.", ""),
        "f_package_off": ("אוטומציות הגיבוי של השער מושבתות", "{names}", "הפעל אותן (הגדרות, אוטומציות); השער נשען עליהן כשהוא לא רץ."),
        "f_watchdog": ("השמירה האוטומטית של השער כבויה", "", "הדלק Watchdog בדף המידע של התוסף, כדי שה-Supervisor יפעיל את השער מחדש אם הוא קורס."),
        "f_policy_broad": ("תבניות הקריאה מתירות כלי כתיבה", "{names}", "הסר תבניות כמו * או ha_config_set_* מ-read_tool_patterns."),
        "f_options_changed": ("הגדרות השער השתנו בזמן שהוא לא רץ", "{keys} ב-{when}", "אם זה לא היית אתה, בדוק את הגדרות התוסף."),
        "f_downtime": ("השער לא רץ", "{mins} דקות, עד {when}", "בדוק את לוג התוסף; כשהשער לא רץ, רק אוטומציות הגיבוי אוכפות את הנעילה."),
        "f_anomaly": ("פעילות חריגה: פרץ מחיקות", "{n} קריאות מחיקה או עצירה בתוך דקה ב-{when} (האחרונה: {tool}); השער נעל את עצמו", "בדוק את יומן הביקורת. אם זה היית אתה, נקה את האירועים בדשבורד."),
        "f_anomaly_warn": ("פעילות חריגה: הרבה כתיבות", "{n} כתיבות בתוך דקה ב-{when} (האחרונה: {tool})", "בסדר כשבונים משהו; אחרת בדוק את יומן הביקורת."),
        "f_redacted": ("סודות הוסתרו מהסוכן", "{n} ערכים ב-24 שעות, האחרון דרך {tool}", "הסוכן ביקש קבצים או נתונים עם פרטי גישה. בסדר אם ציפית לזה; אחרת בדוק את יומן הביקורת."),
    },
}

# Add-ons that let a person or an agent change the system from a shell, an editor
# or a flow editor. Installed but not listed in any mechanism = a path around the gate.
EDIT_ADDON_HINTS = ("ssh", "terminal", "vscode", "code_server", "code-server", "configurator",
                    "file_editor", "appdaemon", "nodered", "node_red", "node-red", "portainer",
                    "pyscript", "samba", "ftp", "sftp", "webdav")


def TS(key, **kw):
    v = SCAN_STRINGS.get(LANG, SCAN_STRINGS["en"]).get(key) or SCAN_STRINGS["en"].get(key, key)
    if isinstance(v, str) and kw:
        return v.format(**kw)
    return v


def _finding(sev, key, **kw):
    title, detail, fix = TS(key)
    return {"severity": sev, "key": key, "title": title,
            "detail": detail.format(**kw) if kw else detail, "fix": fix}


def _ws_tokens():
    """Long-lived tokens via the HA websocket (may be refused for the add-on user)."""
    try:
        res = _ws_call([{"type": "auth/refresh_tokens"}])
        toks = res[0].get("result") or []
        return [t.get("client_name") or t.get("client_id") or "?" for t in toks
                if t.get("type") == "long_lived_access_token"]
    except Exception as e:
        log(f"token listing unavailable: {e}")
        return None


FIX_KINDS = ("boot_manual", "uninstall_uncontrolled", "update_addons", "enable_backstop", "watchdog_on")


def apply_fix(kind):
    """Carry out one of the scan's one-tap fixes, then rescan. Only the user
    triggers this (MQTT agent_gate/cmd/fix); the agent cannot reach the topic."""
    fix = next((f for f in LAST_SCAN.get("fixes", []) if f.get("kind") == kind), None)
    label = TS("fix_" + kind) if kind in FIX_KINDS else kind
    if not fix:
        log(f"fix {kind}: nothing to do")
        return
    errors = []
    try:
        if kind == "boot_manual":
            for slug in fix.get("slugs", []):
                code, _ = _sup_request("POST", f"/addons/{slug}/options", {"boot": "manual"})
                if code != 200:
                    errors.append(f"{slug}: {code}")
        elif kind == "uninstall_uncontrolled":
            for slug in fix.get("slugs", []):
                code, _ = _sup_request("POST", f"/addons/{slug}/uninstall", {}, timeout=120)
                if code != 200:
                    errors.append(f"{slug}: {code}")
        elif kind == "update_addons":
            for slug in fix.get("slugs", []):
                code, _ = _sup_request("POST", f"/addons/{slug}/update", {"backup": True}, timeout=600)
                if code != 200:
                    errors.append(f"{slug}: {code}")
        elif kind == "enable_backstop":
            ok = ha_call_service("automation", "turn_on", {"entity_id": fix.get("entities", [])})
            if not ok:
                errors.append("automation.turn_on")
        elif kind == "watchdog_on":
            code, _ = _sup_request("POST", f"/addons/{SELF_SLUG}/options", {"watchdog": True})
            if code != 200:
                errors.append(f"watchdog: {code}")
    except Exception as e:
        errors.append(str(e))
    audit({"tool": "fix", "decision": "ok" if not errors else "error", "reason": kind,
           "mode": STATE["mode"], "window_id": STATE.get("window_id"), "args_preview": json.dumps(fix, ensure_ascii=False)[:300]})
    if errors:
        notify(TS("report_title"), TS("fix_failed", label=label, err="; ".join(errors)[:200]), tag="agent_gate_fix")
    else:
        notify(TS("report_title"), TS("fix_done", label=label), tag="agent_gate_fix")
    time.sleep(2)
    run_scan("fix")


SCAN_COOLDOWN = 60  # seconds between scan starts
_LAST_SCAN_START = 0.0


def run_scan(source="manual"):
    global _LAST_SCAN_START
    if not SCAN_LOCK.acquire(blocking=False):
        log("scan already running")
        return
    if source == "manual" and time.time() - _LAST_SCAN_START < SCAN_COOLDOWN:
        log("scan ignored: last scan started less than a minute ago")
        SCAN_LOCK.release()
        return
    _LAST_SCAN_START = time.time()
    try:
        if MQTT_CLIENT:
            MQTT_CLIENT.publish(f"{BASE}/scan/state", "scanning", qos=1, retain=True)
            if source != "startup":
                time.sleep(2)  # keep the "scanning" state visible on the dashboard
        findings = []
        now = now_utc()
        # 1. gate state
        actual = _LAST_ACTUAL or actual_states()
        windows = active_windows()
        if windows:
            since = min((w.get("opened_at") or iso(now)) for w in windows.values())
            findings.append(_finding("info", "f_open", names=", ".join(mech_name(k) for k in windows),
                                     since=fmt_local(since)))
        dev = compute_deviation(actual)
        if dev:
            findings.append(_finding("critical", "f_deviation", names=", ".join(mech_name(k) for k in dev)))
        if not UPSTREAM.hostname:
            findings.append(_finding("warning", "f_upstream"))
        # backstop automations
        try:
            code, states = _sup_request("GET", "/core/api/states", timeout=30)
            st_by_id = {s.get("entity_id"): s.get("state") for s in (states if isinstance(states, list) else [])}
            ids = set(st_by_id)
        except Exception:
            st_by_id, ids = {}, set()
        backstop = ("automation.agent_gate_guard_when_gate_is_offline",
                    "automation.agent_gate_guard_on_long_deviation",
                    "automation.agent_gate_relay_phone_actions")
        missing = [a for a in backstop if ids and a not in ids]
        if missing:
            findings.append(_finding("warning", "f_package", names=", ".join(missing)))
        disabled = [a for a in backstop if st_by_id.get(a) == "off"]
        if disabled:
            findings.append(_finding("critical", "f_package_off", names=", ".join(disabled)))
        # tamper protection: policy, watchdog, downtime, option changes, decoys
        write_like = ("ha_config_set_*", "ha_call_service", "ha_set_*", "ha_remove_*", "ha_delete_*",
                      "ha_write_file", "ha_manage_*", "ha_restart")
        broad = [p for p in READ_PATTERNS if p in ("*", "ha_*", "ha_config_*")
                 or any(fnmatch.fnmatchcase(w.replace("*", "x"), p) for w in write_like)]
        if broad:
            findings.append(_finding("critical", "f_policy_broad", names=", ".join(broad)))
        try:
            code, me = _sup_request("GET", f"/addons/{SELF_SLUG}/info", timeout=20)
            me = me.get("data", {}) if code == 200 else {}
            if me and me.get("watchdog") is False:
                findings.append(_finding("warning", "f_watchdog"))
        except Exception:
            pass
        for e in tamper_events_recent():
            if e.get("kind") == "options_changed":
                findings.append(_finding("info", "f_options_changed", keys=", ".join(e.get("keys") or []),
                                         when=fmt_local(e["ts"])))
            elif e.get("kind") == "down":
                findings.append(_finding("warning", "f_downtime", mins=e.get("minutes"), when=fmt_local(e["ts"])))
        for e in anomaly_events_recent():
            if e.get("kind") == "anomaly_lock":
                findings.append(_finding("critical", "f_anomaly", n=e.get("count"), when=fmt_local(e["ts"]), tool=e.get("tool")))
            else:
                findings.append(_finding("warning", "f_anomaly_warn", n=e.get("count"), when=fmt_local(e["ts"]), tool=e.get("tool")))
        reds = redactions_recent()
        if reds:
            findings.append(_finding("info", "f_redacted", n=sum(r.get("n", 0) for r in reds), tool=reds[0].get("tool")))
        if CANARY_ENABLED:
            hits = canary_hits_recent()
            if hits:
                h = hits[0]
                findings.append(_finding("critical", "f_canary", n=len(hits), what=h.get("what"),
                                         where=h.get("where"), when=fmt_local(h["ts"])))
            else:
                place_canaries()
                findings.append(_finding("ok", "f_canary_ok", n=len(CANARY_FILES)))
        if not windows and not dev and not missing and UPSTREAM.hostname:
            findings.append(_finding("ok", "f_gate_ok"))
        # 2. add-ons
        unprotected, hostnet, ports, addon_updates, ssh_pw, addon_pw, tunnels = [], [], [], [], [], [], []
        uncontrolled, boot_auto = [], []
        uncontrolled_slugs, boot_auto_slugs, update_slugs = [], [], []
        controlled = {x for m in MECHANISMS for x in m["addons"]}
        try:
            code, data = _sup_request("GET", "/addons", timeout=30)
            addons = data.get("data", {}).get("addons", []) if code == 200 else []
        except Exception:
            addons = []
        for a in addons:
            slug = a.get("slug")
            if not slug:
                continue
            if slug != SELF_SLUG and slug not in controlled and any(h in slug.lower() for h in EDIT_ADDON_HINTS):
                uncontrolled.append(a.get("name") or slug)
                uncontrolled_slugs.append(slug)
            if a.get("state") != "started" and not a.get("update_available") and slug not in controlled:
                continue
            try:
                code, info = _sup_request("GET", f"/addons/{slug}/info", timeout=20)
                info = info.get("data", {}) if code == 200 else {}
            except Exception:
                info = {}
            name = info.get("name") or a.get("name") or slug
            running = info.get("state") == "started"
            if info.get("update_available") or a.get("update_available"):
                addon_updates.append(f"{name} ({info.get('version')} -> {info.get('version_latest')})")
                if slug != SELF_SLUG:
                    update_slugs.append(slug)
            if slug in controlled and info.get("boot") == "auto":
                boot_auto.append(name)
                boot_auto_slugs.append(slug)
            if not running:
                continue
            if slug != SELF_SLUG and info.get("protected") is False:
                unprotected.append(name)
            if info.get("host_network"):
                hostnet.append(name)
            net = info.get("network") or {}
            mapped = [str(v) for v in net.values() if v]
            if mapped and slug != SELF_SLUG:
                ports.append(f"{name} ({', '.join(mapped)})")
            opts = info.get("options") or {}
            pw = opts.get("password")
            if "ssh" in slug and pw:
                ssh_pw.append(name)
            elif pw and isinstance(pw, str):
                addon_pw.append(name)
            if any(t in slug for t in ("cloudflared", "ngrok", "tailscale", "zerotier", "wireguard")):
                tunnels.append(name)
        if unprotected:
            findings.append(_finding("critical", "f_protection", names=", ".join(unprotected)))
        if uncontrolled:
            findings.append(_finding("warning", "f_uncontrolled", names=", ".join(uncontrolled)))
        if boot_auto:
            findings.append(_finding("warning", "f_boot_auto", names=", ".join(boot_auto)))
        if ssh_pw:
            findings.append(_finding("warning", "f_ssh_pw", names=", ".join(ssh_pw)))
        if hostnet:
            findings.append(_finding("info", "f_hostnet", names=", ".join(hostnet)))
        if ports:
            findings.append(_finding("info", "f_ports", names=", ".join(ports)))
        if addon_pw:
            findings.append(_finding("info", "f_addon_pw", names=", ".join(addon_pw)))
        if tunnels:
            findings.append(_finding("info", "f_tunnel", names=", ".join(tunnels)))
        if addon_updates:
            findings.append(_finding("info", "f_update_addons", names=", ".join(addon_updates)))
        # 3. core / os / supervisor updates
        for path, key in (("/core/info", "f_update_core"), ("/os/info", "f_update_os"),
                          ("/supervisor/info", "f_update_sup")):
            try:
                code, d = _sup_request("GET", path, timeout=20)
                d = d.get("data", {}) if code == 200 else {}
                if d.get("update_available"):
                    findings.append(_finding("warning" if key == "f_update_core" else "info", key,
                                             cur=d.get("version"), latest=d.get("version_latest")))
            except Exception:
                pass
        # 4. backups
        age = latest_full_backup_age_hours()
        if age is None:
            findings.append(_finding("warning", "f_backup_none"))
        elif age > 48:
            findings.append(_finding("warning", "f_backup_old", age=int(age)))
        # 5. tokens
        toks = _ws_tokens()
        if toks:
            findings.append(_finding("info", "f_tokens", n=len(toks), names=", ".join(toks[:10])))
        findings.sort(key=lambda f: SEV_ORDER.get(f["severity"], 9))
        counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}
        score, band = security_score(findings)
        # One-tap fixes the gate can carry out for the user (never on its own).
        fixes = []
        if boot_auto_slugs:
            fixes.append({"kind": "boot_manual", "slugs": boot_auto_slugs, "names": boot_auto})
        if uncontrolled_slugs:
            fixes.append({"kind": "uninstall_uncontrolled", "slugs": uncontrolled_slugs, "names": uncontrolled})
        if update_slugs:
            fixes.append({"kind": "update_addons", "slugs": update_slugs, "names": addon_updates})
        if disabled:
            fixes.append({"kind": "enable_backstop", "entities": disabled, "names": disabled})
        if any(f["key"] == "f_watchdog" for f in findings):
            fixes.append({"kind": "watchdog_on", "names": []})
        for f in fixes:
            f["label"] = TS("fix_" + f["kind"])
        report = {"ts": iso(now), "source": source, "counts": counts, "findings": findings,
                  "score": score, "band": band, "fixes": fixes, "markdown": scan_markdown(findings, now)}
        # notify on new critical findings
        prev = {f["key"] for f in LAST_SCAN.get("findings", []) if f["severity"] == "critical"}
        new_crit = [f for f in findings if f["severity"] == "critical" and f["key"] not in prev]
        LAST_SCAN.clear()
        LAST_SCAN.update(report)
        _append_jsonl(SCANS_PATH, {k: v for k, v in report.items() if k != "markdown"})
        remember_scan(report)
        write_report_files(report)
        if new_crit and source != "startup":
            notify(TS("notify_title"), TS("notify_new") + "\n" + "\n".join(f"- {f['title']}: {f['detail']}" for f in new_crit),
                   tag="agent_gate_scan")
        publish_scan()
        log(f"scan done: {counts}")
    except Exception as e:
        log(f"scan error: {e}")
        LAST_SCAN.clear()
        LAST_SCAN.update({"ts": iso(now_utc()), "counts": {}, "findings": [],
                          "markdown": TS("scan_failed", e=str(e))})
        publish_scan()
    finally:
        SCAN_LOCK.release()


REPORT_DIR = "/share/agent_gate"


def write_report_files(report):
    """Latest report as .md and .json under /share (reachable from File editor,
    Samba, VS Code) and served by the gate at REPORT_PATH."""
    try:
        os.makedirs(REPORT_DIR, exist_ok=True)
        stamp = report["ts"].replace(":", "").replace("-", "")[:15]
        with open(os.path.join(REPORT_DIR, "scan_latest.md"), "w", encoding="utf-8") as f:
            f.write(report["markdown"].replace("\n\n", "\n") + "\n")
        with open(os.path.join(REPORT_DIR, "scan_latest.json"), "w", encoding="utf-8") as f:
            json.dump({k: v for k, v in report.items() if k != "markdown"}, f, ensure_ascii=False, indent=1)
        with open(os.path.join(REPORT_DIR, f"scan_{stamp}.md"), "w", encoding="utf-8") as f:
            f.write(report["markdown"].replace("\n\n", "\n") + "\n")
    except Exception as e:
        log(f"could not write report files: {e}")


REPORT_HTML = """<!doctype html><html lang="{lang}" dir="{dir}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Agent Gate</title>
<style>body{{font-family:system-ui,sans-serif;background:#111;color:#eee;margin:0;padding:16px;max-width:760px}}
button,a.b{{display:inline-block;font-size:18px;padding:14px 20px;margin:6px 4px 14px 0;border-radius:12px;border:0;
background:#2d6cdf;color:#fff;text-decoration:none;cursor:pointer}}button.g{{background:#444}}
pre{{white-space:pre-wrap;background:#1c1c1c;padding:14px;border-radius:12px;font-size:15px;line-height:1.5}}
#ok{{color:#7bd88f;margin-inline-start:8px}}</style></head><body>
<h2>{title}</h2>
<button onclick="cp()">{copy}</button><span id="ok"></span><br>
<a class="b g" href="{base}/scan.md" download="agent_gate_scan.md">{dl_md}</a>
<a class="b g" href="{base}/scan.json" download="agent_gate_scan.json">{dl_json}</a>
<pre id="t">{text}</pre>
<script>function cp(){{var t=document.getElementById('t').innerText;
function done(){{document.getElementById('ok').textContent='{copied}';}}
if(navigator.clipboard&&window.isSecureContext){{navigator.clipboard.writeText(t).then(done);return;}}
var ta=document.createElement('textarea');ta.value=t;ta.style.position='fixed';ta.style.opacity=0;document.body.appendChild(ta);
ta.focus();ta.select();try{{document.execCommand('copy');done();}}catch(e){{}}document.body.removeChild(ta);}}
function rf(){{fetch('{base}/scan.txt?t='+Date.now(),{{cache:'no-store'}}).then(function(r){{return r.text()}}).then(function(x){{if(x)document.getElementById('t').textContent=x;}}).catch(function(){{}});}}
document.addEventListener('visibilitychange',function(){{if(!document.hidden)rf();}});window.addEventListener('pageshow',rf);setInterval(rf,30000);</script>
</body></html>"""


def report_page():
    md = LAST_SCAN.get("markdown") or ("אין סריקה עדיין." if LANG == "he" else "No scan yet.")
    plain = re.sub(r"\*\*(.+?)\*\*", r"\1", md).replace("\n\n", "\n")
    he = LANG == "he"
    import html as _html
    return REPORT_HTML.format(lang=LANG, dir="rtl" if he else "ltr",
                              title="סריקת אבטחה" if he else "Security scan",
                              copy="העתק ללוח" if he else "Copy to clipboard",
                              copied="הועתק" if he else "Copied",
                              dl_md="הורד .md" if he else "Download .md",
                              dl_json="הורד .json" if he else "Download .json",
                              base=REPORT_PATH, text=_html.escape(plain))


def scan_markdown(findings, when):
    icons = {"critical": "🔴", "warning": "🟠", "info": "🔵", "ok": "🟢"}
    lines = [f"**{TS('report_title')}** · {when.astimezone().strftime('%d/%m %H:%M')}"]
    c = sum(1 for f in findings if f["severity"] == "critical")
    w = sum(1 for f in findings if f["severity"] == "warning")
    i = sum(1 for f in findings if f["severity"] == "info")
    lines.append(TS("summary", c=c, w=w, i=i) + " · " + TS("score_line", score=security_score(findings)[0]))
    if not findings:
        lines.append(TS("no_findings"))
    for f in findings:
        line = f"{icons.get(f['severity'], '')} **{f['title']}**"
        if f["detail"]:
            line += f": {f['detail']}"
        lines.append(line)
        if f["fix"]:
            lines.append(f"  · {TS('fix')}: {f['fix']}")
    return "\n\n".join(lines)


def publish_scan():
    if not MQTT_CLIENT or not LAST_SCAN:
        return
    counts = LAST_SCAN.get("counts", {})
    state = "critical" if counts.get("critical") else ("warning" if counts.get("warning") else "ok")
    MQTT_CLIENT.publish(f"{BASE}/scan/state", state, qos=1, retain=True)
    MQTT_CLIENT.publish(f"{BASE}/scan/attributes", json.dumps({
        "ts": LAST_SCAN.get("ts"), "counts": counts, "findings": LAST_SCAN.get("findings", []),
        "score": LAST_SCAN.get("score"), "band": LAST_SCAN.get("band"),
        "fixes": LAST_SCAN.get("fixes", []),
        "markdown": LAST_SCAN.get("markdown", ""),
        "report_url": f"http://{ha_host()}:{int(OPT.get('listen_port') or 9584)}{REPORT_PATH}/",
        "files": [f"{REPORT_DIR}/scan_latest.md", f"{REPORT_DIR}/scan_latest.json"]},
        ensure_ascii=False), qos=1, retain=True)
    avail = {f["kind"]: f for f in LAST_SCAN.get("fixes", [])}
    for kind in FIX_KINDS:
        f = avail.get(kind)
        MQTT_CLIENT.publish(f"{BASE}/fix/{kind}/state", "ON" if f else "OFF", qos=1, retain=True)
        MQTT_CLIENT.publish(f"{BASE}/fix/{kind}/attributes", json.dumps({
            "label": TS("fix_" + kind), "names": (f or {}).get("names", []),
            "slugs": (f or {}).get("slugs", []), "entities": (f or {}).get("entities", [])},
            ensure_ascii=False), qos=1, retain=True)
    if LAST_SCAN.get("score") is not None:
        MQTT_CLIENT.publish(f"{BASE}/scan/score/state", str(LAST_SCAN["score"]), qos=1, retain=True)
        MQTT_CLIENT.publish(f"{BASE}/scan/score/attributes", json.dumps({
            "ts": LAST_SCAN.get("ts"), "band": LAST_SCAN.get("band"), "counts": counts,
            "weights": SCORE_WEIGHTS,
            "deductions": [{"title": f["title"], "severity": f["severity"], "points": SCORE_WEIGHTS.get(f["severity"], 0)}
                           for f in LAST_SCAN.get("findings", []) if SCORE_WEIGHTS.get(f["severity"], 0)]},
            ensure_ascii=False), qos=1, retain=True)
    publish_scan_history()


def publish_scan_history():
    """Slots 1..N (newest first): state is the scan time, attributes hold counts and text."""
    if not MQTT_CLIENT:
        return
    for n in range(1, SCAN_SLOTS + 1):
        if n <= len(SCAN_HISTORY):
            h = SCAN_HISTORY[n - 1]
            c = h.get("counts") or {}
            sev = "critical" if c.get("critical") else ("warning" if c.get("warning") else "ok")
            MQTT_CLIENT.publish(f"{BASE}/scan/h{n}/state", _scan_label(h.get("ts")), qos=1, retain=True)
            MQTT_CLIENT.publish(f"{BASE}/scan/h{n}/attributes", json.dumps({
                "ts": h.get("ts"), "counts": c, "severity": sev, "score": h.get("score"),
                "summary": TS("summary", c=c.get("critical", 0), w=c.get("warning", 0), i=c.get("info", 0))
                           + (f" · {h.get('score')}/100" if h.get("score") is not None else ""),
                "markdown": h.get("markdown", "")}, ensure_ascii=False), qos=1, retain=True)
        else:
            MQTT_CLIENT.publish(f"{BASE}/scan/h{n}/state", "none", qos=1, retain=True)
            MQTT_CLIENT.publish(f"{BASE}/scan/h{n}/attributes", json.dumps({"severity": "none", "summary": "", "markdown": ""}),
                                qos=1, retain=True)


def scan_loop():
    hours = int(OPT.get("scan_interval_hours") or 0)
    time.sleep(90)
    publish_scan_history()
    run_scan("startup")
    while hours:
        time.sleep(hours * 3600)
        run_scan("scheduled")


# --------------------------------------------------------------------------
# 6. MCP proxy
# --------------------------------------------------------------------------
UPSTREAM = urlsplit(OPT.get("upstream_mcp_url") or "")
HOP_HEADERS = {"host", "content-length", "transfer-encoding", "connection", "keep-alive"}

GATE_TOOLS = [
    {"name": "gate_status",
     "description": "Agent Gate: is the gate locked or open, until when, which mechanisms are on, "
                    "pending command approvals. Always allowed.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "gate_run_command",
     "description": "Run a shell command on the Home Assistant host side (inside the Agent Gate "
                    "container, with /addons, /homeassistant and /share mounted read-write). "
                    "Refused while the gate is locked. Destructive commands (delete, move, docker, "
                    "restart ...) are held for the user's approval on their phone: the call returns an "
                    "approval_id; call again with only approval_id once the user approved.",
     "inputSchema": {"type": "object",
                     "properties": {"command": {"type": "string", "description": "sh -c command"},
                                    "cwd": {"type": "string", "description": "working directory, default /addons"},
                                    "timeout_seconds": {"type": "integer", "default": 60, "maximum": 600},
                                    "approval_id": {"type": "string",
                                                    "description": "re-run a held command after approval"}}}},
]


def jsonrpc_result(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def tool_text(text, is_error=False):
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def forward(method, path, headers, body, timeout=120):
    """Returns (status, headers_list, response_obj) for streaming or (status, headers, bytes)."""
    conn_cls = http.client.HTTPSConnection if UPSTREAM.scheme == "https" else http.client.HTTPConnection
    conn = conn_cls(UPSTREAM.hostname, UPSTREAM.port or (443 if UPSTREAM.scheme == "https" else 80),
                    timeout=timeout)
    up_path = UPSTREAM.path or "/"
    if UPSTREAM.query:
        up_path += "?" + UPSTREAM.query
    hdrs = {k: v for k, v in headers.items() if k.lower() not in HOP_HEADERS}
    if body is not None:
        hdrs["Content-Length"] = str(len(body))
    conn.request(method, up_path, body=body, headers=hdrs)
    return conn, conn.getresponse()


def parse_sse(raw):
    """Return list of (event_name, data_text) from an SSE body."""
    events = []
    name, data = None, []
    for line in raw.decode("utf-8", "replace").split("\n"):
        line = line.rstrip("\r")
        if line == "":
            if data:
                events.append((name, "\n".join(data)))
            name, data = None, []
        elif line.startswith("event:"):
            name = line[6:].strip()
        elif line.startswith("data:"):
            data.append(line[5:].lstrip())
    if data:
        events.append((name, "\n".join(data)))
    return events


def build_sse(events):
    out = []
    for name, data in events:
        if name:
            out.append(f"event: {name}")
        for d in data.split("\n"):
            out.append(f"data: {d}")
        out.append("")
    return ("\n".join(out) + "\n").encode("utf-8")


def inject_gate_tools(msg):
    if isinstance(msg, dict) and isinstance(msg.get("result"), dict) and "tools" in msg["result"]:
        tools = [t for t in msg["result"]["tools"] if t.get("name") not in GATE_TOOL_NAMES]
        msg["result"]["tools"] = tools + GATE_TOOLS
    return msg


def rewrite_tools_list_body(ctype, raw):
    try:
        if "text/event-stream" in ctype:
            events = parse_sse(raw)
            new = []
            for name, data in events:
                try:
                    new.append((name, json.dumps(inject_gate_tools(json.loads(data)), ensure_ascii=False)))
                except Exception:
                    new.append((name, data))
            return build_sse(new)
        obj = json.loads(raw.decode("utf-8"))
        if isinstance(obj, list):
            obj = [inject_gate_tools(m) for m in obj]
        else:
            obj = inject_gate_tools(obj)
        return json.dumps(obj, ensure_ascii=False).encode("utf-8")
    except Exception as e:
        log(f"tools/list rewrite skipped: {e}")
        return raw


class GateHandler(http.server.BaseHTTPRequestHandler):
    server_version = "AgentGate/0.1"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype="application/json", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _send_json(self, code, obj, extra=None):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"), extra=extra)

    def _endpoint_ok(self):
        return self.path.split("?", 1)[0] == ENDPOINT_PATH

    def _send_bytes(self, code, body, ctype, download=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if download:
            self.send_header("Content-Disposition", f'attachment; filename="{download}"')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            self._send_json(200, {"status": "alive", "mode": STATE["mode"]})
            return
        path = self.path.split("?", 1)[0]
        if path.startswith(REPORT_PATH):
            sub = path[len(REPORT_PATH):].strip("/")
            if sub == "":
                self._send_bytes(200, report_page().encode("utf-8"), "text/html; charset=utf-8")
            elif sub == "scan.txt":
                md = LAST_SCAN.get("markdown") or ""
                plain = re.sub(r"\*\*(.+?)\*\*", r"\1", md).replace("\n\n", "\n")
                self._send_bytes(200, plain.encode("utf-8"), "text/plain; charset=utf-8")
            elif sub == "scan.md":
                self._send_bytes(200, (LAST_SCAN.get("markdown") or "").replace("\n\n", "\n").encode("utf-8"),
                                 "text/markdown; charset=utf-8", "agent_gate_scan.md")
            elif sub == "scan.json":
                body = json.dumps({k: v for k, v in LAST_SCAN.items() if k != "markdown"},
                                  ensure_ascii=False, indent=1).encode("utf-8")
                self._send_bytes(200, body, "application/json; charset=utf-8", "agent_gate_scan.json")
            else:
                self._send_json(404, {"error": "not_found"})
            return
        if not self._endpoint_ok():
            self._send_json(404, {"error": "not_found"})
            return
        if not UPSTREAM.hostname:
            self._send_json(503, {"error": "upstream_mcp_url not configured"})
            return
        # Long-lived SSE stream: pass through untouched, connection-close framing.
        try:
            conn, resp = forward("GET", self.path, self.headers, None, timeout=3600)
        except Exception as e:
            self._send_json(502, {"error": f"upstream unreachable: {e}"})
            return
        try:
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() not in HOP_HEADERS:
                    self.send_header(k, v)
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            while True:
                chunk = resp.read1(4096) if hasattr(resp, "read1") else resp.read(4096)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except Exception:
            pass
        finally:
            conn.close()

    def do_DELETE(self):
        if not self._endpoint_ok():
            self._send_json(404, {"error": "not_found"})
            return
        try:
            conn, resp = forward("DELETE", self.path, self.headers, None)
            raw = resp.read()
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() not in HOP_HEADERS:
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            conn.close()
        except Exception as e:
            self._send_json(502, {"error": f"upstream unreachable: {e}"})

    def do_POST(self):
        if not self._endpoint_ok():
            self._send_json(404, {"error": "not_found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        try:
            msg = json.loads(body.decode("utf-8")) if body else None
        except Exception:
            msg = None
        if isinstance(msg, dict) and msg.get("method") == "tools/call":
            params = msg.get("params") or {}
            name = params.get("name", "")
            args = params.get("arguments") or {}
            decision, reason = evaluate_tool_call(name, args)
            audit({"tool": name, "decision": decision, "reason": reason,
                   "mode": STATE["mode"], "window_id": STATE.get("window_id"),
                   "args_preview": json.dumps(args, ensure_ascii=False)[:300]})
            if decision == "deny":
                self._send_json(200, jsonrpc_result(msg.get("id"), tool_text(f"DENIED: {reason}", True)))
                return
            if decision == "local":
                self._send_json(200, jsonrpc_result(msg.get("id"), run_gate_tool(name, args)))
                return
        if isinstance(msg, list) and any(isinstance(m, dict) and m.get("method") == "tools/call" for m in msg):
            self._send_json(200, {"jsonrpc": "2.0", "id": None,
                                  "error": {"code": -32600, "message": "batched tools/call not supported by Agent Gate"}})
            return
        if not UPSTREAM.hostname:
            self._send_json(503, {"error": "upstream_mcp_url not configured"})
            return
        try:
            conn, resp = forward("POST", self.path, self.headers, body)
            raw = resp.read()
            ctype = resp.getheader("Content-Type", "") or ""
            if isinstance(msg, dict) and msg.get("method") == "tools/list":
                raw = rewrite_tools_list_body(ctype, raw)
            elif isinstance(msg, dict) and msg.get("method") == "tools/call":
                raw = redact_response_body(ctype, raw, (msg.get("params") or {}).get("name", ""))
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() not in HOP_HEADERS:
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            conn.close()
        except Exception as e:
            log(f"upstream error: {e}")
            self._send_json(502, {"error": f"upstream unreachable: {e}"})


class ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, BrokenPipeError, TimeoutError)):
            return  # health probes and dropped clients; not worth a traceback
        super().handle_error(request, client_address)


# --------------------------------------------------------------------------
# 7. gate tools
# --------------------------------------------------------------------------
def gate_status_text():
    actual = _LAST_ACTUAL or actual_states()
    with STATE_LOCK:
        st = json.loads(json.dumps(STATE))
    lines = [f"mode: {st['mode']}"]
    for m in MECHANISMS:
        a = actual.get(m["key"], {})
        w = st.get("windows", {}).get(m["key"])
        if w:
            lines.append(f"{m['key']}: OPEN until {w.get('end') or 'the user closes it'}, running now={a.get('running')}")
        else:
            lines.append(f"{m['key']}: closed, running now={a.get('running')}")
    pend = [f"{k}: {v['command'][:100]} ({v['status']})" for k, v in st.get("pending", {}).items()]
    lines.append("pending approvals: " + (", ".join(pend) if pend else "none"))
    lines.append("Only the user can open, extend or lock the gate (dashboard or phone).")
    return "\n".join(lines)


def execute_command(command, cwd, timeout, approval_id=None):
    cwd = cwd or ("/addons" if os.path.isdir("/addons") else "/")
    started = time.time()
    try:
        proc = subprocess.run(["sh", "-c", command], cwd=cwd, capture_output=True, timeout=timeout)
        rc = proc.returncode
        out = proc.stdout.decode("utf-8", "replace")
        err = proc.stderr.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        rc, out, err = -1, "", f"timeout after {timeout}s"
    except Exception as e:
        rc, out, err = -1, "", str(e)
    with STATE_LOCK:
        wid = STATE.get("window_id")
    _append_jsonl(COMMANDS_PATH, {"ts": iso(now_utc()), "window_id": wid, "command": command,
                                  "cwd": cwd, "rc": rc, "seconds": round(time.time() - started, 1),
                                  "approval_id": approval_id})
    limit = 20000
    text = f"exit code: {rc}\n--- stdout ---\n{out[:limit]}"
    if len(out) > limit:
        text += f"\n... ({len(out) - limit} more bytes)"
    if err:
        text += f"\n--- stderr ---\n{err[:limit]}"
    text, n = redact_text(text)
    note_redactions("gate_run_command", n)
    return tool_text(text, rc != 0)


def run_gate_tool(name, args):
    if name == "gate_status":
        return tool_text(gate_status_text())
    if name != "gate_run_command":
        return tool_text(f"unknown gate tool {name}", True)
    if not is_active("commands"):
        return tool_text("DENIED: Agent Gate is locked (or the 'commands' mechanism is off). "
                         "Ask the user to open the gate from the dashboard, then retry.", True)
    approval_id = (args.get("approval_id") or "").strip()
    if approval_id:
        with STATE_LOCK:
            p = STATE["pending"].get(approval_id)
            if not p:
                return tool_text(f"unknown approval_id {approval_id}", True)
            status = p.get("status")
            if status == "pending":
                return tool_text(f"approval {approval_id} still pending; the user has not answered yet.", True)
            if status in ("rejected", "expired"):
                return tool_text(f"approval {approval_id} was {status}; the command will not run.", True)
            if status == "done":
                return tool_text(f"approval {approval_id} was already used.", True)
            p["status"] = "done"
            save_state()
        res = execute_command(p["command"], p.get("cwd"), p.get("timeout", 60), approval_id)
        publish_all()
        return res
    command = (args.get("command") or "").strip()
    if not command:
        return tool_text("command is required", True)
    hit = canary_match(command)
    if hit:
        trip_canary("gate_run_command", hit, command)
        return tool_text("DENIED: that is a decoy; the gate has been locked and the user notified.", True)
    if touches_protected({"c": command}):
        return tool_text("DENIED: command touches the gate itself.", True)
    try:
        timeout = min(600, max(1, int(args.get("timeout_seconds") or 60)))
    except Exception:
        timeout = 60
    cwd = args.get("cwd") or None
    if is_destructive(command):
        pid = uuid.uuid4().hex[:6]
        with STATE_LOCK:
            STATE["pending"][pid] = {"command": command, "cwd": cwd, "timeout": timeout,
                                     "created": iso(now_utc()), "status": "pending"}
            save_state()
        notify(T("approve_title"), f"[{pid}] {command[:400]}",
               actions=[{"action": f"AGENT_GATE_APPROVE_{pid}", "title": T("btn_approve")},
                        {"action": f"AGENT_GATE_REJECT_{pid}", "title": T("btn_reject")}],
               tag=f"agent_gate_approval_{pid}")
        publish_all()
        return tool_text(f"HELD for user approval (destructive pattern). approval_id={pid}. "
                         f"The user has {OPT.get('approval_timeout_minutes', 3)} minutes to approve on their "
                         f"phone. Tell the user, wait, then call gate_run_command with approval_id only.")
    return execute_command(command, cwd, timeout)


# --------------------------------------------------------------------------
# 8. main
# --------------------------------------------------------------------------
def main():
    global MQTT_CLIENT
    os.makedirs(DATA_DIR, exist_ok=True)
    save_state()
    port = int(OPT.get("listen_port") or 9584)
    log(f"mechanisms: {[m['key'] for m in MECHANISMS]}")
    log(f"mounts: {MOUNTS}")
    if not UPSTREAM.hostname:
        log("WARNING: upstream_mcp_url is empty; gate tools work, HA tools will fail until it is set")
    else:
        log(f"upstream: {UPSTREAM.scheme}://{UPSTREAM.hostname}:{UPSTREAM.port}{UPSTREAM.path}")
    if mqtt is not None and SUPERVISOR_TOKEN:
        try:
            MQTT_CLIENT = mqtt_connect()
            publish_discovery()
            log("MQTT connected, discovery published")
        except Exception as e:
            log(f"MQTT unavailable: {e} (dashboard control disabled)")
    if SUPERVISOR_TOKEN:
        enforce_on_start()
        threading.Thread(target=ensure_dashboard, daemon=True).start()
    place_canaries()
    tamper_check_on_start()
    publish_all(actual=actual_states() if SUPERVISOR_TOKEN else {})
    threading.Thread(target=timer_loop, daemon=True).start()
    if SUPERVISOR_TOKEN:
        threading.Thread(target=scan_loop, daemon=True).start()
    log("=" * 60)
    log(f"MCP gate endpoint: http://<home-assistant-ip>:{port}{ENDPOINT_PATH}")
    log(f"Scan report page: http://<home-assistant-ip>:{port}{REPORT_PATH}/ (also /share/agent_gate/)")
    log("Set this as 'MCP server URL' in the Webhook Proxy add-on.")
    log("=" * 60)
    srv = ThreadingServer(("0.0.0.0", port), GateHandler)

    # The gate runs as PID 1 (init: false), and PID 1 ignores SIGTERM unless a
    # handler is installed. Without this, every stop or update waits for the
    # Supervisor's 10 s timeout and ends with SIGKILL (exit code 137).
    def _stop(signum, frame):
        log(f"signal {signum}: shutting down")
        try:
            save_state()
            if MQTT_CLIENT:
                MQTT_CLIENT.publish(AVAIL_TOPIC, "offline", qos=1, retain=True)
                MQTT_CLIENT.loop_stop()
        except Exception:
            pass
        threading.Thread(target=srv.shutdown, daemon=True).start()
    import signal
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    srv.serve_forever()
    log("stopped")


if __name__ == "__main__":
    main()

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

import fnmatch
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
    import paho.mqtt.client as mqtt
except Exception:  # pragma: no cover - the image always has it
    mqtt = None

# --------------------------------------------------------------------------
# 1. config + state
# --------------------------------------------------------------------------
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
        "backup_on_open": True,
        "backup_mode": "always",
        "backup_min_interval_hours": 6,
        "backup_skip_windows_up_to_minutes": 0,
        "default_window_minutes": 30,
        "read_tool_patterns": ["ha_get_*", "ha_list_*", "ha_search", "ha_config_get_*",
                               "ha_config_list_*", "ha_read_file", "ha_eval_template",
                               "ha_get_skill_guide", "ha_report_issue"],
        "protected_patterns": ["agent_gate"],
        "destructive_patterns": [],
        "mechanisms": [],
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
        "mode": "locked",            # locked | open
        "window_id": None,
        "opened_at": None,
        "window_end": None,          # None while open == "until I close"
        "desired": {m["key"]: m["default_on"] for m in MECHANISMS},
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
        for m in MECHANISMS:
            base["desired"].setdefault(m["key"], m["default_on"])
        return base
    except Exception:
        return default_state()


STATE = load_state()

SETTINGS_PATH = os.path.join(DATA_DIR, "settings.json")
SETTINGS_KEYS = {
    "backup_mode": ("always", "if_stale", "never"),
    "backup_min_interval_hours": (1, 168),
    "backup_skip_windows_up_to_minutes": (0, 1440),
    "reminder_minutes": (0, 1440),
}


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
    mode = str(setting("backup_mode") or ("always" if OPT.get("backup_on_open", True) else "never"))
    skip_short = int(setting("backup_skip_windows_up_to_minutes") or 0)
    if mode == "never":
        return False, "backup_mode=never"
    if skip_short and minutes and minutes <= skip_short:
        return False, f"window of {minutes} min is within backup_skip_windows_up_to_minutes={skip_short}"
    if mode == "if_stale":
        max_age = float(setting("backup_min_interval_hours") or 6)
        age = latest_full_backup_age_hours()
        if age is not None and age < max_age:
            return False, f"last full backup is {age:.1f} h old (< {max_age:g} h)"
        return True, "no recent full backup" if age is None else f"last full backup is {age:.1f} h old"
    return True, "backup_mode=always"


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
    # Persistent notification as a fallback that is always visible in HA.
    ha_call_service("persistent_notification", "create",
                    {"title": title, "message": message,
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


def evaluate_tool_call(name, arguments):
    """Returns (decision, reason). decision in {'allow','deny','local'}."""
    if name in GATE_TOOL_NAMES:
        return "local", "gate tool"
    if is_read_tool(name):
        # Reading the gate's own entities is fine; only changing them is protected.
        return "allow", "read tool"
    if name not in PROTECTED_EXEMPT and (touches_protected(arguments) or any(p in name.lower() for p in PROTECTED)):
        return "deny", "touches the gate's own entities or topics; only the dashboard controls the gate"
    with STATE_LOCK:
        if STATE["mode"] == "open" and STATE["desired"].get("ha_write", False):
            return "allow", "window open"
    return "deny", ("Agent Gate is LOCKED. Write tools are refused until the user opens a "
                    "window from the dashboard. Ask the user to open the gate, then retry.")


# --------------------------------------------------------------------------
# 4. window engine
# --------------------------------------------------------------------------
def addon_mechanisms():
    return [m for m in MECHANISMS if m["addons"]]


def actual_states():
    """Live truth: for every add-on-backed mechanism, is any add-on running."""
    out = {}
    for m in addon_mechanisms():
        states = {slug: addon_state(slug) for slug in m["addons"]}
        out[m["key"]] = {"running": any(s == "started" for s in states.values()), "addons": states}
    with STATE_LOCK:
        open_ = STATE["mode"] == "open"
        out["ha_write"] = {"running": open_ and STATE["desired"].get("ha_write", False)}
        out["commands"] = {"running": open_ and STATE["desired"].get("commands", False)}
    return out


def compute_deviation(actual):
    """Locked but an editing add-on is running -> deviation (security issue).
    Open but an enabled mechanism is stopped -> informational only."""
    with STATE_LOCK:
        locked = STATE["mode"] != "open"
        desired = dict(STATE["desired"])
    dev = []
    for m in addon_mechanisms():
        a = actual.get(m["key"], {})
        if locked and a.get("running"):
            dev.append(m["key"])
        elif not locked and not desired.get(m["key"]) and a.get("running"):
            dev.append(m["key"])
    return dev


def apply_addons(open_):
    with STATE_LOCK:
        desired = dict(STATE["desired"])
    jobs = []
    for m in addon_mechanisms():
        want = open_ and desired.get(m["key"], False)
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


def open_window(minutes, source="dashboard"):
    """minutes == 0 means 'until I close'."""
    with STATE_LOCK:
        if STATE["mode"] == "opening":
            log("open requested while an open is already in progress; ignored")
            return
        if STATE["mode"] == "open":
            # Already open: treat as extension to the requested length from now.
            STATE["window_end"] = iso(now_utc() + timedelta(minutes=minutes)) if minutes else None
            save_state()
            log(f"window re-timed: {STATE['window_end']}")
            publish_all()
            return
        STATE["mode"] = "opening"
        STATE["window_id"] = uuid.uuid4().hex[:8]
        STATE["opened_at"] = iso(now_utc())
        STATE["window_end"] = iso(now_utc() + timedelta(minutes=minutes)) if minutes else None
        STATE["last_reminder"] = STATE["opened_at"]
        STATE["deviation_since"] = None
        STATE["deviation_notified"] = False
        wid = STATE["window_id"]
        save_state()
    publish_all()
    backup = None
    need, why = backup_needed(minutes)
    log(f"backup before opening: {'yes' if need else 'skipped'} ({why})")
    if need:
        backup = create_full_backup(f"agent_gate_{datetime.now().strftime('%Y%m%d_%H%M')}")
        if not backup:
            notify("Agent Gate", "Backup failed. The window was NOT opened.", tag="agent_gate_window")
            with STATE_LOCK:
                STATE["mode"] = "locked"
                save_state()
            publish_all()
            return
    with STATE_LOCK:
        STATE["mode"] = "open"
        STATE["backup"] = backup
        save_state()
    apply_addons(True)
    _append_jsonl(HISTORY_PATH, {"event": "open", "window_id": wid, "ts": iso(now_utc()),
                                 "minutes": minutes, "source": source, "backup": backup,
                                 "desired": STATE["desired"]})
    with STATE_LOCK:
        end = STATE["window_end"]
    notify("Agent Gate OPEN", f"Window open until {fmt_local(end) if end else 'you close it'}.",
           actions=[{"action": "AGENT_GATE_LOCK", "title": "Lock now"},
                    {"action": "AGENT_GATE_EXTEND_60", "title": "+1 hour"}],
           tag="agent_gate_window")
    publish_all()
    log("window OPEN")


def extend_window(minutes):
    with STATE_LOCK:
        if STATE["mode"] != "open":
            return
        base = parse_iso(STATE["window_end"]) or now_utc()
        if base < now_utc():
            base = now_utc()
        STATE["window_end"] = iso(base + timedelta(minutes=minutes))
        save_state()
        end = STATE["window_end"]
    _append_jsonl(HISTORY_PATH, {"event": "extend", "ts": iso(now_utc()), "minutes": minutes})
    publish_all()
    log(f"window extended to {end}")


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


def lock_window(reason="dashboard"):
    with STATE_LOCK:
        was_open = STATE["mode"] in ("open", "opening")
        wid = STATE.get("window_id")
        opened_at = parse_iso(STATE.get("opened_at"))
        STATE["mode"] = "locked"
        STATE["window_end"] = None
        STATE["pending"] = {}
        save_state()
    apply_addons(False)
    publish_all()
    if was_open:
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
        lines = [f"Locked ({reason}). {len(cmds)} command(s) ran."]
        for c in cmds[-15:]:
            lines.append(f"- {c.get('ts', '')[11:16]} rc={c.get('rc')} {c.get('command', '')[:80]}")
        lines.append(f"Changed files: {len(changed)}" + (" (first 20)" if len(changed) > 20 else ""))
        for p in changed[:20]:
            lines.append(f"- {p}")
        notify("Agent Gate LOCKED", "\n".join(lines), tag="agent_gate_window")
    log(f"window LOCKED ({reason})")


def fmt_local(iso_s):
    dt = parse_iso(iso_s)
    if not dt:
        return "?"
    return dt.astimezone().strftime("%H:%M")


def timer_loop():
    """Every 10 s: expiry, reminders, deviation grace, pending-approval expiry."""
    last_actual_pub = 0
    while True:
        try:
            with STATE_LOCK:
                mode = STATE["mode"]
                end = parse_iso(STATE.get("window_end"))
                last_rem = parse_iso(STATE.get("last_reminder"))
            now = now_utc()
            if mode == "open" and end and now >= end:
                lock_window("timer expired")
            elif mode == "open":
                rem_min = int(setting("reminder_minutes") or 0)
                if rem_min and last_rem and now - last_rem >= timedelta(minutes=rem_min):
                    with STATE_LOCK:
                        STATE["last_reminder"] = iso(now)
                        save_state()
                    notify("Agent Gate still OPEN",
                           f"Open until {fmt_local(iso(end)) if end else 'you close it'}.",
                           actions=[{"action": "AGENT_GATE_LOCK", "title": "Lock now"},
                                    {"action": "AGENT_GATE_EXTEND_60", "title": "+1 hour"}],
                           tag="agent_gate_window")
            # pending approvals expire
            with STATE_LOCK:
                tmo = timedelta(minutes=int(OPT.get("approval_timeout_minutes") or 3))
                for pid, p in list(STATE["pending"].items()):
                    if p.get("status") == "pending" and now - parse_iso(p["created"]) > tmo:
                        p["status"] = "expired"
                if STATE["pending"]:
                    save_state()
            # live state + deviation every 30 s
            if time.time() - last_actual_pub >= 30:
                last_actual_pub = time.time()
                actual = actual_states()
                dev = compute_deviation(actual)
                handle_deviation(dev)
                publish_all(actual=actual, deviation=dev)
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
    names = ", ".join(MECH_BY_KEY[k]["name"] for k in dev if k in MECH_BY_KEY)
    if not notified:
        notify("Agent Gate: deviation",
               f"{names} running while the gate says it should be off. "
               f"Stopping in {int(grace.total_seconds() // 60)} min unless you open a window.",
               actions=[{"action": "AGENT_GATE_OPEN_60", "title": "Open 1 hour"},
                        {"action": "AGENT_GATE_LOCK", "title": "Stop it now"}],
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
        end = parse_iso(STATE.get("window_end"))
    if mode == "opening":
        log("startup: previous open was interrupted -> locking")
        lock_window("restart during open")
    elif mode == "open" and end and now_utc() >= end:
        log("startup: window expired while down -> locking")
        lock_window("expired while gate was down")
    elif mode == "locked":
        # Stop anything that should not be running while locked.
        apply_addons(False)


# --------------------------------------------------------------------------
# 5. MQTT entities
# --------------------------------------------------------------------------
MQTT_CLIENT = None
BASE = "agent_gate"
AVAIL_TOPIC = f"{BASE}/availability"
DEVICE = {"identifiers": ["agent_gate"], "name": "Agent Gate",
          "manufacturer": "Local add-on", "model": "Access gate", "sw_version": "0.1.0"}
DURATION_BUTTONS = [("open_5", "Open 5 min", 5), ("open_15", "Open 15 min", 15),
                    ("open_30", "Open 30 min", 30), ("open_60", "Open 1 hour", 60),
                    ("open_180", "Open 3 hours", 180), ("open_unlimited", "Open until I close", 0),
                    ("extend_60", "Add 1 hour", -60), ("lock_now", "Lock now", -1)]


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


def publish_discovery():
    if not MQTT_CLIENT:
        return
    _disc("switch", "master", {"name": "Agent access", "icon": "mdi:shield-lock-open",
                               "state_topic": f"{BASE}/master/state", "command_topic": f"{BASE}/cmd/master"})
    for m in MECHANISMS:
        _disc("switch", f"mech_{m['key']}", {"name": m["name"], "icon": "mdi:toggle-switch",
                                            "state_topic": f"{BASE}/mech/{m['key']}/state",
                                            "command_topic": f"{BASE}/cmd/mech/{m['key']}",
                                            "json_attributes_topic": f"{BASE}/mech/{m['key']}/attributes",
                                            "entity_category": "config"})
    for obj, name, _ in DURATION_BUTTONS:
        _disc("button", obj, {"name": name, "icon": "mdi:timer-outline",
                              "command_topic": f"{BASE}/cmd/button", "payload_press": obj})
    _disc("sensor", "status", {"name": "Gate status", "icon": "mdi:shield-check",
                               "state_topic": f"{BASE}/status/state",
                               "json_attributes_topic": f"{BASE}/status/attributes"})
    _disc("sensor", "window_end", {"name": "Window ends", "device_class": "timestamp",
                                   "state_topic": f"{BASE}/window_end/state"})
    _disc("sensor", "remaining", {"name": "Minutes remaining", "icon": "mdi:timer-sand",
                                  "unit_of_measurement": "min", "state_topic": f"{BASE}/remaining/state"})
    _disc("binary_sensor", "deviation", {"name": "Gate deviation", "device_class": "problem",
                                         "state_topic": f"{BASE}/deviation/state",
                                         "json_attributes_topic": f"{BASE}/deviation/attributes"})
    _disc("select", "backup_mode", {"name": "Backup before opening", "icon": "mdi:backup-restore",
                                    "options": ["always", "if_stale", "never"],
                                    "state_topic": f"{BASE}/setting/backup_mode/state",
                                    "command_topic": f"{BASE}/cmd/setting/backup_mode",
                                    "entity_category": "config"})
    _disc("number", "backup_min_interval_hours", {"name": "Backup max age (hours)", "icon": "mdi:clock-outline",
                                                  "min": 1, "max": 168, "step": 1, "mode": "box",
                                                  "unit_of_measurement": "h",
                                                  "state_topic": f"{BASE}/setting/backup_min_interval_hours/state",
                                                  "command_topic": f"{BASE}/cmd/setting/backup_min_interval_hours",
                                                  "entity_category": "config"})
    _disc("number", "backup_skip_minutes", {"name": "Skip backup for windows up to (min)", "icon": "mdi:timer-off-outline",
                                            "min": 0, "max": 180, "step": 5, "mode": "slider",
                                            "unit_of_measurement": "min",
                                            "state_topic": f"{BASE}/setting/backup_skip_windows_up_to_minutes/state",
                                            "command_topic": f"{BASE}/cmd/setting/backup_skip_windows_up_to_minutes",
                                            "entity_category": "config"})
    _disc("number", "reminder_minutes", {"name": "Reminder every (min)", "icon": "mdi:bell-ring-outline",
                                         "min": 0, "max": 240, "step": 15, "mode": "slider",
                                         "unit_of_measurement": "min",
                                         "state_topic": f"{BASE}/setting/reminder_minutes/state",
                                         "command_topic": f"{BASE}/cmd/setting/reminder_minutes",
                                         "entity_category": "config"})
    _disc("sensor", "pending", {"name": "Pending approvals", "icon": "mdi:account-question",
                                "state_topic": f"{BASE}/pending/state",
                                "json_attributes_topic": f"{BASE}/pending/attributes"})


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
    open_ = st["mode"] == "open"
    opening = st["mode"] == "opening"
    end = parse_iso(st.get("window_end"))
    remaining = max(0, int((end - now_utc()).total_seconds() // 60)) if (open_ and end) else (None if open_ else 0)
    pub = MQTT_CLIENT.publish
    pub(f"{BASE}/master/state", "ON" if (open_ or opening) else "OFF", qos=1, retain=True)
    for m in MECHANISMS:
        a = actual.get(m["key"], {})
        # Switch shows the mechanism's part in the window; attributes carry the live truth.
        pub(f"{BASE}/mech/{m['key']}/state", "ON" if st["desired"].get(m["key"]) else "OFF", qos=1, retain=True)
        pub(f"{BASE}/mech/{m['key']}/attributes",
            json.dumps({"running_now": a.get("running"), "addons": a.get("addons", {}),
                        "in_window": bool(st["desired"].get(m["key"]))}), qos=1, retain=True)
    status = "deviation" if deviation else ("open" if open_ else ("opening" if st["mode"] == "opening" else "locked"))
    pub(f"{BASE}/status/state", status, qos=1, retain=True)
    pub(f"{BASE}/status/attributes", json.dumps({
        "window_id": st.get("window_id"), "opened_at": st.get("opened_at"),
        "window_end": st.get("window_end") or ("until closed" if open_ else None),
        "backup": st.get("backup"), "deviation": deviation,
        "actual": {k: v.get("running") for k, v in actual.items()},
    }), qos=1, retain=True)
    pub(f"{BASE}/window_end/state", st.get("window_end") or "None", qos=1, retain=True)
    pub(f"{BASE}/remaining/state", "unknown" if remaining is None else str(remaining), qos=1, retain=True)
    pub(f"{BASE}/deviation/state", "ON" if deviation else "OFF", qos=1, retain=True)
    pub(f"{BASE}/deviation/attributes", json.dumps({"mechanisms": deviation,
                                                     "since": st.get("deviation_since")}), qos=1, retain=True)
    for key in SETTINGS_KEYS:
        val = setting(key)
        if val is None:
            val = {"backup_mode": "always", "backup_min_interval_hours": 6,
                   "backup_skip_windows_up_to_minutes": 0, "reminder_minutes": 60}[key]
        pub(f"{BASE}/setting/{key}/state", str(val), qos=1, retain=True)
    pend = {k: v for k, v in st.get("pending", {}).items() if v.get("status") == "pending"}
    pub(f"{BASE}/pending/state", str(len(pend)), qos=1, retain=True)
    pub(f"{BASE}/pending/attributes", json.dumps({
        "items": [{"id": k, "command": v["command"][:120], "created": v["created"]} for k, v in pend.items()]
    }, ensure_ascii=False), qos=1, retain=True)


def on_mqtt_message(client, userdata, msg):
    try:
        topic = msg.topic
        payload = msg.payload.decode("utf-8", "replace").strip()
        log(f"mqtt {topic} = {payload}")
        if topic == f"{BASE}/cmd/master":
            if payload.upper() == "ON":
                threading.Thread(target=open_window, args=(int(OPT.get("default_window_minutes") or 30),),
                                 daemon=True).start()
            else:
                threading.Thread(target=lock_window, args=("dashboard",), daemon=True).start()
        elif topic.startswith(f"{BASE}/cmd/mech/"):
            key = topic.rsplit("/", 1)[1]
            if key in MECH_BY_KEY:
                with STATE_LOCK:
                    STATE["desired"][key] = payload.upper() == "ON"
                    open_ = STATE["mode"] == "open"
                    save_state()
                if open_:
                    threading.Thread(target=apply_addons, args=(True,), daemon=True).start()
                publish_all()
        elif topic.startswith(f"{BASE}/cmd/setting/"):
            key = topic.rsplit("/", 1)[1]
            set_setting(key, payload)
            publish_all()
        elif topic == f"{BASE}/cmd/button":
            handle_button(payload)
        elif topic == f"{BASE}/action":
            # forwarded mobile notification actions (see ha/agent_gate_package.yaml)
            handle_action(payload)
    except Exception as e:
        log(f"mqtt message error: {e}")


def handle_button(obj):
    for key, _, minutes in DURATION_BUTTONS:
        if key == obj:
            if minutes == -1:
                threading.Thread(target=lock_window, args=("dashboard",), daemon=True).start()
            elif minutes < 0:
                extend_window(-minutes)
            else:
                threading.Thread(target=open_window, args=(minutes,), daemon=True).start()
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
        threading.Thread(target=lock_window, args=("phone",), daemon=True).start()
    elif action.startswith("AGENT_GATE_EXTEND_"):
        extend_window(int(action.rsplit("_", 1)[1]))
    elif action.startswith("AGENT_GATE_OPEN_"):
        threading.Thread(target=open_window, args=(int(action.rsplit("_", 1)[1]), "phone"),
                         daemon=True).start()
    elif action.startswith("AGENT_GATE_APPROVE_") or action.startswith("AGENT_GATE_REJECT_"):
        pid = action.rsplit("_", 1)[1]
        verdict = "approved" if "APPROVE" in action else "rejected"
        with STATE_LOCK:
            p = STATE["pending"].get(pid)
            if p and p.get("status") == "pending":
                p["status"] = verdict
                save_state()
        log(f"approval {pid}: {verdict}")
        publish_all()


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

    def do_GET(self):
        if self.path == "/healthz":
            self._send_json(200, {"status": "alive", "mode": STATE["mode"]})
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
    if st["mode"] == "open":
        lines.append(f"window ends: {st.get('window_end') or 'when the user closes it'}")
    for m in MECHANISMS:
        a = actual.get(m["key"], {})
        lines.append(f"{m['key']}: in window={'yes' if st['desired'].get(m['key']) else 'no'}, "
                     f"running now={a.get('running')}")
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
    return tool_text(text, rc != 0)


def run_gate_tool(name, args):
    if name == "gate_status":
        return tool_text(gate_status_text())
    if name != "gate_run_command":
        return tool_text(f"unknown gate tool {name}", True)
    with STATE_LOCK:
        open_ = STATE["mode"] == "open" and STATE["desired"].get("commands", False)
    if not open_:
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
        notify("Agent Gate: approve command?", f"[{pid}] {command[:400]}",
               actions=[{"action": f"AGENT_GATE_APPROVE_{pid}", "title": "Approve"},
                        {"action": f"AGENT_GATE_REJECT_{pid}", "title": "Reject"}],
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
    publish_all(actual=actual_states() if SUPERVISOR_TOKEN else {})
    threading.Thread(target=timer_loop, daemon=True).start()
    log("=" * 60)
    log(f"MCP gate endpoint: http://<home-assistant-ip>:{port}{ENDPOINT_PATH}")
    log("Set this as 'MCP server URL' in the Webhook Proxy add-on.")
    log("=" * 60)
    srv = ThreadingServer(("0.0.0.0", port), GateHandler)
    srv.serve_forever()


if __name__ == "__main__":
    main()

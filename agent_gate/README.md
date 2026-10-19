# Agent Gate

A local Home Assistant add-on that puts one switch between an AI agent and
everything it can use to change your system. Locked is the default.

```
Claude  →  Webhook Proxy  →  Agent Gate (:9584)  →  ha-mcp (:9583)
                                   │
                                   ├─ refuses write tools while locked
                                   ├─ gate_run_command (shell inside the gate container,
                                   │   /addons /homeassistant /share mounted)
                                   └─ starts/stops the editing add-ons you list
                                      (SSH, Claude Terminal, VS Code, File editor, AppDaemon ...)
```

Only the dashboard (MQTT entities) or the phone notification buttons open,
extend or close anything. Any tool call whose arguments mention the gate
(`protected_patterns`) is refused even while open, so the agent cannot open
it for itself.

## Mechanisms and windows

A *mechanism* is one access path: `ha_write` (MCP write tools), `commands`
(`gate_run_command`), and one entry per add-on group you list (SSH, Claude
Terminal, file editors, AppDaemon ...). **Each mechanism has its own window**
with its own end time: SSH can be open for an hour while HA writes are open
for three. The big "Open 15 min / 1 hour / 3 hours / until I close" buttons
open every mechanism marked `default_on`; a single mechanism is opened from
its own buttons (or its switch, which uses `default_window_minutes`).

## What happens on the first open

1. Full Supervisor backup according to the backup policy (below); if a backup
   is required and fails, nothing is opened.
2. The add-ons of the opened mechanisms are started (in parallel).
3. The MCP write path and/or `gate_run_command` are enabled.
4. A phone notification listing what is open until when, with "Lock now" and
   "+1 hour" buttons; repeated every `reminder_minutes` while anything is open.

## What happens on close

A mechanism closes from its button, its timer, or "Lock now" (closes all).
Its add-ons are stopped. When a timer closes it you get a one-line
notification. When the **last** open mechanism closes you get the session
summary: commands that ran and files changed under `/addons`,
`/homeassistant`, `/share` since the first open. History goes to
`/data/windows.jsonl`.

## Security scan

`button.agent_gate_scan_now` (also 90 s after every start and every
`scan_interval_hours`) checks: open mechanisms and deviations, editing add-ons
(SSH, terminals, editors, Node-RED, Portainer, Samba ...) that are installed
but not listed in any mechanism, controlled add-ons set to start on boot,
add-ons with protection mode off or host networking, add-ons exposing ports on the host,
an SSH add-on that accepts a password, remote-access tunnels, pending
updates for Core / OS / Supervisor / add-ons, the age of the newest full
backup, long-lived access tokens, and whether the gate's backstop
automations exist. `sensor.agent_gate_scan` is `ok` / `warning` / `critical`
and carries `findings` (severity, title, detail, fix) plus a ready-made
`markdown` report; every scan is appended to `/data/scans.jsonl`. New
critical findings are pushed to the phone. The latest report is also written
to `/share/agent_gate/scan_latest.md` and `.json`, and served on the LAN at
the `report_url` attribute (a page with "Copy to clipboard" and download
buttons; the link is printed in the add-on log).

## Decoys and tamper protection

Two ideas borrowed from endpoint security:

- **Decoys (honeypot).** On start the gate plants files that look like secret
  backups (`canary_files`, default `/homeassistant/secrets_backup.yaml` and
  `/share/agent_gate/credentials.txt`) containing a fake token. No legitimate
  task ever needs them. Any MCP tool call or shell command that mentions a
  decoy path or the fake token is refused, **every mechanism is closed at
  once**, the hit is logged (`/data/canary_hits.jsonl`) and you get a phone
  notification. The scan reports hits of the last 24 h as critical.
- **Tamper protection.** The gate writes a heartbeat every 30 s. On start it
  reports if it was down for more than 2 minutes (nothing enforced the lock
  meanwhile) and if its own options changed while it was down. The scan also
  flags backstop automations that exist but are *disabled*, a switched-off
  Supervisor watchdog, and read-only patterns broad enough to let write tools
  through (`*`, `ha_config_set_*` ...).

## Behaviour monitor

In an open window the gate counts write and delete tool calls per minute.
Plain writes only warn (`anomaly_writes_warn_per_min`, default 60): building
an agent or a dashboard legitimately means many writes. Deletions, removals,
purges, uninstalls, add-on stops and delete-like service calls have no honest
reason to come in bursts, so `anomaly_deletes_lock_per_min` of them (default
5) closes every mechanism and notifies you. In an "until I close" window the
thresholds double. Work over SSH or a terminal is not counted; only calls that
pass through the gate are.

## Secrets never reach the agent

Every tool result and every command output passes through the gate on its way
back. With `redact_secrets` (default on) the gate replaces passwords, tokens,
API keys, bearer/basic headers, JWTs (Home Assistant long-lived tokens),
private keys and credentials in URLs with `[redacted by Agent Gate]`. Keys stay
visible, values do not, so the agent can still read `secrets.yaml` to learn
what exists without learning the values. `redact_patterns` adds your own
regular expressions. Each redaction is counted in the audit log and in
`sensor.agent_gate_security_events`; the scan lists them as a note.

Decoy hits and tamper events of the last 24 h appear on
`sensor.agent_gate_security_events` with a dashboard button
("I reviewed these, clear" = MQTT `agent_gate/action` payload
`AGENT_GATE_CLEAR_HITS`) that acknowledges them.

## Destructive commands

`gate_run_command` holds any command matching `destructive_patterns` and sends
an "Approve / Reject" notification. The agent gets an `approval_id` and must
call again with it after you approve. Unanswered approvals expire after
`approval_timeout_minutes`.

## Deviation

Every 30 s the gate reads the real add-on states from the Supervisor. An
editing add-on running while its mechanism is closed is a deviation: `binary_sensor.agent_gate_deviation` turns on, you get a
notification with "Open 1 hour / Stop it now", and after
`deviation_grace_minutes` the gate stops it.

The HA package in `ha/agent_gate_package.yaml` is the independent backstop:
if the gate itself goes offline, HA stops the editing add-ons and restarts
the gate; if a deviation lasts 10 minutes, HA stops them too.

## Install

1. Copy this folder to `/addons/agent_gate` on the HA host.
2. Settings → Add-ons → Add-on store → ⋮ → Check for updates, then install
   "Agent Gate" from the Local add-ons section.
3. Configuration: set `upstream_mcp_url` to the private URL of the HA MCP
   Server add-on (the Webhook Proxy currently discovers it; it looks like
   `http://<ip>:9583/private_xxxxx`, see the ha-mcp add-on log/config).
   Check the `mechanisms` list matches your add-on slugs.
4. Start the add-on. The log prints the gate's endpoint:
   `http://<ip>:9584/mcp/<token>`.
5. Webhook Proxy add-on → Configuration → "MCP server URL" = that endpoint.
   Restart the proxy.
6. Copy `ha/agent_gate_package.yaml` to `/homeassistant/packages/` (or
   recreate its automations in the UI) and restart HA.
7. On first start the add-on creates an **"Agent Gate" dashboard** in the
   sidebar (standard cards, admin only). Edit it freely; the add-on never
   overwrites an existing dashboard. Set `create_dashboard: false` to skip it.
   The entities appear under the "Agent Gate" MQTT device:
   `switch.agent_gate_master`, `switch.agent_gate_mech_*` (ON = open now),
   `sensor.agent_gate_mech_*_end`, `button.agent_gate_open_*`,
   `button.agent_gate_backup_now`, `sensor.agent_gate_status` (attributes:
   `open_mechanisms`, `open_names`, `soonest_end`, `last_backup_at`),
   `sensor.agent_gate_remaining`, `sensor.agent_gate_open_count`,
   `binary_sensor.agent_gate_deviation`, `sensor.agent_gate_pending`,
   `select.agent_gate_backup_policy`, `switch.agent_gate_backup_skip_short`,
   `number.agent_gate_reminder_minutes`.

### MQTT commands (for your own cards)

Publish to `agent_gate/cmd/open`, `agent_gate/cmd/close` or
`agent_gate/cmd/extend` with a JSON payload: `{"mech": "ssh", "minutes": 60}`.
`mech` is a mechanism key, `all` (every `default_on` mechanism), `open`
(everything currently open, for extend) or keys joined with `+`.
`minutes: 0` means until closed.

Note: the first start locks the system, i.e. it stops every add-on listed
under `mechanisms`.

## Options

- `upstream_mcp_url` (required): ha-mcp private URL.
- `notify_service`: `notify.<this>` for phone notifications (default `notify`).
- `reminder_minutes`: 0 disables reminders.
- `backup_policy`: `always` (full backup before every first open), `every_6h`
  or `daily` (only when the newest full backup the Supervisor knows about,
  from any source, is older than that), or `never`. `backup_skip_short`
  skips the backup for windows of 15 minutes or less. Both are also entities
  (`select.agent_gate_backup_policy`, `switch.agent_gate_backup_skip_short`,
  and `number.agent_gate_reminder_minutes`); a value set on the dashboard
  overrides the option.
- `language`: `en` or `he` for phone notifications.
- `create_dashboard`: create the ready-made dashboard on start (default true).
- `deviation_grace_minutes`, `approval_timeout_minutes`,
  `default_window_minutes` (used by the master switch; the buttons choose
  explicit durations, "Open until I close" has no end).
- `read_tool_patterns`: tool names (glob) that pass while locked. Everything
  else is a write and is refused while locked.
- `protected_patterns`: substrings that mark a call as touching the gate.
- `destructive_patterns`: regexes (case-insensitive) that make a shell command
  require approval.
- `mechanisms`: list of `{key, name, addons[], default_on}`. `ha_write` and
  `commands` are built in.

## Files in /data

`state.json` (per-mechanism windows, session, pending approvals),
`endpoint_token`, `audit.jsonl` (every tool decision), `commands.jsonl`,
`windows.jsonl`.

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

Only the dashboard (MQTT switch / buttons) or the phone notification buttons
open, extend or lock the gate. Any tool call whose arguments mention the
gate (`protected_patterns`) is refused even while open, so the agent cannot
open it for itself.

## What happens on open

1. Full Supervisor backup according to the backup policy (below); if a backup is
   required and fails, the window is not opened.
2. Add-ons of every mechanism whose switch is ON are started.
3. The MCP write path and `gate_run_command` are enabled.
4. A phone notification with "Lock now" and "+1 hour" buttons; repeated every
   `reminder_minutes` while open.

## What happens on lock (button, timer, phone, or gate restart after expiry)

1. Add-ons are stopped, writes refused again.
2. Phone summary: commands that ran in the window and files changed under
   `/addons`, `/homeassistant`, `/share` since the window opened.
3. Window history appended to `/data/windows.jsonl`.

## Destructive commands

`gate_run_command` holds any command matching `destructive_patterns` and sends
an "Approve / Reject" notification. The agent gets an `approval_id` and must
call again with it after you approve. Unanswered approvals expire after
`approval_timeout_minutes`.

## Deviation

Every 30 s the gate reads the real add-on states from the Supervisor. An
editing add-on running while the gate is locked (or while its mechanism is
off) is a deviation: `binary_sensor.agent_gate_deviation` turns on, you get a
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
7. The entities appear under the "Agent Gate" MQTT device:
   `switch.agent_gate_master`, `switch.agent_gate_mech_*`, `button.agent_gate_open_*`,
   `sensor.agent_gate_status`, `sensor.agent_gate_remaining`,
   `binary_sensor.agent_gate_deviation`, `sensor.agent_gate_pending`.

Note: the first start locks the system, i.e. it stops every add-on listed
under `mechanisms`.

## Options

- `upstream_mcp_url` (required): ha-mcp private URL.
- `notify_service`: `notify.<this>` for phone notifications (default `notify`).
- `reminder_minutes`: 0 disables reminders.
- Backup policy: `backup_mode` is `always` (a full backup before every open),
  `if_stale` (only when the newest full backup the Supervisor knows about,
  from any source, is older than `backup_min_interval_hours`), or `never`.
  `backup_skip_windows_up_to_minutes` skips the backup for short windows
  (e.g. 15 means 5 and 15 minute windows open immediately; 0 disables).
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

`state.json` (mode, window, desired mechanisms, pending approvals),
`endpoint_token`, `audit.jsonl` (every tool decision), `commands.jsonl`,
`windows.jsonl`.

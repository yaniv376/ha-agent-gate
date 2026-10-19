# Agent Gate

**One switch between an AI agent and everything it can use to change your
Home Assistant.** Locked by default. You open a timed window from the
dashboard or your phone; the gate backs up, lets the agent work, watches
what it does, and locks again when time is up.

Built for people who let an AI assistant (Claude through the Home Assistant
MCP Server, or any agent using the same path) edit automations, dashboards
and files, and who want to decide *when* that is possible, see what happened,
and have the system defend itself when the agent misbehaves.

```
Agent  →  Webhook Proxy  →  Agent Gate (:9584)  →  Home Assistant MCP Server (:9583)
                                 │
                                 ├─ refuses every write tool while locked
                                 ├─ hides passwords and tokens in every result
                                 ├─ runs shell commands for the agent (with your approval
                                 │   for destructive ones)
                                 ├─ starts and stops the editing add-ons you list
                                 │   (SSH, terminals, VS Code, File editor, AppDaemon ...)
                                 └─ locks itself when the agent trips a decoy or
                                    deletes things in bursts
```

Only you can open, extend or close anything: from the dashboard (MQTT
entities) or the buttons on the phone notification. A tool call that mentions
the gate itself is refused even in an open window, so the agent can never
open the gate for itself or change its settings.

---

## Contents

1. [What you get](#what-you-get)
2. [Install](#install)
3. [Daily use](#daily-use)
4. [The seven protections](#the-seven-protections)
5. [Entities](#entities)
6. [Options](#options)
7. [What the gate does not protect](#what-the-gate-does-not-protect)
8. [FAQ](#faq)
9. [Files](#files)

---

## What you get

- **Timed windows per mechanism.** A *mechanism* is one access path: HA
  writes through MCP, shell commands, and one entry per group of editing
  add-ons. Each has its own window with its own end time.
- **Backup before the first open**, according to a policy you choose
  (always / only if the newest backup is older than 6 h or a day / never,
  and optionally skipped for windows of 15 minutes or less).
- **Phone notifications** with buttons: open for an hour, add an hour, lock
  now, approve or reject a command. Reminders while something is open. A
  session summary on close: commands that ran, files that changed.
- **A ready-made dashboard** created on first start (you can edit it, the
  add-on never overwrites it), and MQTT entities for your own cards.
- **A security scan** of the whole system: unprotected add-ons, exposed
  ports, tunnels, SSH with a password, pending updates, old backups,
  long-lived tokens, editing add-ons outside the gate, add-ons that start on
  boot before the gate can lock them, and the gate's own health. Runs on a
  schedule, on demand, and 90 s after every start. The last five reports are
  kept.
- **Defences** borrowed from endpoint security: decoy files, a behaviour
  monitor, secret redaction, tamper protection, deviation control and an
  independent backstop inside Home Assistant.

---

## Install

Requirements: Home Assistant OS or Supervised, the Mosquitto broker add-on
(the dashboard entities are MQTT), the
[Home Assistant MCP Server](https://github.com/homeassistant-ai/ha-mcp)
add-on, and its Webhook Proxy add-on (or any proxy that forwards your agent
to one URL). A phone with the Companion app for the notification buttons.

1. **Add the repository.** Settings → Add-ons → Add-on store → ⋮ →
   Repositories → paste `https://github.com/yaniv376/ha-agent-gate`, then
   install **Agent Gate**.
2. **Configuration tab.**
   - `upstream_mcp_url`: the private URL of the MCP Server add-on. It looks
     like `http://<ip>:9583/private_xxxxx` and is printed in that add-on's
     log and shown in the Webhook Proxy's configuration.
   - `notify_service`: your phone, e.g. `mobile_app_my_phone`.
   - `mechanisms`: check the add-on slugs match what you have installed
     (Settings → Add-ons → an add-on → the slug is in the page URL). Remove
     entries you do not have.
   - `language`: `en` or `he`.
3. **Start the add-on.** The log prints the gate's endpoint:
   `http://<ip>:9584/mcp/<token>`. On this first start the gate **locks**:
   every add-on listed under `mechanisms` is stopped.
4. **Point the proxy at the gate.** Webhook Proxy add-on → Configuration →
   "MCP server URL" = that endpoint. Restart the proxy. From now on every
   tool call of your agent passes through the gate.
5. **Install the backstop.** Copy `ha/agent_gate_package.yaml` from this
   repository to `/homeassistant/packages/agent_gate.yaml` (packages must be
   enabled in `configuration.yaml`:
   `homeassistant: packages: !include_dir_named packages`), edit the add-on
   slugs inside to match your `mechanisms`, and restart Home Assistant. It
   relays the phone buttons to the gate and, independently of the gate's
   code, stops the editing add-ons and restarts the gate if the gate goes
   offline. The scan warns while it is missing or disabled.
6. **Turn off "Start on boot"** for every add-on listed under `mechanisms`
   (add-on → Info). Otherwise a reboot starts them before the gate can lock
   them. The scan reminds you.
7. Open the **Agent Gate** dashboard in the sidebar, or add the entities to
   your own dashboard (see [Entities](#entities)). The dashboard uses only
   core Home Assistant cards, follows the add-on's `language`, and is one
   phone-first column: status and *Lock now* on top, then the mechanisms,
   the scan, settings and shortcuts, and the open-all buttons at the bottom.
   Each mechanism, the settings, and the scan history open as sub-views with
   a back button. The add-on creates it once and never overwrites your
   edits; *Rebuild this dashboard* (under settings) resets it to the current
   layout, for example after an update that added cards.

---

## Daily use

**Opening.** Press *15 min*, *1 hour*, *3 hours* or *Until I close* to open
every mechanism marked `default_on`, or open one mechanism from its own
buttons. Then:

1. The gate checks the newest full backup and, if the policy says so, makes
   one (about a minute and a half). If a required backup fails, nothing opens.
2. The add-ons of the opened mechanisms start.
3. Write tools and shell commands are allowed.
4. Your phone gets "Agent Gate OPEN ... until ..." with *Lock now* and
   *+1 hour*; a reminder repeats every `reminder_minutes`.

**While open.** The agent works. Shell commands that match
`destructive_patterns` (rm, mv, docker, reboot ...) are held: the agent gets
an `approval_id` and you get "Approve command?" on the phone and on the
dashboard. Unanswered approvals expire after `approval_timeout_minutes`.

**Closing.** A mechanism closes from its button, its timer, *Lock now*, or
on its own when a defence fires. Its add-ons stop. When the last mechanism
closes you get the session summary. Everything is appended to
`/data/windows.jsonl`.

**The score.** Every scan ends in a security score: 100 minus 25 per critical
finding, 10 per warning and 3 per note, never below 0 (`sensor.agent_gate_security_score`,
with the deductions as attributes; 90 and up is good, 70 to 89 fair). The
ready-made dashboard shows it as a gauge with a 7-day trend.

**One-tap fixes.** Findings the gate can repair for you come with a *Fix*
button on the dashboard (each asks for confirmation): turn off start-on-boot
for the controlled add-ons, uninstall editing add-ons outside the gate,
update add-ons (with a backup), enable the backstop automations, turn on the
gate's watchdog. `binary_sensor.agent_gate_fix_<kind>` is `on` while a fix is
available; MQTT `agent_gate/cmd/fix` with the kind as payload runs it. The
gate never applies a fix on its own, and findings that need you (exposed
ports, host networking, tokens, Core updates) keep their explanation only.

**Scanning.** *Scan now* on the dashboard, or on the schedule in
`scan_interval_hours`. The report is on `sensor.agent_gate_scan`, in
`/share/agent_gate/scan_latest.md`, and on a LAN page with copy and
download buttons (`report_url` attribute, also printed in the log). The last
five scans are on `sensor.agent_gate_scan_h1` ... `h5`.

---

## The seven protections

### 1. The lock

While locked, every MCP tool that is not in `read_tool_patterns` is refused
with a message telling the agent to ask you. Shell commands are refused.
Editing add-ons are stopped. Nothing the agent says changes that.

### 2. Protected patterns

Any tool call whose name or arguments mention `agent_gate` (or whatever you
put in `protected_patterns`) is refused even in an open window. The agent can
read the gate's entities but cannot switch them, change the add-on's options,
restart it or edit its files. The dashboard tools in `protected_exempt_tools`
are the exception, so the agent can still build cards that show the gate.

### 3. Decoys (honeypot)

On start the gate plants files that look like secret backups:
`/homeassistant/secrets_backup.yaml` and `/share/agent_gate/credentials.txt`
by default (`canary_files`). They hold a fake Home Assistant token and fake
passwords. No legitimate task ever needs them.

Any tool call or shell command that mentions a decoy path or the fake token
is refused, **every mechanism closes at once**, the hit goes to
`/data/canary_hits.jsonl` and to your phone: "Trap tripped, locked". Hits of
the last 24 h are a critical scan finding and appear on the dashboard with an
"I reviewed these, clear" button. Reading counts, not only writing: an agent
that goes looking for secrets is the one you want to catch.

Do not delete the decoys; the gate recreates them. To move them, change
`canary_files`. To switch the trap off, `canary_enabled: false`.

### 4. Secret redaction

Every tool result and every command output passes back through the gate.
Passwords, tokens, API keys, `Bearer`/`Basic` headers, JWTs (Home Assistant
long-lived tokens), private keys and credentials in URLs are replaced with
`[redacted by Agent Gate]` before the agent sees them. Keys stay visible,
values do not: the agent can read `secrets.yaml` to learn what exists without
learning the values. Add your own regular expressions in `redact_patterns`;
`redact_secrets: false` turns it off. Each redaction is counted in the audit
log, on `sensor.agent_gate_security_events` and as a scan note.

### 5. Behaviour monitor

In an open window the gate counts tool calls per minute.

- **Writes only warn.** Building an automation, a dashboard or an agent
  legitimately means many writes. At `anomaly_writes_warn_per_min` (default
  60) you get a notification with a *Lock now* button; nothing closes.
- **Deletions lock.** Remove / delete / purge / uninstall tools, add-on stops
  and delete-like service calls have no honest reason to come in bursts.
  At `anomaly_deletes_lock_per_min` (default 5) every mechanism closes, the
  call is refused, and you are told.
- In an *Until I close* window the thresholds double: that window means you
  are working on something.

Work over SSH or a terminal is not counted; only calls that pass through the
gate are.

### 6. Tamper protection

- The gate writes a heartbeat every 30 s. When it starts, it reports if it
  was down for more than 2 minutes: during that time nothing enforced the
  lock except the backstop automations.
- It keeps a fingerprint of its own options. If a value changed while it
  was down, you are told which keys. Options added or removed by an update
  do not count.
- The scan flags backstop automations that exist but are disabled, a
  switched-off Supervisor watchdog, and `read_tool_patterns` broad enough to
  let write tools through (`*`, `ha_config_set_*` ...).
- Every stop or update exits cleanly, so the Supervisor never has to kill
  the gate.

### 7. Deviation control and the backstop

Every 30 s the gate compares the real add-on states with its windows. An
editing add-on running while its mechanism is closed is a *deviation*:
`binary_sensor.agent_gate_deviation` turns on, you get "Open 1 hour / Stop it
now", and after `deviation_grace_minutes` the gate stops the add-on.

The Home Assistant package (`ha/agent_gate_package.yaml`) is the independent
backstop: if the gate is offline for 3 minutes, Home Assistant stops the
editing add-ons and restarts the gate; a deviation that lasts 10 minutes is
stopped by Home Assistant too. It does not depend on the gate's code.

---

## Entities

All under the MQTT device **Agent Gate**.

Control: `switch.agent_gate_master` (open all / lock), `switch.agent_gate_mech_<key>`
per mechanism (ON = open now; turning it on uses `default_window_minutes`),
`button.agent_gate_open_15` / `_60` / `_180` / `_unlimited`,
`button.agent_gate_extend_60`, `button.agent_gate_lock_now`,
`button.agent_gate_backup_now`, `button.agent_gate_scan_now`.

Settings: `select.agent_gate_backup_policy`, `switch.agent_gate_backup_skip_short`,
`number.agent_gate_reminder_minutes`. A value set here overrides the option.

Status: `sensor.agent_gate_status` (`locked` / `opening` / `open` /
`deviation`; attributes `open_mechanisms`, `open_names`, `soonest_end`,
`last_backup_at`, `phase`, `canary_hits_24h`, `tamper_events_24h`,
`redactions_24h`), `sensor.agent_gate_mech_<key>_end`,
`sensor.agent_gate_remaining`, `sensor.agent_gate_open_count`,
`binary_sensor.agent_gate_deviation`, `sensor.agent_gate_pending` (held
commands, attribute `items`), `sensor.agent_gate_security_events` (decoy
hits + tamper events + anomalies of the last 24 h, with the lists as
attributes), `sensor.agent_gate_scan` and `sensor.agent_gate_scan_h1..h5`.

**MQTT commands for your own cards.** Publish to `agent_gate/cmd/open`,
`agent_gate/cmd/close` or `agent_gate/cmd/extend` with
`{"mech": "ssh", "minutes": 60}`. `mech` is a mechanism key, `all` (every
`default_on` mechanism), `open` (everything currently open, for extend) or
keys joined with `+`. `minutes: 0` means until closed. Publish to
`agent_gate/action` with `AGENT_GATE_LOCK`, `AGENT_GATE_EXTEND_60`,
`AGENT_GATE_OPEN_60`, `AGENT_GATE_APPROVE_<id>` / `AGENT_GATE_APPROVE_LATEST`,
`AGENT_GATE_REJECT_<id>` / `AGENT_GATE_REJECT_ALL`, or
`AGENT_GATE_CLEAR_HITS` (acknowledge the security events).

---

## Options

Connection and notifications
- `upstream_mcp_url` (required): the MCP Server's private URL.
- `notify_service`: `mobile_app_<phone>`; `notify` sends to everyone.
- `language`: `en` or `he`. Notifications, scan reports and the ready-made
  dashboard follow it.
- `reminder_minutes` (60): reminder while something is open; 0 disables.
- `create_dashboard` (true): create the Agent Gate dashboard if missing.

Windows and backups
- `mechanisms`: list of `{key, name, default_on, addons[]}`. `ha_write` and
  `commands` are built in. `default_on` says whether the big open buttons
  include the mechanism.
- `default_window_minutes` (30): used when a switch is turned on without a
  duration.
- `backup_policy` (`always`): `always`, `every_6h`, `daily` or `never`;
  `backup_skip_short` (false): no backup for windows of 15 minutes or less.
- `deviation_grace_minutes` (5): how long an add-on may run without a window.
- `approval_timeout_minutes` (3): how long a held command waits for you.

Policy
- `read_tool_patterns`: glob patterns of tools that pass while locked.
  Everything else is a write.
- `protected_patterns` (`agent_gate`): substrings that mark a call as
  touching the gate; `protected_exempt_tools`: write tools allowed to
  mention it (dashboards, labels, categories).
- `destructive_patterns`: regular expressions (case-insensitive) that make a
  shell command need your approval.

Defences
- `canary_enabled` (true), `canary_files`: the decoys.
- `redact_secrets` (true), `redact_patterns`: secret redaction.
- `anomaly_enabled` (true), `anomaly_writes_warn_per_min` (60),
  `anomaly_deletes_lock_per_min` (5): the behaviour monitor; 0 disables a
  threshold.
- `scan_interval_hours` (24): scheduled scan; 0 = only on demand.

---

## What the gate does not protect

- **Paths that bypass it.** The gate sees only what passes through it: the
  MCP tools and its own shell tool. A person (or an agent) logged in over SSH
  or a terminal is not watched, which is why those add-ons are stopped while
  locked. The Home Assistant OS debug SSH on port 22222 and direct access to
  the SD card or disk are outside its reach; the scan does not see them
  either.
- **Reads while locked.** Read tools are always allowed, so the agent can
  look at your configuration (with secrets redacted) at any time. That is
  deliberate: it is what makes the agent useful between windows.
- **The agent's own judgement.** Inside an open window a write that is wrong
  but not destructive goes through. Backups, the session summary and the
  audit log are there for that case.
- **You.** Whoever can open the dashboard or receives the phone
  notifications controls the gate. Keep Home Assistant's own login and
  remote access secure; the scan helps with that.

---

## FAQ

**A file called `secrets_backup.yaml` appeared in my config folder.**
That is a decoy (protection 3). It holds nothing real. Leave it there; if you
remove it the gate puts it back on the next start or scan.

**I got "Trap tripped, locked" but it was me testing.**
Good: that is the expected behaviour. Open the dashboard, read the event, and
press "I reviewed these, clear". The next scan is clean again.

**The agent says a tool was denied although the window is open.**
Either the call mentioned the gate itself (protected pattern), touched a
decoy, or came inside a burst of deletions. The reason is in the denial text
and in `/data/audit.jsonl`.

**"Approve command?" has no buttons in the Home Assistant notification
drawer.** The buttons are on the phone push notification (Android or iOS
notification shade) and on the dashboard card that appears while a command
is waiting. The drawer entry is only a copy.

**Opening takes a long time.** A full backup is running (about a minute and
a half). Choose `backup_policy: daily` and `backup_skip_short: true` if you
open often; the status shows "checking the last backup" versus "backup
running" so you know which it is.

**Can the agent update or reconfigure the gate?** No. Everything that
mentions `agent_gate` is refused, including the Supervisor tools. Updates
and option changes are yours, in the Home Assistant UI.

**Does the gate interfere with my scheduled backups or Google Drive
Backup?** No. It only makes a backup of its own before the first open, by
the policy you chose, and reads the backup list to decide.

**I build agents and write many files through MCP. Will the monitor lock
me out?** Writes only warn. Only bursts of deletions, removals and stops lock,
and the thresholds are yours to set.

---

## Files

In the add-on's `/data`: `state.json` (windows, session, pending approvals,
security events), `endpoint_token`, `canary_token`, `audit.jsonl` (every tool
decision and redaction), `commands.jsonl`, `windows.jsonl`, `scans.jsonl`,
`scan_history.json`, `canary_hits.jsonl`.

In `/share/agent_gate`: `scan_latest.md`, `scan_latest.json` and the decoy
`credentials.txt`.

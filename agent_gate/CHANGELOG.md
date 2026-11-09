# Changelog

## 0.6.8

- **Multi-select as plain entities.** Every mechanism now also has a
  `switch.agent_gate_select_<key>` (on = selected) and there are buttons
  `button.agent_gate_open_selected_15 / _60 / _180 / _unlimited` and
  `button.agent_gate_select_clear`. A custom dashboard can build the
  "open several" block with `switch.toggle` and `button.press` only, without
  any `mqtt.publish` card action, so it passes the gate's MQTT write filter.
  Like every gate entity, an agent cannot press or toggle them.

## 0.6.7

- **Open several mechanisms in one go.** The dashboard can now select
  mechanisms (`agent_gate/cmd/select` with a key or switch entity id toggles
  one, `clear` empties the selection) and open all selected ones with a
  single duration (`agent_gate/cmd/open` with `{"mech": "selected", ...}`).
  The selection is shown as a `selected` attribute on every mechanism switch
  and on `sensor.agent_gate_status`, is kept in memory only, and is cleared
  once the selected mechanisms open. The ready-made dashboard has a new
  "Open several" block. Selecting never opens anything by itself.

## 0.6.6

- **A lock pressed while the gate is still opening now wins.** Before, a lock
  that arrived during the backup before opening was forgotten and the whole
  window opened when the backup finished. A lock that arrived while slow
  add-ons (Studio Code Server takes about 25 s) were still starting skipped
  them, because they were not "started" yet; they came up a few seconds later
  with no window and showed as a deviation. Every close now bumps a counter
  that the open checks before and after starting add-ons: if a close came in,
  nothing opens, add-ons that started anyway are stopped again, and no "open"
  notification is sent.
- **Stopping an add-on that is still starting now works.** The Supervisor
  refuses a second job ("Another job is running") while a start runs. Start
  and stop now wait for that job and retry for up to 90 s, and add-ons in the
  `startup` state count as running when the gate locks or enforces a
  deviation.

## 0.6.5

- **A script can no longer send the gate a command (protection 2).** The gate
  takes its commands on MQTT (`agent_gate/cmd/...`, `agent_gate/action`). With
  HA write open, an agent could create a script that builds that topic at run
  time (`'agent' ~ '_gate/cmd/open'`), which the text match never sees, and
  use it to open the commands mechanism, approve its own held commands or
  change the gate's settings. Write calls are now refused when they combine
  MQTT with a Jinja template or a YAML tag, publish to the MQTT discovery
  prefix (whose `~` abbreviation can spell the topic), or fire
  `mobile_app_notification_action`. `\u` and `\x` escapes inside strings are
  decoded before every protected match.
- **No camera pictures while locked.** `ha_get_camera_image` matched the
  `ha_get_*` read pattern, so it worked with the gate locked. New option
  `read_tool_exclude` (default `ha_get_camera_image`) lists read tools that
  still need HA write open.
- **Report files can no longer be redirected by swapping a folder.**
  `gate_agent_files` resolved the path once and then opened it by name. While
  the commands mechanism was open, the shell could replace a folder with a
  link in between, and the gate (root with every capability) would read or
  write through it, for example into its own `state.json`. Files are now
  opened one folder at a time with `O_NOFOLLOW`, and only regular files are
  read or written.
- **Approvals show the whole command.** A held command must be at most 400
  characters (the phone used to show only the first 400) and may not contain
  invisible or direction-control characters. The dashboard's approve button
  acts only when exactly one command waits, and approve-all is gone; reject-all
  still works.

## 0.6.4

- **The shell can no longer read stored credentials (protection 9).** The
  sandboxed shell runs as root without CAP_DAC_OVERRIDE, so it could still open
  every root-owned file, including `.storage` (where Home Assistant keeps its
  MQTT login), `secrets.yaml`, the MCP proxy secrets and Zigbee2MQTT's
  configuration. With an MQTT login, a command could send `cmd/open` to the
  gate and open more mechanisms by itself. Before every command the gate now
  gives the paths in `shell_hidden_paths` to its private uid with mode
  0600/0700: the shell gets "permission denied", while Home Assistant,
  Zigbee2MQTT and the editor add-ons, which run with that capability, read and
  write them as before. A folder is protected as a whole, including new files.
  Turn off with `shell_hide_secrets: false`.
- Note: a Mosquitto ACL alone does not protect the gate topics on the official
  Mosquitto add-on, because its auth plugin allows every topic before the ACL
  file is consulted.

## 0.6.3

- **New mechanism: Report files (`reports`).** A scheduled job that only needs
  to read data and save a report no longer has to open the full shell. The new
  tool `gate_agent_files` lists, reads and writes files without a shell:
  reading inside `agent_files_read_dirs`, writing (replace or append) only
  inside `agent_files_write_dirs`, only text report types (.html .md .txt
  .json .jsonl .csv), no delete, move or rename, symlinks resolved, secret-like
  names (.env, token, secret, password, key files, .storage) refused, output
  redacted. It works while `reports` or `commands` is open. Use it for
  automations that open the gate on a schedule: `{"mech": "reports"}` instead
  of `{"mech": "commands"}`. An unattended shell window can read Home
  Assistant's stored credentials and use them to open more of the gate; a
  `reports` window cannot.

## 0.6.2

- **Commands accept the mechanism's switch entity id.** `cmd/open`, `cmd/close`
  and `cmd/extend` take `{"mech": "switch.agent_gate_mech_ssh"}` as well as
  `{"mech": "ssh"}`. A custom dashboard can now list every mechanism with
  auto-entities and build its buttons from `this.entity_id`, so a mechanism the
  scan adds shows up there without editing the dashboard.

## 0.6.1

- **The MCP server's private path is hidden from the agent.** The gate's own
  log printed the upstream URL with its private path, and the agent can read
  add-on logs. That path is the only thing protecting the MCP server, which
  listens on the LAN and sits *behind* the gate: with it, the gate can be
  bypassed. The log now prints the upstream without the path, and the path,
  the gate's endpoint token and the report token are redacted from every tool
  result (add-on logs, options, files).
- **New scan finding** when the MCP server add-on is reachable on the network
  (host network or a published port): explains what that means and what to
  keep private.

## 0.6.0

Security release. Thanks to Matt Abate (@mattabate) for reading the code and
reporting the first two items.

- **Sandboxed shell (protection 8).** `gate_run_command` used to run with the
  gate's environment, including the Supervisor token, and as a root that
  could read and change the gate's own files. Commands now start through
  `sandbox.py`: clean environment, every capability dropped, `no_new_privs`;
  the gate is non-dumpable and `/data` plus the image belong to a private uid.
  A command can still edit `/homeassistant`, `/addons` and `/share` as
  before, but it cannot read the token, the gate's state or its code.
- **Protected-pattern check hardened.** The match also runs with quotes,
  backslashes and whitespace removed, and a `hassio.*` service call with a
  Jinja template in its arguments is refused. The docs now say plainly that
  this is a text match and what it is for.
- **`anomaly_*_per_min: 0` now disables that threshold** as documented
  (issue #1): the options were read with an `or default` that turned 0 back
  into the default.
- **`SIGINT` is ignored** (pid 1 ignores unhandled signals; only `SIGTERM`
  from the Supervisor stops the gate), and `pkill` / `killall` join the held
  commands.
- **Docs: "What the gate does not protect"** rewritten with the honest
  picture: what an open window hands over, the limits of the held-command
  list, and what a stop of the gate does and does not achieve.

## 0.5.10

- **One tap approves and runs**: when a destructive command is held, the call now
  waits for your answer (`approval_wait_seconds`, default 45, 0 = old behaviour).
  Approve on the phone notification or the dashboard and the command runs and its
  output comes back in the same call, so the agent no longer has to call again
  with the approval id. Reject (or no answer in time) ends the call with a clear
  message; after the wait the old "held, call again with approval_id" reply
  still works.

## 0.5.9

- **Open at once, backup alongside**: new setting *Open at once, backup runs
  alongside* (`switch.agent_gate_backup_parallel`, option `backup_parallel`,
  off by default). When a backup is due, the windows open immediately and the
  full backup runs in parallel instead of the gate waiting about a minute and a
  half. The status shows "backup running alongside". If that backup fails, the
  window stays open and you get a notification that there is no restore point
  from this opening. Anything the agent writes in the first minutes may only be
  partly inside that backup; leave the setting off if you want a restore point
  that is guaranteed to exist before the first write.

## 0.5.8

- **Approval history is split and numbered**: three views (*All*, *Commands*,
  *Gate*) with filter buttons on top. Every line has a number (C1, C2... for
  commands, G1, G2... for opening, extending and locking), counted from the
  start of the log so a number keeps pointing at the same line. The sensor
  `sensor.agent_gate_history` now publishes `cmds` and `gate` (add-on language)
  plus `he_cmds` and `he_gate` (Hebrew) as attributes.

## 0.5.7

- **Approval history**: a new *Approval history* page (button under
  *Settings and shortcuts*, `sensor.agent_gate_history`) lists every command you
  approved, rejected or left unanswered, described in plain words (for example
  "Delete files (/config/www/old)") with the exact command underneath and
  whether it ran fine. Below it, the access windows you opened, extended or
  locked, with how many commands ran and how many files changed.

## 0.5.6

- **Setup checklist**: a *Setup* sub-view (and a red *Setup not finished*
  card on top while steps are missing) checks on every scan that Mosquitto,
  the ha-mcp repository, the MCP Server and the Webhook Proxy are installed
  and running, that the gate has its upstream URL, that the proxy points at
  the gate, that the backstop automations are on and that the controlled
  add-ons do not start on boot. Each missing step links to the page where it
  is done (my.home-assistant.io links for the add-on store).
- **One-tap backstop install**: the gate writes the backstop package itself,
  generated for your add-on slugs and notify service, and reloads
  automations (`install_package` fix). No more copying YAML.
- New sensor `sensor.agent_gate_setup` (steps left; `items` attribute).

## 0.5.5

- A new window end shows on the dashboard immediately; before, it waited
  until the add-ons of every mechanism had been started or checked.

## 0.5.4

- Every dashboard button now gives feedback where you are looking: the
  "Open all" row shows the opening phase and the next close under the
  buttons; "Scan now" says when it was ignored by the one-minute cooldown;
  fix buttons show "Applying the fix..."; "Check updates" reloads the store
  and reports "Checked 19:31: 0.5.4 is the latest version" (or the version
  available); "Backup now" shows the running backup and the last backup time.
- New action `AGENT_GATE_CHECK_UPDATES` on `agent_gate/action`.

## 0.5.3

- Dashboard: the security-events card rendered empty after an options-change
  tamper event (Jinja read `e.keys` as a method); fixed in both languages.
- Mechanism tiles show "until 15:26" so the time is never cut off.

## 0.5.2

- Ready-made dashboard (English): shorter labels so nothing is cut off on
  a phone ("Backup policy", "Check updates", "Rebuild dashboard" full width),
  and the window end on mechanism tiles now reads "until 15:26 (10 min)".

## 0.5.1
- Dashboard: compact one-row tiles instead of tall button cards; mechanism tiles show "closes in N min (HH:MM)" (new `ends` attribute on the mechanism switches); built-in mechanism names follow the language (HA write / Commands).

## 0.5.0
- Ready-made dashboard rebuilt: core cards only, phone-first single column (status and Lock now on top, mechanisms, scan with score and one-tap fixes, settings and shortcuts incl. check/update the gate, open-all buttons at the bottom), sub-views per mechanism, for settings and for the scan history, in the add-on's language. `AGENT_GATE_REBUILD_DASHBOARD` action (button under settings) resets an existing dashboard to the current layout.

## 0.4.8
- An add-on still stopping within 90 s of a close is no longer reported as a deviation (the status flashed "Deviation!" right after Lock now).

## 0.4.7
- One-tap fixes: boot off for controlled add-ons, uninstall uncontrolled editing add-ons, update add-ons with a backup, enable the backstop automations, watchdog on. `binary_sensor.agent_gate_fix_<kind>`, MQTT `agent_gate/cmd/fix`, buttons on the ready-made dashboard.

## 0.4.6
- The report page refreshes its text when reopened and every 30 s, so a cached tab never shows an old scan.

## 0.4.5
- Security score (100 minus 25/10/3 per critical/warning/note) on `sensor.agent_gate_security_score`, in the report, in the scan history, and as a gauge with a 7-day trend on the ready-made dashboard.

## 0.4.4
- Tamper check ignores options added or removed by an update; only changed values of existing keys count.

## 0.4.3
- Behaviour monitor: many writes per minute warn (with a Lock now button); a burst of deletions, removals, stops or uninstalls locks every mechanism. Thresholds double in an "until I close" window.

## 0.4.2
- Secret redaction: passwords, tokens, API keys, bearer/basic headers, JWTs, private keys and URL credentials are hidden in tool results and command output.
- `sensor.agent_gate_security_events` with the decoy hits, tamper events and redaction count of the last 24 h, and an "I reviewed these, clear" dashboard button (`AGENT_GATE_CLEAR_HITS`).

## 0.4.1
- `phase` attribute on the status sensor (checking the last backup vs. backup running) while opening.

## 0.4.0
- Decoy files (honeypot): any tool call or shell command touching a decoy path or the fake token is refused and locks every mechanism.
- Tamper protection: downtime and option changes reported on start; scan flags disabled backstop automations, watchdog off and over-broad read patterns.

## 0.3.9
- Config map in the current object form (`local_apps`).

## 0.3.8
- Clean shutdown on SIGTERM (the gate runs as PID 1); no more exit code 137 on stop or update.

## 0.3.7
- Approve or reject held commands from the dashboard (`AGENT_GATE_APPROVE_LATEST`, `AGENT_GATE_REJECT_ALL`); the persistent notification says where the buttons are.

## 0.3.6
- Scan flags editing add-ons installed but outside any mechanism, and controlled add-ons set to start on boot.

## 0.3.5
- Manual scans within a minute of the previous one are ignored.

## 0.3.4
- `scanning` state published while a scan runs, for dashboard feedback.

## 0.3.3
- Mechanism options listed as key, name, default_on, addons.

## 0.3.2
- Last five scan reports kept and published as `sensor.agent_gate_scan_h1..h5`.

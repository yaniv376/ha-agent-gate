# Changelog

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

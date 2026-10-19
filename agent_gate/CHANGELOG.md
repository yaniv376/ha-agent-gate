# Changelog

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

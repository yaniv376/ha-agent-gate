# Changelog

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

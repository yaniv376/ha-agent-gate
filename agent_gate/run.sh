#!/usr/bin/env sh
# Agent Gate runner. The gate is a long-running service; if it exits the
# Supervisor watchdog restarts it, and on every start the gate re-evaluates
# the lock (an expired window is closed before the MCP listener opens).

echo "[agent_gate] Starting..."
exec python3 /app/gate.py

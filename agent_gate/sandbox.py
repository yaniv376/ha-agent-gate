"""Launcher for gate_run_command: drop every capability, then run the command.

The gate itself runs as root with the Supervisor token in its environment.
Commands the agent runs must not inherit that power, so they are started
through this file: it clears the ambient set, drops every capability from the
bounding set, turns on no_new_privs (no way back through setuid binaries) and
only then execs the shell. The uid stays 0, which is what lets the agent edit
the root-owned files in /homeassistant, /addons and /share; but without
CAP_DAC_OVERRIDE it cannot open anything owned by the gate's private uid
(/data, /app and the rest of the image), and without CAP_SYS_PTRACE it cannot
read the gate's /proc/1/environ or memory (the gate is non-dumpable).
"""
import ctypes
import os
import sys

PR_CAPBSET_DROP, PR_SET_NO_NEW_PRIVS, PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL = 24, 38, 47, 4


def main():
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
    for cap in range(64):
        if libc.prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0:
            break
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        sys.stderr.write("sandbox: cannot set no_new_privs\n")
        sys.exit(126)
    # Verify before handing over: an empty bounding set is the whole point.
    try:
        with open("/proc/self/status", encoding="utf-8") as f:
            st = f.read()
        bnd = [l for l in st.splitlines() if l.startswith("CapBnd:")][0].split()[1]
        if int(bnd, 16) != 0:
            sys.stderr.write("sandbox: capabilities still present, refusing to run\n")
            sys.exit(126)
    except (OSError, IndexError, ValueError):
        pass
    args = sys.argv[1:]
    if not args:
        sys.exit(126)
    os.execvp(args[0], args)


if __name__ == "__main__":
    main()

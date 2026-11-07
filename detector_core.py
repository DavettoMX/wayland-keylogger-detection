#!/usr/bin/env python3
"""
Keylogger detector — deterministic heuristic core (NO LLM).

Scans running processes for runtime signals of a keylogger, focusing on the
strongest tell on Linux: a non-privileged-service process holding an open file
descriptor to /dev/input/event*. Pure /proc inspection, no code execution of
the target.

Permissions: to read /proc/<pid>/fd of processes owned by other users (e.g. a
keylogger started with sudo), run this scanner as root too.

Output: a list of findings (dicts). Use detector_agent.py to get an LLM-written
verdict on top of these facts.
"""

import os
import re
from pathlib import Path

INPUT_DEV_RE = re.compile(r"^/dev/input/event\d+$")

# Module artifacts that reveal keyboard-capture libraries in a process map.
LIB_SIGNS = (
    ("evdev", re.compile(r"/evdev/.*\.so|_input\.[^/]*\.so")),
    ("pynput", re.compile(r"/pynput/")),
    ("Xlib", re.compile(r"/Xlib/")),
)

# Weak, easily-renamed hint in the command line. 'keyboard' alone is too common
# (gsd-keyboard etc.), so only the distinctive tokens.
CMDLINE_HINT_RE = re.compile(r"keylog|keystroke", re.IGNORECASE)

# Legitimate input consumers: display servers / compositors / input daemons.
# These are EXPECTED to hold /dev/input fds, so they are not keyloggers.
# Matched against the resolved executable path (/proc/<pid>/exe).
INPUT_CONSUMER_ALLOWLIST = (
    "/usr/bin/gnome-shell",
    "/usr/bin/Xorg",
    "/usr/bin/Xwayland",
    "/usr/bin/kwin_wayland",
    "/usr/bin/sway",
    "/usr/bin/weston",
    "/usr/libexec/gsd-",          # GNOME settings daemons (prefix)
    "/usr/lib/systemd/systemd",   # logind seat management
    "/usr/bin/libinput",
)

# Common script interpreters — a keylogger is usually one of these running a
# user-owned script, unlike a compiled system service.
INTERPRETER_RE = re.compile(r"/(python[0-9.]*|perl|ruby|node|bash|sh)$")


def _read(path):
    try:
        return Path(path).read_text(errors="replace")
    except (OSError, PermissionError):
        return ""


def _read_bytes(path):
    try:
        return Path(path).read_bytes()
    except (OSError, PermissionError):
        return b""


def iter_pids():
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            yield int(entry)


def process_fds(pid):
    """Return list of (fd_num, target_path) for a pid's open descriptors."""
    out = []
    fd_dir = f"/proc/{pid}/fd"
    try:
        fds = os.listdir(fd_dir)
    except (OSError, PermissionError):
        return out  # not ours / vanished — caller may flag unreadable
    for fd in fds:
        try:
            target = os.readlink(f"{fd_dir}/{fd}")
        except OSError:
            continue
        out.append((fd, target))
    return out


def fd_readable(pid):
    """True if we can list the pid's fd dir (False usually means owned by root)."""
    try:
        os.listdir(f"/proc/{pid}/fd")
        return True
    except (OSError, PermissionError):
        return False


def cmdline(pid):
    raw = _read_bytes(f"/proc/{pid}/cmdline")
    return raw.replace(b"\x00", b" ").decode(errors="replace").strip()


def exe_path(pid):
    """Resolved executable behind the process, or '' if unreadable."""
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return ""


def is_allowlisted_consumer(exe):
    return any(exe.startswith(p) for p in INPUT_CONSUMER_ALLOWLIST)


def fd_is_writable(pid, fd):
    """Read /proc/<pid>/fdinfo/<fd> and decide if the fd was opened for writing."""
    for line in _read(f"/proc/{pid}/fdinfo/{fd}").splitlines():
        if line.startswith("flags:"):
            try:
                flags = int(line.split()[1], 8)
            except (IndexError, ValueError):
                return False
            # O_WRONLY=1, O_RDWR=2 in the low access-mode bits.
            return (flags & 0o3) in (1, 2)
    return False


def writable_regular_files(pid):
    """Regular files the process has open for writing (candidate log sinks)."""
    out = []
    for fd, target in process_fds(pid):
        if not target.startswith("/"):
            continue
        if target.startswith(("/dev/", "/proc/", "/sys/")):
            continue
        if target.endswith((" (deleted)",)):
            target = target[: -len(" (deleted)")]
        if os.path.isfile(target) and fd_is_writable(pid, fd):
            out.append(target)
    return out


def proc_status(pid):
    info = {}
    for line in _read(f"/proc/{pid}/status").splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            info[k.strip()] = v.strip()
    return info


def analyze_pid(pid, self_pid):
    """Return a finding dict for a pid, or None if nothing noteworthy."""
    if pid == self_pid:
        return None

    reasons = []
    score = 0.0

    cmd = cmdline(pid)
    exe = exe_path(pid)
    maps = _read(f"/proc/{pid}/maps")
    status = proc_status(pid)
    uid = status.get("Uid", "").split("\t")[0] if status.get("Uid") else "?"

    # Signal 1: open fd to /dev/input/event*  (necessary, but not sufficient —
    # the Wayland/X compositor legitimately holds these too).
    input_fds = sorted(
        {t for _, t in process_fds(pid) if INPUT_DEV_RE.match(t)}
    )
    if not input_fds:
        # Without an input-device fd there is no evdev keylogger to see here.
        # Still surface a weak cmdline/library hint, but never as high risk.
        pass
    else:
        # Known-legitimate input consumer (compositor / input daemon): benign.
        if is_allowlisted_consumer(exe):
            return {
                "pid": pid, "uid": uid, "exe": exe,
                "cmdline": cmd or "(unreadable)",
                "input_devices": input_fds,
                "score": 0.0,
                "reasons": [
                    f"holds {len(input_fds)} input-device fd(s) but is a known "
                    f"legitimate input consumer ({exe}) — expected, not a keylogger"
                ],
                "benign": True,
            }

        score += 0.4
        reasons.append(
            f"open fd to input device(s): {', '.join(input_fds)}"
        )

        # Signal: a script interpreter (python/perl/…) holding an input fd is
        # far more keylogger-like than a compiled system service.
        if INTERPRETER_RE.search(exe):
            score += 0.25
            reasons.append(f"input fd held by a script interpreter ({exe})")

        # Signal: running as root while driven by a user-owned script (classic
        # 'sudo python keylogger.py'). Detected via a user-home arg.
        if uid == "0" and "/home/" in cmd:
            score += 0.2
            reasons.append("running as root to execute a user-home script (sudo'd)")

        # Signal: writing to a regular file while capturing input = log sink.
        logs = writable_regular_files(pid)
        if logs:
            score += 0.3
            reasons.append(f"writing to log-like file(s): {', '.join(logs[:5])}")

    # Signal 2: keyboard-capture library mapped into the process.
    for name, rx in LIB_SIGNS:
        if rx.search(maps):
            score += 0.15
            reasons.append(f"keyboard-capture library mapped: {name}")

    # Signal 5 (weak): distinctive cmdline token.
    if CMDLINE_HINT_RE.search(cmd):
        score += 0.1
        reasons.append(f"suspicious cmdline keyword in: {cmd!r}")

    if not reasons:
        return None

    return {
        "pid": pid,
        "uid": uid,
        "exe": exe,
        "cmdline": cmd or "(unreadable)",
        "input_devices": input_fds,
        "score": round(min(score, 1.0), 2),
        "reasons": reasons,
    }


def scan():
    """Scan all processes; return (findings, warnings)."""
    self_pid = os.getpid()
    findings = []
    unreadable = 0
    for pid in iter_pids():
        if not os.path.isdir(f"/proc/{pid}"):
            continue
        if not fd_readable(pid) and os.geteuid() != 0:
            unreadable += 1
        f = analyze_pid(pid, self_pid)
        if f:
            findings.append(f)
    findings.sort(key=lambda d: d["score"], reverse=True)

    warnings = []
    if os.geteuid() != 0 and unreadable:
        warnings.append(
            f"{unreadable} process(es) had unreadable fds (owned by other users). "
            "Re-run with sudo to inspect root-owned processes such as a sudo keylogger."
        )
    return findings, warnings


if __name__ == "__main__":
    import json

    found, warns = scan()
    for w in warns:
        print("WARN:", w)
    print(json.dumps(found, indent=2))

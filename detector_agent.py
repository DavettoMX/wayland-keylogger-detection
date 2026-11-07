#!/usr/bin/env python3
"""
Keylogger detector agent — deterministic scan + local-LLM reasoning.

Architecture:
  detector_core.scan()  -> hard facts (findings JSON)
  local LLM (llama.cpp)  -> reads the facts, writes a reasoned verdict/report

The LLM NEVER decides detection by itself and is NOT trusted to invent facts:
it only explains and classifies the deterministic findings. This keeps the
result reproducible and auditable — the point of the lab.

LLM backend: llama.cpp's OpenAI-compatible server. Start it first, e.g.:

  ~/src/llama.cpp/build/bin/llama-server \
      -m ~/models/Qwen_Qwen3.5-9B-Q4_K_M.gguf \
      --port 8080 -c 4096

Config via env (all optional):
  LLM_BASE_URL   default http://localhost:8080/v1
  LLM_MODEL      default "local"  (llama-server ignores the name)
  LLM_API_KEY    default "sk-no-key"  (llama-server ignores it)

Usage:
  sudo -E .venv/bin/python detector_agent.py            # scan once + LLM report
  sudo .venv/bin/python detector_agent.py --no-llm      # facts only
  sudo -E .venv/bin/python detector_agent.py --watch 3  # rescan every 3s
  sudo .venv/bin/python detector_agent.py --json        # raw findings as JSON

(-E preserves your LLM_* env vars through sudo.)
"""

import os
import sys
import json
import time
import urllib.request
import urllib.error

import detector_core

BASE_URL = os.environ.get("LLM_BASE_URL", "http://localhost:8080/v1")
MODEL = os.environ.get("LLM_MODEL", "local")
API_KEY = os.environ.get("LLM_API_KEY", "sk-no-key")

SYSTEM_PROMPT = (
    "You are a defensive security analyst assistant. You are given DETERMINISTIC "
    "findings from a host scanner that inspected /proc for keylogger behavior. "
    "The findings are ground truth: do not invent processes, PIDs, or signals "
    "not present in them. For each finding, classify the likelihood that it is a "
    "keylogger (none / low / medium / high) and explain which signals drove the "
    "verdict, in plain language. The strongest signal is a user process holding "
    "an open file descriptor to /dev/input/event*. Be concise. If there are no "
    "findings, say the host looks clean for this check."
)


def call_llm(findings, warnings):
    user_content = json.dumps(
        {"findings": findings, "scanner_warnings": warnings}, indent=2
    )
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Scanner output:\n{user_content}"},
        ],
        "temperature": 0.2,
        "stream": False,
    }
    req = urllib.request.Request(
        f"{BASE_URL}/chat/completions",
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {API_KEY}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            body = json.loads(resp.read())
        return body["choices"][0]["message"]["content"].strip()
    except urllib.error.URLError as e:
        return (
            f"[LLM unavailable: {e}]\n"
            f"Start llama-server at {BASE_URL} (see header of this file), "
            "or run with --no-llm to see the raw findings."
        )
    except (KeyError, json.JSONDecodeError) as e:
        return f"[LLM returned an unexpected response: {e}]"


def print_facts(findings, warnings):
    for w in warnings:
        print(f"  \033[33mWARN:\033[0m {w}")
    if not findings:
        print("  No suspicious processes found for this check.")
        return
    for f in findings:
        color = "\033[31m" if f["score"] >= 0.7 else "\033[33m"
        print(f"  {color}PID {f['pid']}\033[0m (uid {f['uid']}, score {f['score']})")
        print(f"    cmd: {f['cmdline']}")
        for r in f["reasons"]:
            print(f"    - {r}")


def run_once(use_llm):
    findings, warnings = detector_core.scan()

    print("=" * 64)
    print(f"  SCAN @ {time.strftime('%Y-%m-%d %H:%M:%S')} — deterministic facts")
    print("=" * 64)
    print_facts(findings, warnings)

    if use_llm:
        print("-" * 64)
        print("  LLM VERDICT")
        print("-" * 64)
        print(call_llm(findings, warnings))
    print()
    return findings


def main():
    args = sys.argv[1:]

    if "--json" in args:
        findings, warnings = detector_core.scan()
        print(json.dumps({"findings": findings, "warnings": warnings}, indent=2))
        return

    use_llm = "--no-llm" not in args

    if "--watch" in args:
        try:
            interval = float(args[args.index("--watch") + 1])
        except (IndexError, ValueError):
            interval = 3.0
        print(f"Watching every {interval}s. Ctrl+C to stop.")
        try:
            while True:
                run_once(use_llm)
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\nStopped.")
    else:
        run_once(use_llm)


if __name__ == "__main__":
    main()

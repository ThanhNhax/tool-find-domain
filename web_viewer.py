#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mini web viewer for domain scan results (Flask) + trigger scan button

- HTML in templates/index.html
- Reads available domains from CSV or JSONL in --out-dir (latest file)
- UI: search + pagination + copy + Scan button
- /scan triggers background scan process (subprocess)
- /api/scan_status returns running status

Behavior fixes:
- If --out-dir does not exist: auto-create (no crash)
- If folder exists but no results files yet: serve empty list + note (no crash)
- Scan defaults LOCKED to 5 domains/request: --tier regular --batch-size 5

Install:
  pip install flask

Run:
  python web_viewer.py --out-dir ./out_dynadot --host 127.0.0.1 --port 8080
Open:
  http://127.0.0.1:8080
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# ----------------------------
# Utilities
# ----------------------------


def _truthy(v: Any) -> bool:
    """
    Treat these as available:
      - True
      - "true", "1"
      - "yes"  (Dynadot REST v2 available=Yes/No)
      - "available"
    """
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    return s in ("true", "1", "yes", "available")


def _find_latest_file(out_dir: Path, exts: Tuple[str, ...]) -> Optional[Path]:
    candidates: List[Path] = []
    for ext in exts:
        candidates.extend(out_dir.glob(f"*{ext}"))
        candidates.extend(out_dir.glob(f"results*{ext}"))
        candidates.extend(out_dir.glob(f"rtb_results*{ext}"))
    candidates = [p for p in candidates if p.is_file()]
    if not candidates:
        return None
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0]


def _detect_source(out_dir: Path) -> Tuple[Optional[str], Optional[Path]]:
    """
    Safe auto-detect: returns (None, None) if no files yet.
    """
    csv_file = _find_latest_file(out_dir, (".csv",))
    jsonl_file = _find_latest_file(out_dir, (".jsonl",))
    if csv_file:
        return ("csv", csv_file)
    if jsonl_file:
        return ("jsonl", jsonl_file)
    return (None, None)


# ----------------------------
# Data cache (reload on change)
# ----------------------------


@dataclass
class Cache:
    out_dir: Path
    source: str
    file_path: Optional[Path] = None
    mtime: float = 0.0
    available_domains: List[str] = None  # type: ignore

    def __post_init__(self) -> None:
        self.available_domains = []

    def _load_csv(self, path: Path) -> List[str]:
        avail: List[str] = []
        with path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                d = (row.get("domain") or "").strip()
                if not d:
                    continue
                if _truthy(row.get("available")):
                    avail.append(d)
        return avail

    def _load_jsonl(self, path: Path) -> List[str]:
        avail: List[str] = []
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                d = str(obj.get("domain", "")).strip()
                if not d:
                    continue
                if _truthy(obj.get("available")):
                    avail.append(d)
        return avail

    def refresh_if_needed(self) -> None:
        # resolve file
        if self.source == "auto":
            src, p = _detect_source(self.out_dir)
            self.file_path = p
            if not src or not p:
                # no files yet -> empty state
                self.available_domains = []
                self.mtime = 0.0
                return
            src_effective = src
        else:
            src_effective = self.source
            if src_effective == "csv":
                self.file_path = _find_latest_file(self.out_dir, (".csv",))
            elif src_effective == "jsonl":
                self.file_path = _find_latest_file(self.out_dir, (".jsonl",))
            else:
                raise ValueError("--source must be auto|csv|jsonl")

        if not self.file_path or not self.file_path.exists():
            self.available_domains = []
            self.mtime = 0.0
            return

        new_mtime = self.file_path.stat().st_mtime
        if new_mtime <= self.mtime and self.available_domains:
            return

        if src_effective == "csv":
            data = self._load_csv(self.file_path)
        else:
            data = self._load_jsonl(self.file_path)

        data = sorted(set(d.strip() for d in data if d.strip()))
        self.available_domains = data
        self.mtime = new_mtime


CACHE: Optional[Cache] = None

# ----------------------------
# Scan trigger (background)
# ----------------------------

SCAN_STATE: Dict[str, Any] = {
    "running": False,
    "started_at": None,
    "ended_at": None,
    "last_exit_code": None,
    "last_error": None,
}

SCAN_CMD: List[str] = []  # populated in main


def _run_scan_bg() -> None:
    try:
        SCAN_STATE["running"] = True
        SCAN_STATE["started_at"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        SCAN_STATE["ended_at"] = None
        SCAN_STATE["last_error"] = None
        SCAN_STATE["last_exit_code"] = None

        p = subprocess.run(
            SCAN_CMD,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
            check=False,
        )
        SCAN_STATE["last_exit_code"] = int(p.returncode)
    except Exception as e:
        SCAN_STATE["last_error"] = f"{type(e).__name__}: {e}"
    finally:
        SCAN_STATE["running"] = False
        SCAN_STATE["ended_at"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


# ----------------------------
# Routes
# ----------------------------


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/domains")
def api_domains():
    assert CACHE is not None
    CACHE.refresh_if_needed()

    q = (request.args.get("q") or "").strip().lower()
    page = int(request.args.get("page") or "1")
    per_page = int(request.args.get("per_page") or "200")
    if page < 1:
        page = 1
    if per_page < 1:
        per_page = 1
    if per_page > 5000:
        per_page = 5000

    items = CACHE.available_domains
    if q:
        items = [d for d in items if q in d.lower()]

    total = len(items)
    start = (page - 1) * per_page
    end = start + per_page
    page_items = items[start:end]

    source_file = str(CACHE.file_path) if CACHE.file_path else None
    updated_at = (
        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(CACHE.mtime))
        if CACHE.mtime
        else None
    )

    note = None
    if not source_file:
        note = "No results file found in out-dir yet. Click Scan to generate data."

    return jsonify(
        {
            "total": total,
            "page": page,
            "per_page": per_page,
            "items": page_items,
            "source_file": source_file,
            "updated_at": updated_at,
            "note": note,
        }
    )


@app.get("/api/scan_status")
def api_scan_status():
    return jsonify(
        {
            "running": bool(SCAN_STATE["running"]),
            "started_at": SCAN_STATE["started_at"],
            "ended_at": SCAN_STATE["ended_at"],
            "last_exit_code": SCAN_STATE["last_exit_code"],
            "last_error": SCAN_STATE["last_error"],
            "cmd": SCAN_CMD,
        }
    )


@app.post("/scan")
def trigger_scan():
    if SCAN_STATE["running"]:
        return jsonify({"ok": False, "error": "scan already running"}), 409

    t = threading.Thread(target=_run_scan_bg, daemon=True)
    t.start()
    return jsonify({"ok": True, "status": "scan started", "cmd": SCAN_CMD})


# ----------------------------
# Main
# ----------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        "web_viewer.py",
        description="Mini web UI for viewing available domains + trigger scan.",
    )
    p.add_argument(
        "--out-dir", default="./out", help="Folder containing results.csv/results.jsonl"
    )
    p.add_argument("--source", choices=["auto", "csv", "jsonl"], default="auto")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)

    p.add_argument(
        "--scan-script",
        default="dynadot_bulk_scan_sync.py",
        help="Scanner script to run on button click",
    )
    p.add_argument(
        "--scan-args", default="", help="Extra args appended to scan command (string)"
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)  # auto-create out dir

    global CACHE
    CACHE = Cache(out_dir=out_dir, source=args.source)
    CACHE.refresh_if_needed()

    # Build scan command (LOCKED defaults):
    # Always run scanner with tier=regular and batch-size=5.
    global SCAN_CMD
    SCAN_CMD = [
        sys.executable,
        args.scan_script,
        "--out-dir",
        str(out_dir),
        "--tier",
        "regular",
        "--batch-size",
        "5",
    ]

    # Optional: allow extra scan args, but block tier/batch-size overrides
    if args.scan_args.strip():
        extra = args.scan_args.strip().split()
        blocked = {"--tier", "--batch-size"}
        filtered: List[str] = []
        i = 0
        while i < len(extra):
            tok = extra[i]
            if tok in blocked:
                i += 2 if (i + 1) < len(extra) else 1
                continue
            filtered.append(tok)
            i += 1
        SCAN_CMD.extend(filtered)

    print(f"Serving on http://{args.host}:{args.port}")
    print(f"Reading from: {out_dir} (source={args.source})")
    print(f"Scan command: {' '.join(SCAN_CMD)}")

    app.run(host=args.host, port=args.port, debug=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

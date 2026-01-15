#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dynadot reverse scanner (SYNC) - 5 domains per request, CSV only, rotate every 1000

Requirements:
- Python 3.10+
- No external deps

API:
  GET https://api.dynadot.com/restful/v2/domains/bulk_search
  Headers:
    Accept: application/json
    Authorization: Bearer <API_KEY>
  Query:
    domain_name_list=d1,d2,d3,d4,d5  (comma-separated, no whitespace)

Key features:
- Base-36 labels over alphabet: a-z0-9
- Reverse order:
    len=max -> ... -> len=min
    within same len: from index BASE^len-1 down to 0
- Batch size fixed: 5 domains per call
- Output CSV:
    domain,available
  (available kept as raw string from API: "Yes"/"No"/others)
- Rotate output files every N records (default 1000)
- Reads DYNADOT_API_KEY from .env (default .env)
- Supports starting from a label in reverse order: --start-label
    - start-mode=include: start at that label
    - start-mode=after  : start at the previous label (reverse progression)
- Optional --insecure to disable SSL verification (debug only)

Examples:
  python dynadot_reverse_scan_5.py --tld uk.com --min-len 1 --max-len 3 --limit 2000
  python dynadot_reverse_scan_5.py --tld uk.com --min-len 3 --max-len 3 --start-label cqg --start-mode include --limit 100
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import random
import ssl
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
ALPHABET_INDEX = {ch: i for i, ch in enumerate(ALPHABET)}
BASE = len(ALPHABET)

API_URL = "https://api.dynadot.com/restful/v2/domains/bulk_search"

BATCH_SIZE_FIXED = 5


# -------------------------
# .env loader (no deps)
# -------------------------
def load_env_file(path: Path) -> None:
    """
    Minimal .env parser:
    - KEY=VALUE per line
    - ignores blank lines and comments starting with #
    - does not overwrite existing environment variables
    """
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, v = s.split("=", 1)
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        if k and (k not in os.environ):
            os.environ[k] = v


# -------------------------
# Base-36 helpers
# -------------------------
def validate_label(label: str) -> None:
    if not label:
        raise ValueError("label is empty")
    for ch in label:
        if ch not in ALPHABET_INDEX:
            raise ValueError(f"Invalid label '{label}': '{ch}' not in a-z0-9")


def label_to_index(label: str) -> int:
    validate_label(label)
    x = 0
    for ch in label:
        x = x * BASE + ALPHABET_INDEX[ch]
    return x


def index_to_label(index: int, length: int) -> str:
    if length <= 0:
        raise ValueError("length must be > 0")
    max_index = BASE**length
    if index < 0 or index >= max_index:
        raise ValueError(f"index out of range for length={length}: {index}")
    chars = ["a"] * length
    x = index
    for pos in range(length - 1, -1, -1):
        x, rem = divmod(x, BASE)
        chars[pos] = ALPHABET[rem]
    return "".join(chars)


def iter_labels_reverse(
    min_len: int,
    max_len: int,
    start_label: Optional[str],
    start_mode: str,
) -> Iterator[str]:
    """
    Reverse iteration:
      length: max_len down to min_len
      index: BASE^length - 1 down to 0

    start_label semantics in reverse:
    - include: start at start_label (must be within [min_len,max_len])
    - after  : start at label "before it" in reverse order => index(start_label)-1
              (because reverse goes downward)
    """
    if min_len < 1 or max_len < min_len:
        raise ValueError("invalid min_len/max_len")

    start_len: Optional[int] = None
    start_idx: Optional[int] = None
    if start_label:
        validate_label(start_label)
        start_len = len(start_label)
        if start_len < min_len or start_len > max_len:
            raise ValueError("--start-label length out of scope")
        start_idx = label_to_index(start_label)
        if start_mode not in ("include", "after"):
            raise ValueError("start_mode must be include|after")
        if start_mode == "after":
            # reverse goes down; "after" means next in reverse => idx-1
            start_idx -= 1

    for length in range(max_len, min_len - 1, -1):
        total = BASE**length
        last = total - 1

        if start_label is None:
            begin = last
        elif length > (start_len or 0):
            # lengths bigger than start_len happen earlier in reverse order; skip them
            continue
        elif length == start_len:
            # start at start_idx (clamped)
            idx = start_idx if start_idx is not None else last
            if idx > last:
                idx = last
            begin = idx
        else:
            # smaller lengths come later; start from last
            begin = last

        for idx in range(begin, -1, -1):
            yield index_to_label(idx, length)


def iter_domains(labels: Iterator[str], tld: str) -> Iterator[str]:
    for lab in labels:
        yield f"{lab}.{tld}"


# -------------------------
# Output writer (rotate CSV)
# -------------------------
@dataclass
class Row:
    domain: str
    available: str


class RotatingCSV:
    """
    Rotate output every N rows:
      results_<runid>_<part>.csv
    Append-safe.
    """

    def __init__(self, out_dir: Path, rotate_every: int, run_id: str):
        if rotate_every < 1:
            raise ValueError("--rotate-every must be >= 1")
        self.out_dir = out_dir
        self.rotate_every = rotate_every
        self.run_id = run_id

        self.out_dir.mkdir(parents=True, exist_ok=True)

        self.part = 1
        self.count_in_part = 0
        self.total = 0

        self._f = None
        self._w = None
        self._open_part()

    def _path(self, part: int) -> Path:
        return self.out_dir / f"results_{self.run_id}_{part:06d}.csv"

    def _close_part(self) -> None:
        try:
            if self._f:
                self._f.close()
        except Exception:
            pass
        self._f = None
        self._w = None

    def _open_part(self) -> None:
        self._close_part()
        path = self._path(self.part)
        self._f = path.open("a", encoding="utf-8", newline="")
        self._w = csv.DictWriter(self._f, fieldnames=["domain", "available"])
        if path.stat().st_size == 0:
            self._w.writeheader()
            self._f.flush()
        self.count_in_part = 0

    def write_one(self, r: Row) -> None:
        if self.count_in_part >= self.rotate_every:
            self.part += 1
            self._open_part()
        assert self._w is not None and self._f is not None
        self._w.writerow({"domain": r.domain, "available": r.available})
        self.count_in_part += 1
        self.total += 1

    def flush(self) -> None:
        try:
            if self._f:
                self._f.flush()
        except Exception:
            pass

    def close(self) -> None:
        self.flush()
        self._close_part()


# -------------------------
# Dynadot call + parse
# -------------------------
def build_url(domains: List[str]) -> str:
    # domain_name_list is one comma-separated string
    q = ",".join(domains)
    return f"{API_URL}?{urllib.parse.urlencode({'domain_name_list': q})}"


def http_get_json(
    url: str, api_key: str, timeout_s: float, insecure: bool
) -> Tuple[int, Dict[str, Any], str]:
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {api_key}",
        "User-Agent": "dynadot-reverse-scan/1.0",
    }
    req = urllib.request.Request(url, headers=headers, method="GET")
    ctx = ssl._create_unverified_context() if insecure else None

    try:
        if ctx is not None:
            with urllib.request.urlopen(req, timeout=timeout_s, context=ctx) as r:
                status = int(getattr(r, "status", 200))
                text = r.read().decode("utf-8", errors="replace")
        else:
            with urllib.request.urlopen(req, timeout=timeout_s) as r:
                status = int(getattr(r, "status", 200))
                text = r.read().decode("utf-8", errors="replace")
        payload = json.loads(text) if text else {}
        return status, payload, text
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(text) if text else {}
        except Exception:
            payload = {"_raw": text[:500]}
        return int(e.code), payload, text


def parse_domain_result_list(payload: Dict[str, Any]) -> Dict[str, str]:
    """
    Returns mapping: domain_lower -> available_string (raw)
    """
    out: Dict[str, str] = {}
    if not isinstance(payload, dict):
        return out
    data = payload.get("data")
    if not isinstance(data, dict):
        return out
    lst = data.get("domain_result_list")
    if not isinstance(lst, list):
        return out
    for item in lst:
        if not isinstance(item, dict):
            continue
        dn = item.get("domain_name")
        if not isinstance(dn, str) or not dn:
            continue
        av = item.get("available")
        out[dn.lower()] = "" if av is None else str(av)
    return out


# -------------------------
# Main loop
# -------------------------
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser("dynadot_reverse_scan_5.py")

    ap.add_argument("--tld", default="uk.com")
    ap.add_argument("--min-len", type=int, default=1)
    ap.add_argument("--max-len", type=int, default=3)
    ap.add_argument("--start-label", default=None)
    ap.add_argument("--start-mode", choices=["include", "after"], default="include")

    ap.add_argument("--out-dir", default="./out_dynadot")
    ap.add_argument("--rotate-every", type=int, default=1000)
    ap.add_argument("--run-id", default="")
    ap.add_argument("--env-file", default=".env")

    ap.add_argument("--timeout-s", type=float, default=20.0)
    ap.add_argument("--sleep", type=float, default=0.2)
    ap.add_argument("--max-attempts", type=int, default=3)
    ap.add_argument("--limit", type=int, default=0, help="0 = no limit")

    ap.add_argument(
        "--insecure", action="store_true", help="Disable SSL verification (debug only)"
    )

    args = ap.parse_args(argv)

    load_env_file(Path(args.env_file))
    api_key = os.environ.get("DYNADOT_API_KEY", "").strip()
    if not api_key:
        print(
            "ERROR: Missing DYNADOT_API_KEY. Put it in .env or export env var.",
            file=sys.stderr,
        )
        return 2

    run_id = args.run_id.strip() or dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    writer = RotatingCSV(
        Path(args.out_dir), rotate_every=args.rotate_every, run_id=run_id
    )

    labels = iter_labels_reverse(
        args.min_len, args.max_len, args.start_label, args.start_mode
    )
    domains_iter = iter_domains(labels, args.tld)

    produced = 0
    batch: List[str] = []

    try:
        for domain in domains_iter:
            batch.append(domain)
            if len(batch) < BATCH_SIZE_FIXED:
                continue

            produced = process_batch(
                batch=batch,
                api_key=api_key,
                writer=writer,
                timeout_s=args.timeout_s,
                insecure=args.insecure,
                max_attempts=args.max_attempts,
                produced=produced,
                limit=args.limit,
            )
            batch = []

            if args.limit and produced >= args.limit:
                writer.flush()
                return 0

            if args.sleep > 0:
                time.sleep(args.sleep)

        # remainder
        if batch:
            produced = process_batch(
                batch=batch,
                api_key=api_key,
                writer=writer,
                timeout_s=args.timeout_s,
                insecure=args.insecure,
                max_attempts=args.max_attempts,
                produced=produced,
                limit=args.limit,
            )

        writer.flush()
        return 0
    finally:
        writer.close()


def process_batch(
    batch: List[str],
    api_key: str,
    writer: RotatingCSV,
    timeout_s: float,
    insecure: bool,
    max_attempts: int,
    produced: int,
    limit: int,
) -> int:
    url = build_url(batch)

    last_err: Optional[str] = None
    status: Optional[int] = None
    payload: Optional[Dict[str, Any]] = None

    for attempt in range(1, max_attempts + 1):
        try:
            status, p, _text = http_get_json(
                url, api_key=api_key, timeout_s=timeout_s, insecure=insecure
            )
            payload = p

            # Retry on throttling/transient errors
            if status in (429, 500, 502, 503, 504) and attempt < max_attempts:
                time.sleep(0.8 * (2 ** (attempt - 1)) + random.uniform(0, 0.2))
                continue
            break
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
            if attempt < max_attempts:
                time.sleep(0.8 * (2 ** (attempt - 1)) + random.uniform(0, 0.2))
                continue

    # If failed completely: write empty available values (or "ERROR")
    if payload is None:
        for d in batch:
            writer.write_one(
                Row(domain=d, available=f"ERROR:{last_err or 'request_failed'}")
            )
            produced += 1
            if limit and produced >= limit:
                writer.flush()
                print(
                    f"[RUNNING] scanned={produced} last={d} http={status} ERROR",
                    flush=True,
                )
                return produced

        writer.flush()
        # ✅ progress log for failed batch (still show script alive)
        last_d = batch[-1] if batch else ""
        print(
            f"[RUNNING] scanned={produced} last={last_d} http={status} batch=FAIL",
            flush=True,
        )
        return produced

    m = parse_domain_result_list(payload)

    batch_last_domain = batch[-1] if batch else ""
    batch_last_av = ""

    # Write rows; keep exact available string from API. If missing => empty string.
    for d in batch:
        av = m.get(d.lower(), "")
        batch_last_av = av  # keep last for summary log
        writer.write_one(Row(domain=d, available=av))
        produced += 1

        if limit and produced >= limit:
            writer.flush()
            print(
                f"[RUNNING] scanned={produced} last={d} avail={av} http={status}",
                flush=True,
            )
            return produced

    writer.flush()

    # ✅ progress log per batch (5 domains)
    print(
        f"[RUNNING] scanned={produced} last={batch_last_domain} avail={batch_last_av} http={status} batch={len(batch)}",
        flush=True,
    )

    return produced


if __name__ == "__main__":
    raise SystemExit(main())

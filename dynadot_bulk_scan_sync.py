#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dynadot REST v2 bulk_search scanner (SYNC) - minimal outputs + test mode

- Generate domains <label>.<tld> by base-36 a-z0-9 (streaming)
- Call Dynadot REST v2 bulk_search:
    GET https://api.dynadot.com/restful/v2/domains/bulk_search
    Headers:
      Accept: application/json
      Authorization: Bearer <API_KEY>
    Query:
      domain_name_list=<d1>,<d2>,<d3>  (single string, comma-separated, NO whitespace)
- Tier limits (per doc):
    regular: 5, bulk: 10, super: 20
  Tool caps batch-size by tier.

Outputs (rotated, append-safe):
  CSV  : domain,available
  JSONL: {"domain": "...", "available": true/false}

Other:
- Reads DYNADOT_API_KEY from .env (no deps)
- Rotate output files every N records (default 1000)
- Retry + backoff
- Optional --insecure disables SSL verification (debug only)
- TEST MODE: --test-random N prints FULL JSON payload for N random domains then exits
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
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
ALPHABET_INDEX = {ch: i for i, ch in enumerate(ALPHABET)}
BASE = len(ALPHABET)

API_BASE = "https://api.dynadot.com/restful/v2"
BULK_SEARCH_PATH = "/domains/bulk_search"

TIER_LIMITS = {
    "regular": 5,
    "bulk": 10,
    "super": 20,
}


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
        raise FileNotFoundError(f".env not found: {path}")
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
# Base-36 generator
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
    max_index = BASE ** length
    if index < 0 or index >= max_index:
        raise ValueError(f"index out of range for length={length}: {index}")
    chars = ["a"] * length
    x = index
    for pos in range(length - 1, -1, -1):
        x, rem = divmod(x, BASE)
        chars[pos] = ALPHABET[rem]
    return "".join(chars)


def iter_labels(min_len: int,
                max_len: int,
                start_label: Optional[str],
                start_mode: str) -> Iterator[str]:
    if min_len < 1 or max_len < min_len:
        raise ValueError("invalid min_len/max_len")

    start_len = None
    start_idx = None
    if start_label:
        validate_label(start_label)
        start_len = len(start_label)
        start_idx = label_to_index(start_label)
        if start_mode not in ("include", "after"):
            raise ValueError("start_mode must be include|after")
        if start_mode == "after":
            start_idx += 1

    for length in range(min_len, max_len + 1):
        total = BASE ** length

        if start_label is None:
            begin = 0
        elif length < (start_len or 0):
            continue
        elif length == start_len:
            begin = min(max(start_idx or 0, 0), total)
        else:
            begin = 0

        for i in range(begin, total):
            yield index_to_label(i, length)


def iter_domains(labels: Iterator[str], tld: str) -> Iterator[str]:
    for lab in labels:
        yield f"{lab}.{tld}"


def random_label(length: int) -> str:
    return "".join(random.choice(ALPHABET) for _ in range(length))


# -------------------------
# Models + rotating output
# -------------------------

@dataclass
class MinimalRow:
    domain: str
    available: bool


class RotatingWriters:
    """
    Rotate output files every N rows.
      results_<runid>_<part>.csv
      results_<runid>_<part>.jsonl
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

        self._csvf = None
        self._csvw = None
        self._jsonl = None

        self._open_part()

    def _paths(self, part: int) -> Tuple[Path, Path]:
        part_s = f"{part:06d}"
        csv_path = self.out_dir / f"results_{self.run_id}_{part_s}.csv"
        jsonl_path = self.out_dir / f"results_{self.run_id}_{part_s}.jsonl"
        return csv_path, jsonl_path

    def _close_part(self) -> None:
        try:
            if self._csvf:
                self._csvf.close()
        except Exception:
            pass
        try:
            if self._jsonl:
                self._jsonl.close()
        except Exception:
            pass
        self._csvf = None
        self._csvw = None
        self._jsonl = None

    def _open_part(self) -> None:
        self._close_part()
        csv_path, jsonl_path = self._paths(self.part)

        self._csvf = csv_path.open("a", encoding="utf-8", newline="")
        self._csvw = csv.DictWriter(self._csvf, fieldnames=["domain", "available"])
        if csv_path.stat().st_size == 0:
            self._csvw.writeheader()
            self._csvf.flush()

        self._jsonl = jsonl_path.open("a", encoding="utf-8", newline="\n")
        self.count_in_part = 0

    def write_one(self, r: MinimalRow) -> None:
        if self.count_in_part >= self.rotate_every:
            self.part += 1
            self._open_part()

        assert self._csvw is not None and self._csvf is not None and self._jsonl is not None

        self._csvw.writerow({
            "domain": r.domain,
            "available": "true" if r.available else "false",
        })
        self._jsonl.write(json.dumps(asdict(r), ensure_ascii=False) + "\n")

        self.count_in_part += 1
        self.total += 1

    def flush(self) -> None:
        try:
            if self._csvf:
                self._csvf.flush()
        except Exception:
            pass
        try:
            if self._jsonl:
                self._jsonl.flush()
        except Exception:
            pass

    def close(self) -> None:
        self.flush()
        self._close_part()


# -------------------------
# Dynadot REST v2 bulk_search
# -------------------------

def build_bulk_search_url(domains: List[str]) -> str:
    # domain_name_list must be a single comma-separated string, no whitespace
    q = ",".join(domains)
    return f"{API_BASE}{BULK_SEARCH_PATH}?{urllib.parse.urlencode({'domain_name_list': q})}"


def http_get_json(url: str, api_key: str, timeout_s: float, insecure: bool) -> Tuple[int, Dict[str, Any], str]:
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {api_key}",
        "User-Agent": "dynadot-bulk-scan/1.1",
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


def parse_bulk_search(payload: Dict[str, Any]) -> Dict[str, bool]:
    """
    Expected (from your Postman):
      {
        "code": 200,
        "message": "Success",
        "data": {
          "domain_result_list": [
            {"domain_name":"cf4.uk.com","available":"Yes"},
            ...
          ]
        }
      }
    Return: { lower(domain): available_bool }
    """
    if not isinstance(payload, dict):
        return {}

    data = payload.get("data")
    if not isinstance(data, dict):
        return {}

    lst = data.get("domain_result_list")
    if not isinstance(lst, list):
        return {}

    out: Dict[str, bool] = {}
    for item in lst:
        if not isinstance(item, dict):
            continue
        dn = item.get("domain_name")
        if not isinstance(dn, str) or not dn:
            continue
        av = item.get("available")
        s = str(av).strip().lower()
        out[dn.lower()] = (s in ("yes", "true", "1", "available"))
    return out


# -------------------------
# TEST MODE
# -------------------------

def test_random_domains(
    tld: str,
    api_key: str,
    timeout_s: float,
    insecure: bool,
    count: int,
    label_len: int,
    prefix: str = "",
) -> int:
    """
    Build N random domains and call API once (batched) then print FULL payload.
    prefix: optional label prefix, e.g. "aa" => aa? / aa?? depending on label_len
    """
    if count < 1:
        print("--test-random must be >= 1", file=sys.stderr)
        return 2

    if prefix:
        validate_label(prefix)
        if len(prefix) > label_len:
            print(f"prefix too long: len(prefix)={len(prefix)} > label_len={label_len}", file=sys.stderr)
            return 2

    domains: List[str] = []
    seen = set()

    while len(domains) < count:
        tail_len = label_len - len(prefix)
        lab = prefix + (random_label(tail_len) if tail_len > 0 else "")
        d = f"{lab}.{tld}"
        if d in seen:
            continue
        seen.add(d)
        domains.append(d)

    url = build_bulk_search_url(domains)
    print("TEST domains:", domains)
    print("TEST URL:", url)

    status, payload, text = http_get_json(url, api_key=api_key, timeout_s=timeout_s, insecure=insecure)

    print("HTTP status:", status)
    print("FULL JSON payload:")
    print(json.dumps(payload, ensure_ascii=False, indent=2))

    avail_map = parse_bulk_search(payload)
    print("\nPARSED:")
    for d in domains:
        print(d, "=>", avail_map.get(d.lower()))

    return 0


# -------------------------
# Main scan loop
# -------------------------

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser("dynadot_bulk_scan_sync.py")

    ap.add_argument("--tld", default="uk.com")
    ap.add_argument("--min-len", type=int, default=1)
    ap.add_argument("--max-len", type=int, default=3)
    ap.add_argument("--start-label", default=None)
    ap.add_argument("--start-mode", choices=["include", "after"], default="include")

    ap.add_argument("--tier", choices=["regular", "bulk", "super"], default="super",
                    help="Cap request size by tier: regular=5, bulk=10, super=20 (per doc). Default: super.")
    ap.add_argument("--batch-size", type=int, default=20,
                    help="Domains per request (will be capped by tier). Default: 20.")

    ap.add_argument("--sleep", type=float, default=0.3, help="Sleep between requests (seconds)")
    ap.add_argument("--timeout-s", type=float, default=25.0)
    ap.add_argument("--max-attempts", type=int, default=3)

    ap.add_argument("--limit", type=int, default=0, help="0 = no limit (scan all in scope)")
    ap.add_argument("--out-dir", default="./out_dynadot")
    ap.add_argument("--env-file", default=".env", help="Path to .env file (default: .env)")
    ap.add_argument("--insecure", action="store_true", help="Disable SSL verification (debug only)")

    ap.add_argument("--rotate-every", type=int, default=1000)
    ap.add_argument("--run-id", default="", help="Optional run id prefix for output files")

    # Test mode
    ap.add_argument("--test-random", type=int, default=0,
                    help="If >0: call API once with N random domains and print FULL JSON response, then exit.")
    ap.add_argument("--test-prefix", default="",
                    help="Optional label prefix for --test-random, e.g. 'aa' to test aa?.<tld>.")

    args = ap.parse_args(argv)

    # Load .env and get API key
    load_env_file(Path(args.env_file))
    api_key = os.getenv("DYNADOT_API_KEY", "").strip()
    if not api_key:
        print("Missing DYNADOT_API_KEY. Put it in .env (or set env var).", file=sys.stderr)
        return 2

    # Cap by tier
    tier_limit = TIER_LIMITS[args.tier]
    if args.batch_size < 1:
        args.batch_size = 1
    if args.batch_size > tier_limit:
        args.batch_size = tier_limit

    # TEST MODE
    if args.test_random and args.test_random > 0:
        n = min(args.test_random, tier_limit)
        if args.test_random > tier_limit:
            print(f"[warn] --test-random={args.test_random} capped to tier limit={tier_limit}")
        label_len = args.max_len  # use max-len for realistic labels
        return test_random_domains(
            tld=args.tld,
            api_key=api_key,
            timeout_s=args.timeout_s,
            insecure=args.insecure,
            count=n,
            label_len=label_len,
            prefix=args.test_prefix.strip(),
        )

    run_id = args.run_id.strip() or dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    writers = RotatingWriters(Path(args.out_dir), rotate_every=args.rotate_every, run_id=run_id)

    labels = iter_labels(args.min_len, args.max_len, args.start_label, args.start_mode)
    domains_iter = iter_domains(labels, args.tld)

    produced = 0
    batch: List[str] = []

    try:
        for domain in domains_iter:
            batch.append(domain)
            if len(batch) < args.batch_size:
                continue

            produced = process_one_batch(
                batch=batch,
                api_key=api_key,
                timeout_s=args.timeout_s,
                insecure=args.insecure,
                max_attempts=args.max_attempts,
                writers=writers,
                produced=produced,
                limit=args.limit,
                sleep_s=args.sleep,
            )
            batch = []

            if args.limit and produced >= args.limit:
                writers.flush()
                return 0

        if batch:
            produced = process_one_batch(
                batch=batch,
                api_key=api_key,
                timeout_s=args.timeout_s,
                insecure=args.insecure,
                max_attempts=args.max_attempts,
                writers=writers,
                produced=produced,
                limit=args.limit,
                sleep_s=args.sleep,
            )
            if args.limit and produced >= args.limit:
                writers.flush()
                return 0

        writers.flush()
        return 0
    finally:
        writers.close()


def process_one_batch(
    batch: List[str],
    api_key: str,
    timeout_s: float,
    insecure: bool,
    max_attempts: int,
    writers: RotatingWriters,
    produced: int,
    limit: int,
    sleep_s: float,
) -> int:
    url = build_bulk_search_url(batch)

    payload: Optional[Dict[str, Any]] = None
    last_err: Optional[str] = None
    status: Optional[int] = None

    for attempt in range(1, max_attempts + 1):
        try:
            status, p, _text = http_get_json(url, api_key=api_key, timeout_s=timeout_s, insecure=insecure)
            payload = p
            last_err = None

            # retry on throttling / transient server errors
            if status in (429, 500, 502, 503, 504) and attempt < max_attempts:
                time.sleep(0.6 * (2 ** (attempt - 1)) + random.uniform(0, 0.2))
                continue
            break
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
            if attempt < max_attempts:
                time.sleep(0.6 * (2 ** (attempt - 1)) + random.uniform(0, 0.2))
                continue

    if payload is None:
        # request failed -> mark all unavailable (conservative)
        for d in batch:
            writers.write_one(MinimalRow(domain=d, available=False))
            produced += 1
            if produced % 100 == 0:
                writers.flush()
                print(f"[{produced}] last={d} request_failed={last_err}")
            if limit and produced >= limit:
                return produced
        writers.flush()
        if sleep_s > 0:
            time.sleep(sleep_s)
        return produced

    avail_map = parse_bulk_search(payload)

    for d in batch:
        available = bool(avail_map.get(d.lower(), False))
        writers.write_one(MinimalRow(domain=d, available=available))
        produced += 1

        if produced % 100 == 0:
            writers.flush()
            print(f"[{produced}] last={d}")

        if limit and produced >= limit:
            writers.flush()
            return produced

    writers.flush()
    if sleep_s > 0:
        time.sleep(sleep_s)
    return produced


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dynadot reverse scanner (SYNC) — Hyphen separator optional
- 5 domains per request
- CSV only (domain, available)
- rotate every 1000 records

IMPORTANT SPEC (your requirement):
- Counter alphabet is base-36: a-z + 0-9 (NO '-' in alphabet)
- Default render has NO separator between characters (use --sep to enable):
    raw label len=1:  a        -> a
    raw label len=2:  ab       -> ab
    raw label len=3:  vrx      -> vrx
    raw label len=3:  998      -> 998

API:
  GET https://api.dynadot.com/restful/v2/domains/bulk_search
  Headers:
    Accept: application/json
    Authorization: Bearer <API_KEY>
  Query:
    domain_name_list=d1,d2,d3,d4,d5  (comma-separated, no whitespace)

Notes:
- --min-len/--max-len are RAW label length (excluding hyphens)
- --start-label can be provided as raw (e.g., 998) or rendered (e.g., 9-9-8); script strips hyphens

Examples:
  python dynadot_reverse_scan_5.py --tld eu.com --min-len 3 --max-len 3 --limit 2000 --out-dir ./out_dynadot --insecure
  python dynadot_reverse_scan_5.py --tld uk.com --min-len 3 --max-len 3 --start-label v-r-x --start-mode include --limit 200 --sep
  python dynadot_reverse_scan_5.py --tld uk.com --min-len 2 --max-len 3
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

# Base-36 alphabet (counter alphabet) — NO hyphen here
ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
ALPHABET_INDEX = {ch: i for i, ch in enumerate(ALPHABET)}
BASE = len(ALPHABET)  # 36

SEP = ""  # Separator between every character when rendering (set to "-" with --sep)
API_URL = "https://api.dynadot.com/restful/v2/domains/bulk_search"
BATCH_SIZE_FIXED = 5

WAYBACK_API_TEMPLATE = (
    "https://web.archive.org/__wb/sparkline?output=json&url={url}&collection=web"
)

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
# Label helpers (base-36), hyphen separator mode
# -------------------------
def normalize_label_input(label: str) -> str:
    """
    Accept start-label in either form:
      - raw:      998
      - rendered: 9-9-8
      - rendered: v-r-x
    Strip '-' and validate remaining chars are in a-z0-9.
    """
    s = (label or "").strip().lower()
    if not s:
        return ""

    out_chars: List[str] = []
    for ch in s:
        if ch == SEP:
            continue
        if ch not in ALPHABET_INDEX:
            raise ValueError(
                f"Invalid start-label '{label}': '{ch}' not in a-z0-9 or '-'"
            )
        out_chars.append(ch)

    if not out_chars:
        raise ValueError(f"Invalid start-label '{label}': empty after stripping '-'")

    return "".join(out_chars)


def validate_raw_label(raw_label: str) -> None:
    if not raw_label:
        raise ValueError("label is empty")
    for ch in raw_label:
        if ch not in ALPHABET_INDEX:
            raise ValueError(f"Invalid label '{raw_label}': '{ch}' not in a-z0-9")


def label_to_index(raw_label: str) -> int:
    validate_raw_label(raw_label)
    x = 0
    for ch in raw_label:
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


def render_label(raw_label: str) -> str:
    """
    Default: no separator (unless SEP == "-"):
      '998' -> '998'
      'a'   -> 'a'
      'ab'  -> 'ab'
    """
    if SEP == "" or len(raw_label) <= 1:
        return raw_label
    return SEP.join(raw_label)


def iter_labels_reverse(
    min_len: int,
    max_len: int,
    start_label: Optional[str],
    start_mode: str,
) -> Iterator[str]:
    """
    Reverse iteration over RAW labels (no hyphens):
      length: max_len down to min_len
      index: BASE^length - 1 down to 0

    start_label semantics in reverse (after normalization):
    - include: start at start_label
    - after  : start at index(start_label)-1
    """
    if min_len < 1 or max_len < min_len:
        raise ValueError("invalid min_len/max_len")

    start_len: Optional[int] = None
    start_idx: Optional[int] = None

    if start_label:
        raw_start = normalize_label_input(start_label)
        validate_raw_label(raw_start)
        start_len = len(raw_start)
        if start_len < min_len or start_len > max_len:
            raise ValueError(
                "--start-label length out of scope (RAW length excluding '-')"
            )
        start_idx = label_to_index(raw_start)
        if start_mode not in ("include", "after"):
            raise ValueError("start_mode must be include|after")
        if start_mode == "after":
            start_idx -= 1

    for length in range(max_len, min_len - 1, -1):
        total = BASE**length
        last = total - 1

        if start_label is None:
            begin = last
        elif length > (start_len or 0):
            continue
        elif length == start_len:
            idx = start_idx if start_idx is not None else last
            if idx > last:
                idx = last
            begin = idx
        else:
            begin = last

        for idx in range(begin, -1, -1):
            yield index_to_label(idx, length)


def iter_domains(raw_labels: Iterator[str], tld: str) -> Iterator[str]:
    """
    Convert RAW label -> rendered label (with separator if --sep), then attach tld.
    """
    tld = (tld or "").strip().lstrip(".")
    for raw in raw_labels:
        yield f"{render_label(raw)}.{tld}"


# -------------------------
# Output writer (rotate CSV)
# -------------------------
@dataclass
class Row:
    domain: str
    available: str
    is_2_years: str


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
        self._w = csv.DictWriter(
            self._f, fieldnames=["domain", "available", "is_2_years"]
        )
        if path.stat().st_size == 0:
            self._w.writeheader()
            self._f.flush()
        self.count_in_part = 0

    def write_one(self, r: Row) -> None:
        if self.count_in_part >= self.rotate_every:
            self.part += 1
            self._open_part()
        assert self._w is not None and self._f is not None
        self._w.writerow(
            {"domain": r.domain, "available": r.available, "is_2_years": r.is_2_years}
        )
        self.count_in_part += 1

    def flush(self) -> None:
        try:
            if self._f:
                self._f.flush()
        except Exception:
            pass

    def close(self) -> None:
        self.flush()
        self._close_part()


def write_manifest(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    files = sorted([p.name for p in out_dir.glob("*.csv") if p.is_file()])
    manifest = {"generated_at": dt.datetime.now().isoformat(), "files": files}
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=True, indent=2), encoding="utf-8"
    )


# -------------------------
# Dynadot call + parse
# -------------------------
def build_url(domains: List[str]) -> str:
    q = ",".join(domains)
    return f"{API_URL}?{urllib.parse.urlencode({'domain_name_list': q})}"


def http_get_json(
    url: str, api_key: str, timeout_s: float, insecure: bool
) -> Tuple[int, Dict[str, Any], str]:
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {api_key}",
        "User-Agent": "dynadot-reverse-scan-sep/1.0",
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
    Expected:
      payload["data"]["domain_result_list"] = [{"domain_name": "...", "available": "Yes/No"}, ...]
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
# Wayback age check
# -------------------------
def parse_wayback_ts(ts: str) -> dt.datetime:
    if not isinstance(ts, str):
        raise ValueError("timestamp is not a string")
    if len(ts) != 14 or not ts.isdigit():
        raise ValueError("timestamp must be 14 digits")
    try:
        return dt.datetime.strptime(ts, "%Y%m%d%H%M%S").replace(
            tzinfo=dt.timezone.utc
        )
    except ValueError as exc:
        raise ValueError("timestamp has invalid date/time components") from exc


def fetch_wayback_sparkline(
    domain: str, timeout_s: float, max_attempts: int
) -> Dict[str, Any]:
    url = WAYBACK_API_TEMPLATE.format(url=domain)
    headers_list = [
        {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0 Safari/537.36"
            ),
            "Accept": "application/json,text/plain,*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://web.archive.org/",
            "Connection": "close",
        },
        {
            "User-Agent": "dynadot-reverse-scan-sep/1.0",
            "Accept": "application/json",
        },
    ]

    last_err: Optional[Exception] = None
    for attempt in range(1, max_attempts + 1):
        for headers in headers_list:
            req = urllib.request.Request(url, headers=headers, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=timeout_s) as r:
                    status = int(getattr(r, "status", 200))
                    text = r.read().decode("utf-8", errors="replace")
                if status != 200:
                    raise urllib.error.HTTPError(url, status, "HTTP error", None, None)
                return json.loads(text) if text else {}
            except urllib.error.HTTPError as exc:
                last_err = exc
                if exc.code in (429, 500, 502, 503, 504, 498) and attempt < max_attempts:
                    time.sleep(0.8 * (2 ** (attempt - 1)) + random.uniform(0, 0.2))
                    continue
                raise
            except urllib.error.URLError as exc:
                last_err = exc
                if attempt < max_attempts:
                    time.sleep(0.8 * (2 ** (attempt - 1)) + random.uniform(0, 0.2))
                    continue
                raise
            except json.JSONDecodeError as exc:
                raise ValueError("JSON parse error") from exc

    if last_err is not None:
        raise last_err
    return {}


def is_at_least_2_years(first_ts: str) -> bool:
    first_dt = parse_wayback_ts(first_ts)
    now_utc = dt.datetime.now(dt.timezone.utc)
    return (now_utc - first_dt).days >= 730


def get_is_2_years(
    domain: str,
    cache: Dict[str, str],
    timeout_s: float,
    max_attempts: int,
) -> str:
    cached = cache.get(domain)
    if cached is not None:
        return cached
    try:
        payload = fetch_wayback_sparkline(domain, timeout_s=timeout_s, max_attempts=max_attempts)
        first_ts = payload.get("first_ts")
        last_ts = payload.get("last_ts")
        if not first_ts or not last_ts:
            cache[domain] = ""
            return ""
        is_2 = "true" if is_at_least_2_years(str(first_ts)) else "false"
        cache[domain] = is_2
        return is_2
    except Exception:
        cache[domain] = ""
        return ""


# -------------------------
# Main loop
# -------------------------
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser("dynadot_reverse_scan_5.py")

    ap.add_argument("--tld", default="uk.com")
    ap.add_argument("--min-len", type=int, default=1, help="RAW label length (excluding '-')")
    ap.add_argument("--max-len", type=int, default=3, help="RAW label length (excluding '-')")
    ap.add_argument("--start-label", default=None, help="RAW '998' or rendered '9-9-8'")
    ap.add_argument("--start-mode", choices=["include", "after"], default="include")
    ap.add_argument("--sep", action="store_true", help="Enable '-' separator between every character")

    ap.add_argument("--out-dir", default="./out_dynadot")
    ap.add_argument("--rotate-every", type=int, default=1000)
    ap.add_argument("--run-id", default="")
    ap.add_argument("--env-file", default=".env")

    ap.add_argument("--timeout-s", type=float, default=20.0)
    ap.add_argument("--sleep", type=float, default=0.2)
    ap.add_argument("--max-attempts", type=int, default=3)
    ap.add_argument("--limit", type=int, default=0, help="0 = no limit (records written)")

    ap.add_argument("--insecure", action="store_true", help="Disable SSL verification (debug only)")
    ap.add_argument("--age-timeout-s", type=float, default=20.0)
    ap.add_argument("--age-sleep", type=float, default=0.0)
    ap.add_argument("--age-max-attempts", type=int, default=2)
    age_group = ap.add_mutually_exclusive_group()
    age_group.add_argument("--check-age", dest="check_age", action="store_true")
    age_group.add_argument("--no-check-age", dest="check_age", action="store_false")
    ap.set_defaults(check_age=True)

    args = ap.parse_args(argv)

    global SEP
    if args.sep:
        SEP = "-"

    load_env_file(Path(args.env_file))
    api_key = os.environ.get("DYNADOT_API_KEY", "").strip()
    if not api_key:
        print("ERROR: Missing DYNADOT_API_KEY. Put it in .env or export env var.", file=sys.stderr)
        return 2

    run_id = args.run_id.strip() or dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    writer = RotatingCSV(Path(args.out_dir), rotate_every=args.rotate_every, run_id=run_id)

    raw_labels = iter_labels_reverse(args.min_len, args.max_len, args.start_label, args.start_mode)
    domains_iter = iter_domains(raw_labels, args.tld)

    produced = 0
    batch: List[str] = []
    age_cache: Dict[str, str] = {}

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
                check_age=args.check_age,
                age_timeout_s=args.age_timeout_s,
                age_sleep=args.age_sleep,
                age_max_attempts=args.age_max_attempts,
                age_cache=age_cache,
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
                check_age=args.check_age,
                age_timeout_s=args.age_timeout_s,
                age_sleep=args.age_sleep,
                age_max_attempts=args.age_max_attempts,
                age_cache=age_cache,
                produced=produced,
                limit=args.limit,
            )

        writer.flush()
        return 0
    finally:
        writer.close()
        try:
            write_manifest(Path(args.out_dir))
        except Exception:
            pass


def process_batch(
    batch: List[str],
    api_key: str,
    writer: RotatingCSV,
    timeout_s: float,
    insecure: bool,
    max_attempts: int,
    check_age: bool,
    age_timeout_s: float,
    age_sleep: float,
    age_max_attempts: int,
    age_cache: Dict[str, str],
    produced: int,
    limit: int,
) -> int:
    url = build_url(batch)

    status: Optional[int] = None
    payload: Optional[Dict[str, Any]] = None
    last_err: Optional[str] = None

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
            payload = None
            if attempt < max_attempts:
                time.sleep(0.8 * (2 ** (attempt - 1)) + random.uniform(0, 0.2))
                continue

    if payload is None:
        # No available value returned -> write empty string
        for d in batch:
            is_2 = (
                get_is_2_years(d, age_cache, age_timeout_s, age_max_attempts)
                if check_age
                else ""
            )
            writer.write_one(Row(domain=d, available="", is_2_years=is_2))
            produced += 1
            if limit and produced >= limit:
                writer.flush()
                print(f"[RUNNING] scanned={produced} last={d} http={status} ERROR={last_err}", flush=True)
                return produced
            if check_age and age_sleep > 0:
                time.sleep(age_sleep)
        writer.flush()
        print(f"[RUNNING] scanned={produced} last={batch[-1]} http={status} batch=FAIL ERROR={last_err}", flush=True)
        return produced

    m = parse_domain_result_list(payload)

    missing = 0
    batch_last_domain = batch[-1]
    batch_last_av = ""

    for d in batch:
        av = m.get(d.lower())
        if av is None:
            av = ""   # missing result -> empty
            missing += 1
        batch_last_av = av
        is_2 = (
            get_is_2_years(d, age_cache, age_timeout_s, age_max_attempts)
            if check_age
            else ""
        )
        writer.write_one(Row(domain=d, available=av, is_2_years=is_2))
        produced += 1

        if limit and produced >= limit:
            writer.flush()
            print(f"[RUNNING] scanned={produced} last={d} avail={av} http={status}", flush=True)
            return produced
        if check_age and age_sleep > 0:
            time.sleep(age_sleep)

    writer.flush()
    if missing:
        print(
            f"[RUNNING] scanned={produced} last={batch_last_domain} avail={batch_last_av} http={status} batch={len(batch)} missing={missing}",
            flush=True,
        )
    else:
        print(
            f"[RUNNING] scanned={produced} last={batch_last_domain} avail={batch_last_av} http={status} batch={len(batch)}",
            flush=True,
        )

    return produced


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SYNC scanner for:
  https://rtb.namecheapapi.com/api/picks/<domain>

Purpose: quick testing endpoint behavior (e.g., domain "masking") under constrained environments.

Key:
- No aiohttp, no async.
- Uses requests if available; otherwise falls back to urllib.
- Supports base-36 label generator (a-z0-9) and --max-domains for quick testing.
- Outputs: JSONL + CSV (append-safe).
- Optional SSL verify disable for debugging environments lacking CA bundle.

SECURITY NOTE:
- Using --insecure disables TLS certificate verification. Use only for testing.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import logging
import random
import ssl
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

# Disable InsecureRequestWarning if requests/urllib3 is present
try:
    import urllib3  # type: ignore
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # type: ignore
except Exception:
    pass

ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
ALPHABET_INDEX = {ch: i for i, ch in enumerate(ALPHABET)}
BASE = len(ALPHABET)  # 36

DEFAULT_BASE_URL = "https://rtb.namecheapapi.com/api/picks"

# Try requests; fallback to urllib if not available
try:
    import requests  # type: ignore
except Exception:
    requests = None  # type: ignore

if requests is None:
    import urllib.request
    import urllib.error


# ---------------------------
# Helpers
# ---------------------------

def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def configure_logging(v: int) -> logging.Logger:
    level = logging.INFO
    if v >= 2:
        level = logging.DEBUG
    elif v == 0:
        level = logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    return logging.getLogger("rtb_scan_sync")


# ---------------------------
# Base-36 generator
# ---------------------------

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
                start_label: Optional[str] = None,
                start_mode: str = "include") -> Iterator[str]:
    if min_len < 1 or max_len < min_len:
        raise ValueError("invalid min_len/max_len")

    start_len = None
    start_idx = None
    if start_label is not None:
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

        for idx in range(begin, total):
            yield index_to_label(idx, length)


def iter_domains(labels: Iterable[str], tld: str) -> Iterator[Tuple[str, str]]:
    for lab in labels:
        yield f"{lab}.{tld}", lab


# ---------------------------
# Payload extraction
# ---------------------------

def extract_fields(payload: Dict[str, Any]) -> Dict[str, Any]:
    exact = payload.get("exact_match") or {}
    return {
        "raw_type": payload.get("type"),
        "exact_match_domain": exact.get("domain"),
        "exact_match_tld": exact.get("tld"),
        "exact_match_is_supported": exact.get("is_supported"),
        "exact_match_campaign_type": exact.get("campaignType"),
        "enable_cart_verification": exact.get("enable_cart_verification"),
    }


def maybe_trim_raw(payload: Dict[str, Any], max_chars: int) -> Dict[str, Any]:
    """
    Avoid huge JSONL rows. If max_chars <= 0: keep full payload.
    If payload json string exceeds max_chars, keep only a minimal subset.
    """
    if max_chars <= 0:
        return payload
    try:
        s = json.dumps(payload, ensure_ascii=False)
        if len(s) <= max_chars:
            return payload
    except Exception:
        pass

    # minimal subset
    exact = payload.get("exact_match")
    return {
        "type": payload.get("type"),
        "exact_match": exact,
        "note": f"raw trimmed (>{max_chars} chars)",
    }


# ---------------------------
# Result model + writers
# ---------------------------

@dataclass
class RTBResult:
    domain: str
    label: str
    tld: str
    checked_at: str
    ok: bool
    http_status: Optional[int] = None
    error: Optional[str] = None

    exact_match_domain: Optional[str] = None
    exact_match_tld: Optional[str] = None
    exact_match_is_supported: Optional[bool] = None
    exact_match_campaign_type: Optional[Any] = None
    enable_cart_verification: Optional[bool] = None

    raw_type: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None


class Writers:
    def __init__(self, out_dir: Path):
        out_dir.mkdir(parents=True, exist_ok=True)
        self.jsonl_path = out_dir / "rtb_results.jsonl"
        self.csv_path = out_dir / "rtb_results.csv"

        self._jsonl = self.jsonl_path.open("a", encoding="utf-8", newline="\n")
        self._csv = self.csv_path.open("a", encoding="utf-8", newline="")

        self._csv_writer = csv.DictWriter(
            self._csv,
            fieldnames=[
                "domain", "label", "tld", "checked_at", "ok", "http_status",
                "exact_match_is_supported", "enable_cart_verification",
                "exact_match_domain", "exact_match_tld", "raw_type", "error"
            ],
        )
        if self.csv_path.stat().st_size == 0:
            self._csv_writer.writeheader()
            self._csv.flush()

    def write_one(self, r: RTBResult) -> None:
        self._jsonl.write(json.dumps(asdict(r), ensure_ascii=False) + "\n")
        self._csv_writer.writerow({
            "domain": r.domain,
            "label": r.label,
            "tld": r.tld,
            "checked_at": r.checked_at,
            "ok": str(bool(r.ok)).lower(),
            "http_status": "" if r.http_status is None else r.http_status,
            "exact_match_is_supported": "" if r.exact_match_is_supported is None else str(bool(r.exact_match_is_supported)).lower(),
            "enable_cart_verification": "" if r.enable_cart_verification is None else str(bool(r.enable_cart_verification)).lower(),
            "exact_match_domain": r.exact_match_domain or "",
            "exact_match_tld": r.exact_match_tld or "",
            "raw_type": r.raw_type or "",
            "error": r.error or "",
        })

    def flush(self) -> None:
        self._jsonl.flush()
        self._csv.flush()

    def close(self) -> None:
        try:
            self._jsonl.close()
        except Exception:
            pass
        try:
            self._csv.close()
        except Exception:
            pass


# ---------------------------
# HTTP
# ---------------------------

def http_get_json(url: str, timeout_s: float, user_agent: str, insecure: bool) -> Tuple[int, Dict[str, Any], str]:
    """
    Returns: (status_code, json_payload, raw_text)
    Raises on fatal network errors.
    """
    headers = {"User-Agent": user_agent, "Accept": "application/json,text/plain,*/*"}

    if requests is not None:
        resp = requests.get(url, headers=headers, timeout=timeout_s, verify=(not insecure))
        status = resp.status_code
        text = resp.text
        payload = json.loads(text)
        return status, payload, text

    # urllib fallback
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

        payload = json.loads(text)
        return status, payload, text

    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(text)
        except Exception:
            payload = {"_raw": text[:500]}
        return int(e.code), payload, text


def fetch_one(domain: str, label: str, tld: str, base_url: str, args, log: logging.Logger) -> RTBResult:
    url = f"{base_url.rstrip('/')}/{domain}"
    checked_at = now_iso()

    last_err: Optional[str] = None
    last_status: Optional[int] = None

    for attempt in range(1, args.max_attempts + 1):
        try:
            status, payload, _text = http_get_json(url, args.timeout_s, args.user_agent, args.insecure)
            last_status = status

            if status in (429, 500, 502, 503, 504):
                last_err = f"HTTP {status}"
                if attempt < args.max_attempts:
                    sleep_s = args.backoff_base_s * (2 ** (attempt - 1)) + random.uniform(0, args.backoff_jitter_s)
                    log.warning("retrying domain=%s attempt=%s sleep=%.2fs reason=%s", domain, attempt, sleep_s, last_err)
                    time.sleep(sleep_s)
                    continue
                return RTBResult(domain, label, tld, checked_at, ok=False, http_status=status, error=last_err)

            fields = extract_fields(payload)
            raw = maybe_trim_raw(payload, args.raw_max_chars)

            return RTBResult(
                domain=domain,
                label=label,
                tld=tld,
                checked_at=checked_at,
                ok=True,
                http_status=status,
                raw_type=fields["raw_type"],
                exact_match_domain=fields["exact_match_domain"],
                exact_match_tld=fields["exact_match_tld"],
                exact_match_is_supported=fields["exact_match_is_supported"],
                exact_match_campaign_type=fields["exact_match_campaign_type"],
                enable_cart_verification=fields["enable_cart_verification"],
                raw=raw,
            )

        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
            if attempt < args.max_attempts:
                sleep_s = args.backoff_base_s * (2 ** (attempt - 1)) + random.uniform(0, args.backoff_jitter_s)
                log.warning("retrying domain=%s attempt=%s sleep=%.2fs error=%s", domain, attempt, sleep_s, last_err)
                time.sleep(sleep_s)
                continue

    return RTBResult(domain, label, tld, checked_at, ok=False, http_status=last_status, error=last_err)


# ---------------------------
# CLI
# ---------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser("rtb_scan_sync.py", description="SYNC caller for rtb.namecheapapi.com picks endpoint.")
    p.add_argument("--tld", default="uk.com")
    p.add_argument("--base-url", default=DEFAULT_BASE_URL)

    p.add_argument("--min-len", type=int, default=1)
    p.add_argument("--max-len", type=int, default=2)
    p.add_argument("--start-label", default=None)
    p.add_argument("--start-mode", choices=["include", "after"], default="include")
    p.add_argument("--max-domains", type=int, default=20)

    p.add_argument("--timeout-s", type=float, default=15.0)
    p.add_argument("--max-attempts", type=int, default=3)
    p.add_argument("--backoff-base-s", type=float, default=0.8)
    p.add_argument("--backoff-jitter-s", type=float, default=0.2)
    p.add_argument("--sleep-ms", type=int, default=0, help="sleep between requests (ms)")
    p.add_argument("--user-agent", default="Mozilla/5.0 (compatible; rtb_scan_sync/1.0)")

    # Debug/testing options
    p.add_argument("--insecure", action="store_true", default=True,
                  help="Disable TLS cert verification (default: enabled for test).")
    p.add_argument("--secure", dest="insecure", action="store_false",
                  help="Enable TLS cert verification.")
    p.add_argument("--raw-max-chars", type=int, default=20000,
                  help="Trim raw payload if exceeds this JSON size; 0 keeps full raw (default: 20000).")

    p.add_argument("--out-dir", default="./out_test")
    p.add_argument("-v", "--verbose", action="count", default=1)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    log = configure_logging(args.verbose)

    out_dir = Path(args.out_dir)
    writers = Writers(out_dir)

    labels = iter_labels(args.min_len, args.max_len, args.start_label, args.start_mode)
    total = 0

    try:
        for domain, label in iter_domains(labels, args.tld):
            r = fetch_one(domain, label, args.tld, args.base_url, args, log)
            writers.write_one(r)
            total += 1

            if total % 5 == 0:
                writers.flush()
                log.info(
                    "progress=%s last=%s ok=%s http=%s exact_supported=%s exact_domain=%s",
                    total, r.domain, r.ok, r.http_status, r.exact_match_is_supported, r.exact_match_domain
                )

            if args.sleep_ms > 0:
                time.sleep(args.sleep_ms / 1000.0)

            if args.max_domains and total >= args.max_domains:
                break

        writers.flush()
        log.info("done. wrote=%s outputs=%s,%s", total, writers.jsonl_path, writers.csv_path)
        return 0
    finally:
        writers.close()


if __name__ == "__main__":
    raise SystemExit(main())

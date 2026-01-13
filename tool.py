




#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Namecheap bulk availability checker for <label>.<tld> with base-36 label enumeration.

Key features:
- Streaming generation of labels (base-36 counter over alphabet a-z0-9)
- Batch calls to Namecheap namecheap.domains.check (max 50 per request)
- Retry with exponential backoff, basic throttling support
- Canary check to prevent useless runs (e.g., TLD unsupported/invalid)
- Append-safe outputs: JSONL + CSV (+ optional available_only.csv)
- Resume using checkpoint.json with periodic atomic checkpoint writes
- Controlled concurrency with ordered writing/checkpointing

Authoring intent: production-grade operational stability.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import csv
import dataclasses
import datetime as dt
import json
import logging
import os
import random
import re
import sys
import time
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    # Optional dependency (recommended). If absent, ENV-only is fine.
    from dotenv import load_dotenv  # type: ignore
except Exception:  # pragma: no cover
    load_dotenv = None  # type: ignore

import xml.etree.ElementTree as ET


ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
ALPHABET_INDEX = {ch: i for i, ch in enumerate(ALPHABET)}
BASE = len(ALPHABET)  # 36

NAMECHEAP_LIVE_ENDPOINT = "https://api.namecheap.com/xml.response"
NAMECHEAP_SANDBOX_ENDPOINT = "https://api.sandbox.namecheap.com/xml.response"

MAX_DOMAINS_PER_CHECK = 50  # per official docs :contentReference[oaicite:2]{index=2}


# ---------------------------
# Data models
# ---------------------------

@dataclasses.dataclass(frozen=True)
class DomainCheckItem:
    domain: str
    label: str
    tld: str


@dataclasses.dataclass
class DomainCheckResult:
    domain: str
    label: str
    tld: str
    available: bool
    premium: Optional[bool] = None
    price: Optional[float] = None
    currency: Optional[str] = None
    checked_at: str = ""
    error: Optional[str] = None
    raw: Optional[dict] = None


@dataclasses.dataclass
class Checkpoint:
    tld: str
    min_len: int
    max_len: int
    next_label: Optional[str]
    processed: int
    updated_at: str

    @staticmethod
    def path(out_dir: Path) -> Path:
        return out_dir / "checkpoint.json"


# ---------------------------
# Utilities: base-36 labels
# ---------------------------

def validate_label(label: str) -> None:
    if not label:
        raise ValueError("label is empty")
    for ch in label:
        if ch not in ALPHABET_INDEX:
            raise ValueError(
                f"Invalid label '{label}': character '{ch}' not in allowed alphabet a-z0-9"
            )


def index_to_label(index: int, length: int) -> str:
    """Convert 0 <= index < 36^length to base-36 string with fixed length."""
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


def label_to_index(label: str) -> int:
    """Convert base-36 label to integer index in [0, 36^len-1]."""
    validate_label(label)
    x = 0
    for ch in label:
        x = x * BASE + ALPHABET_INDEX[ch]
    return x


def iter_labels(min_len: int,
                max_len: int,
                start_label: Optional[str] = None,
                start_mode: str = "include") -> Iterator[str]:
    """
    Yield labels in order:
      len=1: a..z 0..9
      len=2: aa..99
      ...
    start_label: if provided, start at label (include) or after it.
    """
    if min_len < 1 or max_len < min_len:
        raise ValueError("invalid min_len/max_len")

    start_len = None
    start_idx = None
    if start_label is not None:
        validate_label(start_label)
        start_len = len(start_label)
        start_idx = label_to_index(start_label)
        if start_mode not in ("include", "after"):
            raise ValueError("start_mode must be 'include' or 'after'")
        if start_mode == "after":
            start_idx += 1

    for length in range(min_len, max_len + 1):
        total = BASE ** length

        if start_label is None or start_len is None:
            begin = 0
        elif length < start_len:
            continue
        elif length == start_len:
            begin = min(max(start_idx or 0, 0), total)
        else:
            begin = 0

        for idx in range(begin, total):
            yield index_to_label(idx, length)


# ---------------------------
# Namecheap client
# ---------------------------

class NamecheapError(RuntimeError):
    pass


def build_requests_session(timeout_s: float, max_retries: int) -> requests.Session:
    """
    requests.Session with retry for transient HTTP issues.
    Note: Namecheap throttling behavior may appear as 429/503 or sometimes as XML error;
    we handle both transport- and application-level errors.
    """
    session = requests.Session()
    retry = Retry(
        total=max_retries,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET", "POST"),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.request = _wrap_timeout(session.request, timeout_s)
    return session


def _wrap_timeout(func, timeout_s: float):
    def wrapped(*args, **kwargs):
        kwargs.setdefault("timeout", timeout_s)
        return func(*args, **kwargs)
    return wrapped


def parse_namecheap_xml(xml_text: str) -> Tuple[dict, List[dict]]:
    """
    Returns:
      meta: dict with Status, Errors (list), Warnings (list), RequestedCommand, Server, ExecutionTime
      results: list of domain result dicts with keys:
        Domain, Available, IsPremiumName, PremiumRegistrationPrice, ... (as strings)
    """
    root = ET.fromstring(xml_text)

    # Namespace handling: xmlns="http://api.namecheap.com/xml.response"
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    status = root.attrib.get("Status", "")
    errors_el = root.find(f"{ns}Errors")
    warnings_el = root.find(f"{ns}Warnings")
    requested_cmd_el = root.find(f"{ns}RequestedCommand")
    server_el = root.find(f"{ns}Server")
    exec_el = root.find(f"{ns}ExecutionTime")

    errors: List[dict] = []
    if errors_el is not None:
        for err in errors_el.findall(f"{ns}Error"):
            errors.append({
                "Number": err.attrib.get("Number"),
                "Text": (err.text or "").strip(),
            })

    warnings: List[str] = []
    if warnings_el is not None:
        for w in warnings_el.findall(f"{ns}Warning"):
            warnings.append((w.text or "").strip())

    meta = {
        "Status": status,
        "Errors": errors,
        "Warnings": warnings,
        "RequestedCommand": (requested_cmd_el.text or "").strip() if requested_cmd_el is not None else "",
        "Server": (server_el.text or "").strip() if server_el is not None else "",
        "ExecutionTime": (exec_el.text or "").strip() if exec_el is not None else "",
    }

    results: List[dict] = []
    cmd_resp = root.find(f"{ns}CommandResponse")
    if cmd_resp is not None:
        for dcr in cmd_resp.findall(f"{ns}DomainCheckResult"):
            results.append(dict(dcr.attrib))

    return meta, results


def is_tld_unsupported_error(meta: dict) -> bool:
    """
    Heuristic: for canary, stop early if errors indicate invalid/unsupported TLD.
    Namecheap may emit textual errors (e.g., 'TLD is invalid', 'TLD is not supported in API').
    Error code lists show similar wording for other commands; for check, docs do not list all TLD errors,
    so we match by message text. :contentReference[oaicite:3]{index=3}
    """
    errors = meta.get("Errors") or []
    combined = " | ".join((e.get("Text") or "") for e in errors).lower()
    patterns = [
        r"\btld\b.*\binvalid\b",
        r"\btld\b.*\bnot supported\b",
        r"\bnot supported\b.*\btld\b",
        r"\binvalid\b.*\btld\b",
        r"\bunsupported\b.*\btld\b",
        r"\btld is not supported\b",
        r"\btld is invalid\b",
    ]
    return any(re.search(p, combined) for p in patterns)


class NamecheapClient:
    def __init__(
        self,
        api_user: str,
        api_key: str,
        username: str,
        client_ip: str,
        endpoint: str,
        currency_default: str = "USD",
        timeout_s: float = 30.0,
        max_transport_retries: int = 3,
        app_max_attempts: int = 5,
        app_backoff_base_s: float = 1.0,
        app_backoff_jitter_s: float = 0.2,
        logger: Optional[logging.Logger] = None,
    ):
        self.api_user = api_user
        self.api_key = api_key
        self.username = username
        self.client_ip = client_ip
        self.endpoint = endpoint
        self.currency_default = currency_default
        self.session = build_requests_session(timeout_s, max_transport_retries)
        self.app_max_attempts = app_max_attempts
        self.app_backoff_base_s = app_backoff_base_s
        self.app_backoff_jitter_s = app_backoff_jitter_s
        self.log = logger or logging.getLogger(__name__)

    def domains_check(self, domains: Sequence[str]) -> Tuple[dict, List[dict]]:
        if not domains:
            raise ValueError("domains list is empty")
        if len(domains) > MAX_DOMAINS_PER_CHECK:
            raise ValueError(f"Namecheap allows max {MAX_DOMAINS_PER_CHECK} domains per check request")

        params = {
            "ApiUser": self.api_user,
            "ApiKey": self.api_key,
            "UserName": self.username,
            "ClientIp": self.client_ip,
            "Command": "namecheap.domains.check",
            "DomainList": ",".join(domains),
        }

        last_exc: Optional[Exception] = None
        for attempt in range(1, self.app_max_attempts + 1):
            try:
                resp = self.session.get(self.endpoint, params=params)
                text = resp.text
                meta, results = parse_namecheap_xml(text)

                # Application-level errors in XML
                if meta.get("Status") != "OK":
                    err_text = json.dumps(meta.get("Errors", []), ensure_ascii=False)
                    # Backoff and retry for likely throttling/temporary issues
                    if self._is_retryable_meta(meta) and attempt < self.app_max_attempts:
                        self._sleep_backoff(attempt, reason=f"API Status={meta.get('Status')} errors={err_text}")
                        continue
                    raise NamecheapError(f"Namecheap API Status={meta.get('Status')} errors={err_text}")

                # Some throttling may still return Status=OK but include error entries
                if meta.get("Errors"):
                    err_text = json.dumps(meta.get("Errors", []), ensure_ascii=False)
                    if self._is_retryable_meta(meta) and attempt < self.app_max_attempts:
                        self._sleep_backoff(attempt, reason=f"Errors present: {err_text}")
                        continue

                return meta, results

            except (requests.RequestException, ET.ParseError, NamecheapError) as e:
                last_exc = e
                if attempt < self.app_max_attempts:
                    self._sleep_backoff(attempt, reason=f"exception={type(e).__name__}: {e}")
                    continue
                break

        raise NamecheapError(f"Namecheap domains.check failed after {self.app_max_attempts} attempts: {last_exc}")

    def _sleep_backoff(self, attempt: int, reason: str) -> None:
        base = self.app_backoff_base_s * (2 ** (attempt - 1))
        jitter = random.uniform(0, self.app_backoff_jitter_s)
        sleep_s = base + jitter
        self.log.warning("Retrying after backoff: attempt=%s sleep=%.2fs reason=%s", attempt, sleep_s, reason)
        time.sleep(sleep_s)

    def _is_retryable_meta(self, meta: dict) -> bool:
        # Heuristic: treat some error texts as retryable
        errors = meta.get("Errors") or []
        txt = " ".join((e.get("Text") or "") for e in errors).lower()
        retryable_markers = [
            "too many requests",
            "throttle",
            "temporar",
            "try again",
            "timeout",
            "service unavailable",
            "rate limit",
        ]
        return any(m in txt for m in retryable_markers)


# ---------------------------
# Output writers (append-safe)
# ---------------------------

class OutputWriters:
    def __init__(self, out_dir: Path, write_available_only: bool):
        self.out_dir = out_dir
        self.out_dir.mkdir(parents=True, exist_ok=True)

        self.jsonl_path = out_dir / "results.jsonl"
        self.csv_path = out_dir / "results.csv"
        self.avail_csv_path = out_dir / "available_only.csv"

        self.write_available_only = write_available_only

        self._csv_file = None
        self._csv_writer = None
        self._avail_csv_file = None
        self._avail_csv_writer = None

        self._open_files()

    def _open_files(self) -> None:
        # JSONL: append always safe
        self._jsonl_file = self.jsonl_path.open("a", encoding="utf-8", newline="\n")

        # CSV: create header if new/empty
        self._csv_file = self.csv_path.open("a", encoding="utf-8", newline="")
        self._csv_writer = csv.DictWriter(
            self._csv_file,
            fieldnames=["domain", "label", "available", "premium", "price", "currency", "checked_at"],
        )
        if self.csv_path.stat().st_size == 0:
            self._csv_writer.writeheader()
            self._csv_file.flush()

        if self.write_available_only:
            self._avail_csv_file = self.avail_csv_path.open("a", encoding="utf-8", newline="")
            self._avail_csv_writer = csv.DictWriter(
                self._avail_csv_file,
                fieldnames=["domain", "label", "available", "premium", "price", "currency", "checked_at"],
            )
            if self.avail_csv_path.exists() and self.avail_csv_path.stat().st_size == 0:
                self._avail_csv_writer.writeheader()
                self._avail_csv_file.flush()
            elif not self.avail_csv_path.exists():
                # open("a") will have created it; ensure header
                self._avail_csv_writer.writeheader()
                self._avail_csv_file.flush()

    def write_many(self, rows: Sequence[DomainCheckResult]) -> None:
        for r in rows:
            obj = dataclasses.asdict(r)
            self._jsonl_file.write(json.dumps(obj, ensure_ascii=False) + "\n")

            self._csv_writer.writerow({
                "domain": r.domain,
                "label": r.label,
                "available": str(bool(r.available)).lower(),
                "premium": "" if r.premium is None else str(bool(r.premium)).lower(),
                "price": "" if r.price is None else f"{r.price:.4f}",
                "currency": "" if r.currency is None else r.currency,
                "checked_at": r.checked_at,
            })

            if self.write_available_only and r.available and self._avail_csv_writer is not None:
                self._avail_csv_writer.writerow({
                    "domain": r.domain,
                    "label": r.label,
                    "available": "true",
                    "premium": "" if r.premium is None else str(bool(r.premium)).lower(),
                    "price": "" if r.price is None else f"{r.price:.4f}",
                    "currency": "" if r.currency is None else r.currency,
                    "checked_at": r.checked_at,
                })

        self._jsonl_file.flush()
        self._csv_file.flush()
        if self.write_available_only and self._avail_csv_file is not None:
            self._avail_csv_file.flush()

    def close(self) -> None:
        for f in [getattr(self, "_jsonl_file", None), self._csv_file, self._avail_csv_file]:
            try:
                if f:
                    f.close()
            except Exception:
                pass


# ---------------------------
# Checkpointing
# ---------------------------

def atomic_write_json(path: Path, data: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def load_checkpoint(out_dir: Path) -> Optional[Checkpoint]:
    p = Checkpoint.path(out_dir)
    if not p.exists():
        return None
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return Checkpoint(
            tld=d["tld"],
            min_len=int(d["min_len"]),
            max_len=int(d["max_len"]),
            next_label=d.get("next_label"),
            processed=int(d.get("processed", 0)),
            updated_at=d.get("updated_at", ""),
        )
    except Exception:
        return None


def save_checkpoint(out_dir: Path, cp: Checkpoint) -> None:
    p = Checkpoint.path(out_dir)
    atomic_write_json(p, dataclasses.asdict(cp))


# ---------------------------
# Core pipeline
# ---------------------------

def chunked(iterable: Iterable[str], size: int) -> Iterator[List[str]]:
    buf: List[str] = []
    for x in iterable:
        buf.append(x)
        if len(buf) >= size:
            yield buf
            buf = []
    if buf:
        yield buf


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def domain_items_from_labels(labels: Sequence[str], tld: str) -> List[DomainCheckItem]:
    return [DomainCheckItem(domain=f"{lab}.{tld}", label=lab, tld=tld) for lab in labels]


def parse_bool(s: str) -> bool:
    return str(s).strip().lower() == "true"


def safe_float(s: Optional[str]) -> Optional[float]:
    if s is None:
        return None
    s = s.strip()
    if not s:
        return None
    try:
        return float(s)
    except Exception:
        return None


def check_batch(
    client: NamecheapClient,
    items: Sequence[DomainCheckItem],
    currency_default: str,
) -> Tuple[List[DomainCheckResult], dict]:
    """
    Returns: (per-domain results, batch_raw_meta)
    batch_raw_meta: minimal for debugging
    """
    domains = [it.domain for it in items]
    checked_at = now_iso()

    try:
        meta, results = client.domains_check(domains)

        # Build lookup from response
        by_domain: Dict[str, dict] = {r.get("Domain", ""): r for r in results}

        out: List[DomainCheckResult] = []
        for it in items:
            r = by_domain.get(it.domain)
            if not r:
                out.append(DomainCheckResult(
                    domain=it.domain, label=it.label, tld=it.tld,
                    available=False,
                    premium=None, price=None, currency=None,
                    checked_at=checked_at,
                    error="missing DomainCheckResult in response",
                    raw={"meta": meta},
                ))
                continue

            available = parse_bool(r.get("Available", "false"))
            is_premium = parse_bool(r.get("IsPremiumName", "false"))
            price = safe_float(r.get("PremiumRegistrationPrice")) if is_premium else None

            out.append(DomainCheckResult(
                domain=it.domain,
                label=it.label,
                tld=it.tld,
                available=available,
                premium=is_premium,
                price=price,
                currency=currency_default if (is_premium and price is not None) else None,
                checked_at=checked_at,
                error=None,
                raw={
                    "meta": {
                        "Status": meta.get("Status"),
                        "Errors": meta.get("Errors"),
                        "ExecutionTime": meta.get("ExecutionTime"),
                        "Server": meta.get("Server"),
                    },
                    "attrs": r,
                },
            ))

        batch_raw = {
            "Status": meta.get("Status"),
            "Errors": meta.get("Errors"),
            "ExecutionTime": meta.get("ExecutionTime"),
            "Server": meta.get("Server"),
        }
        return out, batch_raw

    except Exception as e:
        # Mark all items errored
        err = f"{type(e).__name__}: {e}"
        out = [DomainCheckResult(
            domain=it.domain, label=it.label, tld=it.tld,
            available=False,
            premium=None, price=None, currency=None,
            checked_at=checked_at,
            error=err,
            raw=None,
        ) for it in items]
        return out, {"error": err}


def run_canary(client: NamecheapClient, tld: str, log: logging.Logger) -> None:
    samples = [f"a.{tld}", f"aa.{tld}", f"zzz.{tld}"]
    log.info("Running canary check: %s", ", ".join(samples))
    meta, _ = client.domains_check(samples)

    if meta.get("Errors") and is_tld_unsupported_error(meta):
        err_text = json.dumps(meta.get("Errors", []), ensure_ascii=False)
        raise SystemExit(
            f"Canary failed: Namecheap API indicates TLD '{tld}' is invalid/unsupported. "
            f"Errors={err_text}. Stopping to avoid useless scan."
        )

    # If errors exist but not clearly TLD-related, still stop; otherwise you risk noisy full scans.
    if meta.get("Errors"):
        err_text = json.dumps(meta.get("Errors", []), ensure_ascii=False)
        raise SystemExit(
            f"Canary failed: Namecheap API returned errors for '{tld}'. Errors={err_text}. "
            f"Please fix credentials/IP/access or confirm TLD support before scanning."
        )

    log.info("Canary OK (no TLD/support errors detected).")


def configure_logging(verbosity: int) -> logging.Logger:
    level = logging.INFO
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 0:
        level = logging.WARNING

    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    return logging.getLogger("domain_tool")


def load_env(dotenv_path: Optional[str], log: logging.Logger) -> None:
    if load_dotenv is None:
        if dotenv_path:
            log.warning("python-dotenv not installed; ignoring --dotenv. Install with: pip install python-dotenv")
        return
    load_dotenv(dotenv_path=dotenv_path, override=False)


def require_env(var: str) -> str:
    v = os.getenv(var, "").strip()
    if not v:
        raise SystemExit(f"Missing required environment variable: {var}")
    return v


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render <label>.<tld> using base-36 labels (a-z0-9), check Namecheap availability in batches, output JSONL/CSV with resume.",
    )
    parser.add_argument("--tld", default="uk.com", help="TLD part (default: uk.com)")
    parser.add_argument("--min-len", type=int, default=1, help="Minimum label length (default: 1)")
    parser.add_argument("--max-len", type=int, default=3, help="Maximum label length (default: 3)")
    parser.add_argument("--start-label", default=None, help="Start label for resume/manual start, e.g., ab, a9, 000")
    parser.add_argument("--start-mode", choices=["include", "after"], default="include",
                        help="Whether to include or start after --start-label (default: include)")
    parser.add_argument("--resume", action="store_true", help="Resume from checkpoint.json (if exists)")
    parser.add_argument("--checkpoint-every", type=int, default=500,
                        help="Write checkpoint every N domains written (default: 500)")
    parser.add_argument("--batch-size", type=int, default=50, help="Domains per API call (default: 50; max 50)")
    parser.add_argument("--concurrency", type=int, default=1, help="Concurrent in-flight batches (default: 1)")
    parser.add_argument("--sleep-ms", type=int, default=200, help="Sleep between batches in ms (default: 200)")
    parser.add_argument("--out-dir", default="./out", help="Output directory (default: ./out)")
    parser.add_argument("--available-only", action="store_true", help="Also write available_only.csv")
    parser.add_argument("--sandbox", action="store_true", help="Use Namecheap sandbox endpoint")
    parser.add_argument("--currency", default="USD", help="Currency label for premium price (default: USD)")
    parser.add_argument("--dotenv", default=None, help="Path to .env file (default: none; if installed python-dotenv)")
    parser.add_argument("--skip-canary", action="store_true", help="Skip canary check (not recommended)")
    parser.add_argument("-v", "--verbose", action="count", default=1, help="Increase verbosity (use -vv for debug)")

    args = parser.parse_args(argv)

    log = configure_logging(args.verbose)
    load_env(args.dotenv, log)

    # Enforce constraints
    if args.batch_size < 1:
        raise SystemExit("--batch-size must be >= 1")
    if args.batch_size > MAX_DOMAINS_PER_CHECK:
        log.warning("batch-size=%s exceeds Namecheap max=%s; clamping to %s",
                    args.batch_size, MAX_DOMAINS_PER_CHECK, MAX_DOMAINS_PER_CHECK)
        args.batch_size = MAX_DOMAINS_PER_CHECK  # per docs :contentReference[oaicite:4]{index=4}

    if args.concurrency < 1 or args.concurrency > 10:
        raise SystemExit("--concurrency must be in [1, 10] (operational safety bound)")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Resolve start_label from checkpoint if resume
    start_label = args.start_label
    processed_from_checkpoint = 0
    if args.resume:
        cp = load_checkpoint(out_dir)
        if cp:
            processed_from_checkpoint = cp.processed
            if start_label is None:
                start_label = cp.next_label
                # Resume should generally include next_label (already computed)
                args.start_mode = "include"
            log.info("Loaded checkpoint: next_label=%s processed=%s updated_at=%s",
                     cp.next_label, cp.processed, cp.updated_at)
        else:
            log.info("No checkpoint found; starting fresh.")

    # Validate start_label if any
    if start_label is not None:
        validate_label(start_label)

    # Credentials (ENV/.env)
    api_user = require_env("NAMECHEAP_API_USER")
    api_key = require_env("NAMECHEAP_API_KEY")
    username = require_env("NAMECHEAP_USERNAME")
    client_ip = require_env("NAMECHEAP_CLIENT_IP")

    endpoint = NAMECHEAP_SANDBOX_ENDPOINT if args.sandbox else NAMECHEAP_LIVE_ENDPOINT

    client = NamecheapClient(
        api_user=api_user,
        api_key=api_key,
        username=username,
        client_ip=client_ip,
        endpoint=endpoint,
        currency_default=args.currency,
        logger=log,
    )

    if not args.skip_canary:
        run_canary(client, args.tld, log)

    writers = OutputWriters(out_dir=out_dir, write_available_only=args.available_only)

    # Prepare label iterator
    labels_iter = iter_labels(
        min_len=args.min_len,
        max_len=args.max_len,
        start_label=start_label,
        start_mode=args.start_mode,
    )

    # Progress tracking & checkpointing
    start_time = time.time()
    processed = processed_from_checkpoint
    since_checkpoint = 0
    last_label_written: Optional[str] = None

    # Concurrency with ordered writing/checkpointing:
    # - Submit up to N batches
    # - Always write results in submission order (stable checkpoint progression)
    executor = cf.ThreadPoolExecutor(max_workers=args.concurrency)
    in_flight: List[cf.Future] = []
    batch_queue: List[List[str]] = []

    def submit_one(batch_labels: List[str]) -> cf.Future:
        items = domain_items_from_labels(batch_labels, args.tld)
        return executor.submit(check_batch, client, items, args.currency)

    try:
        # Prime pipeline
        for batch_labels in chunked(labels_iter, args.batch_size):
            batch_queue.append(batch_labels)
            in_flight.append(submit_one(batch_labels))
            if len(in_flight) >= args.concurrency:
                break

        # Main loop
        while in_flight:
            # Always take oldest future to preserve order
            fut = in_flight.pop(0)
            batch_labels = batch_queue.pop(0)

            rows, batch_raw = fut.result()
            writers.write_many(rows)

            processed += len(rows)
            since_checkpoint += len(rows)
            last_label_written = batch_labels[-1] if batch_labels else last_label_written

            # Determine next_label for checkpoint (immediately after last_label_written)
            next_label = None
            if last_label_written is not None:
                # Compute next label by treating current as start_label in "after" mode
                # but without building a new iterator: do base-36 increment with carry.
                next_label = increment_label(last_label_written)

            # Periodic checkpoint
            if since_checkpoint >= args.checkpoint_every:
                cp = Checkpoint(
                    tld=args.tld,
                    min_len=args.min_len,
                    max_len=args.max_len,
                    next_label=next_label,
                    processed=processed,
                    updated_at=now_iso(),
                )
                save_checkpoint(out_dir, cp)
                since_checkpoint = 0

            # Console progress
            elapsed = max(time.time() - start_time, 1e-6)
            rate = processed / elapsed
            log.info(
                "Progress: processed=%s last_label=%s rate=%.2f domains/s batch_raw=%s",
                processed, last_label_written, rate, batch_raw if args.verbose >= 2 else {"Status": batch_raw.get("Status"), "error": batch_raw.get("error")}
            )

            # Sleep between batches (rate limiting hygiene)
            if args.sleep_ms > 0:
                time.sleep(args.sleep_ms / 1000.0)

            # Refill pipeline
            while len(in_flight) < args.concurrency:
                try:
                    next_batch = next(chunked(labels_iter, args.batch_size))
                except StopIteration:
                    break
                batch_queue.append(next_batch)
                in_flight.append(submit_one(next_batch))

        # Final checkpoint
        next_label_final = increment_label(last_label_written) if last_label_written else start_label
        cp = Checkpoint(
            tld=args.tld,
            min_len=args.min_len,
            max_len=args.max_len,
            next_label=next_label_final,
            processed=processed,
            updated_at=now_iso(),
        )
        save_checkpoint(out_dir, cp)

        log.info("Done. Total processed=%s. Outputs: %s, %s",
                 processed, writers.jsonl_path, writers.csv_path)
        if args.available_only:
            log.info("Also wrote: %s", writers.avail_csv_path)
        return 0

    finally:
        writers.close()
        executor.shutdown(wait=True)


def increment_label(label: str) -> Optional[str]:
    """
    Return the next label in the same length if possible; otherwise carry to longer length
    is not handled here (because enumeration increases length only after finishing shorter lengths).
    For checkpointing, we DO want cross-length carry. Therefore:
      - If label is the last label of its length (e.g., '9', '99', '999'), we return None to indicate
        "next is the first label of next length" in the global iterator.
    Caller can treat None as "advance length boundary".
    """
    if label is None:
        return None
    validate_label(label)
    length = len(label)
    idx = label_to_index(label)
    max_idx = (BASE ** length) - 1
    if idx >= max_idx:
        return None
    return index_to_label(idx + 1, length)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)

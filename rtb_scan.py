#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Async scanner for Namecheap RTB picks endpoint:
  https://rtb.namecheapapi.com/api/picks/<domain>

WARNING:
- This is NOT the official Namecheap DomainsCheck API.
- Response may be masked, unstable, rate-limited, or blocked.
- It may not represent availability. Use at your own risk and ensure you have permission.

Features:
- Async HTTP with aiohttp
- Concurrency limit (semaphore)
- Retry + exponential backoff for 429/5xx/timeouts
- Streaming domain generation (base-36 a-z0-9) OR input file
- JSONL + CSV output (append-safe)
- Progress logs

Install:
  pip install aiohttp
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import datetime as dt
import json
import logging
import os
import random
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Iterable, Iterator, List, Optional, Tuple

import aiohttp

ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
ALPHABET_INDEX = {ch: i for i, ch in enumerate(ALPHABET)}
BASE = len(ALPHABET)  # 36

DEFAULT_BASE_URL = "https://rtb.namecheapapi.com/api/picks"


# ---------------------------
# Base-36 label generator
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


def iter_domains_from_labels(labels: Iterable[str], tld: str) -> Iterator[Tuple[str, str]]:
    for lab in labels:
        yield f"{lab}.{tld}", lab


# ---------------------------
# Data model + output
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

    # extracted fields (best-effort)
    exact_match_domain: Optional[str] = None
    exact_match_tld: Optional[str] = None
    exact_match_is_supported: Optional[bool] = None
    exact_match_campaign_type: Optional[Any] = None
    enable_cart_verification: Optional[bool] = None

    # raw (minimal)
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

    def write_many(self, rows: List[RTBResult]) -> None:
        for r in rows:
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
# HTTP client
# ---------------------------

def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def extract_fields(payload: Dict[str, Any]) -> Dict[str, Any]:
    exact = payload.get("exact_match") or {}
    # best-effort: fields may vary
    return {
        "raw_type": payload.get("type"),
        "exact_match_domain": exact.get("domain"),
        "exact_match_tld": exact.get("tld"),
        "exact_match_is_supported": exact.get("is_supported"),
        "exact_match_campaign_type": exact.get("campaignType"),
        "enable_cart_verification": exact.get("enable_cart_verification"),
    }


async def fetch_one(
    session: aiohttp.ClientSession,
    base_url: str,
    domain: str,
    label: str,
    tld: str,
    *,
    timeout_s: float,
    max_attempts: int,
    backoff_base_s: float,
    backoff_jitter_s: float,
) -> RTBResult:
    url = f"{base_url.rstrip('/')}/{domain}"
    checked_at = now_iso()

    last_err: Optional[str] = None
    last_status: Optional[int] = None

    for attempt in range(1, max_attempts + 1):
        try:
            async with session.get(url, timeout=timeout_s) as resp:
                last_status = resp.status
                text = await resp.text()

                if resp.status in (429, 500, 502, 503, 504):
                    last_err = f"HTTP {resp.status}"
                    if attempt < max_attempts:
                        await asyncio.sleep(backoff_base_s * (2 ** (attempt - 1)) + random.uniform(0, backoff_jitter_s))
                        continue
                    return RTBResult(domain, label, tld, checked_at, ok=False, http_status=resp.status, error=last_err)

                # Expect JSON
                try:
                    payload = json.loads(text)
                except Exception as e:
                    return RTBResult(domain, label, tld, checked_at, ok=False, http_status=resp.status,
                                     error=f"JSON parse error: {e}", raw={"text": text[:500]})

                fields = extract_fields(payload)
                return RTBResult(
                    domain=domain,
                    label=label,
                    tld=tld,
                    checked_at=checked_at,
                    ok=True,
                    http_status=resp.status,
                    raw_type=fields["raw_type"],
                    exact_match_domain=fields["exact_match_domain"],
                    exact_match_tld=fields["exact_match_tld"],
                    exact_match_is_supported=fields["exact_match_is_supported"],
                    exact_match_campaign_type=fields["exact_match_campaign_type"],
                    enable_cart_verification=fields["enable_cart_verification"],
                    raw=payload,  # you can trim if too big
                )

        except asyncio.TimeoutError:
            last_err = "timeout"
        except aiohttp.ClientError as e:
            last_err = f"aiohttp error: {e}"
        except Exception as e:
            last_err = f"unexpected error: {type(e).__name__}: {e}"

        if attempt < max_attempts:
            await asyncio.sleep(backoff_base_s * (2 ** (attempt - 1)) + random.uniform(0, backoff_jitter_s))

    return RTBResult(domain, label, tld, checked_at, ok=False, http_status=last_status, error=last_err)


async def worker_loop(
    name: str,
    queue: "asyncio.Queue[Tuple[str, str]]",
    session: aiohttp.ClientSession,
    base_url: str,
    tld: str,
    sem: asyncio.Semaphore,
    results_out: "asyncio.Queue[RTBResult]",
    args: argparse.Namespace,
    log: logging.Logger,
) -> None:
    while True:
        item = await queue.get()
        if item is None:  # type: ignore
            queue.task_done()
            return
        domain, label = item
        async with sem:
            r = await fetch_one(
                session,
                base_url,
                domain,
                label,
                tld,
                timeout_s=args.timeout_s,
                max_attempts=args.max_attempts,
                backoff_base_s=args.backoff_base_s,
                backoff_jitter_s=args.backoff_jitter_s,
            )
        await results_out.put(r)
        queue.task_done()


async def writer_loop(
    results_in: "asyncio.Queue[RTBResult]",
    writers: Writers,
    *,
    flush_every: int,
    log: logging.Logger,
) -> None:
    buf: List[RTBResult] = []
    processed = 0
    while True:
        r = await results_in.get()
        if r is None:  # type: ignore
            results_in.task_done()
            break
        buf.append(r)
        processed += 1
        results_in.task_done()

        if len(buf) >= flush_every:
            writers.write_many(buf)
            log.info("Written %s results (last=%s ok=%s http=%s)",
                     processed, buf[-1].domain, buf[-1].ok, buf[-1].http_status)
            buf = []

    if buf:
        writers.write_many(buf)
        log.info("Written final %s buffered results", len(buf))


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
    return logging.getLogger("rtb_scan")


def iter_input_domains(path: Path) -> Iterator[str]:
    # One domain per line, allow blank/comment lines
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        yield s


async def main_async(args: argparse.Namespace) -> int:
    log = configure_logging(args.verbose)

    out_dir = Path(args.out_dir)
    writers = Writers(out_dir)

    queue: asyncio.Queue[Tuple[str, str]] = asyncio.Queue(maxsize=args.queue_size)
    results_q: asyncio.Queue[RTBResult] = asyncio.Queue(maxsize=args.queue_size)

    sem = asyncio.Semaphore(args.concurrency)

    timeout = aiohttp.ClientTimeout(total=None)  # we pass per-request timeout explicitly

    headers = {
        "User-Agent": args.user_agent,
        "Accept": "application/json,text/plain,*/*",
    }

    connector = aiohttp.TCPConnector(limit=0, ssl=True)

    async with aiohttp.ClientSession(timeout=timeout, headers=headers, connector=connector) as session:
        # start workers
        workers = [
            asyncio.create_task(worker_loop(f"w{i}", queue, session, args.base_url, args.tld, sem, results_q, args, log))
            for i in range(args.concurrency)
        ]
        writer_task = asyncio.create_task(writer_loop(results_q, writers, flush_every=args.flush_every, log=log))

        # producer
        produced = 0

        if args.input_file:
            # use provided domains
            for d in iter_input_domains(Path(args.input_file)):
                # derive label (best-effort: left part before .tld)
                label = d.split(".", 1)[0]
                await queue.put((d, label))
                produced += 1
        else:
            labels = iter_labels(args.min_len, args.max_len, args.start_label, args.start_mode)
            for domain, label in iter_domains_from_labels(labels, args.tld):
                await queue.put((domain, label))
                produced += 1
                if args.max_domains and produced >= args.max_domains:
                    break

        log.info("Enqueued %s domains. Waiting for completion...", produced)

        # signal workers to stop
        for _ in workers:
            await queue.put(None)  # type: ignore

        await queue.join()

        # stop writer
        await results_q.put(None)  # type: ignore
        await results_q.join()

        for w in workers:
            await w
        await writer_task

    writers.close()
    log.info("Done. Outputs: %s, %s", writers.jsonl_path, writers.csv_path)
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser("rtb_scan.py", description="Async caller for rtb.namecheapapi.com picks endpoint.")
    p.add_argument("--tld", default="uk.com", help="TLD (default: uk.com)")
    p.add_argument("--base-url", default=DEFAULT_BASE_URL, help=f"Base URL (default: {DEFAULT_BASE_URL})")

    # generator mode
    p.add_argument("--min-len", type=int, default=1)
    p.add_argument("--max-len", type=int, default=3)
    p.add_argument("--start-label", default=None)
    p.add_argument("--start-mode", choices=["include", "after"], default="include")
    p.add_argument("--max-domains", type=int, default=0, help="Limit total domains (0 = no limit)")

    # input-file mode
    p.add_argument("--input-file", default=None, help="Optional: file containing domains, one per line")

    # async/runtime
    p.add_argument("--concurrency", type=int, default=10, help="Concurrent requests (default: 10)")
    p.add_argument("--queue-size", type=int, default=2000)
    p.add_argument("--timeout-s", type=float, default=20.0)
    p.add_argument("--max-attempts", type=int, default=5)
    p.add_argument("--backoff-base-s", type=float, default=0.8)
    p.add_argument("--backoff-jitter-s", type=float, default=0.2)
    p.add_argument("--flush-every", type=int, default=50)
    p.add_argument("--user-agent", default="Mozilla/5.0 (compatible; rtb_scan/1.0)")
    p.add_argument("--out-dir", default="./out_rtb")
    p.add_argument("-v", "--verbose", action="count", default=1)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if args.max_domains == 0:
        args.max_domains = None
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        raise SystemExit(130)

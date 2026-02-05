import argparse
import csv
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Filter: exactly 3 labels (label.xx.yyy)
# label length 1..6, allowed chars: a-z 0-9 -
DOMAIN_RE = re.compile(
    r"^(?P<label>[a-z0-9-]{1,6})\.(?P<sld>[a-z0-9-]+)\.(?P<tld>[a-z0-9-]+)$",
    re.IGNORECASE,
)


def _sanitize_json_text(text: str) -> str:
    """
    Best-effort fix for common malformed JSON cases like:
      - subdomains: [...] (missing quotes on key)
      - missing comma between "success": true and subdomains
      - missing comma between ] and "cached"
    """
    # Quote key if needed: subdomains: -> "subdomains":
    text = re.sub(r'(\bsubdomains)\s*:', r'"\1":', text)

    # Insert comma between: "success": true "subdomains":
    text = re.sub(
        r'("success"\s*:\s*(true|false))\s*("subdomains"\s*:)',
        r"\1,\n\3",
        text,
        flags=re.IGNORECASE,
    )

    # Insert comma between end of array and next key: ] "cached":
    text = re.sub(
        r'(\])\s*("cached"\s*:)',
        r"\1,\n\2",
        text,
        flags=re.IGNORECASE,
    )

    # Insert comma between end of object and next key: } "cached":
    text = re.sub(
        r'(\})\s*("cached"\s*:)',
        r"\1,\n\2",
        text,
        flags=re.IGNORECASE,
    )

    return text


def load_json_file(path: Path) -> Optional[Dict[str, Any]]:
    raw = path.read_text(encoding="utf-8", errors="ignore").strip()
    if not raw:
        return None

    # Try normal JSON
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    # Try sanitized JSON
    try:
        fixed = _sanitize_json_text(raw)
        return json.loads(fixed)
    except json.JSONDecodeError as e:
        print(f"[WARN] JSON parse failed: {path.name} ({e})")
        return None


def ip_to_available(ip_value: Any) -> str:
    """
    Mapping rule (your requirement):
      - ip == "none"  -> Yes
      - otherwise (e.g. real IP) -> No
    """
    if isinstance(ip_value, str) and ip_value.strip().lower() == "none":
        return "Yes"
    return "No"


def iter_subdomain_records(obj: Dict[str, Any]) -> Iterable[Tuple[str, str]]:
    """
    Yield (domain, available) from obj["subdomains"] list of objects.
    """
    subs = obj.get("subdomains")
    if not isinstance(subs, list):
        return

    for item in subs:
        if not isinstance(item, dict):
            continue

        sd = item.get("subdomain")
        if not isinstance(sd, str) or not sd.strip():
            continue

        domain = sd.strip().lower().rstrip(".")
        available = ip_to_available(item.get("ip"))

        yield domain, available


def filter_records(records: Iterable[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """
    Keep only domains matching label.xx.yyy where label length 1..6.
    De-dup by domain (first occurrence wins).
    """
    out: List[Tuple[str, str]] = []
    seen = set()

    for domain, available in records:
        if domain in seen:
            continue
        if DOMAIN_RE.match(domain):
            seen.add(domain)
            out.append((domain, available))
    return out


def write_csv_chunks(records: List[Tuple[str, str]], out_dir: Path, chunk_size: int = 1000) -> List[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    written: List[Path] = []

    total = len(records)
    if total == 0:
        return written

    file_index = 1
    for i in range(0, total, chunk_size):
        chunk = records[i : i + chunk_size]
        out_path = out_dir / f"results_{ts}_{file_index:06d}.csv"

        with out_path.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            # Dynadot format like your screenshot
            w.writerow(["domain", "available", "is_2_years"])
            for domain, available in chunk:
                w.writerow([domain, available, ""])

        written.append(out_path)
        file_index += 1

    return written


def main():
    ap = argparse.ArgumentParser(
        description="Read JSON in input/, extract subdomains, filter label.xx.yyy (label 1..6), export Dynadot CSV (1000 per file)."
    )
    ap.add_argument("--input", default="input", help="Input folder containing .json files (default: input)")
    ap.add_argument("--output", default="out_dynadot", help="Output folder for CSV files (default: out_dynadot)")
    ap.add_argument("--chunk", type=int, default=1000, help="Domains per CSV file (default: 1000)")
    args = ap.parse_args()

    in_dir = Path(args.input)
    out_dir = Path(args.output)

    if not in_dir.exists() or not in_dir.is_dir():
        raise SystemExit(f"[ERR] Input folder not found: {in_dir.resolve()}")

    json_files = sorted(in_dir.glob("*.json"))
    if not json_files:
        raise SystemExit(f"[ERR] No .json files in: {in_dir.resolve()}")

    extracted_count = 0
    all_records: List[Tuple[str, str]] = []

    for p in json_files:
        data = load_json_file(p)
        if not isinstance(data, dict):
            continue

        recs = list(iter_subdomain_records(data))
        extracted_count += len(recs)
        all_records.extend(recs)

    filtered = filter_records(all_records)
    written = write_csv_chunks(filtered, out_dir, chunk_size=args.chunk)

    print(f"[OK] JSON files: {len(json_files)}")
    print(f"[OK] Extracted records: {extracted_count}")
    print(f"[OK] Matched pattern: {len(filtered)}")
    print(f"[OK] CSV written: {len(written)} -> {out_dir.resolve()}")
    if written:
        print(f"[OK] Example output: {written[0].name}")


if __name__ == "__main__":
    main()

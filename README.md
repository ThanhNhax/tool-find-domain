# Namecheap bulk domain checker (base-36 label) — CLI

Tool sinh domain dạng:

với `label` chỉ gồm **a-z** và **0-9** (36 ký tự), theo cơ chế **base-36 counter**:

- `len=1`: `a..z` rồi `0..9`
- `len=2`: `aa..az`, `a0..a9`, `ba..`, …, `99`
- `len=3`: `aaa..999`
- ... tăng dần theo `--max-len`

Sau đó tool check availability bằng Namecheap API `namecheap.domains.check` theo batch và ghi output ra:
- `results.jsonl` (append-safe)
- `results.csv` (append-safe)
- (optional) `available_only.csv`
- `checkpoint.json` để resume

---

## 1) Yêu cầu

- Python **3.10+**
- `requests`
- Khuyến nghị: `python-dotenv` để đọc `.env`

Cài đặt:

```bash
pip install -U requests python-dotenv


python tool.py --tld uk.com --min-len 1 --max-len 3 --batch-size 100 --out-dir ./out


python tool.py --tld uk.com --max-len 4 --start-label ab --start-mode after --out-dir ./out



python dynadot_bulk_scan_sync.py   --tld uk.com --min-len 3 --max-len 3   --tier super --batch-size 5   --limit 200   --out-dir ./out_dynadot   --insecure
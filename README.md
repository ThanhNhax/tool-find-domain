# Namecheap bulk domain checker (base-36 label) — CLI

Tool sinh toàn bộ domain dạng:

  <label>.<tld>

với label chỉ gồm **a-z** và **0-9** (36 ký tự), theo cơ chế **base-36 counter**:
- len=1: a..z 0..9
- len=2: aa..az a0..a9 ba.. 99
- len=3: aaa..999
- ... (tăng dần theo `--max-len`)

Sau đó check availability bằng Namecheap API `namecheap.domains.check` theo batch,
ghi output ra:
- `results.jsonl` (append-safe)
- `results.csv` (append-safe)
- (optional) `available_only.csv`

Ngoài ra có `checkpoint.json` để resume.

## Yêu cầu
- Python 3.10+
- `requests`
- (khuyến nghị) `python-dotenv` để đọc `.env`

Cài đặt:
```bash
pip install requests python-dotenv

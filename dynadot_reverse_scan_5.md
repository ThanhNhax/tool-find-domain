# dynadot_reverse_scan_5.py — Hướng dẫn sử dụng nhanh

Tool CLI dùng để **scan availability domain qua Dynadot REST v2 (bulk_search)** theo cơ chế **base-36 nhưng chạy NGƯỢC**.

Mục tiêu chính:

- Scan nhanh phần **cuối của không gian domain** (ví dụ: `zzz → aaa`)
- Mỗi lần gọi API **5 domain** (an toàn, đúng tier `regular`)
- Ghi output gọn: `domain` + giá trị `available` (`Yes` / `No`)

---

## 1. Nguyên lý hoạt động

- Sinh domain dạng:

```
<label>.<tld>
```

- `label` gồm **36 ký tự**:

```
a-z + 0-9
```

- Thứ tự sinh: **NGƯỢC**

```
zzz → zzy → zzx → ... → aaa
```

- Mỗi request:
  - Gọi Dynadot API với **5 domain / lần**
  - Không convert `Yes/No`

---

## 2. Yêu cầu

- Python **3.10+**
- File `.env` chứa API key:

```env
DYNADOT_API_KEY=xxxxx
```

> `.env` phải nằm cùng thư mục với `dynadot_reverse_scan_5.py`

---

## 3. Output

Tool ghi kết quả ra CSV, **tự rotate 1000 record / file**:

```
out_dynadot/
  results_YYYYMMDD_HHMMSS_000001.csv
  results_YYYYMMDD_HHMMSS_000002.csv
```

### Format CSV

```csv
domain,available
zzz.eu.com,No
zzy.eu.com,Yes
```

- `available` giữ **nguyên giá trị API trả về** (`Yes` / `No`)

---

## 4. Câu lệnh chạy cơ bản

### Ví dụ: scan 3 ký tự, tối đa 2000 domain

```bash
python dynadot_reverse_scan_5.py \
  --tld eu.com \
  --min-len 3 \
  --max-len 3 \
  --limit 2000 \
  --out-dir ./out_dynadot \
  --insecure
```

### Giải thích nhanh

| Flag         | Ý nghĩa                                    |
| ------------ | ------------------------------------------ |
| `--tld`      | TLD cần scan (vd: `eu.com`)                |
| `--min-len`  | Độ dài label tối thiểu                     |
| `--max-len`  | Độ dài label tối đa                        |
| `--limit`    | Tổng domain scan (0 = không giới hạn)      |
| `--out-dir`  | Thư mục output                             |
| `--insecure` | Tắt SSL verify (fix lỗi cert trên Windows) |

---

## 5. Log khi chạy

Tool sẽ log để báo **script đang chạy**:

```text
[RUNNING] scanned=5 last=zzz.eu.com avail=No http=200
[RUNNING] scanned=10 last=zzy.eu.com avail=Yes http=200
```

Nếu không thấy log:

- Kiểm tra `--limit`
- Kiểm tra API key
- Kiểm tra network / SSL

---

## 6. Lỗi thường gặp

### ❌ Missing DYNADOT_API_KEY

```text
Missing DYNADOT_API_KEY
```

➡️ Kiểm tra:

- File `.env` có đúng tên không
- Có chạy lệnh trong đúng folder không

Test nhanh:

```bash
python -c "import os; print(os.getenv('DYNADOT_API_KEY'))"
```

---

### ❌ SSL: CERTIFICATE_VERIFY_FAILED

➡️ Thêm flag:

```bash
--insecure
```

---

## 7. Khi nào nên dùng tool này?

- Muốn scan **cuối dải domain** (premium / hiếm)
- Muốn test nhanh Dynadot availability
- Không cần web UI
- Chạy batch nhỏ, an toàn API

---

## 8. Ghi chú

- Tool **không resume**, nên dùng `--limit` để chia nhỏ block scan
- Có thể chạy nhiều lần, output append-safe

---

Internal / Private use.

add IP dynadot

python dynadot_reverse_scan_5.py --tld uk.com --min-len 3 --max-len 6 --out-dir ./out_dynadot

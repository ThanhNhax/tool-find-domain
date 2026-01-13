Test nhanh 5 domain

python dynadot_bulk_scan_sync.py \
  --tld uk.com \
  --min-len 3 --max-len 3 \
  --tier super \
  --batch-size 5 \
  --limit 5 \
  --insecure
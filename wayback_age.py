import json
from datetime import datetime, timezone
from urllib import request, error

API_TEMPLATE = "https://web.archive.org/__wb/sparkline?output=json&url={url}&collection=web"

def parseWaybackTs(ts: str) -> datetime:
    if not isinstance(ts, str):
        raise ValueError("timestamp is not a string")
    if len(ts) != 14 or not ts.isdigit():
        raise ValueError("timestamp must be 14 digits")
    try:
        return datetime.strptime(ts, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError("timestamp has invalid date/time components") from exc


def fetchSparkline(url: str) -> dict:
    api_url = API_TEMPLATE.format(url=url)
    # Internet Archive may reject requests without browser-like headers.
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
            "User-Agent": "wayback-age-tool/1.0 (+https://example.com)",
            "Accept": "application/json",
        },
    ]

    last_err = None
    for headers in headers_list:
        req = request.Request(api_url, method="GET", headers=headers)
        try:
            with request.urlopen(req, timeout=20) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"HTTP error: {resp.status}")
                data = resp.read().decode("utf-8")
                return json.loads(data)
        except error.HTTPError as exc:
            last_err = exc
            if exc.code != 498:
                raise RuntimeError(f"HTTP error: {exc.code}") from exc
        except error.URLError as exc:
            last_err = exc
            raise RuntimeError(f"Network error: {exc.reason}") from exc
        except json.JSONDecodeError as exc:
            raise ValueError("JSON parse error") from exc

    if isinstance(last_err, error.HTTPError):
        raise RuntimeError(f"HTTP error: {last_err.code}") from last_err
    if last_err is not None:
        raise RuntimeError("Request failed") from last_err

    raise RuntimeError("Request failed")


def evaluateAge(first_ts: str) -> bool:
    first_dt = parseWaybackTs(first_ts)
    now_utc = datetime.now(timezone.utc)
    delta_days = (now_utc - first_dt).days
    return delta_days >= 730


def main(url: str) -> None:
    data = fetchSparkline(url)
    first_ts = data.get("first_ts")
    last_ts = data.get("last_ts")

    if not first_ts or not last_ts:
        raise KeyError("Missing first_ts/last_ts in response")

    first_iso = parseWaybackTs(first_ts).strftime("%Y-%m-%dT%H:%M:%SZ")
    last_iso = parseWaybackTs(last_ts).strftime("%Y-%m-%dT%H:%M:%SZ")

    result = {
        "url": url,
        "first_ts": first_ts,
        "last_ts": last_ts,
        "first_iso": first_iso,
        "last_iso": last_iso,
        "is_at_least_2_years": evaluateAge(first_ts),
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main("4v9.mex.com")

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    res.status(405).json({ error: 'Method Not Allowed' });
    return;
  }

  const domain = String(req.query.domain || '').trim();
  if (!domain) {
    res.status(400).json({ error: 'Missing domain' });
    return;
  }

  const url =
    'https://web.archive.org/__wb/sparkline?output=json&url=' +
    encodeURIComponent(domain) +
    '&collection=web';

  const headers = {
    accept: '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'cache-control': 'no-cache',
    pragma: 'no-cache',
    referer: 'https://web.archive.org/web/20260000000000*/' + domain,
    'user-agent':
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
  };

  const cookie = process.env.WAYBACK_COOKIE;
  if (cookie) {
    headers.cookie = cookie;
  }

  try {
    const { statusCode, body } = await httpGet(url, headers);
    res.status(statusCode || 200);
    res.setHeader('content-type', 'application/json; charset=utf-8');
    res.send(body || '{}');
  } catch (err) {
    res.status(502).json({ error: 'Wayback fetch failed', detail: String(err) });
  }
}

function httpGet(url, headers) {
  return new Promise((resolve, reject) => {
    const https = require('https');
    const req = https.request(
      url,
      {
        method: 'GET',
        headers,
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          resolve({ statusCode: res.statusCode, body: data });
        });
      },
    );
    req.on('error', reject);
    req.end();
  });
}

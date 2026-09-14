// bazzar-udid — приём UDID для регистрации сертификата, размещён на российском
// хостинге (Timeweb), чтобы установка профиля работала из РФ без VPN.
// Зависимостей нет — только встроенный http. Порт берётся из окружения (Timeweb задаёт PORT).
const http = require('http');

const MARKET_URL = (process.env.MARKET_URL || 'https://bazzar-serts.shop').replace(/\/+$/, '');
const PORT = process.env.PORT || 3000;

function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// Apple OTA Profile Service enrollment profile (unsigned).
// URL — это наш же /receive (на том же российском хосте).
function buildProfile(receiveUrl) {
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
    '<plist version="1.0">',
    '<dict>',
    '  <key>PayloadContent</key>',
    '  <dict>',
    '    <key>URL</key>',
    `    <string>${esc(receiveUrl)}</string>`,
    '    <key>DeviceAttributes</key>',
    '    <array>',
    '      <string>UDID</string>',
    '      <string>VERSION</string>',
    '      <string>PRODUCT</string>',
    '    </array>',
    '  </dict>',
    '  <key>PayloadOrganization</key>',
    '  <string>Bazzar Certs</string>',
    '  <key>PayloadDisplayName</key>',
    '  <string>Bazzar Certs</string>',
    '  <key>PayloadVersion</key>',
    '  <integer>1</integer>',
    '  <key>PayloadUUID</key>',
    '  <string>9F025114-16CA-4AE1-B0E3-F5E5170B1E6E</string>',
    '  <key>PayloadIdentifier</key>',
    '  <string>com.bazzar.certs.enroll</string>',
    '  <key>PayloadDescription</key>',
    '  <string>Разрешите доступ к идентификатору устройства для регистрации сертификата Bazzar Certs.</string>',
    '  <key>PayloadType</key>',
    '  <string>Profile Service</string>',
    '</dict>',
    '</plist>',
  ].join('\n');
}

const server = http.createServer((req, res) => {
  let u;
  try {
    u = new URL(req.url, `https://${req.headers.host || 'localhost'}`);
  } catch {
    res.writeHead(400); return res.end('bad request');
  }
  const path = u.pathname;
  const host = req.headers.host || 'udid.bazzar-serts.shop';

  // Health check (Timeweb дергает /health).
  if (path === '/health' || path === '/') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
    return res.end('ok');
  }

  // GET /generate?code=... → отдаём .mobileconfig. Callback (URL) ведёт на наш же /receive.
  if (path === '/generate' && (req.method === 'GET' || req.method === 'HEAD')) {
    const code = u.searchParams.get('code') || '';
    let receiveUrl = `https://${host}/receive`;
    if (code) receiveUrl += `?code=${encodeURIComponent(code)}`;
    const xml = buildProfile(receiveUrl);
    res.writeHead(200, {
      'Content-Type': 'application/x-apple-aspen-config; charset=utf-8',
      'Content-Disposition': 'attachment; filename="bazzar-enroll.mobileconfig"',
      'Cache-Control': 'no-store',
    });
    return res.end(req.method === 'HEAD' ? undefined : xml);
  }

  // POST /receive → iPhone присылает подписанный PKCS#7 с атрибутами; вытаскиваем UDID.
  if (path === '/receive' && req.method === 'POST') {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > 1_000_000) { req.destroy(); return; } // защита от мусора
      chunks.push(c);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      const m = raw.match(/<key>UDID<\/key>\s*<string>([^<]+)<\/string>/);
      const udid = m ? m[1] : null;
      const pm = raw.match(/<key>PRODUCT<\/key>\s*<string>([^<]+)<\/string>/);
      const product = pm ? pm[1] : '';
      const code = u.searchParams.get('code') || '';
      if (!udid) {
        res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end('Failed to extract UDID');
      }
      let redirect = `${MARKET_URL}/auth?udid=${encodeURIComponent(udid)}&model=${encodeURIComponent(product)}`;
      if (code) redirect += `&code=${encodeURIComponent(code)}`;
      // Safari сам пройдёт по 301 и вернёт пользователя на сайт (российский апекс).
      res.writeHead(301, { Location: redirect });
      res.end();
    });
    req.on('error', () => { try { res.writeHead(500); res.end('error'); } catch {} });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('not found');
});

server.listen(PORT, () => console.log(`[bazzar-udid] listening on ${PORT}, market=${MARKET_URL}`));

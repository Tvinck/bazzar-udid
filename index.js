// bazzar-udid — российский фронт (Timeweb) для флоу установки, чтобы всё работало из РФ без VPN.
// 1) Приём UDID: /generate (профиль) + /receive (UDID -> 301 на /auth) + /health.
// 2) Прокси подписи: /api/* -> немецкий сигнер (signer origin), т.к. Cloudflare из РФ режется,
//    а origin сигнера имеет самоподписанный серт (напрямую iOS не примет). Телефон видит только
//    российский хост с валидным HTTPS; прокси сам ходит на сигнер (сервер->сервер работает).
const http = require('http');
const https = require('https');
const cluster = require('cluster');

const MARKET_URL = (process.env.MARKET_URL || 'https://bazzar-serts.shop').replace(/\/+$/, '');
const PORT = process.env.PORT || 3000;
// Origin сигнера: прямой IP немецкого VPS + его vhost (самоподписанный серт игнорируем на стороне сервера).
const SIGNER_ORIGIN_IP = process.env.SIGNER_ORIGIN_IP || '103.227.84.8';
const SIGNER_HOST = process.env.SIGNER_HOST || 'signer.bazzar-serts.shop';

function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

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

// Соединения с сигнером держим открытыми и переиспользуем: без этого каждый запрос заново делал TLS-рукопожатие
// с Германией (лишние ~0,2–0,5 с и нагрузка на процессор).
const signerAgent = new https.Agent({ keepAlive: true, keepAliveMsecs: 15000, maxSockets: 256, maxFreeSockets: 32 });

// Разрешение браузеру (CORS). Сигнер отдаёт его сам, но если прокси отвечает ошибкой без него, Safari видит
// не «сервер занят», а «Load failed» — и сайт не может сам повторить запрос (клиенту — «Нет связи»).
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS',
  'Access-Control-Max-Age': '86400',
};

// Прокси запроса на origin сигнера (немецкий VPS, самоподписанный серт → rejectUnauthorized:false).
function proxyToSigner(req, res, u) {
  // Предварительный запрос браузера (OPTIONS) отвечаем сами — без поездки в Германию; кэшируется на сутки.
  if (req.method === 'OPTIONS') {
    res.writeHead(204, { ...CORS, 'Access-Control-Allow-Headers': req.headers['access-control-request-headers'] || 'Content-Type' });
    return res.end();
  }
  const headers = { ...req.headers, host: SIGNER_HOST };
  delete headers['accept-encoding']; // пусть отдаёт как есть, без сюрпризов со сжатием
  delete headers.connection; // соединением с сигнером управляет agent (keep-alive)
  const options = {
    host: SIGNER_ORIGIN_IP,
    port: 443,
    method: req.method,
    path: u.pathname + (u.search || ''),
    servername: SIGNER_HOST,
    rejectUnauthorized: false,
    agent: signerAgent,
    headers,
    timeout: 60000,
  };
  const fail = (status, code, message) => {
    if (res.headersSent) { res.destroy(); return; } // файл уже начали отдавать — просто обрываем
    try {
      res.writeHead(status, { ...CORS, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify({ success: false, code, error: message }));
    } catch {}
  };
  const up = https.request(options, (upRes) => {
    res.writeHead(upRes.statusCode || 502, upRes.headers);
    upRes.pipe(res);
  });
  up.on('timeout', () => { up.destroy(Object.assign(new Error('upstream timeout'), { code: 'UPSTREAM_TIMEOUT' })); });
  up.on('error', (e) => {
    console.error(`[bazzar-udid] signer ${req.method} ${u.pathname}: ${e.code || ''} ${e.message}`);
    // 503/504 — сайт сам подождёт и повторит; клиент увидит «сервер занят», а не «нет связи»
    if (e.code === 'UPSTREAM_TIMEOUT') fail(504, 'SIGNER_TIMEOUT', 'Сервер подписи не ответил вовремя. Повторяем…');
    else fail(503, 'SIGNER_UNREACHABLE', 'Сервер подписи временно недоступен. Повторяем…');
  });
  // клиент ушёл (закрыл страницу / оборвал загрузку) — не качаем файл из Германии впустую
  res.on('close', () => { if (!res.writableFinished) up.destroy(); });
  req.pipe(up);
}

const server = http.createServer((req, res) => {
  let u;
  try {
    u = new URL(req.url, `https://${req.headers.host || 'localhost'}`);
  } catch {
    res.writeHead(400); return res.end('bad request');
  }
  const path = u.pathname;
  const host = (req.headers.host || 'udid.bazzar-serts.shop').toLowerCase();

  // Короткий бренд-домен bzzr.su (для коротких ссылок в приложениях) → наш сайт, любой адрес.
  if (host === 'bzzr.su' || host === 'www.bzzr.su') {
    res.writeHead(301, { Location: MARKET_URL + u.pathname + u.search, 'Cache-Control': 'no-store' });
    return res.end();
  }

  // Прокси подписи на сигнер (/api/sign, /api/jobs, /api/manifest, /api/download, ...).
  if (path.startsWith('/api/')) {
    return proxyToSigner(req, res, u);
  }

  if (path === '/health' || path === '/') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
    return res.end('ok');
  }

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

  if (path === '/receive' && req.method === 'POST') {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > 1_000_000) { req.destroy(); return; }
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
      res.writeHead(301, { Location: redirect });
      res.end();
    });
    req.on('error', () => { try { res.writeHead(500); res.end('error'); } catch {} });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('not found');
});

// Несколько рабочих копий — по одной на ядро (одна программа Node использует одно ядро).
// Число — env WORKERS, по умолчанию 2 (под конфигурацию 2 ядра; os.cpus() в контейнере показывает ядра хоста).
// Копия упала — главный процесс поднимает новую.
const WORKERS = Math.max(1, Number(process.env.WORKERS) || 2);
if (cluster.isPrimary && WORKERS > 1) {
  for (let i = 0; i < WORKERS; i++) cluster.fork();
  cluster.on('exit', (w, code, sig) => {
    console.error(`[bazzar-udid] worker ${w.process.pid} exited (${sig || code}) — restarting`);
    setTimeout(() => cluster.fork(), 1000);
  });
  console.log(`[bazzar-udid] primary ${process.pid}: ${WORKERS} workers on ${PORT}`);
} else {
  server.listen(PORT, () => console.log(`[bazzar-udid] ${cluster.isWorker ? 'worker ' + process.pid : 'single'} listening on ${PORT}, market=${MARKET_URL}, signer=${SIGNER_ORIGIN_IP}`));
}

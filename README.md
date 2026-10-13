# bazzar-udid

Небольшой сервис приёма UDID для регистрации сертификата Bazzar Certs.
Размещается на российском хостинге (Timeweb App Platform), чтобы установка
профиля работала из России без VPN (зарубежный `api.bazzar-serts.shop` за
Cloudflare из РФ системным установщиком iOS не пробивается).

## Endpoints
- `GET /generate?code=<order>` — отдаёт `.mobileconfig` (Apple OTA Profile Service). Callback (`URL`) ведёт на `/receive` этого же хоста.
- `POST /receive?code=<order>` — принимает подписанный ответ iPhone, вытаскивает UDID и делает `301` на `https://bazzar-serts.shop/auth?udid=...&model=...&code=...`.
- `GET /health` — проверка состояния.

## Запуск
```
npm start   # node index.js, слушает process.env.PORT (Timeweb задаёт сам)
```
Env: `MARKET_URL` (по умолчанию `https://bazzar-serts.shop`), `PORT`, `WORKERS` (рабочих копий, по умолчанию 2 — по одной на ядро), `SIGNER_ORIGIN_IP`, `SIGNER_HOST`.

Прокси `/api/*` → сервер подписи: соединения переиспользуются (keep-alive); предварительный запрос браузера (OPTIONS) отвечается сразу; если сервер подписи недоступен — `503`/`504` JSON с CORS (сайт сам повторит), а не «Load failed».

Зависимостей нет — только встроенный `http`.

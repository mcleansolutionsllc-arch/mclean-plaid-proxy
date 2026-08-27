# McLean Plaid Proxy

Minimal Node.js proxy that sits between the McLean Solutions calculators app and Plaid's API. It exists because the app's hosting environment (Perplexity `pplx.app`) strips Plaid body-authentication fields, which breaks direct Plaid calls.

## What it does

- Accepts HMAC-authenticated requests from the McLean calculators app
- Forwards them to Plaid's Production API with the real `client_id` and `secret`
- Returns Plaid's response to the caller

## Auth

Every call must include:
- `X-Signature`: hex HMAC-SHA256 of `<timestamp>.<rawBody>` using `HMAC_SHARED_SECRET`
- `X-Timestamp`: unix millis (must be within 5 min of server time)

## Env vars

- `PLAID_ENV` — `production` or `sandbox`
- `PLAID_CLIENT_ID` — Plaid client ID
- `PLAID_SECRET` — Plaid API secret
- `HMAC_SHARED_SECRET` — 64-char hex string shared with the calculators app
- `ALLOWED_ORIGIN` — CORS origin (calculators app URL)
- `PORT` — defaults to 8080

## Health check

`GET /healthz` returns `{"ok": true, "env": "production"}` without auth.

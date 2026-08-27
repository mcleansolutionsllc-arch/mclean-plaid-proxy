/**
 * fly-plaid-proxy
 *
 * Small Express service that proxies Plaid API calls for the McLean Solutions app.
 * The pplx.app published sandbox strips Plaid's body-auth fields (client_id / secret)
 * through its outbound proxy, so those calls must be made from a host where env vars
 * flow through unmodified. This service runs on Fly.io and injects client_id + secret
 * into each Plaid request body server-side.
 *
 * Security:
 *   - Every /plaid/* route requires an HMAC-SHA256 signature over `${ts}.${rawBody}`
 *     using HMAC_SHARED_SECRET, delivered via X-Signature + X-Timestamp headers.
 *   - CORS is restricted to ALLOWED_ORIGIN (comma-separated).
 *   - No request/response bodies or secrets are ever logged.
 */

import express, { type Request, type Response, type NextFunction } from "express";
import cors from "cors";
import crypto from "node:crypto";
import "dotenv/config";

// ---------------------------------------------------------------------------
// Env validation
// ---------------------------------------------------------------------------

type PlaidEnv = "sandbox" | "development" | "production";

const REQUIRED_ENV = [
  "PLAID_ENV",
  "PLAID_CLIENT_ID",
  "PLAID_SECRET",
  "HMAC_SHARED_SECRET",
  "ALLOWED_ORIGIN",
] as const;

const missing = REQUIRED_ENV.filter((k) => !process.env[k] || process.env[k]!.length === 0);
if (missing.length > 0) {
  // eslint-disable-next-line no-console
  console.error(
    JSON.stringify({
      level: "fatal",
      msg: "missing_required_env",
      missing,
    }),
  );
  process.exit(1);
}

const PLAID_ENV = process.env.PLAID_ENV as PlaidEnv;
if (!["sandbox", "development", "production"].includes(PLAID_ENV)) {
  // eslint-disable-next-line no-console
  console.error(
    JSON.stringify({
      level: "fatal",
      msg: "invalid_plaid_env",
      value: PLAID_ENV,
    }),
  );
  process.exit(1);
}

const PLAID_CLIENT_ID = process.env.PLAID_CLIENT_ID!;
const PLAID_SECRET = process.env.PLAID_SECRET!;
const HMAC_SHARED_SECRET = process.env.HMAC_SHARED_SECRET!;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN!;
const PORT = parseInt(process.env.PORT ?? "8080", 10);

const PLAID_HOST: string = (() => {
  switch (PLAID_ENV) {
    case "sandbox":
      return "https://sandbox.plaid.com";
    case "development":
      return "https://development.plaid.com";
    case "production":
      return "https://production.plaid.com";
  }
})();

const ALLOWED_ORIGINS = ALLOWED_ORIGIN.split(",").map((s) => s.trim()).filter(Boolean);

// Signature freshness window (ms).
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;

// Upstream request timeout (ms).
const PLAID_TIMEOUT_MS = 20_000;

// ---------------------------------------------------------------------------
// App setup
// ---------------------------------------------------------------------------

const app = express();
app.disable("x-powered-by");

app.use(
  cors({
    origin(origin, cb) {
      // Allow same-origin / server-to-server requests with no Origin header.
      if (!origin) return cb(null, true);
      if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      return cb(new Error("origin_not_allowed"));
    },
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "X-Signature", "X-Timestamp"],
  }),
);

// Capture raw body buffer for HMAC verification while still parsing JSON.
app.use(
  express.json({
    limit: "1mb",
    verify: (req, _res, buf) => {
      (req as Request & { rawBody?: Buffer }).rawBody = Buffer.from(buf);
    },
  }),
);

// ---------------------------------------------------------------------------
// Structured request logging (no bodies, no secrets)
// ---------------------------------------------------------------------------

app.use((req: Request, res: Response, next: NextFunction) => {
  const started = Date.now();
  res.on("finish", () => {
    const line = {
      ts: new Date().toISOString(),
      method: req.method,
      path: req.path,
      status: res.statusCode,
      ms: Date.now() - started,
      plaidReqId: (res.getHeader("x-plaid-request-id") as string | undefined) ?? null,
    };
    // eslint-disable-next-line no-console
    console.log(JSON.stringify(line));
  });
  next();
});

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

app.get("/healthz", (_req: Request, res: Response) => {
  res.json({
    status: "ok",
    plaidEnv: PLAID_ENV,
    clientIdPrefix: PLAID_CLIENT_ID.slice(0, 6),
  });
});

// ---------------------------------------------------------------------------
// HMAC auth middleware
// ---------------------------------------------------------------------------

function verifyHmac(req: Request, res: Response, next: NextFunction): void {
  const sig = req.header("X-Signature");
  const tsHeader = req.header("X-Timestamp");

  if (!sig || !tsHeader) {
    res.status(401).json({ error: "unauthorized", reason: "missing_signature_headers" });
    return;
  }

  const ts = Number(tsHeader);
  if (!Number.isFinite(ts)) {
    res.status(401).json({ error: "unauthorized", reason: "invalid_timestamp" });
    return;
  }

  if (Math.abs(Date.now() - ts) > MAX_CLOCK_SKEW_MS) {
    res.status(401).json({ error: "unauthorized", reason: "stale_timestamp" });
    return;
  }

  const rawBody = (req as Request & { rawBody?: Buffer }).rawBody ?? Buffer.alloc(0);
  const payload = Buffer.concat([
    Buffer.from(`${tsHeader}.`, "utf8"),
    rawBody,
  ]);

  const expected = crypto
    .createHmac("sha256", HMAC_SHARED_SECRET)
    .update(payload)
    .digest();

  let provided: Buffer;
  try {
    provided = Buffer.from(sig, "hex");
  } catch {
    res.status(401).json({ error: "unauthorized", reason: "bad_signature_encoding" });
    return;
  }

  if (provided.length !== expected.length) {
    res.status(401).json({ error: "unauthorized", reason: "bad_signature" });
    return;
  }

  if (!crypto.timingSafeEqual(provided, expected)) {
    res.status(401).json({ error: "unauthorized", reason: "bad_signature" });
    return;
  }

  next();
}

// ---------------------------------------------------------------------------
// Plaid forwarding helper
// ---------------------------------------------------------------------------

async function forwardToPlaid(
  plaidPath: string,
  incomingBody: Record<string, unknown>,
  res: Response,
): Promise<void> {
  const url = `${PLAID_HOST}${plaidPath}`;
  const body = {
    ...(incomingBody ?? {}),
    client_id: PLAID_CLIENT_ID,
    secret: PLAID_SECRET,
  };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PLAID_TIMEOUT_MS);

  try {
    const upstream = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    const plaidReqId = upstream.headers.get("x-plaid-request-id");
    if (plaidReqId) res.setHeader("x-plaid-request-id", plaidReqId);

    const text = await upstream.text();
    res.status(upstream.status);
    const ct = upstream.headers.get("content-type");
    if (ct) res.setHeader("Content-Type", ct);
    res.send(text);
  } catch (err) {
    const message =
      err instanceof Error
        ? err.name === "AbortError"
          ? "upstream_timeout"
          : err.message
        : "unknown_error";
    res.status(502).json({ error: "upstream_error", message });
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// Plaid endpoints
// ---------------------------------------------------------------------------

const PLAID_ROUTES: Array<{ route: string; plaidPath: string }> = [
  { route: "/plaid/link/token/create", plaidPath: "/link/token/create" },
  { route: "/plaid/item/public_token/exchange", plaidPath: "/item/public_token/exchange" },
  { route: "/plaid/accounts/get", plaidPath: "/accounts/get" },
  { route: "/plaid/transactions/sync", plaidPath: "/transactions/sync" },
  { route: "/plaid/transactions/get", plaidPath: "/transactions/get" },
  { route: "/plaid/item/remove", plaidPath: "/item/remove" },
  { route: "/plaid/institutions/get_by_id", plaidPath: "/institutions/get_by_id" },
];

for (const { route, plaidPath } of PLAID_ROUTES) {
  app.post(route, verifyHmac, async (req: Request, res: Response) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    await forwardToPlaid(plaidPath, body, res);
  });
}

// Generic passthrough — safety valve for endpoints not explicitly listed above.
app.post("/plaid/passthrough", verifyHmac, async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as { path?: unknown; data?: unknown };
  const path = typeof body.path === "string" ? body.path : "";
  if (!path.startsWith("/")) {
    res.status(400).json({ error: "invalid_request", message: "path must start with /" });
    return;
  }
  const data =
    body.data && typeof body.data === "object" && !Array.isArray(body.data)
      ? (body.data as Record<string, unknown>)
      : {};
  await forwardToPlaid(path, data, res);
});

// ---------------------------------------------------------------------------
// Error handler (catches CORS rejections, JSON parse errors, etc.)
// ---------------------------------------------------------------------------

app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  const message = err instanceof Error ? err.message : "error";
  if (message === "origin_not_allowed") {
    res.status(403).json({ error: "forbidden", reason: "origin_not_allowed" });
    return;
  }
  res.status(400).json({ error: "bad_request", message });
});

// ---------------------------------------------------------------------------
// Listen
// ---------------------------------------------------------------------------

app.listen(PORT, "0.0.0.0", () => {
  // eslint-disable-next-line no-console
  console.log(
    JSON.stringify({
      ts: new Date().toISOString(),
      level: "info",
      msg: "listening",
      port: PORT,
      plaidEnv: PLAID_ENV,
      allowedOrigins: ALLOWED_ORIGINS,
    }),
  );
});

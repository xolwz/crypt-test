import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import crypto from "node:crypto";

const app = express();
app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "16kb" }));

const MASTER = process.env.MASTER_SECRET || "";
if (MASTER.length < 32) {
  console.error("MASTER_SECRET must be set to at least 32 characters");
  process.exit(1);
}

// Optional allowlists (comma separated). Empty = allow all valid-format IDs.
const BUILDS = new Set(
  (process.env.BUILDS || "").split(",").map(s => s.trim().toLowerCase()).filter(Boolean)
);
const MACHINES = new Set(
  (process.env.MACHINES || "").split(",").map(s => s.trim().toLowerCase()).filter(Boolean)
);

const KEY_TTL = Number(process.env.KEY_TTL || 300); // seconds
const HEX64 = /^[a-f0-9]{64}$/;
const BUILD_ID = /^[a-f0-9]{16,64}$/;
const MACHINE_ID = /^[a-z0-9._:-]{8,128}$/i;

const limiter = rateLimit({
  windowMs: 60_000,
  max: Number(process.env.RATE_LIMIT || 30),
  standardHeaders: true,
  legacyHeaders: false,
});

function hmac(key, data) {
  return crypto.createHmac("sha256", key).update(data).digest();
}

function payloadKey(buildId) {
  return hmac(MASTER, `payload-key:${buildId}`);
}

function signature(buildId, nonce, expires) {
  return hmac(MASTER, `sig:${buildId}|${nonce}|${expires}`).toString("hex");
}

app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "coercionary-key-server", time: Date.now() });
});

app.post("/v1/key", limiter, (req, res) => {
  const { buildId, machineId, nonce } = req.body || {};

  if (typeof buildId !== "string" || !BUILD_ID.test(buildId))
    return res.status(400).json({ ok: false, error: "bad buildId" });
  if (typeof machineId !== "string" || !MACHINE_ID.test(machineId))
    return res.status(400).json({ ok: false, error: "bad machineId" });
  if (typeof nonce !== "string" || nonce.length < 8 || nonce.length > 128)
    return res.status(400).json({ ok: false, error: "bad nonce" });

  const b = buildId.toLowerCase();
  const m = machineId.toLowerCase();

  if (BUILDS.size && !BUILDS.has(b))
    return res.status(403).json({ ok: false, error: "unknown build" });
  if (MACHINES.size && !MACHINES.has(m))
    return res.status(403).json({ ok: false, error: "machine not licensed" });

  const expires = Math.floor(Date.now() / 1000) + KEY_TTL;
  const key = payloadKey(b).toString("hex");
  const sig = signature(b, nonce, expires);

  res.set("Cache-Control", "no-store");
  res.json({ ok: true, key, expires, sig, ttl: KEY_TTL });
});

app.post("/v1/verify", limiter, (req, res) => {
  const { buildId, nonce, expires, sig } = req.body || {};
  if (typeof buildId !== "string" || !BUILD_ID.test(buildId) ||
      typeof nonce !== "string" || !Number.isInteger(expires) ||
      typeof sig !== "string" || sig.length !== 64)
    return res.status(400).json({ ok: false, error: "bad request" });

  const b = buildId.toLowerCase();
  const want = signature(b, nonce, expires);
  const got = Buffer.from(sig, "hex");
  const ref = Buffer.from(want, "hex");
  const valid = got.length === ref.length && crypto.timingSafeEqual(got, ref);
  const fresh = expires >= Math.floor(Date.now() / 1000);
  res.json({ ok: valid && fresh, valid, fresh });
});

// 404
app.use((_req, res) => res.status(404).json({ ok: false, error: "not found" }));

const port = Number(process.env.PORT || 8080);
app.listen(port, "0.0.0.0", () => {
  console.log(`key server listening on 0.0.0.0:${port}`);
});

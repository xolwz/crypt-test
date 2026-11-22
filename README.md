# Coercionary Key Server

Offline payloads stay offline-crackable. This service releases the payload key
at runtime, so the file alone is not enough.

## Endpoints

### `GET /health`
```json
{ "ok": true, "service": "coercionary-key-server", "time": 1730000000000 }
```

### `POST /v1/key`
Request:
```json
{ "buildId": "a1b2c3d4e5f60718", "machineId": "abc123...", "nonce": "random-16-bytes" }
```
Response (200):
```json
{
  "ok": true,
  "key": "64 hex chars (32-byte payload key)",
  "expires": 1730000300,
  "sig": "64 hex chars HMAC",
  "ttl": 300
}
```
Errors:
- `400` bad buildId/machineId/nonce
- `403` build not in `BUILDS` allowlist, or machine not in `MACHINES`
- `429` rate limited

### `POST /v1/verify`
```json
{ "buildId": "a1b2c3d4e5f60718", "nonce": "...", "expires": 1730000300, "sig": "..." }
```
```json
{ "ok": true, "valid": true, "fresh": true }
```

## Configuration (Railway → Variables)

| Variable | Required | Meaning |
|---|---|---|
| `MASTER_SECRET` | yes | 32+ chars. Derives payload keys + signatures. |
| `BUILDS` | no | Comma-separated allowed buildIds. Empty = any valid format. |
| `MACHINES` | no | Comma-separated allowed machine ids. Empty = any valid. |
| `KEY_TTL` | no | Seconds a key response is valid. Default 300. |
| `RATE_LIMIT` | no | Requests/minute/IP. Default 30. |
| `PORT` | auto | Railway injects it. Server binds `0.0.0.0`. |

## Deploy (GitHub or CLI)

1. Push this folder to a GitHub repo.
2. Railway → New Project → Deploy from GitHub repo → select it.
3. Settings → Variables → add `MASTER_SECRET` (and optional allowlists).
4. Settings → Networking → Generate Domain.
5. Health check: `https://<domain>/health`.

CLI alternative (no GitHub):
```powershell
cd key-server
npm i -g @railway/cli
railway login
railway link
railway up
```

## Provision a build

Payload key for a build is deterministic from `MASTER_SECRET` + `buildId`:

```powershell
$env:MASTER_SECRET="<same secret as Railway>"
node tools/provision.mjs a1b2c3d4e5f60718
```
Output includes `payloadKey` (64 hex). Use that as the AES-256 key when packing
the payload for that `buildId`.

## Loader protocol

1. Generate a random `nonce` (16 bytes hex) and a stable `machineId`.
2. `POST /v1/key` with `{ buildId, machineId, nonce }` over HTTPS.
3. Verify `sig` = `HMAC-SHA256(MASTER_SECRET, "sig:" + buildId + "|" + nonce + "|" + expires)`.
   (The loader only needs to check that the response is signed; if you do not
   want the master secret in the client, skip local signature verification and
   rely on TLS plus server-side allowlists.)
4. Check `expires` is in the future.
5. Use `key` as the AES-256 payload key.

If the request fails, the payload must not decrypt. That is the point: the
file's local key share is useless without the server response.

## Notes

- Do not put `MASTER_SECRET` in the binary. Only the server holds it.
- Use `MACHINES` if you want per-machine licensing; populate it from an admin
  tool or a database later.
- The server never stores per-user secrets; keys are derived on demand.
- Keep `BUILDS` non-empty in production so random buildIds cannot fetch keys.

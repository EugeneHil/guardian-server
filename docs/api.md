# Guardian server API

This is the wire contract between `guardian-server` and its two clients: the macOS agent (Bearer token) and the admin panel (HTTP Basic). It describes what the code does; `scripts/test_docs.py` fails CI when a route or error code appears in `src/*.cpp` but not here. Policy semantics (blocklist, default allow) belong to guardian-core; the server never evaluates a request, it only stores, validates and serves policies.

Base URL: `https://<host>:8443`. Examples use `<vps-ip>`, `wdn_<64 hex>` and `<pin>` as placeholders.

## Conventions

- Every response produced by the Api carries `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`. Transport-level errors (400, 413 and 414 produced by the HTTP layer before the request reaches the Api) are JSON error bodies without these two headers.
- Every error body is JSON: `{"error":"<code>","message":"<text>"}`. Messages are fixed strings; no exception text, path or stack trace is ever returned. `invalid_events` and `invalid_draft` add an `errors` array of `{"path","message"}`.
- JSON responses use `Content-Type: application/json; charset=utf-8`. Clients must compare the media type tolerantly (do not match the whole header against `application/json`).
- Request bodies are limited to 1 MiB; larger bodies get `413 payload_too_large`.
- HEAD, OPTIONS, PATCH and DELETE are answered by the server with a JSON `405`; other unknown methods get `400`. `/healthz` answers only `GET`.

## TLS and the SPKI pin

The server certificate is self-signed (ECDSA P-256, SAN = the host). The agent does not use a CA store; it pins the hash of the certificate's public key: `base64(SHA-256(DER SubjectPublicKeyInfo))`. This is the same format as `curl --pinnedpubkey sha256//<pin>`.

Procedure:

1. On the VPS: `guardian-server cert generate --host <vps-ip>` writes the certificate and key (default directory `data/tls`) and prints `SPKI pin: <pin>`. It refuses to overwrite existing files.
2. Later, recompute the pin from the certificate alone with `guardian-server cert pin <certFile>` (prints only the pin).
3. Give `<pin>` to the agent configuration. The agent must refuse the connection when the presented key hashes to anything else. A renewed certificate has a new key (`cert generate` always creates one), so renewal changes the pin and every agent must be given the new value.
4. Check by hand: `curl --pinnedpubkey 'sha256//<pin>' -k https://<vps-ip>:8443/healthz` (`-k` only disables CA validation; the pin check still applies).

## Authentication

| Client | Header | Routes |
|---|---|---|
| Agent | `Authorization: Bearer wdn_<64 hex>` | `GET /api/v1/policy`, `POST /api/v1/events` |
| Admin | `Authorization: Basic base64(admin:<password>)` | every route under `/api/v1/admin/` and the static panel |
| none | | `GET /healthz` |

- The `agentId` is derived from the token on the server; it is never read from a request body.
- The scheme name is case-insensitive, followed by exactly one space. A Bearer value is at most 256 bytes of visible ASCII; a Basic header at most 1024 bytes.
- An agent token on an admin route, admin credentials on an agent route, a revoked token, or any malformed or oversized header all give `401`, never `500` or access.
- `agents.json` is re-read on every authentication, so `token add` / `token remove` take effect immediately without a restart.

### Throttle

- 5 consecutive failed authentications from one remote address lock that address out for 60 seconds. Every request from a locked-out address gets `429 too_many_requests` with `Retry-After: <seconds>`, even with valid credentials, and is not charged again.
- A successful authentication resets the failure count.
- The throttle is kept per realm (agent or admin) and remote address, so clients behind one NAT share it within a realm. A successful login only resets the failures of its own realm: a valid agent token does not clear failed admin attempts.
- Missing, malformed, unknown or wrong credentials each count as one failure. Unknown paths and wrong methods (`404`/`405`) are answered before authentication and do not count.

## Agent endpoints

### GET /healthz

No authentication.

```sh
curl --pinnedpubkey 'sha256//<pin>' -k https://<vps-ip>:8443/healthz
# 200 {"status":"ok","version":"0.1.0"}
```

### GET /api/v1/policy

Returns the exact stored text of the active `vN.json`; its `"version"` field equals N.

```sh
curl --pinnedpubkey 'sha256//<pin>' -k -i \
  -H 'Authorization: Bearer wdn_<64 hex>' \
  -H 'If-None-Match: "v3"' \
  https://<vps-ip>:8443/api/v1/policy
```

- `200`: body is the policy JSON, headers `ETag: "v3"` and `Content-Type: application/json; charset=utf-8`.
- `304`: the active version matches `If-None-Match`; `ETag` is set and the body is empty.
- `401` / `429`: see the table below.

ETag rules:

- The tag is `"v<N>"` (quoted, strong) where N is the active version.
- `If-None-Match` is matched against that tag. Accepted forms: `"v3"`, the weak form `W/"v3"`, a comma-separated list (`"v2", "v3"`), and `*` (matches always). Blanks around elements are ignored. A malformed element simply does not match, so the full policy is returned.
- A fresh server bootstraps an empty policy as v1 (`{"schemaVersion":1,"version":1,"rules":[]}`), so the first publish is v2.

### POST /api/v1/events

Body: a JSON array of 1 to 500 events. The batch is all-or-nothing at validation time: if any item is invalid, nothing is stored.

```sh
curl --pinnedpubkey 'sha256//<pin>' -k -i \
  -H 'Authorization: Bearer wdn_<64 hex>' \
  -H 'Content-Type: application/json' \
  --data '[{"ts":"2026-10-21T08:30:00Z",
            "process":{"path":"/usr/bin/curl","signingId":"com.apple.curl","teamId":null},
            "responsible":null,
            "file":"/Users/alice/Documents/report.pdf",
            "decision":"deny","ruleId":"block-docs"}]' \
  https://<vps-ip>:8443/api/v1/events
# 200 {"accepted":1}
```

Event format:

| Field | Type | Rule |
|---|---|---|
| `ts` | string | required, ISO-8601 UTC timestamp such as `2026-10-21T08:30:00Z` |
| `process` | object | required; `path` required string; `signingId`, `teamId` optional strings (absent or null) |
| `responsible` | object or null | optional; same shape as `process` but `path` is optional too |
| `file` | string | required |
| `decision` | string | required, exactly `"deny"` or `"allow"` |
| `ruleId` | string | optional |

All strings are at most 4096 bytes. Unknown keys are ignored. The body must be strictly valid UTF-8 and JSON nested no deeper than 64 levels. Escaped control characters in strings (for example `\u0001`) are stored verbatim (raw control bytes inside a JSON string fail parsing as `invalid JSON`); the panel escapes them.

Validation error shape (`400`), for example when item 2 has no `file`:

```json
{"error":"invalid_events","message":"One or more events are invalid.",
 "errors":[{"path":"[2].file","message":"required string"}]}
```

`path` is a JSON-path-like pointer: `$` for the whole body (`invalid UTF-8`, `nested too deeply`, `invalid JSON`, `must be an array`, `must not be empty`, `more than 500 items`) or `[i].field` for an item (messages include `required string`, `longer than 4096 bytes`, `must be an object`, `must be an ISO-8601 UTC timestamp`, `must be "deny" or "allow"`). A batch can report several errors at once.

Delivery semantics are at-least-once. A valid batch is appended event by event; a storage failure midway can leave a prefix persisted and return `500 storage`. An agent that retries a batch after a 5xx or a network error may therefore create duplicates; the server does no de-duplication. Stored events get `agentId` and `receivedAt` attached.

## Admin endpoints

All of these require Basic credentials and use the admin throttle. Examples assume `-u admin` (curl prompts for the password; do not put it on a shared command line).

### GET /api/v1/admin/policy

```sh
curl --pinnedpubkey 'sha256//<pin>' -k -u admin https://<vps-ip>:8443/api/v1/admin/policy
```

Returns `{"active":{"version":N,"policy":{...}},"draft":null}`, or with a draft present `"draft":{"text":"<raw text>","validation":{"valid":false,"errors":[{"path":"...","message":"..."}]}}`.

### PUT /api/v1/admin/policy/draft

State-changing admin calls (this one and `POST .../publish`) must carry the request header `X-Guardian-Request: 1`, otherwise they fail with `400 bad_request` after authentication. A cross-site form post cannot set a custom header, so this stops CSRF through the browser's cached Basic credentials. The panel sends it automatically.

Body is the raw policy text. It is saved even when invalid; the response reports validation (via `guardian::parsePolicy`): `200 {"valid":true,"errors":[]}`.

```sh
curl --pinnedpubkey 'sha256//<pin>' -k -u admin -X PUT -H 'X-Guardian-Request: 1' \
  --data-binary @policy.json https://<vps-ip>:8443/api/v1/admin/policy/draft
```

Drafts carry `"version": 0` by convention; an omitted `version` is accepted and a supplied one is ignored.

### POST /api/v1/admin/policy/publish

```sh
curl --pinnedpubkey 'sha256//<pin>' -k -u admin -X POST -H 'X-Guardian-Request: 1' \
  https://<vps-ip>:8443/api/v1/admin/policy/publish
# 200 {"version":4}
```

- `200 {"version":N+1}`: the draft is committed as `vN+1.json`, becomes active and is cleared. The server assigns the version; whatever the draft says is overwritten with N+1.
- `409 no_draft`: there is no draft.
- `422 invalid_draft` with `errors`: the draft does not validate; an invalid policy is never published. Validation messages may echo keys or ids the admin typed.
- If clearing the draft fails after the commit, the call reports an error although the new version is already active; a retry would publish the same content again as N+2.
- Published files are written with alphabetically ordered keys, two-space indentation and a trailing newline.

### GET /api/v1/admin/events?limit=

Newest first. `limit` is digits only, 1 to 1000, default 100; anything else gives `400 bad_request`.

```sh
curl --pinnedpubkey 'sha256//<pin>' -k -u admin 'https://<vps-ip>:8443/api/v1/admin/events?limit=50'
```

Returns `{"events":[{"ts","process":{"path","signingId","teamId"},"responsible":null|{...},"file","decision","ruleId","agentId","receivedAt"}]}`. Missing optional strings are returned as empty strings.

### Static panel

`GET /`, `/app.js`, `/panel.css`, `/tokens.css` serve `index.html`, `app.js`, `panel.css`, `tokens.css` from `webRoot`, after admin authentication. The allowlist is fixed; a file system path is never taken from the URL. Only the HTML document carries `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'` and `Referrer-Policy: no-referrer`. A missing file gives `404 not_found`.

## Status and error codes

| Status | `error` code | Where | Meaning |
|---|---|---|---|
| 200 | | all routes | success |
| 304 | | `GET /api/v1/policy` | active version matches `If-None-Match`; no body |
| 400 | `invalid_events` | `POST /api/v1/events` | any item or the body is invalid; `errors` lists them |
| 400 | `bad_request` | `GET /api/v1/admin/events`; `PUT .../draft` and `POST .../publish` without `X-Guardian-Request: 1`; malformed requests rejected by the HTTP layer | bad `limit`, bad request line or unknown method |
| 401 | `unauthorized` | agent and admin routes | missing, malformed, wrong or revoked credentials; `WWW-Authenticate: Bearer` (agent) or `Basic realm="Guardian", charset="UTF-8"` (admin) |
| 404 | `not_found` | any unknown path, a missing static file | no such resource |
| 405 | `method_not_allowed` | known path, wrong method (including HEAD, OPTIONS, PATCH, DELETE) | `Allow` header lists the supported methods |
| 409 | `no_draft` | `POST /api/v1/admin/policy/publish` | nothing to publish |
| 413 | `payload_too_large` | any route | body over 1 MiB |
| 414 | `uri_too_long` | any route | request target too long (HTTP layer) |
| 422 | `invalid_draft` | `POST /api/v1/admin/policy/publish` | draft failed validation; `errors` lists them |
| 429 | `too_many_requests` | agent and admin routes | throttled; `Retry-After` in seconds |
| 500 | `storage` | any route | a storage read or write failed |
| 500 | `internal` | any route | unexpected failure |
| other 4xx | `error` | HTTP layer | generic fallback for statuses without a dedicated code |

Route summary:

| Method and path | Auth | Success |
|---|---|---|
| `GET /healthz` | none | 200 |
| `GET /api/v1/policy` | Bearer | 200, 304 |
| `POST /api/v1/events` | Bearer | 200 |
| `GET /api/v1/admin/policy` | Basic | 200 |
| `PUT /api/v1/admin/policy/draft` | Basic | 200 |
| `POST /api/v1/admin/policy/publish` | Basic | 200 |
| `GET /api/v1/admin/events` | Basic | 200 |
| `GET /`, `/app.js`, `/panel.css`, `/tokens.css` | Basic | 200 |

## Agent checklist (Plan 4)

- Pin the SPKI hash; never fall back to CA validation.
- Poll `GET /api/v1/policy` with `If-None-Match` set to the last `ETag`; treat `304` as "unchanged", cache the last good policy, and keep enforcing it when the server is unreachable.
- Compare `Content-Type` by media type only.
- Send events in batches of at most 500; on 5xx or timeout retry later knowing duplicates are possible. On `400 invalid_events` do not retry the same batch; fix or drop the offending items.
- On `429` wait for `Retry-After`; on `401` stop and report a credentials problem (do not hammer: five failures lock the address out).

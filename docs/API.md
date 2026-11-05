# API

Local Python OpenAPI: `http://127.0.0.1:8000/docs` and `/openapi.json`. The Vercel backend is private; public Next.js routes expose only the following operations.

## POST /api/analyze

```json
{"kind":"url","content":"https://example.com","headers":""}
```

`kind`: `url`, `email`, `qr`, or `screenshot`. QR requests contain the decoded URL; screenshot requests contain reviewed OCR text. Images never go to this API. Content limit: 30,000 characters (URL validation: 4,096); optional raw email headers: 20,000; entire HTTP request: 128 KB. Unsupported protocols and malformed URLs return 422. Requests exceeding the body limit return 413. A disconnected backend returns 503.

The response contains `id`, `createdAt`, `kind`, `risk`, `summary`, `signals`, `models`, `details`, `links`, `unavailable`, `recommendations`, `privacy`, `evidenceText`, and `method`. `risk` is `low`, `review`, or `high`, not a probability. Each model includes its calibrated output, threshold, positive class, feature contributions and out-of-domain flag. Authentication results always include `verified:false`.

Responses use `Cache-Control: no-store`. Submitted text is never written to application logs or persistence by the analysis path.

## GET /api/health

Service availability, model availability, optional cloud history availability, and feature flags for reputation/external AI. No credential values are exposed.

## GET /api/models

Measured evaluation, split sizes, comparator results, data-source URLs/checksums and limitations. No private inputs are included.

## Optional /api/history

Requires `DATABASE_URL`, the schema in `backend/schema.sql`, and a browser-generated 64-hex-character bearer token in `X-History-Token`. The server stores only its SHA-256 digest as the owner key.

- `POST`: `{id,kind,risk,signal_count}`; inserts only for that owner.
- `GET`: most recent 100 metadata records for that owner.
- `DELETE`: deletes only that owner’s records.

Without a valid token: 401. Without configured PostgreSQL: 503. Tokens live on the device and are not account recovery credentials. The UI supports opt-in metadata writes and clearing; it does not rebuild full analysis history from these metadata-only records. Configure identity and authorization before using this as an organizational persistence service.

## Threat intelligence in scan responses

URL and QR requests accept `check_reputation` (boolean, default `true`). False skips external providers while retaining the local feed, heuristics and ML. Scans add `url`, `verdict` (`phishing`, `high_risk`, `suspicious`, or `unknown`), `providers`, `evidence` and `checked_at` to the existing analysis schema. These are PhishGuardX fields, not the native provider schema. Provider entries include source, status, matched/confirmed flags, availability, cache use, timestamps, a query-redacted matched indicator, and an explanatory message. Current result exports contain these fields; saved-history exports omit indicator URLs and evidence quotes.

`not_found` is absence of a provider record, never a safety verdict. A verified phishing match overrides a low heuristic verdict. Stale/unverified indicators remain visibly unconfirmed. Provider failure does not discard ML/heuristic results.

## GET /api/threat-intelligence

Actual last-known API availability and last successful checks, feed count/freshness/sync status, storage persistence, and local model availability. Does not query providers or trigger sync. No credentials or bulk feed indicators are exposed.

## GET /api/cron/threat-feed (scheduler only)

Requires `Authorization: Bearer <CRON_SECRET>`. The frontend forwards an authenticated request to backend `POST /internal/feed-sync`. An unconfigured secret or missing/wrong authorization returns 401. The sync uses a persistent atomic lease, validates the complete snapshot, and preserves the previous data on failure. Hosting schedules this daily; local operators can run `python -m backend.sync_feed --once` or run the worker loop.

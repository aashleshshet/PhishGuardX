# OpenPhish and independent threat intelligence

Two unrelated services are configured independently. Application code is open source; provider feed data retains its own license. The deployment owner confirmed written permission for public use of the OpenPhish.com Community Feed. That permission does not automatically transfer to forks. No raw feed is committed or redistributed.

## Verified provider contracts

- [OpenPhish.eu API documentation](https://openphish.eu/api-docs): GET `https://openphish.eu/api/check?url=...`. Native negative response: `{"found":false}`. Positive response: `found:true` and a `phish` object with `url`, `status`, and optional `id`, `target_brand`, `verified_at`. The adapter requires a matching URL and `status:verified` for a confirmed phishing verdict. Other statuses are unverified. Anonymous quota is 100 requests/hour; this app defaults to 90 and caps configuration at 100. No undocumented credential scheme is invented. Its [terms](https://openphish.eu/terms) are separate from the feed service.
- [OpenPhish.com Community Feed](https://openphish.com/phishing_feeds.html): official source `https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt`, currently updated every 12 hours. This app never downloads more often than every 12 hours. [Feed terms](https://openphish.com/terms.html) require the appropriate permission for public redistribution. The configured website uses an authorized hash-only local database and exposes only the indicator submitted by the current scanner.
- [PhishTank](https://checkurl.dev.phishtank.com/api_info.php): POST form `url`, `format=json`, optional `app_key`; checks `in_database`, `verified` and `valid`. HTTP 509/429 trigger backoff. Application budget defaults to a conservative 10 requests/hour for this adapter.
- [Google Safe Browsing v4](https://developers.google.com/safe-browsing/v4/lookup-api): optional API key; positive cache lifetime never exceeds the response's `cacheDuration`. Review Google's usage terms before enabling this optional service.
- [URLhaus](https://urlhaus-api.abuse.ch/): optional Auth-Key, exact URL lookup. Its malware evidence is labeled as malware rather than phishing; online/offline record status is preserved.

Documentation was checked during implementation. Automated tests use HTTPX MockTransport fixtures. The actual application never uses these fixtures or invents a provider result.

## Configuration and storage

Copy `.env.example`, export the desired settings into the backend process environment (a root `.env` is not automatically loaded by plain Uvicorn), set API flags as needed, and set the exact official feed URL plus `OPENPHISH_FEED_PERMISSION_CONFIRMED=true` only when entitled to the intended usage. Missing source/permission/persistent hosted storage results in `not_configured`; no download happens. API endpoint and timeout are configurable, with trusted HTTPS origin/path validation and bounded timeouts. No arbitrary outbound endpoint is accepted.

Local development uses `.data/threats.sqlite3`; override with `OPENPHISH_DB_PATH`. Hosted deployments use `THREAT_DATABASE_URL` (or `THREAT_POSTGRES_URL`) from a separately connected Neon resource. This is distinct from optional user-history `DATABASE_URL`. Three namespaced tables hold indicator hashes, bounded TTL verdict cache records, and provider/sync metadata. URLs, query values, credentials, raw feed text and raw API payloads are not persisted by this store. Hashes are not encryption and should still be treated as security data.

Vercel's free plan runs the authenticated cron daily. Set a strong independent `CRON_SECRET` for each deployment environment. The deployed schedule is `0 4 * * *` UTC with the platform's scheduling tolerance. Locally, `python -m backend.sync_feed` runs a periodic worker; `--once` performs one eligible sync. Feed refresh uses a shared database lease and respects Retry-After, so concurrent workers cannot bypass provider frequency limits. Failed/empty/malformed downloads preserve the previous snapshot. Snapshots older than 36 hours are stale and cannot establish a fresh confirmed match.

## Evidence and privacy

Order: URL validation → local feed → enabled OpenPhish.eu API unless a fresh feed match already confirms phishing → other enabled providers → existing URL heuristics and trained model → combined verdict. A confirmed record always raises concern; a no-match never lowers suspicious evidence or yields a safe verdict. A stale match remains unconfirmed and does not suppress a live API check.

URL/QR scanners expose a live-check opt-out. Live checks send the normalized public URL including query parameters to configured providers; private links should use local-only analysis. Submitted destinations are never visited. Provider failures are logged as structured provider/code events without URL strings, raw exception text or credentials. Displayed matches hide query values; local history removes indicators entirely. Current scan JSON exports include the current analysis and provider evidence.

Quotas and cache state are shared across hosted instances in PostgreSQL. Network operations use HTTPX, reject redirects, enforce response size/time limits, and validate Pydantic schemas. Malformed responses, authentication failures, HTTP errors, timeout and unavailable storage are reported honestly. Cache expiry is configurable and capped. All absent credentials are reflected as disabled/not-configured status.

## Verification

Run `.venv/bin/python -m pytest backend/tests -q`, `npm --prefix frontend test`, and `npm --prefix frontend run build`. Tests cover matches, no-match/unknown, invalid URLs, normalization, exact match identity, private URL exclusion, sensitive logging/cache redaction, cache expiry, API errors/timeouts/malformed payloads, HTTP and local budget rate limits, missing configuration, feed deduplication, atomic replacement failure, stale feeds, feed permission/persistence guards and scheduler authentication. No live phishing destination is needed or visited.

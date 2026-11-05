# Verification record

Verified on 5 November 2026.

- Backend: 24 pytest tests passed, including malformed inputs, offline-only URL handling, model parity, imported headers, input limits, and privacy behavior.
- Frontend: strict TypeScript check passed; Next.js production Webpack build passed with Clerk enabled.
- Mailbox server: 9 tests passed for signed-out denial, user-scoped credential lookup, missing mail scopes, metadata-only inbox listing, selected-message import, response-size limits, expired permission handling, and token exclusion from responses.
- Browser: sample email analysis, real uploaded QR decoding, and real uploaded screenshot OCR were exercised using authored `.example` fixtures. QR and screenshot flows produced meaningful risk explanations. Images were processed locally before explicit analysis.
- Live deployment: `/api/health` returned 200 with models ready, `/api/analyze` returned 200 and high concern for an authored impersonation URL, and signed-out `/api/mailbox` returned 401.
- Live browser: Clerk development sign-in dialog loaded with Google/email options; mobile 390 × 844 layout and both themes were inspected. No account credentials or private mailbox contents were used for testing.
- Source excludes development secrets, raw training datasets, local tooling and test artifacts.

## Remaining external setup / unverified paths

- Google and Microsoft mailbox OAuth clients must be configured in Clerk with custom provider credentials and read-only scopes. Real provider consent, token refresh and private-message import were not exercised because no authorized test mailboxes or provider client credentials were supplied.
- Signed-in name/avatar rendering uses the real Clerk user object, but a full human sign-in was not performed by the agent.
- Hosted PostgreSQL is not provisioned; its persistence operations and Docker Compose have not been tested against a running database.
- The optional Chrome extension was supplied and pointed at the actual production hostname, but was not installed or published.
- Historical held-out model metrics are reproducible measurements, not claims about current real-world detection accuracy. See model cards.

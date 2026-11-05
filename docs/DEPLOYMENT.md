# Deployment

## Vercel

Import `aashleshshet/PhishGuardX` as one Vercel project from the repository root. `vercel.json` declares two Services:

- `frontend`: Next.js, root `frontend/`.
- `backend`: FastAPI, root `backend/`, entrypoint `app:app`.

The frontend's `BACKEND_URL` is injected from a private service binding. Public ingress routes only to the frontend. No manually hardcoded backend hostname or API key is needed. Vercel Services is beta; account-level availability and platform limits apply. Use Node 22 and Python 3.12+.

GitHub Actions verifies TypeScript, the production build, and backend tests. Vercel Git integration can create previews and production deployments. The workflow does not itself bypass checks or promote releases. Configure branch protections/deployment checks for a team release process.

## Clerk accounts and mailbox access

See [account setup](ACCOUNTS.md). The free Clerk Marketplace resource is connected to the project. This launch intentionally uses its development instance on vercel.app; no production-domain ownership is implied. Custom Google/Microsoft provider credentials must be configured separately for mail scopes.

## Optional PostgreSQL

The public baseline runs without a database. To enable opt-in anonymous metadata storage:

1. Provision your own PostgreSQL database using your chosen provider/plan.
2. Apply `backend/schema.sql` once using a trusted database client.
3. Set the backend’s `DATABASE_URL` through the deployment platform's secret settings.
4. Redeploy. The health endpoint enables the Settings toggle when configuration is present.
5. Test create/read/delete with an isolated test token and verify owner separation.

Do not place database credentials in source code, client environment variables, URLs sent to users, or GitHub Actions output. Use separate development, preview and production databases. Implement retention and account-based ownership before storing organizational records.

## Local Docker

`compose.yaml` includes PostgreSQL 17, schema initialization, FastAPI and Next.js. Set a development `POSTGRES_PASSWORD` in the ignored root `.env`, then `docker compose up --build`. Ports are bound to loopback. Database data is retained in a named volume. Changing the schema file does not migrate existing volumes automatically.

## Chrome extension

Open `chrome://extensions`, enable Developer mode and load `extension/` as unpacked. The extension is not published to the Chrome Web Store. Its allowlisted deployment hostname must match the actual production site in `manifest.json`, `popup.js` and `popup.html`. It reads the current tab URL only when the user clicks the explicit button, and sends only a subsequently submitted URL.

## Production considerations

The app is a functional portfolio baseline. Before large-scale public use, configure distributed rate limits and bot controls, privacy-aware operational monitoring, a recent labeled evaluation corpus, provider consent flows, account authorization for shared persistence, and disaster recovery. Do not claim that missing threat intelligence or unknown results establish safety.

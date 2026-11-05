# Accounts and connected email

PhishGuardX uses `@clerk/nextjs` v7. The sidebar, header and Settings display the actual signed-in user’s name, avatar and primary email. Without a session, they offer sign-in. Local scan history is scoped to the Clerk user ID, and raw inputs are cleared on account changes. Local storage is not a secure vault and remains accessible to someone using the same browser profile.

## Clerk through Vercel

The project has a free Hobby Clerk Marketplace resource named PhishGuardX. Its development keys are provisioned in development, preview and production deployment environments. The owner chose development sign-in on vercel.app for this launch. Set `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` and `CLERK_SECRET_KEY` from the same instance; never commit the latter.

For local work, link the Vercel project and run `vercel env pull frontend/.env.local --environment development`. Start the frontend on `http://localhost:3000`. For a production Clerk instance, configure an owned custom domain and migrate through the Clerk dashboard.

## Enable Google mailbox connections

1. Create a Google Cloud OAuth web client and configure its consent screen for your app. Enable the Gmail API.
2. In Clerk’s Google social connection, use custom OAuth credentials. Copy the exact redirect URI shown by Clerk into Google’s authorized redirect URIs.
3. Configure `https://www.googleapis.com/auth/gmail.readonly`. During testing, add allowed test users in Google Cloud. Public availability of restricted Gmail scopes requires Google's verification process.
4. The user signs in to PhishGuardX, selects Connect Google, reads the consent notice, and grants read-only access on Google’s own screen.

## Enable Microsoft mailbox connections

1. Register a web app in Microsoft Entra. Select supported account types appropriate for your audience (including personal Microsoft accounts if needed).
2. Configure Microsoft as a Clerk social connection using custom OAuth credentials, with the exact callback URI Clerk supplies.
3. Enable delegated `Mail.Read` and `offline_access`, alongside the identity scopes Clerk requires. Some organizations require administrator consent.
4. The user selects Connect Microsoft and grants read-only access on Microsoft’s own screen.

Clerk’s shared development OAuth credentials support sign-in, but cannot be relied on for custom mail scopes or provider access tokens. Configure your own clients before declaring mailbox import ready. Do not place client secrets in the public frontend or send them in chat.

## Data flow and verification

`GET /api/mailbox?provider=google|microsoft` requires a valid Clerk session. The server obtains only that user's provider token and checks its read scope. It fetches 10 inbox summaries. Adding `id` retrieves a single selected message for review; analysis remains a separate explicit action. Responses use `no-store`; tokens stay server-side. Provider requests allow only official Gmail/Microsoft Graph hosts, reject redirects, have timeouts and bounded response sizes.

Before a release, verify consent, cancel, reconnect, expired-token errors, and a selected-message import with an authorized test mailbox for each configured provider. Do not use real private inbox messages as automated fixtures. No provider mailboxes were accessed during initial implementation.

References: [Clerk on Vercel](https://clerk.com/docs/guides/development/integrations/platforms/vercel-marketplace), [Clerk social connections](https://clerk.com/docs/guides/configure/auth-strategies/social-connections/overview), [Gmail scopes](https://developers.google.com/workspace/gmail/api/auth/scopes), [Microsoft Graph permissions](https://learn.microsoft.com/en-us/graph/permissions-reference#mailread).

# Responsible use and privacy

PhishGuardX is a defensive educational tool. It surfaces warning signs and uncertainty, not a final safety certification. Do not rely on it alone for financial transfers, credential disclosure, incident response, or corporate enforcement.

Submitted URLs are parsed as data. The analysis engine never retrieves the target, resolves its hostname, expands redirects or opens it in the browser. Arbitrary text is never executed and is never treated as instructions to an LLM. React renders evidence as text, not HTML. Model files are parsed JSON, not pickle.

Images remain on-device. English OCR assets and fonts are self-hosted; no image is sent to an OCR provider. Users review extracted text and explicitly submit it to the Python service. The analysis path processes inputs in memory and does not retain them or log request bodies. Hosting infrastructure may retain standard connection metadata.

Local history is on by default and can be disabled or cleared. It removes raw input, evidence quotes, destination URLs/domains and model feature snippets. Records are scoped to the signed-in Clerk user (or guest) on this device. Records and preferences live in browser localStorage; anyone with access to that browser profile may see them. Exporting a current result may include the analyzed text, so share downloaded reports thoughtfully. Optional cloud metadata sync is off by default.

No third-party generative AI, live reputation provider, WHOIS lookup or visual-language model is enabled. Email authentication headers are untrusted imported data; “pass” is not verified. OCR can miss text, and risk rules can flag educational discussions about scams. Never automatically block or accuse a sender based solely on this output.

For accidental credential disclosure, use the official service to change the credential, review sessions and enable MFA. For workplace incidents, contact the organization’s security team. Report suspicious messages through the original provider's reporting channel.

## Connected accounts

Clerk manages identity, sessions, and encrypted provider credentials. The interface displays the signed-in user’s name, email and avatar. Account connection is separate from analyzing a message. Google Gmail read-only or Microsoft Mail.Read permission is requested after explicit consent. Browsing fetches at most 10 recent inbox summaries; selecting a message retrieves its body for review. Only pressing Analyze submits it to the analysis service. No sending, deleting, background scans, or provider tokens in browser responses. Disconnect through Manage account, and revoke access in the provider account when necessary.

The current vercel.app launch uses Clerk development keys at the owner’s request. Use a custom domain and production instance before a general production launch.

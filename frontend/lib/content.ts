import type { ScanKind } from "./types";
export const samples: Record<ScanKind, string> = {
  email:
    "From: Account Security <support@paypal-verification.example>\nSubject: Urgent: your account will be suspended\nReply-To: collect@account-review.example\nAuthentication-Results: mail.example; spf=fail; dkim=fail; dmarc=fail\n\nYour account has been limited. Verify your password immediately to avoid suspension. Confirm your login credentials at https://paypal.verify-account.example/login within 24 hours.",
  url: "https://paypal.verify-account.example/login?session=review",
  qr: "https://parcel-redelivery.example/pay?fee=1.99",
  screenshot:
    "Account verification required\nYour account will be suspended within 24 hours. Enter your password and verification code immediately to keep access.\nhttps://microsoft.account-verify.example/login",
};
export const kindLabels: Record<ScanKind, string> = {
  email: "Email analysis",
  url: "URL scan",
  qr: "QR scan",
  screenshot: "Screenshot analysis",
};
export const articles = [
  {
    id: "domain",
    category: "LINK SAFETY",
    title: "Look past the familiar name.",
    intro: "A brand name in a link is not the same as a brand’s domain.",
    minutes: 3,
    body: [
      "In paypal.com.account-check.example, the registered domain is account-check.example. The familiar brand appears only as a subdomain. Read the hostname from right to left and identify its registered domain.",
      "A padlock means the connection is encrypted. Attackers can also obtain HTTPS certificates, so encryption does not establish who operates a website.",
      "When a message asks you to sign in, open the organization’s official app or use a bookmark you already trust. Avoid copying a destination from an unexpected message.",
    ],
  },
  {
    id: "urgency",
    category: "SOCIAL ENGINEERING",
    title: "Urgency is part of the trick.",
    intro: "Why “act now” should make you slow down.",
    minutes: 2,
    body: [
      "Threats of account closure, missed deliveries, and limited-time rewards try to shorten your decision-making process. A deadline is an indicator to investigate, not proof that a message is fraudulent.",
      "Pause before following instructions. Check the request through a contact method you already know. Do not use a phone number supplied only in the suspicious message.",
      "Never share a one-time verification code, password, or recovery phrase with someone who contacts you unexpectedly.",
    ],
  },
  {
    id: "qr",
    category: "QR AWARENESS",
    title: "A QR code is still a link.",
    intro: "Check the destination before you scan and go.",
    minutes: 3,
    body: [
      "QR codes can conceal a link until you decode them. A sticker placed over a legitimate payment or parking code may point to an unrelated destination.",
      "Preview the destination. Check the actual registered domain, the context in which you received the code, and whether a request for payment makes sense.",
      "PhishGuardX decodes an image in your browser. It analyzes the extracted URL without navigating to it. A code can also contain non-URL data, which this scanner will identify rather than open.",
    ],
  },
  {
    id: "headers",
    category: "EMAIL AUTHENTICATION",
    title: "What email headers can tell you.",
    intro: "SPF, DKIM and DMARC, without the jargon.",
    minutes: 4,
    body: [
      "SPF checks whether a sending server is permitted to send for a domain. DKIM checks a cryptographic signature. DMARC checks alignment with the visible From domain and defines handling policy.",
      "An authentication pass does not mean a message is harmless. A malicious sender can authenticate their own domain. Failures can also result from forwarding or misconfiguration.",
      "PhishGuardX interprets Authentication-Results supplied in pasted headers. It does not independently verify those headers; copied results may be forged. Trust the results added by your own receiving mail provider.",
    ],
  },
  {
    id: "clicked",
    category: "NEXT STEPS",
    title: "Already clicked? Take a breath.",
    intro: "A few practical steps to regain control.",
    minutes: 3,
    body: [
      "Close the suspicious page. If you entered a password, change it through the official app or a known address, then review active sessions and enable multifactor authentication.",
      "If you downloaded something, avoid opening it. Use trusted security software or contact your organization’s security team. If you shared payment information, contact your bank using its official contact details.",
      "Report the message through your mail provider’s phishing-reporting option. Save relevant evidence if your organization asks for it, without forwarding the malicious link to unsuspecting people.",
    ],
  },
];
export function exportJSON(value: unknown, name: string) {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

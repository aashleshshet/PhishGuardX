import type { Metadata } from "next";
import localFont from "next/font/local";
import "./globals.css";
import { Workspace } from "@/components/workspace";
import { AuthProvider } from "@/components/auth-provider";
const googleSans = localFont({
  src: [
    {
      path: "../public/fonts/google-sans-latin.woff2",
      weight: "400 700",
      style: "normal",
    },
  ],
  variable: "--font-google-sans",
  display: "swap",
});
export const metadata: Metadata = {
  title: "PhishGuardX — Clarity before you click",
  description:
    "Understand suspicious emails, links, QR codes and screenshots with private, evidence-first phishing analysis.",
  icons: { icon: "/icon.svg" },
};
export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" data-scroll-behavior="smooth" suppressHydrationWarning>
      <body className={googleSans.variable}>
        <script
          dangerouslySetInnerHTML={{
            __html: `try{const s=JSON.parse(localStorage.getItem('pgx-settings-v1')||'{}');if(s.theme==='dark')document.documentElement.dataset.theme='dark'}catch{}`,
          }}
        />
        <AuthProvider>
          <Workspace>{children}</Workspace>
        </AuthProvider>
      </body>
    </html>
  );
}

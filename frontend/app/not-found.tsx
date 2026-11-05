import Link from "next/link";
export default function NotFound() {
  return (
    <main className="not-found">
      <h1>That page wandered off.</h1>
      <p>Your workspace is right where you left it.</p>
      <Link href="/" className="button button-primary">
        Back to overview
      </Link>
    </main>
  );
}

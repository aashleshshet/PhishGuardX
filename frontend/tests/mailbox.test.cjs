const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const ts = require("typescript");

// Compile the actual server modules; mock only external services, never mailbox logic.
function moduleUnderTest(file, dependencies = {}, overrides = {}) {
  const output = ts.transpileModule(
    fs.readFileSync(path.join(__dirname, "..", file), "utf8"),
    {
      compilerOptions: {
        module: ts.ModuleKind.CommonJS,
        target: ts.ScriptTarget.ES2022,
      },
    },
  ).outputText;
  const exports = {};
  vm.runInNewContext(output, {
    exports,
    Buffer,
    URL,
    AbortSignal,
    Response,
    fetch,
    process,
    require(name) {
      if (name === "server-only") return {};
      if (name in dependencies) return dependencies[name];
      throw new Error(`Unexpected dependency: ${name}`);
    },
    ...overrides,
  });
  return exports;
}
const json = (value) => Response.json(value);
const mailbox = (fetcher) =>
  moduleUnderTest("lib/mailbox.ts", {}, { fetch: fetcher });

test("rejects unsupported providers and path-like message identifiers without fetching", async () => {
  const m = mailbox(() => {
    throw Error("Unexpected network request");
  });
  assert.throws(
    () => m.validateProvider("https://attacker.example"),
    /Choose Google/,
  );
  await assert.rejects(
    m.importMessage("google", "test-token", "../messages"),
    /Invalid message/,
  );
});

test("Google listing requests metadata only and limits the picker to ten messages", async () => {
  const calls = [];
  const m = mailbox(async (url, options) => {
    calls.push(url);
    assert.equal(options.redirect, "error");
    assert.equal(options.cache, "no-store");
    assert.equal(options.headers.Authorization, "Bearer test-token");
    return url.includes("maxResults=10")
      ? json({
          messages: Array.from({ length: 12 }, (_, i) => ({ id: `abc${i}` })),
        })
      : json({
          payload: {
            headers: [
              { name: "Subject", value: "Fixture subject" },
              { name: "From", value: "fixture@example.test" },
            ],
          },
        });
  });
  const messages = await m.listMessages("google", "test-token");
  assert.equal(messages.length, 10);
  assert.equal(calls.length, 11);
  assert(calls.slice(1).every((url) => url.includes("format=metadata")));
  assert.equal(messages[0].subject, "Fixture subject");
  assert.equal(messages[0].content, undefined);
});

test("selected Google message decodes base64url without retrieving attachments", async () => {
  const content = "Subject: Fixture\n\nPlease review this test.";
  const m = mailbox(async (url) => {
    assert(url.endsWith("/abc?format=raw"));
    return json({ raw: Buffer.from(content).toString("base64url") });
  });
  assert.equal(
    (await m.importMessage("google", "test-token", "abc")).content,
    content,
  );
});

test("oversized provider responses are refused", async () => {
  const m = mailbox(async () => new Response("x".repeat(4 * 1024 * 1024 + 1)));
  await assert.rejects(
    m.importMessage("google", "test-token", "abc"),
    (error) => error.status === 413,
  );
});

test("expired provider permission produces a reconnect error", async () => {
  const m = mailbox(async () => new Response("", { status: 401 }));
  await assert.rejects(
    m.listMessages("microsoft", "test-token"),
    (error) => error.status === 403 && /Reconnect/.test(error.message),
  );
});

test("Microsoft imports request plain text and remove header line breaks", async () => {
  const m = mailbox(async (url, options) => {
    assert.equal(new URL(url).hostname, "graph.microsoft.com");
    assert.equal(options.headers.Prefer, 'outlook.body-content-type="text"');
    return json({
      body: { content: "Test body" },
      internetMessageHeaders: [
        { name: "Subject", value: "Fixture\r\nInjected: no" },
        { name: "X-Private", value: "not needed" },
      ],
    });
  });
  const result = await m.importMessage("microsoft", "test-token", "abc=");
  assert.equal(result.content, "Test body");
  assert.equal(result.headers, "Subject: Fixture Injected: no");
});

function route(userId, scopes, tokenCallback = () => {}) {
  const m = mailbox(async () => json({ messages: [] }));
  const handler = moduleUnderTest(
    "app/api/mailbox/route.ts",
    {
      "@/lib/mailbox": m,
      "next/server": { NextResponse: Response },
      "@clerk/nextjs/server": {
        auth: async () => ({ userId }),
        clerkClient: async () => ({
          users: {
            getUserOauthAccessToken: async (id, provider) => {
              tokenCallback(id, provider);
              return { data: [{ token: "test-token", scopes }] };
            },
          },
        }),
      },
    },
    {
      process: {
        env: {
          CLERK_SECRET_KEY: "test-only",
          NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY: "test-only",
        },
      },
    },
  );
  return handler.GET({
    nextUrl: new URL("https://app.example/api/mailbox?provider=google"),
  });
}
test("signed-out mailbox request is denied before any credential lookup", async () => {
  const response = await route(null, [], () =>
    assert.fail("Credentials must not be read"),
  );
  assert.equal(response.status, 401);
  assert.equal(response.headers.get("cache-control"), "no-store");
});
test("signed-in users without mail permission cannot import email", async () => {
  const response = await route("user_test", ["openid", "email"]);
  assert.equal(response.status, 403);
});
test("credential lookup uses the authenticated user and never returns the token", async () => {
  const response = await route(
    "user_test",
    ["https://www.googleapis.com/auth/gmail.readonly"],
    (id, provider) => {
      assert.equal(id, "user_test");
      assert.equal(provider, "google");
    },
  );
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "private, no-store");
  const body = await response.text();
  assert(!body.includes("test-token"));
});

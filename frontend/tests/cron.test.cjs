const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const ts = require("typescript");
function route(env, fetcher) {
  const exports = {};
  const logs = [];
  const source = fs.readFileSync(
    path.join(__dirname, "../app/api/cron/threat-feed/route.ts"),
    "utf8",
  );
  vm.runInNewContext(
    ts.transpileModule(source, {
      compilerOptions: {
        module: ts.ModuleKind.CommonJS,
        target: ts.ScriptTarget.ES2022,
      },
    }).outputText,
    {
      exports,
      Buffer,
      URL,
      AbortSignal,
      Response,
      process: { env },
      fetch: fetcher,
      console: { info: (x) => logs.push(x), warn: (x) => logs.push(x) },
      require: (name) => {
        assert.equal(name, "node:crypto");
        return require(name);
      },
    },
  );
  return { ...exports, logs };
}
const request = (auth) =>
  new Request("https://app.example/api/cron/threat-feed", {
    headers: auth ? { authorization: auth } : {},
  });
test("scheduler rejects missing, incorrect and unset secrets before network access", async () => {
  for (const [secret, auth] of [
    ["fixture", null],
    ["fixture", "Bearer wrong"],
    ["", "Bearer "],
  ]) {
    const r = route({ CRON_SECRET: secret }, () =>
      assert.fail("Unexpected network"),
    );
    assert.equal((await r.GET(request(auth))).status, 401);
  }
});
test("scheduler authenticates backend and reports an eligible or not-due outcome", async () => {
  const r = route(
    { CRON_SECRET: "fixture", BACKEND_URL: "https://internal.example" },
    async (url, options) => {
      assert.equal(String(url), "https://internal.example/internal/feed-sync");
      assert.equal(options.headers.Authorization, "Bearer fixture");
      assert.equal(options.method, "POST");
      assert.equal(options.redirect, "error");
      return Response.json({ status: "not_due" });
    },
  );
  const response = await r.GET(request("Bearer fixture"));
  assert.equal(response.status, 200);
  assert.equal((await response.json()).status, "not_due");
  assert(r.logs.every((x) => !x.includes("fixture")));
});
test("scheduler requires a configured backend", async () => {
  assert.equal(
    (
      await route({ CRON_SECRET: "fixture" }, () => assert.fail()).GET(
        request("Bearer fixture"),
      )
    ).status,
    503,
  );
});
test("scheduler exposes provider failures as retryable HTTP failures", async () => {
  for (const [status, expected] of [
    ["unavailable", 503],
    ["not_configured", 503],
    ["rate_limited", 429],
  ]) {
    const r = route(
      { CRON_SECRET: "fixture", BACKEND_URL: "https://internal.example" },
      async () => Response.json({ status }),
    );
    assert.equal((await r.GET(request("Bearer fixture"))).status, expected);
  }
});
test("scheduler handles backend timeouts without exposing exception details", async () => {
  const r = route(
    { CRON_SECRET: "fixture", BACKEND_URL: "https://internal.example" },
    async () => {
      throw Error("sensitive fixture");
    },
  );
  const response = await r.GET(request("Bearer fixture"));
  assert.equal(response.status, 503);
  assert(!(await response.text()).includes("sensitive"));
  assert(r.logs.every((x) => !x.includes("sensitive")));
});

import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import worker from "../src/index.js";
import { TOOLS, runTool } from "../src/tools.js";
import { signToken, taintFilename } from "../src/uploadlink.js";
import { installFakeWiki, WIKI } from "./fake-wiki.js";

const SECRET = "s".repeat(40);
const ORIGIN = "https://moin-mcp.example";
const ENV = { MOIN_URL: WIKI, MOIN_USER: "bot", MOIN_PASSWORD: "pw", ALLOW_WRITES: "true", UPLOAD_SECRET: SECRET };
const SETTINGS = { url: WIKI, username: "bot", password: "pw", allowWrites: true, uploadSecret: SECRET, origin: ORIGIN };
const sha = (b) => createHash("sha256").update(b).digest("hex");
const bytes = (n, seed = 1) => Uint8Array.from({ length: n }, (_, i) => (i * 31 + seed) & 0xff);

async function link(args, settings = SETTINGS) {
  const r = await runTool(TOOLS.find((t) => t.name === "create_upload_link"), args, settings);
  return { error: r.isError ? r.content[0].text : null, out: r.structuredContent };
}
async function upload(url, body, env = ENV, method = "PUT") {
  const res = await worker.fetch(new Request(url, { method, body }), env);
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch {}
  return { status: res.status, json, text, headers: res.headers };
}

let wiki;
beforeEach(() => { wiki = installFakeWiki(); });

test("a link uploads a file once, without Cloudflare Access", async () => {
  const { error, out } = await link({ page: "Notes", name: "report.pdf" });
  assert.equal(error, null);
  assert.ok(out.upload_url.startsWith(`${ORIGIN}/upload/`));
  assert.match(out.curl, /^curl --fail-with-body -T <file> '/);
  assert.equal(out.replaces, null);

  const data = bytes(300_000);
  wiki.requests.length = 0;
  const r = await upload(out.upload_url, data);
  assert.equal(r.status, 200, r.text);
  assert.equal(r.json.size, 300_000);
  assert.equal(r.json.sha256, sha(data));
  assert.deepEqual(wiki.attachments.get("Notes\u0000report.pdf"), data);

  const again = await upload(out.upload_url, bytes(10, 9));
  assert.equal(again.status, 409);
  assert.match(again.json.error, /LINK_USED/);
  assert.deepEqual(wiki.attachments.get("Notes\u0000report.pdf"), data);
});

test("the browser page is served for a live link and refused for a used one", async () => {
  const { out } = await link({ page: "P <x>", name: "a.png" });
  const page = await upload(out.upload_url, undefined, ENV, "GET");
  assert.equal(page.status, 200);
  assert.match(page.headers.get("Content-Type"), /text\/html/);
  assert.equal(page.headers.get("Referrer-Policy"), "no-referrer");
  assert.match(page.text, /Upload to P &#60;x&#62;/); // escaped
  assert.doesNotMatch(page.text, /<x>/);
  await upload(out.upload_url, bytes(5));
  const used = await upload(out.upload_url, undefined, ENV, "GET");
  assert.equal(used.status, 409);
  assert.match(used.text, /LINK_USED/);
});

test("existing attachments need overwrite, and a replace link works once", async () => {
  wiki.attachments.set("P\u0000a.txt", bytes(10));
  assert.match((await link({ page: "P", name: "a.txt" })).error, /ATTACHMENT_EXISTS/);
  const { out } = await link({ page: "P", name: "a.txt", overwrite: true });
  assert.equal(out.replaces, sha(bytes(10)));

  const same = await upload(out.upload_url, bytes(10)); // identical bytes: nothing written, link still live
  assert.equal(same.json.unchanged, true);
  const first = await upload(out.upload_url, bytes(20));
  assert.equal(first.status, 200);
  assert.equal((await upload(out.upload_url, bytes(30))).status, 409);
  assert.deepEqual(wiki.attachments.get("P\u0000a.txt"), bytes(20));
});

test("a link made for a new file stops working if someone attaches that name first", async () => {
  const { out } = await link({ page: "P", name: "n" });
  wiki.attachments.set("P\u0000n", bytes(3));
  assert.equal((await upload(out.upload_url, bytes(4))).status, 409);
});

test("forged, tampered and expired links are refused", async () => {
  const { out } = await link({ page: "P", name: "n" });
  const [body, sig] = out.upload_url.split("/upload/")[1].split(".");
  const forged = await signToken("x".repeat(40), { p: "P", n: "n", h: null, m: 100, e: Date.now() / 1000 + 60 });
  const expired = await signToken(SECRET, { p: "P", n: "n", h: null, m: 100, e: Date.now() / 1000 - 1 });
  const other = await signToken(SECRET, { p: "Other", n: "n", h: null, m: 100, e: Date.now() / 1000 + 60 });
  for (const [token, re] of [
    [forged, /LINK_INVALID/],
    [`${body}x.${sig}`, /LINK_INVALID/],
    [`${body}.${sig.slice(0, -2)}`, /LINK_INVALID/],
    ["garbage", /LINK_INVALID/],
    [expired, /LINK_EXPIRED/],
  ]) {
    const r = await upload(`${ORIGIN}/upload/${token}`, bytes(4));
    assert.equal(r.status, 401, token);
    assert.match(r.json.error, re);
  }
  assert.equal((await upload(`${ORIGIN}/upload/${other}`, bytes(4))).status, 200); // a valid token for another page works only there
  assert.equal(wiki.attachments.has("P\u0000n"), false);
});

test("size cap, empty body and wrong methods", async () => {
  const { out } = await link({ page: "P", name: "n", max_bytes: 1000 });
  const big = await upload(out.upload_url, bytes(1001));
  assert.equal(big.status, 413);
  assert.match((await upload(out.upload_url, new Uint8Array(0))).json.error, /EMPTY/);
  assert.equal((await upload(out.upload_url, bytes(3), ENV, "POST")).status, 405);
  assert.equal(wiki.attachments.size, 0);
  assert.equal((await upload(out.upload_url, bytes(1000))).status, 200);
});

test("upload links need the secret and writes, and the secret must be long enough", async () => {
  assert.match((await link({ page: "P", name: "n" }, { ...SETTINGS, uploadSecret: "" })).error, /UPLOAD_LINKS_UNAVAILABLE/);
  const { out } = await link({ page: "P", name: "n" });
  assert.equal((await upload(out.upload_url, bytes(3), { ...ENV, UPLOAD_SECRET: undefined })).status, 503);
  assert.equal((await upload(out.upload_url, bytes(3), { ...ENV, ALLOW_WRITES: "false" })).status, 403);
  assert.equal((await upload(out.upload_url, bytes(3), { ...ENV, UPLOAD_SECRET: "short" })).status, 500);
});

test("names are stored the way MoinMoin taints them", async () => {
  assert.equal(taintFilename("a/b:c<d>..e\\f"), "a_b_c_d__e_f");
  const { out } = await link({ page: "P", name: "x/y.txt" });
  assert.equal(out.name, "x_y.txt");
  await upload(out.upload_url, bytes(3));
  assert.ok(wiki.attachments.has("P\u0000x_y.txt"));
});

test("/mcp still requires Cloudflare Access", async () => {
  const res = await worker.fetch(new Request(`${ORIGIN}/mcp`, { method: "POST", body: "{}" }),
    { ...ENV, CF_ACCESS_TEAM_DOMAIN: "t.cloudflareaccess.com", CF_ACCESS_AUD: "aud" });
  assert.equal(res.status, 401);
});

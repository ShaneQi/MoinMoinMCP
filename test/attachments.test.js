import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { TOOLS, runTool, decodeBase64Arg, MAX_ATTACHMENT_BYTES } from "../src/tools.js";
import { installFakeWiki, WIKI } from "./fake-wiki.js";

const SETTINGS = { url: WIKI, username: "bot", password: "pw", allowWrites: true };
const tool = (name) => TOOLS.find((t) => t.name === name);
async function call(name, args, settings = SETTINGS) {
  const r = await runTool(tool(name), args, settings);
  return { error: r.isError ? r.content[0].text : null, out: r.structuredContent };
}
const sha = (b) => createHash("sha256").update(b).digest("hex");
const bytes = (n, seed = 1) => Uint8Array.from({ length: n }, (_, i) => (i * 31 + seed) & 0xff);
const b64 = (b) => Buffer.from(b).toString("base64");

let wiki;
beforeEach(() => {
  wiki = installFakeWiki({
    sources: {
      "https://files.example/big.bin": bytes(300_000),
      "https://files.example/missing": 404,
      "https://files.example/huge": new Uint8Array(MAX_ATTACHMENT_BYTES + 1),
    },
  });
});

test("put_attachment from base64 reports size and sha256", async () => {
  const data = bytes(1000);
  const { error, out } = await call("put_attachment", { page: "P", name: "a.bin", content_base64: b64(data) });
  assert.equal(error, null);
  assert.equal(out.size, 1000);
  assert.equal(out.sha256, sha(data));
  assert.deepEqual(wiki.attachments.get("P\u0000a.bin"), data);
});

test("base64 with line breaks, URL-safe alphabet and no padding is accepted", () => {
  const data = bytes(100);
  const wrapped = b64(data).replace(/(.{76})/g, "$1\n");
  assert.deepEqual(decodeBase64Arg("x", wrapped), data);
  const urlsafe = Buffer.from(data).toString("base64url");
  assert.deepEqual(decodeBase64Arg("x", urlsafe), data);
  assert.throws(() => decodeBase64Arg("x", "abcde"), /INVALID_ATTACHMENT/);
  assert.throws(() => decodeBase64Arg("x", "ab$d"), /INVALID_ATTACHMENT/);
});

test("put_attachment from source_url downloads on the server", async () => {
  const { error, out } = await call("put_attachment", { page: "P", name: "big.bin", source_url: "https://files.example/big.bin" });
  assert.equal(error, null);
  assert.equal(out.size, 300_000);
  assert.equal(out.sha256, sha(bytes(300_000)));
  assert.deepEqual(wiki.sourceRequests, ["https://files.example/big.bin"]);
});

test("put_attachment refuses bad sources, both or neither content, and oversize files", async () => {
  assert.match((await call("put_attachment", { page: "P", name: "x", source_url: "https://files.example/missing" })).error, /SOURCE_FAILED: .*404/);
  assert.match((await call("put_attachment", { page: "P", name: "x", source_url: "ftp://files.example/a" })).error, /INVALID_ARGUMENTS/);
  assert.match((await call("put_attachment", { page: "P", name: "x", source_url: "https://u:p@files.example/a" })).error, /INVALID_ARGUMENTS/);
  assert.match((await call("put_attachment", { page: "P", name: "x" })).error, /exactly one/);
  assert.match((await call("put_attachment", { page: "P", name: "x", content_base64: "AA==", source_url: "https://files.example/big.bin" })).error, /exactly one/);
  assert.match((await call("put_attachment", { page: "P", name: "x", source_url: "https://files.example/huge" })).error, /TOO_LARGE/);
  assert.equal(wiki.attachments.size, 0);
});

test("a sha256 mismatch writes nothing", async () => {
  const { error } = await call("put_attachment", { page: "P", name: "a", content_base64: "AAAA", sha256: "0".repeat(64) });
  assert.match(error, /CHECKSUM_MISMATCH/);
  assert.equal(wiki.attachments.size, 0);
});

test("writes are refused when disabled, before any download", async () => {
  const off = { ...SETTINGS, allowWrites: false };
  for (const [name, args] of [
    ["put_attachment", { page: "P", name: "a", source_url: "https://files.example/big.bin" }],
    ["create_upload_link", { page: "P", name: "a" }],
  ]) {
    assert.match((await call(name, args, off)).error, /WRITES_DISABLED/, name);
  }
  assert.deepEqual(wiki.sourceRequests, []);
  assert.deepEqual(wiki.requests, []);
});

test("HTTP 413 from the wiki's web server is explained", async () => {
  installFakeWiki({ maxBody: 10_000 });
  const { error } = await call("put_attachment", { page: "P", name: "a", content_base64: b64(bytes(20_000)) });
  assert.match(error, /TOO_LARGE: .*HTTP 413.*client_max_body_size/);
});

test("encodeCallBytes matches encodeCall", async () => {
  const { encodeCall, encodeCallBytes, decodeCall } = await import("../src/xmlrpc.js");
  for (const n of [0, 1, 2, 3, 4, 5, 1000]) {
    const params = ["Pä<ge>&", "n", bytes(n), [{ x: bytes(n + 1), y: "z" }]];
    assert.equal(new TextDecoder().decode(encodeCallBytes("putAttachment", params)), encodeCall("putAttachment", params));
    assert.deepEqual(decodeCall(new TextDecoder().decode(encodeCallBytes("m", params))).params[2], bytes(n));
  }
});

test("source_url without Content-Length, and a short body", async () => {
  const data = bytes(70_000);
  const chunked = () => new ReadableStream({ start(c) { c.enqueue(data.subarray(0, 30_000)); c.enqueue(data.subarray(30_000)); c.close(); } });
  const real = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    if (String(url) === "https://files.example/stream") return new Response(chunked());
    if (String(url) === "https://files.example/gzip") return new Response(data, { headers: { "Content-Length": "123", "Content-Encoding": "gzip" } });
    if (String(url) === "https://files.example/short") return new Response(data.subarray(0, 10), { headers: { "Content-Length": "20" } });
    return real(url, init);
  };
  const ok = await call("put_attachment", { page: "P", name: "s", source_url: "https://files.example/stream" });
  assert.equal(ok.out.sha256, sha(data));
  const gz = await call("put_attachment", { page: "P", name: "g", source_url: "https://files.example/gzip" });
  assert.equal(gz.out.size, 70_000);
  const short = await call("put_attachment", { page: "P", name: "t", source_url: "https://files.example/short" });
  assert.match(short.error, /SOURCE_FAILED/);
});

test("base64ToBytes is strict and matches Buffer", async () => {
  const { base64ToBytes, bytesToBase64 } = await import("../src/xmlrpc.js");
  for (const n of [0, 1, 2, 3, 4, 100, 4097]) {
    const b = bytes(n, n);
    assert.deepEqual(base64ToBytes(Buffer.from(b).toString("base64")), b);
    assert.equal(bytesToBase64(b), Buffer.from(b).toString("base64"));
  }
  for (const bad of ["A", "AAA", "A===", "AA=A", "AA AA", "AAAé"]) assert.throws(() => base64ToBytes(bad), TypeError, bad);
});


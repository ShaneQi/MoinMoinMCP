import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { TOOLS, runTool, decodeBase64Arg, MAX_ATTACHMENT_BYTES } from "../src/tools.js";
import { uploadClient, UPLOAD_TTL_MS } from "../src/uploads.js";
import { installFakeWiki, WIKI } from "./fake-wiki.js";
import { fakeNamespace } from "./fake-durable-object.js";

let SETTINGS, uploads;
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
  uploads = fakeNamespace();
  SETTINGS = { url: WIKI, username: "bot", password: "pw", allowWrites: true, uploads: uploadClient(uploads) };
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
    ["put_attachment_chunk", { page: "P", name: "a", index: 0, content_base64: "AAAA" }],
    ["finish_attachment_upload", { page: "P", name: "a", upload_id: "0123456789abcdef", chunks: 1 }],
  ]) {
    assert.match((await call(name, args, off)).error, /WRITES_DISABLED/, name);
  }
  assert.deepEqual(wiki.sourceRequests, []);
  assert.deepEqual(wiki.requests, []);
});

test("chunked upload: staged off the wiki, written once", async () => {
  const data = bytes(250_000, 7);
  const parts = [data.subarray(0, 100_000), data.subarray(100_000, 200_000), data.subarray(200_000)];
  const first = await call("put_attachment_chunk", { page: "P", name: "f.zip", index: 0, content_base64: b64(parts[0]) });
  assert.equal(first.error, null);
  const id = first.out.upload_id;
  assert.match(id, /^[0-9a-f]{16}$/);
  for (const i of [2, 1]) { // order doesn't matter
    assert.equal((await call("put_attachment_chunk", { page: "P", name: "f.zip", index: i, upload_id: id, content_base64: b64(parts[i]) })).error, null);
  }
  assert.deepEqual(wiki.requests, []); // nothing reached the wiki yet
  assert.ok(uploads.objects.get(id).alarm > Date.now() + UPLOAD_TTL_MS - 5000);

  const { error, out } = await call("finish_attachment_upload", { page: "P", name: "f.zip", upload_id: id, chunks: 3, sha256: sha(data).toUpperCase() });
  assert.equal(error, null);
  assert.equal(out.size, 250_000);
  assert.equal(out.sha256, sha(data));
  assert.deepEqual(wiki.attachments.get("P\u0000f.zip"), data);
  assert.deepEqual([...wiki.attachments.keys()], ["P\u0000f.zip"]);
  assert.deepEqual(wiki.requests, ["getAuthToken", "system.multicall"]); // one upload, nothing else
  assert.equal(uploads.objects.get(id).data.size, 0); // staging cleared
  assert.match((await call("finish_attachment_upload", { page: "P", name: "f.zip", upload_id: id, chunks: 3 })).error, /UPLOAD_NOT_FOUND/);
});

test("finish with a missing chunk or wrong checksum keeps the chunks", async () => {
  const { out } = await call("put_attachment_chunk", { page: "P", name: "f", index: 0, content_base64: "AAAA" });
  const id = out.upload_id;
  await call("put_attachment_chunk", { page: "P", name: "f", index: 2, upload_id: id, content_base64: "BBBB" });
  const missing = await call("finish_attachment_upload", { page: "P", name: "f", upload_id: id, chunks: 3 });
  assert.match(missing.error, /UPLOAD_INCOMPLETE: chunk 1 of 3/);
  await call("put_attachment_chunk", { page: "P", name: "f", index: 1, upload_id: id, content_base64: "CCCC" });
  const bad = await call("finish_attachment_upload", { page: "P", name: "f", upload_id: id, chunks: 3, sha256: "a".repeat(64) });
  assert.match(bad.error, /CHECKSUM_MISMATCH/);
  const short = await call("finish_attachment_upload", { page: "P", name: "f", upload_id: id, chunks: 2 });
  assert.match(short.error, /chunks 2 were sent too/);
  assert.equal(wiki.attachments.size, 0);

  const discarded = await call("finish_attachment_upload", { page: "P", name: "f", upload_id: id, chunks: 3, discard: true });
  assert.equal(discarded.out.discarded, 3);
  assert.equal(uploads.objects.get(id).data.size, 0);
});

test("an upload is bound to its page and name, capped in size, and expires", async () => {
  const { out } = await call("put_attachment_chunk", { page: "P", name: "f", index: 0, content_base64: "AAAA" });
  const id = out.upload_id;
  assert.match((await call("put_attachment_chunk", { page: "Q", name: "f", index: 1, upload_id: id, content_base64: "AAAA" })).error, /this upload is for f on P/);
  assert.match((await call("finish_attachment_upload", { page: "P", name: "g", upload_id: id, chunks: 1 })).error, /this upload is for f on P/);
  assert.match((await call("put_attachment_chunk", { page: "P", name: "f", index: 1, upload_id: id, content_base64: b64(bytes(1024 * 1024 + 1)) })).error, /a chunk can be at most/);
  const mib = b64(bytes(1024 * 1024));
  let err = null;
  for (let i = 1; i <= 10 && !err; i++) err = (await call("put_attachment_chunk", { page: "P", name: "f", index: i, upload_id: id, content_base64: mib })).error;
  assert.match(err, /TOO_LARGE: the chunks add up to/);
  await uploads.objects.get(id).fireAlarm();
  assert.match((await call("finish_attachment_upload", { page: "P", name: "f", upload_id: id, chunks: 1 })).error, /UPLOAD_NOT_FOUND/);
});

test("chunk tools explain a missing UPLOADS binding", async () => {
  const r = await call("put_attachment_chunk", { page: "P", name: "f", index: 0, content_base64: "AAAA" }, { ...SETTINGS, uploads: null });
  assert.match(r.error, /UPLOADS_UNAVAILABLE/);
});

test("chunk arguments are checked", async () => {
  assert.match((await call("put_attachment_chunk", { page: "P", name: "f", index: 1, content_base64: "AAAA" })).error, /upload_id is required/);
  assert.match((await call("put_attachment_chunk", { page: "P", name: "f", index: 0, upload_id: "../x", content_base64: "AAAA" })).error, /upload_id must be/);
  assert.match((await call("put_attachment_chunk", { page: "P", name: "f", index: 0, content_base64: "" })).error, /must not be empty/);
  assert.match((await call("finish_attachment_upload", { page: "P", name: "f", upload_id: "nope", chunks: 1 })).error, /upload_id must be/);
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


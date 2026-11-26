// The MCP tools. Names, arguments, results and error codes match the earlier
// Python server, so Claude sees no difference.
import { callWiki, pageUrl, WikiError } from "./moin.js";
import { base64ToBytes, bytesToBase64, XmlRpcDateTime } from "./xmlrpc.js";
import { BodyError, readCapped, sha256Hex } from "./bytes.js";
import { createUploadLink, linkSecret, LinkError, LINK_DEFAULT_MINUTES, LINK_MAX_BYTES, LINK_MAX_MINUTES } from "./uploadlink.js";

/** A tool failure, reported to Claude as the tool's error text. */
export class ToolError extends Error {}

// ---------- argument schemas and checks ----------

const str = (description) => ({ type: "string", ...(description && { description }) });
const revision = { anyOf: [{ type: "integer", minimum: 1 }, { type: "null" }], default: null };

function checkArgs(schema, args) {
  if (!args || typeof args !== "object" || Array.isArray(args)) throw new ToolError("INVALID_ARGUMENTS: arguments must be an object");
  const out = {};
  for (const [name, spec] of Object.entries(schema.properties)) {
    let v = args[name];
    if (v === undefined) {
      if (schema.required?.includes(name)) throw new ToolError(`INVALID_ARGUMENTS: ${name} is required`);
      out[name] = spec.default ?? null;
      continue;
    }
    const kinds = spec.anyOf ?? [spec];
    if (v === null && kinds.some((k) => k.type === "null")) {
      out[name] = null;
      continue;
    }
    const kind = kinds.find((k) => k.type !== "null");
    const bad = (why) => new ToolError(`INVALID_ARGUMENTS: ${name} ${why}`);
    switch (kind.type) {
      case "string":
        if (typeof v !== "string") throw bad("must be a string");
        break;
      case "boolean":
        if (typeof v !== "boolean") throw bad("must be true or false");
        break;
      case "integer":
      case "number":
        if (typeof v !== "number" || !Number.isFinite(v)) throw bad("must be a number");
        if (kind.type === "integer" && !Number.isInteger(v)) throw bad("must be an integer");
        if (kind.minimum !== undefined && v < kind.minimum) throw bad(`must be at least ${kind.minimum}`);
        if (kind.exclusiveMinimum !== undefined && v <= kind.exclusiveMinimum) throw bad(`must be greater than ${kind.exclusiveMinimum}`);
        if (kind.maximum !== undefined && v > kind.maximum) throw bad(`must be at most ${kind.maximum}`);
        break;
    }
    out[name] = v;
  }
  return out;
}

// ---------- result checks ----------

const isObj = (v) => !!v && typeof v === "object" && !Array.isArray(v) && !(v instanceof Uint8Array) && !(v instanceof XmlRpcDateTime);
const isStr = (v) => typeof v === "string";
const T = {
  str: isStr,
  int: Number.isInteger,
  bool: (v) => typeof v === "boolean",
  obj: isObj,
  bytes: (v) => v instanceof Uint8Array,
  strs: (v) => Array.isArray(v) && v.every(isStr),
  strsOrNull: (v) => Array.isArray(v) && v.every((x) => x === null || isStr(x)),
  objs: (v) => Array.isArray(v) && v.every(isObj),
  rows: (v) => Array.isArray(v) && v.every((r) => Array.isArray(r) && r.length >= 2 && r.every(isStr)),
};

// Dates become "YYYY-MM-DDTHH:MM:SS"; bytes are left for the caller to encode.
function jsonable(v) {
  if (v instanceof XmlRpcDateTime) return v.toISO();
  if (v instanceof Uint8Array) return v;
  if (Array.isArray(v)) return v.map(jsonable);
  if (isObj(v)) return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, jsonable(x)]));
  return v;
}

// ---------- attachment uploads ----------

// Whole file, however it arrives. A Worker has 128 MB; an upload holds the
// file about twice plus its base64 request body, so this leaves headroom.
export const MAX_ATTACHMENT_BYTES = LINK_MAX_BYTES;
const SOURCE_TIMEOUT_MS = 60_000;
const SHA256_RE = /^[0-9a-fA-F]{64}$/;

const mib = (n) => `${Math.round((n / 1024 / 1024) * 10) / 10} MiB`;
const tooLarge = (size) =>
  new ToolError(`TOO_LARGE: the attachment is ${size} bytes; the limit is ${MAX_ATTACHMENT_BYTES} bytes (${mib(MAX_ATTACHMENT_BYTES)})`);

/** Base64 as Claude or a tool may produce it: line breaks, spaces, URL-safe alphabet and missing padding are fine. */
export function decodeBase64Arg(name, value) {
  let b64 = value.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  if (b64.length % 4 === 1 || !/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) {
    throw new ToolError(`INVALID_ATTACHMENT: ${name} must be valid base64`);
  }
  b64 = b64.replace(/=+$/, "");
  b64 += "=".repeat((4 - (b64.length % 4)) % 4);
  if (b64.length * 0.75 > MAX_ATTACHMENT_BYTES + 3) throw tooLarge(Math.floor(b64.length * 0.75));
  try {
    return base64ToBytes(b64);
  } catch {
    throw new ToolError(`INVALID_ATTACHMENT: ${name} must be valid base64`);
  }
}

function checkSha256(arg) {
  if (arg !== null && !SHA256_RE.test(arg)) throw new ToolError("INVALID_ARGUMENTS: sha256 must be 64 hex digits");
}

async function verifySha256(bytes, expected) {
  const actual = await sha256Hex(bytes);
  if (expected !== null && actual !== expected.toLowerCase()) {
    throw new ToolError(`CHECKSUM_MISMATCH: the content's SHA-256 is ${actual}, not ${expected.toLowerCase()}; nothing was written`);
  }
  return actual;
}

/** Downloads source_url (http/https, no credentials) with a size cap, without buffering more than the limit. */
async function fetchSource(source) {
  let u;
  try {
    u = new URL(source);
  } catch {
    u = null;
  }
  if (!u || (u.protocol !== "https:" && u.protocol !== "http:") || u.username || u.password) {
    throw new ToolError("INVALID_ARGUMENTS: source_url must be an http(s) URL without credentials");
  }
  let res;
  try {
    res = await fetch(u, { headers: { "User-Agent": "moinmoin-mcp/0.4" }, signal: AbortSignal.timeout(SOURCE_TIMEOUT_MS) });
  } catch (e) {
    throw new ToolError(`SOURCE_FAILED: could not download source_url (${e?.name === "TimeoutError" ? "timed out" : e?.message ?? e})`);
  }
  if (!res.ok) throw new ToolError(`SOURCE_FAILED: source_url answered HTTP ${res.status}`);
  try {
    return await readCapped(res.body, {
      length: res.headers.get("Content-Length"),
      exact: !res.headers.get("Content-Encoding"), // a compressed size says nothing about the bytes delivered
      max: MAX_ATTACHMENT_BYTES,
    });
  } catch (e) {
    if (!(e instanceof BodyError)) throw e;
    if (e.kind === "too_large") throw tooLarge(e.size);
    throw new ToolError(`SOURCE_FAILED: download of source_url ${e.kind === "short" ? "ended early" : "broke off"} (${e.message})`);
  }
}

// ---------- tools ----------

const page = str();
const READ = { readOnlyHint: true, destructiveHint: false, openWorldHint: true };
const WRITE = { readOnlyHint: false, destructiveHint: true, openWorldHint: true };

const tool = (name, description, properties, required, annotations, run) => ({
  name, description, annotations, run,
  inputSchema: { type: "object", properties, ...(required.length && { required }) },
});

export const TOOLS = [
  tool("check_connection", "Check wiki connectivity and credentials, and report the server's write mode.",
    {}, [], READ, async ({ ctx }) => ({
      rpc_version: await ctx.rpc(T.int, "getRPCVersionSupported"),
      wiki: await ctx.rpc(T.strsOrNull, "interwikiName"),
      authenticated: !!ctx.settings.username,
      writes_enabled: ctx.settings.allowWrites,
    })),

  tool("get_page", "Read raw MoinMoin markup, optionally at a specific revision.",
    { page, version: revision }, ["page"], READ, async ({ args, ctx }) => ({
      ...ctx.details(args.page, args.version),
      text: args.version
        ? await ctx.rpc(T.str, "getPageVersion", args.page, args.version)
        : await ctx.rpc(T.str, "getPage", args.page),
    })),

  tool("get_page_html", "Read rendered HTML, optionally at a specific revision.",
    { page, version: revision }, ["page"], READ, async ({ args, ctx }) => ({
      ...ctx.details(args.page, args.version),
      html: args.version
        ? await ctx.rpc(T.str, "getPageHTMLVersion", args.page, args.version)
        : await ctx.rpc(T.str, "getPageHTML", args.page),
    })),

  tool("get_page_info", "Get page author, lastModified and version; use before and after edits.",
    { page, version: revision }, ["page"], READ, async ({ args, ctx }) => ({
      ...(args.version
        ? await ctx.rpc(T.obj, "getPageInfoVersion", args.page, args.version)
        : await ctx.rpc(T.obj, "getPageInfo", args.page)),
      ...ctx.details(args.page, args.version),
    })),

  tool("put_page", "Create or replace an entire page. Read it first and preserve processing instructions.",
    { page, text: str() }, ["page", "text"], WRITE,
    ({ args, ctx }) => ctx.write("putPage", args.page, args.text)),

  tool("list_pages", "List sorted wiki page names, optionally limited to a prefix.",
    { prefix: { anyOf: [{ type: "string" }, { type: "null" }], default: null }, include_system: { type: "boolean", default: false } },
    [], READ, async ({ args, ctx }) => {
      const options = { include_system: args.include_system };
      if (args.prefix) options.prefix = args.prefix;
      const pages = await ctx.rpc(T.strs, "getAllPagesEx", options);
      return [...pages].sort(byCodePoint).map((p) => ctx.details(p));
    }),

  tool("search_pages", "Search page content or titles, returning matching names and context.",
    { query: str(), titles: { type: "boolean", default: false }, limit: { type: "integer", minimum: 1, maximum: 500, default: 50 } },
    ["query"], READ, async ({ args, ctx }) => {
      const rows = await ctx.rpc(T.rows, "searchPagesEx", args.query, args.titles ? "title" : "text", 120, false, false, false);
      return rows.slice(0, args.limit).map((row) => ({
        ...ctx.details(row[0]),
        context: row[1],
        url: row[2] || pageUrl(ctx.settings.url, row[0]),
      }));
    }),

  tool("recent_changes", "List changes since the given number of days ago (UTC).",
    { days: { type: "number", exclusiveMinimum: 0, maximum: 3650, default: 7 } }, [], READ,
    async ({ args, ctx }) => {
      const since = XmlRpcDateTime.fromDate(new Date(Date.now() - args.days * 86_400_000));
      const changes = await ctx.rpc(T.objs, "getRecentChanges", since);
      return changes.map((c) => ({ ...c, ...ctx.details(c.name) }));
    }),

  tool("list_links", "List a page's outgoing links.",
    { page }, ["page"], READ, async ({ args, ctx }) => {
      const links = await ctx.rpc(T.objs, "listLinks", args.page);
      return links.map((l) => ({ ...l, url: l.type === 1 ? l.name : pageUrl(ctx.settings.url, l.name) }));
    }),

  tool("get_diff", "Get a base64-encoded Moin binary diff; omitted revisions use the wiki's defaults.",
    { page, from_revision: revision, to_revision: revision }, ["page"], READ, async ({ args, ctx }) => {
      const { diff, ...rest } = await ctx.rpc(T.obj, "getDiff", args.page, args.from_revision, args.to_revision);
      if (!(diff instanceof Uint8Array)) throw new ToolError("INVALID_RESPONSE: getDiff did not return a binary diff");
      return { ...rest, ...ctx.details(args.page, args.to_revision), diff_base64: bytesToBase64(diff) };
    }),

  tool("rename_page", "Rename a page. Confirm this change with the user first.",
    { page, new_name: str() }, ["page", "new_name"], WRITE, async ({ args, ctx }) => ({
      ...(await ctx.write("renamePage", args.page, args.new_name)),
      ...ctx.details(args.new_name),
    })),

  tool("revert_page", "Revert a page to a revision. Confirm this change with the user first.",
    { page, revision: { type: "integer", minimum: 1 } }, ["page", "revision"], WRITE,
    // MoinMoin's revertPage expects the revision as a string.
    ({ args, ctx }) => ctx.write("revertPage", args.page, String(args.revision))),

  tool("list_attachments", "List attachment filenames on a page.",
    { page }, ["page"], READ, async ({ args, ctx }) => ({
      ...ctx.details(args.page),
      attachments: await ctx.rpc(T.strs, "listAttachments", args.page),
    })),

  tool("get_attachment", "Download an attachment as base64, without writing server-local files.",
    { page, name: str() }, ["page", "name"], READ, async ({ args, ctx }) => ({
      ...ctx.details(args.page),
      name: args.name,
      content_base64: bytesToBase64(await ctx.rpc(T.bytes, "getAttachment", args.page, args.name)),
    })),

  tool("put_attachment",
    "Upload an attachment in one call, from content_base64 or from source_url (the server downloads it, so the " +
    "bytes never pass through the conversation; prefer it whenever the file is reachable at a URL). For a local " +
    "file over about 75 KB, use create_upload_link instead. " +
    `Limit ${mib(MAX_ATTACHMENT_BYTES)}. Give sha256 to have the content checked before it is written. ` +
    "May overwrite an existing attachment.",
    {
      page, name: str(),
      content_base64: { anyOf: [{ type: "string" }, { type: "null" }], default: null,
        description: "File content as base64 (line breaks and URL-safe base64 are fine)" },
      source_url: { anyOf: [{ type: "string" }, { type: "null" }], default: null,
        description: "http(s) URL the server downloads the file from" },
      sha256: { anyOf: [{ type: "string" }, { type: "null" }], default: null,
        description: "Expected SHA-256 of the file (hex); nothing is written if it differs" },
    },
    ["page", "name"], WRITE,
    async ({ args, ctx }) => {
      ctx.requireWrites();
      checkSha256(args.sha256);
      if ((args.content_base64 === null) === (args.source_url === null)) {
        throw new ToolError("INVALID_ARGUMENTS: give exactly one of content_base64 or source_url");
      }
      const data = args.source_url !== null
        ? await fetchSource(args.source_url)
        : decodeBase64Arg("content_base64", args.content_base64);
      if (data.length > MAX_ATTACHMENT_BYTES) throw tooLarge(data.length);
      const sha256 = await verifySha256(data, args.sha256);
      return { ...(await ctx.write("putAttachment", args.page, args.name, data)), name: args.name, size: data.length, sha256 };
    }),

  tool("create_upload_link",
    "Make a one-time link for uploading a file as an attachment over plain HTTP, so its bytes never pass " +
    "through the conversation. With a shell, upload it yourself with the returned curl command " +
    "(curl --fail-with-body -T <file> '<url>'); otherwise give the user the link: it opens an upload page in the " +
    "browser. The link works once, for this page and name, until it expires; the upload's result has its size " +
    "and sha256. Refuses if the attachment exists, unless overwrite is true.",
    {
      page, name: str("Attachment file name"),
      overwrite: { type: "boolean", default: false, description: "Allow replacing an existing attachment" },
      expires_minutes: { type: "integer", minimum: 1, maximum: LINK_MAX_MINUTES, default: LINK_DEFAULT_MINUTES },
      max_bytes: { type: "integer", minimum: 1, maximum: LINK_MAX_BYTES, default: LINK_MAX_BYTES },
    },
    ["page", "name"], WRITE,
    async ({ args, ctx }) => {
      ctx.requireWrites();
      if (!ctx.settings.origin || !(await linkSecret(ctx.settings))) {
        throw new ToolError("UPLOAD_LINKS_UNAVAILABLE: an anonymous wiki needs the UPLOAD_SECRET secret on the server for upload links");
      }
      if (!args.name.trim()) throw new ToolError("INVALID_ARGUMENTS: name must not be empty");
      try {
        return await createUploadLink(ctx.settings, {
          page: args.page, name: args.name, overwrite: args.overwrite,
          minutes: args.expires_minutes, maxBytes: args.max_bytes,
        }, ctx.call);
      } catch (e) {
        if (e instanceof LinkError) throw new ToolError(e.message);
        throw e;
      }
    }),

  tool("delete_attachment", "Delete a page attachment. Confirm this change with the user first.",
    { page, name: str() }, ["page", "name"], WRITE,
    ({ args, ctx }) => ctx.write("deleteAttachment", args.page, args.name)),
];

// Python's sorted() order for strings (by code point, not UTF-16 unit).
function byCodePoint(a, b) {
  const x = [...a], y = [...b];
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    const d = x[i].codePointAt(0) - y[i].codePointAt(0);
    if (d) return d;
  }
  return x.length - y.length;
}

/** Runs a tool; returns an MCP CallToolResult. */
export async function runTool(t, rawArgs, settings, call = callWiki) {
  const ctx = {
    settings,
    call,
    details: (p, version) => ({ page: p, url: pageUrl(settings.url, p, version) }),
    async rpc(check, method, ...params) {
      const result = jsonable(await call(settings, method, params));
      if (!check(result)) throw new ToolError(`INVALID_RESPONSE: unexpected result from ${method}`);
      return result;
    },
    requireWrites() {
      if (!settings.allowWrites) throw new ToolError("WRITES_DISABLED: set ALLOW_WRITES=true on the server to enable writes");
    },
    async write(method, p, ...params) {
      ctx.requireWrites();
      if ((await ctx.rpc(T.bool, method, p, ...params)) !== true) {
        throw new ToolError(`WRITE_FAILED: ${method} did not confirm success`);
      }
      return { ok: true, ...ctx.details(p) };
    },
  };
  try {
    const args = checkArgs(t.inputSchema, rawArgs ?? {});
    const out = await t.run({ args, ctx });
    const structured = Array.isArray(out) ? { result: out } : out;
    return { content: [{ type: "text", text: JSON.stringify(structured) }], structuredContent: structured };
  } catch (e) {
    if (e instanceof ToolError || e instanceof WikiError) return { content: [{ type: "text", text: e.message }], isError: true };
    console.error(e);
    return { content: [{ type: "text", text: `Unexpected error: ${e?.message ?? e}` }], isError: true };
  }
}

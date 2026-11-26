// MoinMoin XML-RPC v2 access, with per-call authentication and no shared sessions.
import { decodeResponse, encodeCallBytes, XmlRpcFault, XmlRpcParseError } from "./xmlrpc.js";

const FETCH_TIMEOUT_MS = 60_000;

/** A configuration problem: the server answers MCP requests with 500 until it is fixed. */
export class ConfigError extends Error {}

/** A wiki operation failure, reported to Claude as a tool error. */
export class WikiError extends Error {}

/** { url, username, password, allowWrites, uploadSecret } from the Worker's env; throws ConfigError. */
export function wikiSettings(env) {
  const url = (env.MOIN_URL ?? "").trim();
  endpoint(url);
  const username = env.MOIN_USER ?? "";
  const password = env.MOIN_PASSWORD ?? "";
  if (!!username !== !!password) {
    throw new ConfigError("Set both MOIN_USER and MOIN_PASSWORD, or neither for anonymous access");
  }
  const writes = String(env.ALLOW_WRITES ?? "false").toLowerCase();
  if (writes !== "true" && writes !== "false") throw new ConfigError("ALLOW_WRITES must be true or false");
  const uploadSecret = env.UPLOAD_SECRET ?? "";
  if (uploadSecret && uploadSecret.length < 32) throw new ConfigError("UPLOAD_SECRET must be at least 32 characters");
  return { url, username, password, allowWrites: writes === "true", uploadSecret };
}

function parseUrl(url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    u = null;
  }
  if (!u || (u.protocol !== "http:" && u.protocol !== "https:") || !u.hostname || u.username || u.password || u.hash) {
    throw new ConfigError("MOIN_URL must be an HTTP(S) wiki URL without credentials or a fragment");
  }
  return u;
}

/** The XML-RPC endpoint: MOIN_URL with action=xmlrpc2. */
export function endpoint(url) {
  const u = parseUrl(url);
  u.searchParams.delete("action");
  u.searchParams.append("action", "xmlrpc2");
  return u.toString();
}

// Like Python's quote(s, safe="/"): only letters, digits, "_.-~" and "/" stay as they are.
const quotePath = (s) =>
  encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`).replace(/%2F/g, "/");

/** A browser link to a page (at a revision when given). */
export function pageUrl(url, page, version) {
  const u = new URL(url);
  const path = u.pathname.replace(/\/+$/, "") + "/" + quotePath(page);
  u.searchParams.delete("action");
  u.searchParams.delete("rev");
  if (version != null) {
    u.searchParams.append("action", "recall");
    u.searchParams.append("rev", String(version));
  }
  const query = u.searchParams.toString();
  return `${u.origin}${path}${query ? `?${query}` : ""}`;
}

async function post(url, method, params) {
  let res;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "text/xml", "User-Agent": "moinmoin-mcp/0.4" },
      body: encodeCallBytes(method, params),
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
  } catch (e) {
    console.warn(`wiki request failed (${e?.name ?? "error"})`);
    throw new WikiError("NETWORK: could not reach the wiki; check MOIN_URL and that the wiki is reachable");
  }
  if (res.status === 413) {
    throw new WikiError(
      "TOO_LARGE: the wiki's web server refused the request as too large (HTTP 413); " +
      "raise its request size limit (e.g. nginx client_max_body_size) or upload a smaller file");
  }
  if (!res.ok) throw new WikiError(`Wiki returned HTTP ${res.status}; check MOIN_URL and XML-RPC access`);
  const body = await res.text();
  try {
    return decodeResponse(body);
  } catch (e) {
    if (e instanceof XmlRpcFault) throw new WikiError(e.message);
    if (e instanceof XmlRpcParseError) throw new WikiError("NOT_XMLRPC: check MOIN_URL and enable XML-RPC on the wiki");
    throw e;
  }
}

// A multicall entry is [value] on success or { faultCode, faultString } on failure.
function multicallResult(entry) {
  if (Array.isArray(entry) && entry.length === 1) return entry[0];
  if (entry && typeof entry === "object" && "faultCode" in entry) {
    throw new WikiError(`FAULT ${entry.faultCode}: ${entry.faultString}`);
  }
  throw new WikiError("NOT_XMLRPC: unexpected multicall result from the wiki");
}

// With credentials: a fresh auth token, or AUTH_FAILED.
async function authToken(url, settings) {
  const token = await post(url, "getAuthToken", [settings.username, settings.password]);
  if (!token) throw new WikiError("AUTH_FAILED: wiki rejected the username or password");
  return token;
}

/**
 * Calls one wiki method. With credentials, it gets a fresh auth token and sends
 * applyAuthToken + the call as one system.multicall, as Moin's xmlrpc2 expects.
 */
export async function callWiki(settings, method, params) {
  const url = endpoint(settings.url);
  let result;
  if (settings.username) {
    const token = await authToken(url, settings);
    const results = await post(url, "system.multicall", [[
      { methodName: "applyAuthToken", params: [token] },
      { methodName: method, params },
    ]]);
    if (!Array.isArray(results) || results.length !== 2) {
      throw new WikiError("NOT_XMLRPC: unexpected multicall result from the wiki");
    }
    if (multicallResult(results[0]) !== "SUCCESS") {
      throw new WikiError("AUTH_FAILED: wiki rejected the authentication token");
    }
    result = multicallResult(results[1]);
  } else {
    result = await post(url, method, params);
  }
  if (result && typeof result === "object" && !Array.isArray(result) && "faultCode" in result && "faultString" in result) {
    throw new WikiError(`FAULT ${result.faultCode}: ${result.faultString}`);
  }
  return result;
}

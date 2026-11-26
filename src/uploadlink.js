// One-time upload links: create_upload_link returns
// https://<worker>/upload/<token>, and the file goes there over plain HTTP —
// `curl -T file <url>` from a shell, or the upload page in a browser — so its
// bytes never pass through the conversation.
//
// The token is stateless: HMAC-SHA256 (see linkSecret) over the page, the
// attachment name, a size cap, an expiry, and the attachment's state when the
// link was made (null = absent, else the SHA-256 of its content). An upload is
// accepted only while the attachment is still in that state, so after the
// first upload the link stops working; the wiki itself is the "used" flag.
//
// /upload/* is reached without Cloudflare Access (it needs an Access Bypass
// policy for that path); the token is the authorization.
import { BodyError, readCapped, sha256Hex } from "./bytes.js";
import { callWiki, pageUrl, WikiError } from "./moin.js";
import { base64ToBytes, bytesToBase64 } from "./xmlrpc.js";

export const LINK_MAX_BYTES = 20 * 1024 * 1024;
export const LINK_DEFAULT_MINUTES = 15;
export const LINK_MAX_MINUTES = 60;

const enc = new TextEncoder();
const b64url = (bytes) => bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64url = (s) => {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  return base64ToBytes(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
};

/** The name MoinMoin stores an attachment under (wikiutil.taintfilename in 1.9). */
export function taintFilename(name) {
  let s = name;
  for (const x of ["..", ":", "/", "\\", "<", ">"]) s = s.split(x).join("_");
  return s;
}

/**
 * The key that signs links: UPLOAD_SECRET if set, otherwise one derived from
 * MOIN_PASSWORD with HKDF-SHA256 (salted with the wiki URL, so the password
 * itself never signs anything and other wikis get other keys). null on an
 * anonymous wiki with no UPLOAD_SECRET: upload links are then off. Changing
 * the password invalidates open links, which last an hour at most anyway.
 */
export async function linkSecret(settings) {
  if (settings.uploadSecret) return settings.uploadSecret;
  if (!settings.password) return null;
  const base = await crypto.subtle.importKey("raw", enc.encode(settings.password), "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: enc.encode(`moinmoin-mcp ${settings.url}`), info: enc.encode("upload links v1") },
    base, 256);
  return b64url(new Uint8Array(bits));
}

const hmacKey = (secret) =>
  crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);

export async function signToken(secret, claims) {
  const body = b64url(enc.encode(JSON.stringify(claims)));
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", await hmacKey(secret), enc.encode(body)));
  return `${body}.${b64url(sig)}`;
}

export class LinkError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

/** The token's claims { p, n, h, m, e }, or a LinkError (401) if it is forged, malformed or expired. */
export async function verifyToken(secret, token, nowS = Date.now() / 1000) {
  const m = /^([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/.exec(token);
  let ok = false, claims = null;
  if (m) {
    try {
      ok = await crypto.subtle.verify("HMAC", await hmacKey(secret), fromB64url(m[2]), enc.encode(m[1]));
      if (ok) claims = JSON.parse(new TextDecoder().decode(fromB64url(m[1])));
    } catch {
      ok = false;
    }
  }
  if (!ok || !claims || typeof claims.p !== "string" || typeof claims.n !== "string") {
    throw new LinkError(401, "LINK_INVALID: this upload link is not valid");
  }
  if (!(claims.e > nowS)) throw new LinkError(401, "LINK_EXPIRED: this upload link has expired; ask for a new one");
  return claims;
}

/** null if the page has no such attachment, else the SHA-256 of its content. */
export async function attachmentState(settings, page, name, call = callWiki) {
  const names = await call(settings, "listAttachments", [page]);
  if (!Array.isArray(names)) throw new WikiError("INVALID_RESPONSE: unexpected result from listAttachments");
  if (!names.includes(name)) return null;
  const data = await call(settings, "getAttachment", [page, name]);
  if (!(data instanceof Uint8Array)) throw new WikiError("INVALID_RESPONSE: unexpected result from getAttachment");
  return sha256Hex(data);
}

/** Makes a link; the caller has checked writes are enabled and that linkSecret(settings) is not null. */
export async function createUploadLink(settings, { page, name, overwrite, minutes, maxBytes }, call = callWiki) {
  const stored = taintFilename(name);
  const state = await attachmentState(settings, page, stored, call);
  if (state !== null && !overwrite) {
    throw new LinkError(409, `ATTACHMENT_EXISTS: ${stored} is already attached to ${page}; pass overwrite: true to replace it`);
  }
  const expires = Math.floor(Date.now() / 1000) + minutes * 60;
  const token = await signToken(await linkSecret(settings), { p: page, n: stored, h: state, m: maxBytes, e: expires });
  const url = `${settings.origin}/upload/${token}`;
  return {
    upload_url: url,
    curl: `curl --fail-with-body -T <file> '${url}'`,
    page, name: stored, page_url: pageUrl(settings.url, page),
    replaces: state, // SHA-256 of the attachment it will overwrite, or null
    max_bytes: maxBytes,
    expires_at: new Date(expires * 1000).toISOString(),
  };
}

// ---------- the /upload/<token> endpoint ----------

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

const PAGE_HEADERS = {
  "Content-Type": "text/html; charset=utf-8",
  "Cache-Control": "no-store",
  "Referrer-Policy": "no-referrer", // the URL is the credential
  "X-Frame-Options": "DENY",
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'",
};

function htmlPage(title, body) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><style>
:root{color-scheme:light dark;--fg:#1b1b1f;--muted:#5f6068;--bg:#f7f7f9;--card:#fff;--line:#d9d9e0;--accent:#2f5bd3;--ok:#1d7f46;--bad:#b42318}
@media (prefers-color-scheme:dark){:root{--fg:#ececf1;--muted:#a3a4ad;--bg:#16161a;--card:#202026;--line:#34343c;--accent:#7f9cf5;--ok:#4fc386;--bad:#f97066}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif}
main{max-width:34rem;margin:8vh auto;padding:0 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:24px}
h1{font-size:1.25rem;margin:0 0 4px}p{margin:4px 0}.muted{color:var(--muted);font-size:.9rem}
code{font-size:.9em;overflow-wrap:anywhere}
#drop{display:block;margin:20px 0;padding:28px 16px;border:2px dashed var(--line);border-radius:10px;text-align:center;cursor:pointer}
#drop.over{border-color:var(--accent)}#file{display:none}
button{font:inherit;padding:8px 18px;border-radius:8px;border:0;background:var(--accent);color:#fff;cursor:pointer}
button:disabled{opacity:.5;cursor:default}progress{width:100%;margin-top:16px}
.ok{color:var(--ok)}.bad{color:var(--bad)}</style></head><body><main><div class="card">${body}</div></main></body></html>`;
}

function uploadForm(claims) {
  const replaces = claims.h ? `<p class="muted">Replaces the current attachment.</p>` : "";
  return htmlPage(`Upload ${claims.n}`, `
<h1>Upload to ${esc(claims.p)}</h1>
<p>Saved as <code>${esc(claims.n)}</code></p>${replaces}
<p class="muted">Up to ${Math.round(claims.m / 1024 / 1024 * 10) / 10} MiB · link expires ${esc(new Date(claims.e * 1000).toLocaleString("en-US", { timeZone: "UTC" }))} UTC · works once</p>
<label id="drop" for="file"><span id="pick">Choose a file or drop it here</span><input id="file" type="file"></label>
<button id="go" disabled>Upload</button><progress id="bar" max="1" value="0" hidden></progress><p id="msg" role="status"></p>
<script>
const max=${claims.m},file=document.getElementById("file"),drop=document.getElementById("drop"),go=document.getElementById("go"),
bar=document.getElementById("bar"),msg=document.getElementById("msg"),pick=document.getElementById("pick");let chosen=null;
function choose(f){chosen=f;pick.textContent=f?f.name+" ("+Math.ceil(f.size/1024)+" KB)":"Choose a file or drop it here";
msg.textContent="";msg.className="";if(f&&f.size>max){msg.textContent="That file is over the size limit.";msg.className="bad";chosen=null}go.disabled=!chosen}
file.onchange=()=>choose(file.files[0]);
drop.ondragover=e=>{e.preventDefault();drop.classList.add("over")};drop.ondragleave=()=>drop.classList.remove("over");
drop.ondrop=e=>{e.preventDefault();drop.classList.remove("over");choose(e.dataTransfer.files[0])};
go.onclick=()=>{if(!chosen)return;go.disabled=true;bar.hidden=false;const x=new XMLHttpRequest();x.open("PUT",location.href);
x.upload.onprogress=e=>{if(e.lengthComputable)bar.value=e.loaded/e.total};
x.onload=()=>{let r={};try{r=JSON.parse(x.responseText)}catch{}if(x.status===200){bar.value=1;msg.className="ok";
msg.textContent="Uploaded "+r.name+" ("+r.size+" bytes). You can close this page.";}else{bar.hidden=true;msg.className="bad";
msg.textContent=r.error||("Upload failed (HTTP "+x.status+")")}};
x.onerror=()=>{bar.hidden=true;go.disabled=false;msg.className="bad";msg.textContent="Upload failed: network error"};x.send(chosen)};
</script>`);
}

const errorPage = (status, message) =>
  new Response(htmlPage("Upload link", `<h1>Can't upload</h1><p class="bad">${esc(message)}</p>`), { status, headers: PAGE_HEADERS });

/** Serves /upload/<token>: GET = the upload page, PUT = the file. */
export async function handleUpload(request, settings, token, call = callWiki) {
  const page = request.method === "GET" || request.method === "HEAD";
  if (!page && request.method !== "PUT") {
    return new Response("Method not allowed\n", { status: 405, headers: { Allow: "GET, PUT" } });
  }
  const fail = (status, message) => (page ? errorPage(status, message) : json({ error: message }, status));
  const secret = await linkSecret(settings);
  if (!secret) return fail(503, "UPLOAD_LINKS_UNAVAILABLE: set UPLOAD_SECRET (or MOIN_USER and MOIN_PASSWORD) on the server");

  let claims;
  try {
    claims = await verifyToken(secret, token);
  } catch (e) {
    if (e instanceof LinkError) return fail(e.status, e.message);
    throw e;
  }
  if (!settings.allowWrites) return fail(403, "WRITES_DISABLED: set ALLOW_WRITES=true on the server to enable writes");
  try {
    const used = () => fail(409, "LINK_USED: this link was already used, or the attachment changed since it was made; ask for a new link");
    if ((await attachmentState(settings, claims.p, claims.n, call)) !== claims.h) return used();
    if (page) return new Response(request.method === "HEAD" ? null : uploadForm(claims), { headers: PAGE_HEADERS });

    let data;
    try {
      data = await readCapped(request.body, { length: request.headers.get("Content-Length"), exact: true, max: claims.m });
    } catch (e) {
      if (!(e instanceof BodyError)) throw e;
      if (e.kind === "too_large") return fail(413, `TOO_LARGE: this link takes at most ${claims.m} bytes`);
      return fail(400, `UPLOAD_BROKEN: the upload ${e.kind === "short" ? "ended early" : "broke off"} (${e.message})`);
    }
    if (!data.length) return fail(400, "EMPTY: the upload had no content (with curl, use -T <file>)");
    // Checked again just before writing, so two uploads racing on one link rarely both land.
    if ((await attachmentState(settings, claims.p, claims.n, call)) !== claims.h) return used();
    const sha256 = await sha256Hex(data);
    const result = { ok: true, page: claims.p, name: claims.n, size: data.length, sha256, url: pageUrl(settings.url, claims.p) };
    // Same bytes as the attachment it replaces: nothing to write (and no log entry).
    if (sha256 === claims.h) return json({ ...result, unchanged: true });
    if ((await call(settings, "putAttachment", [claims.p, claims.n, data])) !== true) {
      return fail(502, "WRITE_FAILED: putAttachment did not confirm success");
    }
    console.log(`upload link: ${claims.n} on ${claims.p}, ${data.length} bytes`);
    return json(result);
  } catch (e) {
    if (e instanceof WikiError) return fail(502, e.message);
    throw e;
  }
}

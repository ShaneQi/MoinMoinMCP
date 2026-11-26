# MoinMoin MCP

A Cloudflare Worker that lets Claude read and write a MoinMoin 1.9 wiki through
the wiki's XML-RPC interface (`?action=xmlrpc2`). It speaks MCP over stateless
Streamable HTTP at `POST /mcp` and has no dependencies.

Tools: `check_connection`, `get_page`, `get_page_html`, `get_page_info`,
`list_pages`, `search_pages`, `recent_changes`, `list_links`, `get_diff`,
`list_attachments`, `get_attachment`, and the write tools `put_page`,
`rename_page`, `revert_page`, `put_attachment`, `create_upload_link`,
`delete_attachment`. Write tools return
`WRITES_DISABLED` unless `ALLOW_WRITES=true`.

| File | |
|---|---|
| `src/index.js` | Routes, Cloudflare Access check, settings, `/upload/<token>` |
| `src/access.js` | Cloudflare Access JWT verification (same file as OFCloudMCP and LinkCliMCP) |
| `src/mcp.js` | MCP JSON-RPC handling |
| `src/tools.js` | Tool definitions, argument and result checks |
| `src/moin.js` | Wiki calls (per-call auth token + `system.multicall`), page URLs |
| `src/uploadlink.js` | One-time upload links: signed tokens, the `/upload/<token>` endpoint and its page |
| `src/bytes.js` | SHA-256 and size-capped body reading |
| `src/xmlrpc.js` | XML-RPC encoder/decoder (requests are built as bytes, base64 written straight in) |
| `test/` | `node --test`; `fake-wiki.js` is an in-memory MoinMoin xmlrpc2 endpoint installed as `fetch` |

## Configuration

Set these in the Cloudflare dashboard (Workers → `moinmoin-mcp` → Settings →
Variables and Secrets). `wrangler.toml` keeps them on every deploy
(`keep_bindings`), so a deploy only replaces the code.

| Name | Type | |
|---|---|---|
| `MOIN_URL` | variable | Wiki base URL, e.g. `https://wiki.example.com/` |
| `ALLOW_WRITES` | variable | `true` enables the write tools (default `false`) |
| `CF_ACCESS_TEAM_DOMAIN` | variable | `<team>.cloudflareaccess.com` |
| `CF_ACCESS_AUD` | variable | The Access application's AUD tag (comma-separate several) |
| `MOIN_USER`, `MOIN_PASSWORD` | secrets | Wiki account; leave both unset for an anonymous wiki |
| `UPLOAD_SECRET` | secret | Signs upload links; at least 32 characters (e.g. `openssl rand -hex 32`). Unset = no upload links |

If the Access or wiki settings are missing or invalid, `/mcp` answers `500`
instead of opening up. `xmlrpc` must not be in the wiki's `actions_excluded`.

## Uploading attachments

Three ways, all writing the attachment with one `putAttachment` (one
`ATTNEW` line in the wiki's edit log):

- **`create_upload_link`** (any local file, up to 20 MiB): returns a one-time
  `https://<worker>/upload/<token>` link. Claude uploads with
  `curl --fail-with-body -T <file> '<url>'` from a shell, or gives you the link,
  which opens an upload page (file picker, drag and drop, progress). The file
  goes over plain HTTP, so its bytes never pass through the conversation.
- **`put_attachment` with `source_url`** (up to 20 MiB): the Worker downloads
  the file (http/https, no credentials in the URL, 60 s timeout).
- **`put_attachment` with `content_base64`**: the file inside the tool call;
  only sensible for small files (up to roughly 75 KB). Line-wrapped, URL-safe
  and unpadded base64 are accepted.

Every upload returns `size` and `sha256`; `put_attachment` takes an expected
`sha256` and writes nothing if it differs.

### How upload links work

The token is stateless: HMAC-SHA256 with `UPLOAD_SECRET` over the page, the
attachment name (as MoinMoin will store it), a size cap, an expiry (15 min
by default, at most 60) and the attachment's state when the link was made:
absent, or the SHA-256 of its current content. An upload is accepted only
while the attachment is still in that state, so the first upload uses the
link up, and so does anyone else attaching that name in the meantime. The
wiki is the "used" flag; there is no storage. A link for an existing
attachment needs `overwrite: true`; uploading identical bytes writes nothing
and leaves the link usable.

`/upload/*` is not behind Cloudflare Access (curl in Claude's sandbox can't
sign in to Access): in Zero Trust → Access → Applications, add an
application for `<worker-domain>/upload` with a **Bypass** policy (Everyone).
The token is the authorization there, so treat a link like a short-lived
password. `/mcp` keeps requiring Access. The upload page sends
`Referrer-Policy: no-referrer` and `Cache-Control: no-store`.

Responses from `PUT /upload/<token>` are JSON: `200` with `size`, `sha256`
and the page `url`; `401` invalid or expired link; `409` link already used
(or the attachment changed); `413` over the link's size cap; `403` writes
disabled; `503` no `UPLOAD_SECRET`.

### Limits outside the Worker

The wiki's web server must accept a request about 1.4× the file size (nginx
defaults to 1 MB, `client_max_body_size`); if it refuses, the error says
`TOO_LARGE … HTTP 413`. Encoding a multi-megabyte file takes more CPU time
than the Workers free plan's 10 ms per request, so large uploads need the
paid plan.

## Authentication

Put the Worker's hostname behind a Cloudflare Access application. The Worker
also verifies the Access JWT itself on every `/mcp` request, from
`Cf-Access-Jwt-Assertion` (or `Authorization: Bearer <jwt>`): RS256 against
`https://<team>/cdn-cgi/access/certs`, issuer, audience, and `exp`/`nbf` with
60 s leeway. A missing or invalid token gets `401`; the reason is only logged,
as `access denied: …`. The `workers.dev` and preview URLs are off
(`wrangler.toml`), so the custom domain behind Access is the only way in. `/health` and `/healthz` stay open,
and `/upload/<token>` is authorized by its signed token instead (see above).

## Develop

```sh
npm test    # node --test against an in-memory fake wiki; no dependencies
```

## Deploy

Every push to `main` runs the tests, then deploys with `wrangler deploy`
(`.github/workflows/deploy.yml`). It needs the repository secrets
`CLOUDFLARE_API_TOKEN` (the "Edit Cloudflare Workers" template) and
`CLOUDFLARE_ACCOUNT_ID`. A deploy only replaces the code: variables and
secrets stay (`keep_bindings`), the custom domain is managed in the dashboard,
and `workers.dev` and preview URLs stay off.

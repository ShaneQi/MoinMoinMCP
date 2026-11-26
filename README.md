# MoinMoin MCP

A Cloudflare Worker that lets Claude read and write a MoinMoin 1.9 wiki through
the wiki's XML-RPC interface (`?action=xmlrpc2`). It speaks MCP over stateless
Streamable HTTP at `POST /mcp` and has no dependencies.

Tools: `check_connection`, `get_page`, `get_page_html`, `get_page_info`,
`list_pages`, `search_pages`, `recent_changes`, `list_links`, `get_diff`,
`list_attachments`, `get_attachment`, and the write tools `put_page`,
`rename_page`, `revert_page`, `put_attachment`, `put_attachment_chunk`,
`finish_attachment_upload`, `delete_attachment`. Write tools return
`WRITES_DISABLED` unless `ALLOW_WRITES=true`.

| File | |
|---|---|
| `src/index.js` | Routes, Cloudflare Access check, settings |
| `src/access.js` | Cloudflare Access JWT verification (same file as OFCloudMCP and LinkCliMCP) |
| `src/mcp.js` | MCP JSON-RPC handling |
| `src/tools.js` | Tool definitions, argument and result checks |
| `src/moin.js` | Wiki calls (per-call auth token + `system.multicall`), page URLs |
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

If the Access or wiki settings are missing or invalid, `/mcp` answers `500`
instead of opening up. `xmlrpc` must not be in the wiki's `actions_excluded`.

## Uploading attachments

Attachments can be up to 10 MiB, and there are three ways to send one:

- **`put_attachment` with `source_url`**: the Worker downloads the file
  (http/https, no credentials in the URL, 60 s timeout) and uploads it, so the
  bytes never pass through the conversation. Best for anything that already
  has a URL.
- **`put_attachment` with `content_base64`**: the whole file in one call; fine
  for small files (up to roughly 75 KB). Line-wrapped, URL-safe and unpadded
  base64 are accepted.
- **Chunked**: `put_attachment_chunk` for chunk 0 (it returns an `upload_id`),
  then chunks 1, 2, … with that id, then `finish_attachment_upload` with the
  number of chunks. Each chunk is staged on the page as a temporary attachment
  `<name>.upload-<id>-<nnnn>.part`; finishing reads them back (32 per
  multicall, one auth token), joins them, writes the attachment and deletes
  the parts. A missing chunk or a wrong `sha256` writes nothing and keeps the
  parts so they can be re-sent; `discard: true` removes them. Parts of an
  upload that was never finished stay on the page until deleted.

Every upload returns `size` and `sha256`; pass `sha256` to have the content
checked before anything is written.

Limits outside the Worker: the wiki's web server must accept a request about
1.4× the file size (nginx defaults to 1 MB, `client_max_body_size`); if it
refuses, the tool says `TOO_LARGE … HTTP 413`. Encoding a multi-megabyte file
takes more CPU time than the Workers free plan's 10 ms per request, so large
uploads need the paid plan.

## Authentication

Put the Worker's hostname behind a Cloudflare Access application. The Worker
also verifies the Access JWT itself on every `/mcp` request, from
`Cf-Access-Jwt-Assertion` (or `Authorization: Bearer <jwt>`): RS256 against
`https://<team>/cdn-cgi/access/certs`, issuer, audience, and `exp`/`nbf` with
60 s leeway. A missing or invalid token gets `401`; the reason is only logged,
as `access denied: …`. The `workers.dev` and preview URLs are off
(`wrangler.toml`), so the custom domain behind Access is the only way in. `/health` and `/healthz` stay open.

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

// Staging for chunked attachment uploads, in a Durable Object (one object per
// upload). Chunks never touch the wiki, so its edit log and notifications only
// see the finished attachment. An upload with no new chunk for an hour is
// deleted by the object's alarm.
//
// The object speaks plain HTTP to the Worker (no `cloudflare:workers` import,
// so Node tests can run it against an in-memory storage):
//   PUT    /chunk/<index>  body = chunk bytes; X-Page, X-Name (URI-encoded)
//   POST   /join           body = { chunks, page, name } -> joined bytes, or 409 { missing } / { error }
//   DELETE /               removes the upload -> { chunks }

export const MAX_UPLOAD_BYTES = 10 * 1024 * 1024; // the whole attachment (see src/tools.js)
export const MAX_CHUNK_BYTES = 1024 * 1024; // a storage entry holds at most 2 MB
export const UPLOAD_TTL_MS = 60 * 60_000;

const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

export class UploadStore {
  constructor(ctx) {
    this.storage = ctx.storage;
  }

  async fetch(request) {
    const { pathname } = new URL(request.url);
    const chunk = /^\/chunk\/(\d{1,4})$/.exec(pathname);
    if (request.method === "PUT" && chunk) return this.putChunk(request, Number(chunk[1]));
    if (request.method === "POST" && pathname === "/join") return this.join(await request.json());
    if (request.method === "DELETE" && pathname === "/") return this.discard();
    return json({ error: "not found" }, 404);
  }

  async putChunk(request, index) {
    const page = decodeURIComponent(request.headers.get("X-Page") ?? "");
    const name = decodeURIComponent(request.headers.get("X-Name") ?? "");
    const data = new Uint8Array(await request.arrayBuffer());
    if (data.length > MAX_CHUNK_BYTES) return json({ error: `TOO_LARGE: a chunk can be at most ${MAX_CHUNK_BYTES} bytes` }, 413);
    const meta = (await this.storage.get("meta")) ?? { page, name, sizes: {} };
    if (meta.page !== page || meta.name !== name) {
      return json({ error: `INVALID_ARGUMENTS: this upload is for ${meta.name} on ${meta.page}` }, 409);
    }
    meta.sizes[index] = data.length;
    const total = Object.values(meta.sizes).reduce((n, s) => n + s, 0);
    if (total > MAX_UPLOAD_BYTES) {
      return json({ error: `TOO_LARGE: the chunks add up to ${total} bytes; the limit is ${MAX_UPLOAD_BYTES} bytes` }, 413);
    }
    await this.storage.put({ [`chunk:${index}`]: data, meta });
    await this.storage.setAlarm(Date.now() + UPLOAD_TTL_MS);
    return json({ size: data.length, total });
  }

  async join({ chunks, page, name }) {
    const meta = await this.storage.get("meta");
    if (!meta) return json({ missing: Array.from({ length: chunks }, (_, i) => i), expired: true }, 409);
    if (meta.page !== page || meta.name !== name) {
      return json({ error: `INVALID_ARGUMENTS: this upload is for ${meta.name} on ${meta.page}` }, 409);
    }
    const missing = [];
    for (let i = 0; i < chunks; i++) if (!(i in meta.sizes)) missing.push(i);
    if (missing.length) return json({ missing }, 409);
    const extra = Object.keys(meta.sizes).map(Number).filter((i) => i >= chunks);
    if (extra.length) {
      return json({ error: `INVALID_ARGUMENTS: chunks ${extra.join(", ")} were sent too; chunks should be ${Math.max(...extra) + 1}` }, 409);
    }
    const size = Object.values(meta.sizes).reduce((n, s) => n + s, 0);
    const out = new Uint8Array(size);
    let at = 0;
    for (let i = 0; i < chunks; i++) {
      const part = await this.storage.get(`chunk:${i}`);
      out.set(part, at);
      at += part.length;
    }
    return new Response(out, { headers: { "Content-Type": "application/octet-stream" } });
  }

  async discard() {
    const meta = await this.storage.get("meta");
    await this.storage.deleteAll();
    await this.storage.deleteAlarm();
    return json({ chunks: meta ? Object.keys(meta.sizes).length : 0 });
  }

  async alarm() {
    await this.storage.deleteAll();
  }
}

/** The Worker's side: talks to the upload's Durable Object through the UPLOADS binding. */
export function uploadClient(namespace) {
  const stub = (uploadId) => namespace.get(namespace.idFromName(uploadId));
  const base = "https://upload";
  const fail = async (res) => {
    const body = await res.json().catch(() => ({}));
    return { error: body.error ?? `upload storage answered HTTP ${res.status}`, missing: body.missing, expired: body.expired };
  };
  return {
    async put(uploadId, index, data, page, name) {
      const res = await stub(uploadId).fetch(`${base}/chunk/${index}`, {
        method: "PUT", body: data,
        headers: { "X-Page": encodeURIComponent(page), "X-Name": encodeURIComponent(name) },
      });
      return res.ok ? res.json() : fail(res);
    },
    async join(uploadId, chunks, page, name) {
      const res = await stub(uploadId).fetch(`${base}/join`, { method: "POST", body: JSON.stringify({ chunks, page, name }) });
      return res.ok ? { data: new Uint8Array(await res.arrayBuffer()) } : fail(res);
    },
    async discard(uploadId) {
      return (await stub(uploadId).fetch(`${base}/`, { method: "DELETE" })).json();
    },
  };
}

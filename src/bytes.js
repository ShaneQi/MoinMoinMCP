// Byte helpers shared by put_attachment (source_url) and the upload link.

/** Hex SHA-256 of bytes. */
export async function sha256Hex(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Why readCapped gave up: kind is "too_large" (size = bytes seen), "broken" or "short". */
export class BodyError extends Error {
  constructor(kind, message, size) {
    super(message);
    this.kind = kind;
    this.size = size;
  }
}

/**
 * Reads a body stream into one Uint8Array, refusing more than `max` bytes
 * without buffering past it. `length` is the Content-Length; when it is exact
 * (`exact`: no Content-Encoding) the bytes go straight into one buffer and a
 * body that ends early is refused.
 */
export async function readCapped(body, { length, exact, max }) {
  const declared = Number(length);
  if (Number.isFinite(declared) && declared > max) {
    await body?.cancel();
    throw new BodyError("too_large", `${declared} bytes`, declared);
  }
  if (!body) return new Uint8Array(0);
  const known = exact && Number.isInteger(declared) && declared > 0 ? new Uint8Array(declared) : null;
  const parts = [];
  let size = 0;
  const reader = body.getReader();
  for (;;) {
    let step;
    try {
      step = await reader.read();
    } catch (e) {
      throw new BodyError("broken", e?.message ?? String(e), size);
    }
    if (step.done) break;
    size += step.value.length;
    if (size > max) {
      await reader.cancel();
      throw new BodyError("too_large", `over ${max} bytes`, size);
    }
    if (known && size <= known.length) known.set(step.value, size - step.value.length);
    else parts.push(step.value);
  }
  if (known && !parts.length && size === known.length) return known;
  if (known) throw new BodyError("short", `got ${size} bytes, not the ${declared} announced`, size);
  return concat(parts, size);
}

export function concat(parts, size = parts.reduce((n, p) => n + p.length, 0)) {
  const out = new Uint8Array(size);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

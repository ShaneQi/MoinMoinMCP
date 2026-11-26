// A small XML-RPC codec: enough of the spec for MoinMoin's xmlrpc2 interface,
// with no dependencies (Workers have no DOMParser).
//
// Values map to JavaScript as:
//   int / i4 / i8      number          double            number
//   boolean            boolean         string (or bare)  string
//   nil                null            base64            Uint8Array
//   dateTime.iso8601   XmlRpcDateTime  array / struct    Array / plain object

export class XmlRpcDateTime {
  /** value: the wire form, e.g. "20261114T12:00:00". */
  constructor(value) {
    this.value = value;
  }
  /** A UTC Date as XML-RPC's zone-less "YYYYMMDDTHH:MM:SS". */
  static fromDate(date) {
    const p = (n) => String(n).padStart(2, "0");
    return new XmlRpcDateTime(
      `${date.getUTCFullYear()}${p(date.getUTCMonth() + 1)}${p(date.getUTCDate())}` +
      `T${p(date.getUTCHours())}:${p(date.getUTCMinutes())}:${p(date.getUTCSeconds())}`);
  }
  /** "2026-11-14T12:00:00", as Python's datetime.isoformat() gives it. */
  toISO() {
    const m = /^(\d{4})-?(\d{2})-?(\d{2})T(\d{2}):?(\d{2}):?(\d{2})$/.exec(this.value.trim());
    return m ? `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}` : this.value;
  }
}

/** A <fault> response from the server. */
export class XmlRpcFault extends Error {
  constructor(code, string) {
    super(`FAULT ${code}: ${string}`);
    this.faultCode = code;
    this.faultString = string;
  }
}

/** The response was not XML-RPC (an HTML error page, a login form, ...). */
export class XmlRpcParseError extends Error {}

// ---------- encoding ----------

const escapeXml = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

export function bytesToBase64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

const B64_INDEX = new Int16Array(128).fill(-1);
for (let i = 0; i < 64; i++) B64_INDEX["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charCodeAt(i)] = i;

/** Strict standard base64 (padding required) to bytes, without an intermediate string; throws on bad input. */
export function base64ToBytes(b64) {
  if (b64.length % 4) throw new TypeError("bad base64 length");
  let end = b64.length;
  while (end > 0 && b64.charCodeAt(end - 1) === 61 && b64.length - end < 2) end--;
  const out = new Uint8Array(Math.floor((end * 3) / 4));
  let o = 0, acc = 0, bits = 0;
  for (let i = 0; i < end; i++) {
    const c = b64.charCodeAt(i);
    const v = c < 128 ? B64_INDEX[c] : -1;
    if (v < 0) throw new TypeError("bad base64 character");
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  return out;
}

function encodeValue(v) {
  if (v === null || v === undefined) return "<value><nil/></value>";
  if (typeof v === "boolean") return `<value><boolean>${v ? 1 : 0}</boolean></value>`;
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new TypeError("cannot encode a non-finite number");
    return Number.isInteger(v) ? `<value><int>${v}</int></value>` : `<value><double>${v}</double></value>`;
  }
  if (typeof v === "string") return `<value><string>${escapeXml(v)}</string></value>`;
  if (v instanceof Uint8Array) return `<value><base64>${bytesToBase64(v)}</base64></value>`;
  if (v instanceof XmlRpcDateTime) return `<value><dateTime.iso8601>${escapeXml(v.value)}</dateTime.iso8601></value>`;
  if (Array.isArray(v)) return `<value><array><data>${v.map(encodeValue).join("")}</data></array></value>`;
  if (typeof v === "object") {
    const members = Object.entries(v).map(([k, x]) => `<member><name>${escapeXml(k)}</name>${encodeValue(x)}</member>`);
    return `<value><struct>${members.join("")}</struct></value>`;
  }
  throw new TypeError(`cannot encode ${typeof v}`);
}

export function encodeCall(method, params) {
  return `<?xml version="1.0"?>\n<methodCall><methodName>${escapeXml(method)}</methodName><params>` +
    params.map((p) => `<param>${encodeValue(p)}</param>`).join("") + "</params></methodCall>";
}

const BLOB = "\u0000";
const B64 = new TextEncoder().encode("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
const PAD = 61; // "="

// Writes bytes as base64 ASCII into out at offset; returns the new offset.
function writeBase64(bytes, out, at) {
  const n = bytes.length, full = n - (n % 3);
  for (let i = 0; i < full; i += 3) {
    const v = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out[at++] = B64[v >> 18]; out[at++] = B64[(v >> 12) & 63]; out[at++] = B64[(v >> 6) & 63]; out[at++] = B64[v & 63];
  }
  if (n - full === 1) {
    const v = bytes[full] << 16;
    out[at++] = B64[v >> 18]; out[at++] = B64[(v >> 12) & 63]; out[at++] = PAD; out[at++] = PAD;
  } else if (n - full === 2) {
    const v = (bytes[full] << 16) | (bytes[full + 1] << 8);
    out[at++] = B64[v >> 18]; out[at++] = B64[(v >> 12) & 63]; out[at++] = B64[(v >> 6) & 63]; out[at++] = PAD;
  }
  return at;
}

/**
 * encodeCall as UTF-8 bytes. Binary values are base64-encoded straight into
 * the output, so a large attachment is held once as bytes and once as the
 * request body, with no intermediate strings.
 */
export function encodeCallBytes(method, params) {
  const blobs = [];
  // Encode with a placeholder string (NUL, which XML can't carry anyway) for
  // each binary value, then splice the base64 in.
  const swap = (v) => {
    if (v instanceof Uint8Array) {
      blobs.push(v);
      return BLOB;
    }
    if (Array.isArray(v)) return v.map(swap);
    if (v && typeof v === "object" && !(v instanceof XmlRpcDateTime)) return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, swap(x)]));
    return v;
  };
  const xml = encodeCall(method, params.map(swap));
  const pieces = xml.split(`<value><string>${BLOB}</string></value>`);
  if (pieces.length !== blobs.length + 1) throw new TypeError("cannot encode strings containing NUL");
  const enc = new TextEncoder();
  const text = pieces.map((p, i) => enc.encode(i < blobs.length ? `${p}<value><base64>` : p));
  const close = enc.encode("</base64></value>");
  let size = text.reduce((n, t) => n + t.length, 0);
  for (const b of blobs) size += Math.ceil(b.length / 3) * 4 + close.length;
  const out = new Uint8Array(size);
  let at = 0;
  text.forEach((t, i) => {
    out.set(t, at);
    at += t.length;
    if (i < blobs.length) {
      at = writeBase64(blobs[i], out, at);
      out.set(close, at);
      at += close.length;
    }
  });
  return out;
}

export function encodeResponse(value) {
  return `<?xml version="1.0"?>\n<methodResponse><params><param>${encodeValue(value)}</param></params></methodResponse>`;
}

export function encodeFault(code, string) {
  return `<?xml version="1.0"?>\n<methodResponse><fault>${encodeValue({ faultCode: code, faultString: string })}</fault></methodResponse>`;
}

// ---------- decoding ----------

const ENTITIES = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };

function decodeText(s) {
  return s.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|[a-zA-Z]+);/g, (whole, e) => {
    if (e[0] === "#") {
      const code = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      try { return String.fromCodePoint(code); } catch { throw new XmlRpcParseError(`bad character reference ${whole}`); }
    }
    if (e in ENTITIES) return ENTITIES[e];
    throw new XmlRpcParseError(`unknown entity ${whole}`);
  });
}

// Splits the document into tags and text, dropping the XML declaration,
// comments and doctype; CDATA sections become text.
function tokenize(xml) {
  const tokens = [];
  const re = /<!\[CDATA\[([\s\S]*?)\]\]>|<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<!DOCTYPE[^>]*>|<(\/?)([A-Za-z_][\w.:-]*)((?:\s+[^\s=/>]+\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*(\/?)>|([^<]+)|(<)/g;
  let m;
  while ((m = re.exec(xml))) {
    if (m[1] !== undefined) tokens.push({ text: m[1] });
    else if (m[3] !== undefined) {
      if (m[2]) tokens.push({ close: m[3] });
      else {
        tokens.push({ open: m[3] });
        if (m[5]) tokens.push({ close: m[3] });
      }
    } else if (m[6] !== undefined) tokens.push({ text: decodeText(m[6]) });
    else if (m[7] !== undefined) throw new XmlRpcParseError("malformed markup");
  }
  return tokens;
}

class Reader {
  constructor(xml) {
    this.t = tokenize(xml);
    this.i = 0;
  }
  skipSpace() {
    while (this.i < this.t.length && this.t[this.i].text !== undefined && !this.t[this.i].text.trim()) this.i++;
  }
  peek() {
    this.skipSpace();
    return this.t[this.i];
  }
  open(name) {
    const tok = this.peek();
    if (!tok || tok.open !== name) throw new XmlRpcParseError(`expected <${name}>, got ${describe(tok)}`);
    this.i++;
  }
  close(name) {
    const tok = this.peek();
    if (!tok || tok.close !== name) throw new XmlRpcParseError(`expected </${name}>, got ${describe(tok)}`);
    this.i++;
  }
  /** Text up to the closing tag (concatenated, entities decoded). */
  text(name) {
    let s = "";
    while (this.i < this.t.length && this.t[this.i].text !== undefined) s += this.t[this.i++].text;
    const tok = this.t[this.i];
    if (!tok || tok.close !== name) throw new XmlRpcParseError(`expected </${name}>, got ${describe(tok)}`);
    this.i++;
    return s;
  }
  end() {
    this.skipSpace();
    if (this.i !== this.t.length) throw new XmlRpcParseError("trailing content after the document");
  }
}

const describe = (tok) => !tok ? "end of document" : tok.open ? `<${tok.open}>` : tok.close ? `</${tok.close}>` : "text";

function readValue(r) {
  r.open("value");
  // A <value> without a type tag is a string; it may be empty or whitespace.
  let bare = "";
  while (r.i < r.t.length && r.t[r.i].text !== undefined) bare += r.t[r.i++].text;
  const tok = r.t[r.i];
  if (tok?.close === "value") {
    r.i++;
    return bare;
  }
  if (bare.trim()) throw new XmlRpcParseError("text mixed with a typed value");
  const type = tok?.open;
  if (!type) throw new XmlRpcParseError(`expected a value, got ${describe(tok)}`);
  r.i++;
  let v;
  switch (type) {
    case "int": case "i4": case "i8": {
      const s = r.text(type).trim();
      if (!/^[+-]?\d+$/.test(s)) throw new XmlRpcParseError(`bad integer ${s}`);
      v = Number(s);
      break;
    }
    case "boolean": {
      const s = r.text(type).trim();
      if (s !== "0" && s !== "1") throw new XmlRpcParseError(`bad boolean ${s}`);
      v = s === "1";
      break;
    }
    case "double": {
      const s = r.text(type).trim();
      v = Number(s);
      if (!s || Number.isNaN(v)) throw new XmlRpcParseError(`bad double ${s}`);
      break;
    }
    case "string": v = r.text(type); break;
    case "nil": r.close("nil"); v = null; break;
    case "dateTime.iso8601": v = new XmlRpcDateTime(r.text(type).trim()); break;
    case "base64": {
      const s = r.text(type).replace(/\s+/g, "");
      try { v = base64ToBytes(s); } catch { throw new XmlRpcParseError("bad base64"); }
      break;
    }
    case "array": {
      r.open("data");
      v = [];
      while (r.peek()?.open === "value") v.push(readValue(r));
      r.close("data");
      r.close("array");
      break;
    }
    case "struct": {
      v = {};
      while (r.peek()?.open === "member") {
        r.open("member");
        r.open("name");
        const name = r.text("name");
        v[name] = readValue(r);
        r.close("member");
      }
      r.close("struct");
      break;
    }
    default:
      throw new XmlRpcParseError(`unknown type <${type}>`);
  }
  r.close("value");
  return v;
}

/** Parses a methodResponse: returns its value, or throws XmlRpcFault / XmlRpcParseError. */
export function decodeResponse(xml) {
  const r = new Reader(xml);
  r.open("methodResponse");
  if (r.peek()?.open === "fault") {
    r.open("fault");
    const f = readValue(r);
    r.close("fault");
    r.close("methodResponse");
    r.end();
    if (!f || typeof f !== "object" || !("faultCode" in f)) throw new XmlRpcParseError("malformed fault");
    throw new XmlRpcFault(f.faultCode, f.faultString ?? "");
  }
  r.open("params");
  r.open("param");
  const v = readValue(r);
  r.close("param");
  r.close("params");
  r.close("methodResponse");
  r.end();
  return v;
}

/** Parses a methodCall into { method, params } (used by the tests' fake wiki). */
export function decodeCall(xml) {
  const r = new Reader(xml);
  r.open("methodCall");
  r.open("methodName");
  const method = r.text("methodName").trim();
  const params = [];
  if (r.peek()?.open === "params") {
    r.open("params");
    while (r.peek()?.open === "param") {
      r.open("param");
      params.push(readValue(r));
      r.close("param");
    }
    r.close("params");
  }
  r.close("methodCall");
  r.end();
  return { method, params };
}

// A fake MoinMoin xmlrpc2 endpoint plus fake download URLs, installed as
// globalThis.fetch. Speaks real XML-RPC through src/xmlrpc.js.
import { decodeCall, encodeResponse, encodeFault } from "../src/xmlrpc.js";

export const WIKI = "https://wiki.example/";

export function installFakeWiki({ maxBody = Infinity, sources = {} } = {}) {
  const state = { attachments: new Map(), requests: [], sourceRequests: [] };
  const key = (page, name) => `${page}\u0000${name}`;
  const methods = {
    getAuthToken: (user, pass) => (user === "bot" && pass === "pw" ? "tok" : ""),
    applyAuthToken: (t) => (t === "tok" ? "SUCCESS" : { faultCode: "INVALID", faultString: "bad token" }),
    putAttachment(page, name, data) {
      state.attachments.set(key(page, name), data);
      return true;
    },
    getAttachment(page, name) {
      const v = state.attachments.get(key(page, name));
      if (!v) throw { faultCode: 1, faultString: `No attachment ${name}` };
      return v;
    },
    deleteAttachment(page, name) {
      if (!state.attachments.delete(key(page, name))) throw { faultCode: 1, faultString: `No attachment ${name}` };
      return true;
    },
    listAttachments: (page) =>
      [...state.attachments.keys()].filter((k) => k.startsWith(`${page}\u0000`)).map((k) => k.split("\u0000")[1]),
  };
  const run = (method, params) => {
    if (!methods[method]) throw { faultCode: -32601, faultString: `no method ${method}` };
    return methods[method](...params);
  };

  globalThis.fetch = async (input, init = {}) => {
    const url = String(input);
    if (url in sources) {
      state.sourceRequests.push(url);
      const src = sources[url];
      if (typeof src === "number") return new Response("nope", { status: src });
      return new Response(src);
    }
    if (!url.startsWith(`${WIKI}?action=xmlrpc2`)) throw new TypeError(`fake fetch: unexpected ${url}`);
    const body = typeof init.body === "string" ? init.body : new TextDecoder().decode(init.body);
    if (body.length > maxBody) return new Response("too big", { status: 413 });
    const { method, params } = decodeCall(body);
    state.requests.push(method);
    try {
      if (method === "system.multicall") {
        let authed = false;
        const out = params[0].map(({ methodName, params: p }) => {
          try {
            const v = run(methodName, p);
            if (methodName === "applyAuthToken" && v === "SUCCESS") authed = true;
            if (methodName !== "applyAuthToken" && methodName !== "getAuthToken" && !authed) {
              throw { faultCode: "NOT_AUTHED", faultString: "not authenticated" };
            }
            return [v];
          } catch (f) {
            return { faultCode: f.faultCode, faultString: f.faultString };
          }
        });
        return new Response(encodeResponse(out));
      }
      return new Response(encodeResponse(run(method, params)));
    } catch (f) {
      return new Response(encodeFault(f.faultCode, f.faultString));
    }
  };
  return state;
}

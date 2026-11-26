// Worker entry: verifies the Cloudflare Access JWT (src/access.js), then
// serves MCP at POST /mcp. /health and /healthz need no token.
import { accessConfig, accessToken, verifyAccessJwt } from "./access.js";
import { handleMcp } from "./mcp.js";
import { ConfigError, wikiSettings } from "./moin.js";
import { handleUpload } from "./uploadlink.js";

const unauthorized = () =>
  new Response("Unauthorized\n", { status: 401, headers: { "WWW-Authenticate": "Bearer" } });

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    if (pathname === "/health" || pathname === "/healthz") return new Response("ok\n");
    if (pathname === "/") return new Response("MoinMoin MCP connector. Use /mcp.\n");

    // One-time upload links: the signed token is the authorization, so this
    // path sits behind an Access Bypass policy (see src/uploadlink.js).
    const upload = /^\/upload\/([^/]+)$/.exec(pathname);
    if (upload) {
      const settings = settingsOrError(env);
      return settings instanceof Response ? settings : handleUpload(request, settings, upload[1]);
    }

    if (pathname !== "/mcp") return new Response("Not found\n", { status: 404 });

    const config = accessConfig(env);
    if (!config) {
      return new Response("Server is missing its Cloudflare Access settings (CF_ACCESS_TEAM_DOMAIN and CF_ACCESS_AUD).\n", { status: 500 });
    }
    const token = accessToken(request);
    if (!token) {
      console.warn("access denied: no Cloudflare Access token");
      return unauthorized();
    }
    try {
      await verifyAccessJwt(token, config);
    } catch (e) {
      console.warn(`access denied: ${e?.message ?? e}`);
      return unauthorized();
    }

    if (request.method !== "POST") {
      return new Response("Method not allowed\n", { status: 405, headers: { Allow: "POST" } });
    }
    const settings = settingsOrError(env);
    if (settings instanceof Response) return settings;
    settings.origin = new URL(request.url).origin; // where upload links point
    return handleMcp(request, settings);
  },
};

function settingsOrError(env) {
  try {
    return wikiSettings(env);
  } catch (e) {
    if (!(e instanceof ConfigError)) throw e;
    console.error(`configuration error: ${e.message}`);
    return new Response(`Server configuration error: ${e.message}\n`, { status: 500 });
  }
}

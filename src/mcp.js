// Minimal stateless MCP server over Streamable HTTP (JSON responses only).
import { TOOLS, runTool } from "./tools.js";

const SUPPORTED_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"];

const INSTRUCTIONS =
  "Operate a MoinMoin 1.9 wiki. Read pages before editing; put_page replaces the " +
  "entire page. Use MoinMoin markup, not Markdown, and preserve #format, #acl and " +
  "#pragma lines. Check page metadata for concurrent edits and read back after " +
  "writes. Confirm destructive operations with the user. Attachment content is base64. " +
  "Use the returned url fields to give the user links to relevant wiki pages. " +
  "To upload an attachment that is reachable at a URL, use put_attachment with source_url; for any other file " +
  "over about 75 KB, use create_upload_link and upload it with curl, or give the user the link to open.";

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const ok = (id, result) => ({ jsonrpc: "2.0", id, result });
const fail = (id, code, message) => ({ jsonrpc: "2.0", id, error: { code, message } });

export async function handleMcp(request, settings) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json(fail(null, -32700, "Parse error"), 400);
  }
  const batch = Array.isArray(body);
  const replies = [];
  for (const msg of batch ? body : [body]) {
    const reply = await handleMessage(msg, settings);
    if (reply) replies.push(reply);
  }
  if (!replies.length) return new Response(null, { status: 202 });
  return json(batch ? replies : replies[0]);
}

async function handleMessage(msg, settings) {
  if (!msg || typeof msg !== "object" || msg.jsonrpc !== "2.0" || typeof msg.method !== "string") {
    return msg && typeof msg === "object" && "id" in msg ? fail(msg.id ?? null, -32600, "Invalid request") : null;
  }
  if (!("id" in msg)) return null; // notification

  switch (msg.method) {
    case "initialize": {
      const asked = msg.params?.protocolVersion;
      return ok(msg.id, {
        protocolVersion: SUPPORTED_VERSIONS.includes(asked) ? asked : SUPPORTED_VERSIONS[0],
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "MoinMoin", version: "0.4.0" },
        instructions: INSTRUCTIONS,
      });
    }
    case "ping":
      return ok(msg.id, {});
    case "tools/list":
      return ok(msg.id, {
        tools: TOOLS.map(({ name, description, inputSchema, annotations }) => ({ name, description, inputSchema, annotations })),
      });
    case "tools/call": {
      const tool = TOOLS.find((t) => t.name === msg.params?.name);
      if (!tool) return fail(msg.id, -32602, `Unknown tool: ${msg.params?.name}`);
      return ok(msg.id, await runTool(tool, msg.params.arguments ?? {}, settings));
    }
    default:
      return fail(msg.id, -32601, `Method not found: ${msg.method}`);
  }
}

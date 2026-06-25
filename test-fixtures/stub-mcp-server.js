#!/usr/bin/env node
/**
 * Minimal stub MCP server for end-to-end proxy testing.
 *
 * Speaks newline-delimited JSON-RPC 2.0 over stdio (the MCP stdio transport
 * framing). It is intentionally tiny, just enough surface to prove the proxy
 * forwards non-tools/call messages verbatim and only gates tools/call:
 *
 *   - initialize           -> a stub initialize result
 *   - tools/list           -> one tool, "echo"
 *   - tools/call (echo)    -> echoes the arguments back in the result
 *
 * Every request it receives is one it was actually allowed to see, so if the
 * proxy denies a call this server NEVER sees it (that's what the e2e asserts).
 */

let buf = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buf += chunk;
  let nl;
  while ((nl = buf.indexOf("\n")) !== -1) {
    const line = buf.slice(0, nl);
    buf = buf.slice(nl + 1);
    if (!line.trim()) continue;
    handle(line);
  }
});

function send(obj) {
  process.stdout.write(JSON.stringify(obj) + "\n");
}

function handle(line) {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return; // ignore garbage
  }

  if (msg.method === "initialize") {
    return send({
      jsonrpc: "2.0",
      id: msg.id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "stub-mcp-server", version: "0.0.0" },
      },
    });
  }

  if (msg.method === "tools/list") {
    return send({
      jsonrpc: "2.0",
      id: msg.id,
      result: {
        tools: [
          {
            name: "echo",
            description: "Echo arguments back",
            inputSchema: { type: "object" },
          },
        ],
      },
    });
  }

  if (msg.method === "tools/call") {
    return send({
      jsonrpc: "2.0",
      id: msg.id,
      result: {
        content: [
          { type: "text", text: JSON.stringify(msg.params?.arguments ?? {}) },
        ],
        isError: false,
        // Marker proving the server actually executed this call.
        _executed: true,
        _tool: msg.params?.name,
      },
    });
  }

  // Notifications (no id) get no response.
  if (msg.id !== undefined) {
    send({
      jsonrpc: "2.0",
      id: msg.id,
      error: { code: -32601, message: `method not found: ${msg.method}` },
    });
  }
}

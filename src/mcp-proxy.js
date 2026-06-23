/**
 * MCP proxy — interception logic.
 *
 * The Model Context Protocol speaks JSON-RPC 2.0 over stdio. A proxy sits
 * between the agent and a downstream MCP server, forwarding every message
 * EXCEPT that it intercepts `tools/call` requests, runs them through the
 * firewall policy, and either forwards them, denies them with a JSON-RPC
 * error, or marks them as needing approval.
 *
 * This module implements and tests the message-level interception/decision
 * logic. The full live stdio plumbing (spawning the downstream server, piping
 * both directions) is provided by `createStdioProxy` but the handshake-heavy
 * end-to-end path is a documented roadmap item — see README.
 */

import { processCall } from "./engine.js";

/**
 * Is this JSON-RPC message a tools/call request we should intercept?
 *
 * @param {object} msg parsed JSON-RPC message
 */
export function isToolsCall(msg) {
  return (
    msg &&
    typeof msg === "object" &&
    msg.method === "tools/call" &&
    msg.params &&
    typeof msg.params === "object"
  );
}

/**
 * Convert an MCP tools/call request into our normalized tool call.
 *
 * MCP shape: { method:"tools/call", params: { name, arguments } }
 */
export function mcpRequestToCall(msg) {
  return {
    tool: msg?.params?.name ?? "",
    args: msg?.params?.arguments ?? {},
  };
}

/**
 * Build a JSON-RPC error response denying a tools/call.
 *
 * @param {string|number} id the request id
 * @param {string} reason
 */
export function buildDenyResponse(id, reason) {
  return {
    jsonrpc: "2.0",
    id,
    error: {
      // -32001 is a reasonable application-defined "request blocked" code.
      code: -32001,
      message: `Blocked by agent-firewall: ${reason}`,
    },
  };
}

/**
 * Decide what to do with an inbound MCP message.
 *
 * Returns one of:
 *   { action: "forward", message }      pass the original message downstream
 *   { action: "deny", response }        send this JSON-RPC error back, do NOT forward
 *   { action: "hold", message, result } needs approval (ask); caller decides
 *
 * Non-tools/call messages are always forwarded untouched.
 *
 * @param {object} msg parsed JSON-RPC message
 * @param {object} policy
 * @param {object} [opts] forwarded to processCall (audit, readFile)
 */
export function decideMcpMessage(msg, policy, opts = {}) {
  if (!isToolsCall(msg)) {
    return { action: "forward", message: msg };
  }

  const call = mcpRequestToCall(msg);
  const result = processCall(call, policy, { source: "mcp-proxy", ...opts });

  if (result.decision === "allow") {
    return { action: "forward", message: msg, result };
  }
  if (result.decision === "deny") {
    return {
      action: "deny",
      response: buildDenyResponse(msg.id, result.reason),
      result,
    };
  }
  // ask -> hold for approval; default proxy treats unapproved holds as denies.
  return { action: "hold", message: msg, result };
}

/**
 * ROADMAP: live stdio JSON-RPC proxy.
 *
 * Spawns a downstream MCP server and pipes both directions, applying
 * decideMcpMessage to every inbound (agent -> server) line. This wiring is
 * intentionally thin and is NOT yet covered by an end-to-end live test — the
 * decision logic above is. See README "MCP proxy (roadmap)".
 *
 * @param {object} cfg
 * @param {string[]} cfg.command  [bin, ...args] of the downstream MCP server
 * @param {object} cfg.policy
 * @param {object} [cfg.audit]
 * @param {"deny-holds"|"allow-holds"} [cfg.holdPolicy="deny-holds"]
 */
export function createStdioProxy(cfg) {
  // Lazy import so the pure decision logic carries no child_process dependency
  // for consumers / tests that only need decideMcpMessage.
  // eslint-disable-next-line import/no-unresolved
  return import("node:child_process").then(({ spawn }) => {
    const [bin, ...args] = cfg.command;
    const child = spawn(bin, args, { stdio: ["pipe", "pipe", "inherit"] });

    let buf = "";
    process.stdin.on("data", (chunk) => {
      buf += chunk.toString("utf8");
      let nl;
      while ((nl = buf.indexOf("\n")) !== -1) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (!line.trim()) continue;
        let msg;
        try {
          msg = JSON.parse(line);
        } catch {
          child.stdin.write(line + "\n"); // pass through unparseable lines
          continue;
        }
        const verdict = decideMcpMessage(msg, cfg.policy, {
          audit: cfg.audit,
        });
        if (verdict.action === "forward") {
          child.stdin.write(JSON.stringify(verdict.message) + "\n");
        } else if (verdict.action === "deny") {
          process.stdout.write(JSON.stringify(verdict.response) + "\n");
        } else {
          // hold
          if (cfg.holdPolicy === "allow-holds") {
            child.stdin.write(JSON.stringify(verdict.message) + "\n");
          } else {
            process.stdout.write(
              JSON.stringify(buildDenyResponse(msg.id, verdict.result.reason)) +
                "\n"
            );
          }
        }
      }
    });

    // Downstream -> agent: forward verbatim.
    child.stdout.on("data", (chunk) => process.stdout.write(chunk));
    child.on("exit", (code) => process.exit(code ?? 0));
    return child;
  });
}

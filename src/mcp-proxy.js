/**
 * MCP proxy: interception logic.
 *
 * The Model Context Protocol speaks JSON-RPC 2.0 over stdio. A proxy sits
 * between the agent and a downstream MCP server, forwarding every message
 * EXCEPT that it intercepts `tools/call` requests, runs them through the
 * firewall policy, and either forwards them, denies them with a JSON-RPC
 * error, or marks them as needing approval.
 *
 * This module implements both the message-level interception/decision logic
 * AND the live stdio plumbing (`createStdioProxy`) that spawns a downstream
 * server, pipes both directions, applies the policy to every inbound
 * `tools/call`, and handles newline-delimited JSON framing (including partial
 * frames split across chunks). The whole path is covered by an end-to-end test
 * that spawns a stub MCP server over stdio.
 */

import { processCall } from "./engine.js";
import { spawn } from "node:child_process";

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
 * A stateful newline-delimited frame splitter.
 *
 * MCP-over-stdio uses newline-delimited JSON: one JSON object per line. TCP /
 * pipe chunks do NOT respect message boundaries: a single `data` event may
 * carry half a message, several messages, or a message split across events.
 * This buffers bytes and yields only complete lines, retaining any trailing
 * partial frame for the next push.
 *
 * @returns {{ push(chunk: string|Buffer): string[], flush(): string[] }}
 */
export function createFrameSplitter() {
  let buf = "";
  return {
    /** Feed a chunk; returns the complete lines now available (no trailing partial). */
    push(chunk) {
      buf += typeof chunk === "string" ? chunk : chunk.toString("utf8");
      const lines = [];
      let nl;
      while ((nl = buf.indexOf("\n")) !== -1) {
        lines.push(buf.slice(0, nl));
        buf = buf.slice(nl + 1);
      }
      return lines;
    },
    /** Return any buffered remainder (e.g. a final line without a trailing newline). */
    flush() {
      const rest = buf;
      buf = "";
      return rest ? [rest] : [];
    },
  };
}

/**
 * Apply the firewall to one inbound (agent -> server) line and decide what
 * bytes to send where. Pure: takes a raw line, returns the routing intent.
 * Unparseable / non-JSON lines pass through to the server untouched.
 *
 * @param {string} line a single newline-stripped frame
 * @param {object} policy
 * @param {object} [opts]
 * @param {object} [opts.audit]
 * @param {"deny-holds"|"allow-holds"} [opts.holdPolicy="deny-holds"]
 * @returns {{ toServer?: string, toClient?: string }}
 */
export function routeInboundLine(line, policy, opts = {}) {
  if (!line.trim()) return {};
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    // Not JSON we can reason about, forward verbatim so we never corrupt the
    // protocol stream (e.g. a server that does its own framing).
    return { toServer: line };
  }

  const verdict = decideMcpMessage(msg, policy, { audit: opts.audit });

  if (verdict.action === "forward") {
    return { toServer: JSON.stringify(verdict.message) };
  }
  if (verdict.action === "deny") {
    return { toClient: JSON.stringify(verdict.response) };
  }
  // hold (ask): default is to deny the call back to the client; an
  // approval layer can opt into allow-holds to let it through.
  if (opts.holdPolicy === "allow-holds") {
    return { toServer: JSON.stringify(verdict.message) };
  }
  return {
    toClient: JSON.stringify(buildDenyResponse(msg.id, verdict.result.reason)),
  };
}

/**
 * Core, transport-agnostic proxy loop. Wires a client-side input stream and a
 * downstream server's stdio together, applying the firewall to every inbound
 * frame. Fully injectable so it can be driven by tests without a real process.
 *
 * Inbound  (clientIn  -> serverIn):  policy applied, deny short-circuits to clientOut.
 * Outbound (serverOut -> clientOut): forwarded verbatim (responses are trusted).
 *
 * @param {object} io
 * @param {NodeJS.ReadableStream} io.clientIn   frames FROM the agent
 * @param {NodeJS.WritableStream} io.clientOut  frames TO the agent
 * @param {NodeJS.ReadableStream} io.serverOut  frames FROM the downstream server
 * @param {NodeJS.WritableStream} io.serverIn   frames TO the downstream server
 * @param {object} cfg
 * @param {object} cfg.policy
 * @param {object} [cfg.audit]
 * @param {"deny-holds"|"allow-holds"} [cfg.holdPolicy="deny-holds"]
 * @returns {{ stop(): void }}
 */
export function runProxyLoop(io, cfg) {
  const { clientIn, clientOut, serverOut, serverIn } = io;
  const splitter = createFrameSplitter();

  const onClientData = (chunk) => {
    for (const line of splitter.push(chunk)) {
      const { toServer, toClient } = routeInboundLine(line, cfg.policy, {
        audit: cfg.audit,
        holdPolicy: cfg.holdPolicy,
      });
      if (toServer !== undefined && serverIn.writable !== false) {
        serverIn.write(toServer + "\n");
      }
      if (toClient !== undefined) {
        clientOut.write(toClient + "\n");
      }
    }
  };
  const onClientEnd = () => {
    // Drain any trailing frame that lacked a final newline.
    for (const line of splitter.flush()) {
      const { toServer, toClient } = routeInboundLine(line, cfg.policy, {
        audit: cfg.audit,
        holdPolicy: cfg.holdPolicy,
      });
      if (toServer !== undefined && serverIn.writable !== false) {
        serverIn.write(toServer + "\n");
      }
      if (toClient !== undefined) clientOut.write(toClient + "\n");
    }
    // Half-close the server's stdin so it can exit cleanly.
    if (serverIn.writable !== false && typeof serverIn.end === "function") {
      serverIn.end();
    }
  };
  // Downstream responses are forwarded verbatim (no re-framing, no parsing) so
  // we never alter a valid protocol response.
  const onServerData = (chunk) => clientOut.write(chunk);

  clientIn.on("data", onClientData);
  clientIn.on("end", onClientEnd);
  serverOut.on("data", onServerData);

  return {
    stop() {
      clientIn.off?.("data", onClientData);
      clientIn.off?.("end", onClientEnd);
      serverOut.off?.("data", onServerData);
    },
  };
}

/**
 * Live stdio JSON-RPC proxy.
 *
 * Spawns a downstream MCP server and pipes both directions through
 * `runProxyLoop`, applying the firewall to every inbound `tools/call`. By
 * default the agent talks to this process over its own stdio.
 *
 * @param {object} cfg
 * @param {string[]} cfg.command  [bin, ...args] of the downstream MCP server
 * @param {object} cfg.policy
 * @param {object} [cfg.audit]
 * @param {"deny-holds"|"allow-holds"} [cfg.holdPolicy="deny-holds"]
 * @param {NodeJS.ReadableStream} [cfg.stdin=process.stdin]
 * @param {NodeJS.WritableStream} [cfg.stdout=process.stdout]
 * @param {(code:number)=>void} [cfg.onExit] exit handler (defaults to process.exit)
 * @returns {import("node:child_process").ChildProcess}
 */
export function createStdioProxy(cfg) {
  if (!Array.isArray(cfg.command) || cfg.command.length === 0) {
    throw new Error(
      "agent-firewall mcp: no downstream command given (usage: agent-firewall mcp -- <server> [args...])"
    );
  }
  const [bin, ...args] = cfg.command;
  const clientIn = cfg.stdin ?? process.stdin;
  const clientOut = cfg.stdout ?? process.stdout;
  const onExit = cfg.onExit ?? ((code) => process.exit(code ?? 0));

  let child;
  try {
    child = spawn(bin, args, { stdio: ["pipe", "pipe", "inherit"] });
  } catch (err) {
    throw new Error(
      `agent-firewall mcp: failed to spawn downstream server "${bin}": ${err.message}`
    );
  }

  child.on("error", (err) => {
    clientOut.write(
      JSON.stringify(
        buildDenyResponse(
          null,
          `downstream MCP server "${bin}" failed to start: ${err.message}`
        )
      ) + "\n"
    );
    onExit(1);
  });

  if (clientIn.setEncoding) clientIn.setEncoding("utf8");

  runProxyLoop(
    {
      clientIn,
      clientOut,
      serverOut: child.stdout,
      serverIn: child.stdin,
    },
    cfg
  );

  child.on("exit", (code) => onExit(code ?? 0));
  return child;
}

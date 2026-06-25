import { test } from "node:test";
import assert from "node:assert/strict";
import { processCall } from "../src/engine.js";
import { handlePreToolUse } from "../src/hook-adapter.js";
import { decideMcpMessage } from "../src/mcp-proxy.js";

// Build secret-looking strings at runtime so this file contains no literal that
// resembles a real credential.
const fakeKey = "sk-" + "B".repeat(40);

// A policy that would ALLOW everything: the guards must override it.
const permissive = { default: "allow", rules: [{ action: "allow", tool: "*" }] };

// ---- secret-guard fires on the SHARED engine seam (all three paths) --------

test("secret-guard fires on the check/engine path via processCall", () => {
  const recorded = [];
  const result = processCall(
    { tool: "Write", args: { file_path: "/p/config.js", content: `k="${fakeKey}"` } },
    permissive,
    { source: "check", audit: { record: (e) => recorded.push(e) } }
  );
  assert.equal(result.decision, "deny");
  assert.equal(result.blockedBy, "secret-guard");
  assert.equal(result.ruleIndex, -1);
  // Never echo the secret, never store args.
  assert.equal(result.summaryText.includes(fakeKey), false);
  assert.equal(recorded[0].args, undefined);
  assert.equal(recorded[0].source, "check");
});

test("secret-guard fires on the Claude Code hook path", () => {
  const event = {
    tool_name: "Write",
    tool_input: { file_path: "/p/config.js", content: `k="${fakeKey}"` },
  };
  const { output, result } = handlePreToolUse(event, permissive);
  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  assert.equal(result.blockedBy, "secret-guard");
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /secret-guard/);
  assert.equal(
    output.hookSpecificOutput.permissionDecisionReason.includes(fakeKey),
    false
  );
});

test("secret-guard fires on the MCP proxy path", () => {
  const recorded = [];
  const msg = {
    jsonrpc: "2.0",
    id: 9,
    method: "tools/call",
    params: { name: "write_file", arguments: { file_path: "/p/c.js", content: fakeKey } },
  };
  const v = decideMcpMessage(msg, permissive, { audit: { record: (e) => recorded.push(e) } });
  assert.equal(v.action, "deny");
  assert.equal(v.result.blockedBy, "secret-guard");
  // The JSON-RPC error sent back to the client must not leak the secret.
  assert.equal(v.response.error.message.includes(fakeKey), false);
  assert.equal(recorded[0].source, "mcp-proxy");
  assert.equal(recorded[0].args, undefined);
});

// ---- egress-guard fires on the SHARED engine seam --------------------------

const egressPolicy = {
  default: "allow",
  rules: [{ action: "allow", tool: "*" }],
  egress: { allow: ["api.github.com", "*.openai.com"], action: "deny" },
};

test("egress-guard denies a non-allowlisted host on the engine path", () => {
  const result = processCall(
    { tool: "WebFetch", args: { url: "https://evil.example.com/exfil" } },
    egressPolicy
  );
  assert.equal(result.decision, "deny");
  assert.equal(result.blockedBy, "egress-guard");
  assert.match(result.reason, /egress-guard/);
});

test("egress-guard allows an allowlisted host (defers to policy)", () => {
  const result = processCall(
    { tool: "WebFetch", args: { url: "https://api.github.com/repos" } },
    egressPolicy
  );
  assert.equal(result.decision, "allow");
  assert.equal(result.blockedBy, undefined);
});

test("egress-guard fires on the MCP proxy path too", () => {
  const msg = {
    jsonrpc: "2.0",
    id: 11,
    method: "tools/call",
    params: { name: "http", arguments: { url: "https://evil.example.com" } },
  };
  const v = decideMcpMessage(msg, egressPolicy);
  assert.equal(v.action, "deny");
  assert.equal(v.result.blockedBy, "egress-guard");
});

test("egress action 'ask' holds the call instead of denying", () => {
  const askPolicy = {
    default: "allow",
    rules: [{ action: "allow", tool: "*" }],
    egress: { allow: ["api.github.com"], action: "ask" },
  };
  const result = processCall(
    { tool: "WebFetch", args: { url: "https://other.example.com" } },
    askPolicy
  );
  assert.equal(result.decision, "ask");
  assert.equal(result.blockedBy, "egress-guard");
});

test("egress-guard is inert when not configured (default behaviour unchanged)", () => {
  const result = processCall(
    { tool: "WebFetch", args: { url: "https://anywhere.example.com" } },
    permissive
  );
  assert.equal(result.decision, "allow");
  assert.equal(result.blockedBy, undefined);
});

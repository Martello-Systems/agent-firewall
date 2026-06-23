import { test } from "node:test";
import assert from "node:assert/strict";
import {
  isToolsCall,
  mcpRequestToCall,
  buildDenyResponse,
  decideMcpMessage,
} from "../src/mcp-proxy.js";

const policy = {
  default: "ask",
  rules: [
    { action: "allow", tool: "read_file" },
    { action: "deny", tool: "run_shell", match: { command: "regex:rm\\s+-rf" } },
  ],
};

test("isToolsCall identifies tools/call requests", () => {
  assert.ok(isToolsCall({ method: "tools/call", params: { name: "x" } }));
  assert.ok(!isToolsCall({ method: "tools/list", params: {} }));
  assert.ok(!isToolsCall({ method: "tools/call" })); // no params
  assert.ok(!isToolsCall(null));
});

test("mcpRequestToCall extracts name + arguments", () => {
  const call = mcpRequestToCall({
    method: "tools/call",
    params: { name: "run_shell", arguments: { command: "ls" } },
  });
  assert.deepEqual(call, { tool: "run_shell", args: { command: "ls" } });
});

test("buildDenyResponse is a valid JSON-RPC error", () => {
  const resp = buildDenyResponse(7, "nope");
  assert.equal(resp.jsonrpc, "2.0");
  assert.equal(resp.id, 7);
  assert.equal(resp.error.code, -32001);
  assert.match(resp.error.message, /agent-firewall/);
});

test("non tools/call messages are forwarded untouched", () => {
  const msg = { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} };
  const v = decideMcpMessage(msg, policy);
  assert.equal(v.action, "forward");
  assert.equal(v.message, msg);
});

test("allowed tools/call is forwarded", () => {
  const msg = {
    jsonrpc: "2.0",
    id: 2,
    method: "tools/call",
    params: { name: "read_file", arguments: { path: "/x" } },
  };
  const v = decideMcpMessage(msg, policy);
  assert.equal(v.action, "forward");
  assert.equal(v.result.decision, "allow");
});

test("denied tools/call returns a JSON-RPC error and does not forward", () => {
  const msg = {
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: { name: "run_shell", arguments: { command: "rm -rf /tmp" } },
  };
  const v = decideMcpMessage(msg, policy);
  assert.equal(v.action, "deny");
  assert.equal(v.response.id, 3);
  assert.equal(v.response.error.code, -32001);
  assert.equal(v.result.decision, "deny");
});

test("ask tools/call is held for approval", () => {
  const msg = {
    jsonrpc: "2.0",
    id: 4,
    method: "tools/call",
    params: { name: "unknown_tool", arguments: {} },
  };
  const v = decideMcpMessage(msg, policy);
  assert.equal(v.action, "hold");
  assert.equal(v.result.decision, "ask");
});

test("decideMcpMessage records to audit when provided", () => {
  const recorded = [];
  const fakeAudit = { record: (e) => recorded.push(e) };
  const msg = {
    jsonrpc: "2.0",
    id: 5,
    method: "tools/call",
    params: { name: "run_shell", arguments: { command: "rm -rf /" } },
  };
  decideMcpMessage(msg, policy, { audit: fakeAudit });
  assert.equal(recorded.length, 1);
  assert.equal(recorded[0].source, "mcp-proxy");
  assert.equal(recorded[0].decision, "deny");
});

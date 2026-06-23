import { test } from "node:test";
import assert from "node:assert/strict";
import {
  eventToCall,
  buildHookOutput,
  handlePreToolUse,
} from "../src/hook-adapter.js";

const policy = {
  default: "ask",
  rules: [
    { action: "allow", tool: ["Read", "Glob"] },
    { action: "deny", tool: "Bash", match: { command: "regex:rm\\s+-rf\\s+/" } },
    { action: "deny", tool: "Write", match: { file_path: "glob:**/.env" } },
  ],
};

test("eventToCall maps PreToolUse event to normalized call", () => {
  const event = {
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: { command: "npm test" },
  };
  assert.deepEqual(eventToCall(event), {
    tool: "Bash",
    args: { command: "npm test" },
  });
});

test("buildHookOutput shapes the Claude Code permission decision JSON", () => {
  const out = buildHookOutput("deny", "blocked by policy");
  assert.deepEqual(out, {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: "blocked by policy",
    },
  });
});

test("buildHookOutput coerces unknown decisions to ask", () => {
  const out = buildHookOutput("weird", "x");
  assert.equal(out.hookSpecificOutput.permissionDecision, "ask");
});

test("ALLOW: read-only tool produces permissionDecision allow", () => {
  const event = { tool_name: "Read", tool_input: { file_path: "/x" } };
  const { output, result } = handlePreToolUse(event, policy);
  assert.equal(result.decision, "allow");
  assert.equal(output.hookSpecificOutput.permissionDecision, "allow");
  assert.equal(output.hookSpecificOutput.hookEventName, "PreToolUse");
});

test("DENY: rm -rf / produces permissionDecision deny with reason", () => {
  const event = { tool_name: "Bash", tool_input: { command: "rm -rf /" } };
  const { output, result } = handlePreToolUse(event, policy);
  assert.equal(result.decision, "deny");
  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /DENY/);
});

test("DENY: writing .env produces deny", () => {
  const event = {
    tool_name: "Write",
    tool_input: { file_path: "/proj/.env", content: "SECRET=x" },
  };
  const { output } = handlePreToolUse(event, policy);
  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
});

test("ASK: unmatched write falls to default ask", () => {
  const event = {
    tool_name: "Write",
    tool_input: { file_path: "/proj/index.js", content: "x" },
  };
  const { output, result } = handlePreToolUse(event, policy);
  assert.equal(result.decision, "ask");
  assert.equal(output.hookSpecificOutput.permissionDecision, "ask");
});

test("handlePreToolUse records to audit when provided", () => {
  const recorded = [];
  const fakeAudit = { record: (e) => recorded.push(e) };
  const event = { tool_name: "Bash", tool_input: { command: "rm -rf /" } };
  handlePreToolUse(event, policy, { audit: fakeAudit });
  assert.equal(recorded.length, 1);
  assert.equal(recorded[0].decision, "deny");
  assert.equal(recorded[0].source, "claude-code-hook");
});

// ---- contract conformance (verified against code.claude.com/docs hooks) ----

test("CONTRACT: a deny ALWAYS carries a non-empty permissionDecisionReason", () => {
  // Reason is required by Claude Code when permissionDecision is "deny".
  const fromPolicy = buildHookOutput("deny", "");
  assert.ok(
    fromPolicy.hookSpecificOutput.permissionDecisionReason,
    "deny synthesizes a reason even if none given"
  );

  const event = { tool_name: "Bash", tool_input: { command: "rm -rf /" } };
  const { output } = handlePreToolUse(event, policy);
  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  assert.ok(output.hookSpecificOutput.permissionDecisionReason.length > 0);
});

test("CONTRACT: output uses camelCase hookSpecificOutput fields, no top-level decision", () => {
  const event = { tool_name: "Read", tool_input: { file_path: "/x" } };
  const { output } = handlePreToolUse(event, policy);
  assert.ok("hookSpecificOutput" in output);
  assert.equal(output.hookSpecificOutput.hookEventName, "PreToolUse");
  assert.ok("permissionDecision" in output.hookSpecificOutput);
  // PreToolUse must NOT use the top-level `decision: "block"` form.
  assert.equal("decision" in output, false);
  assert.equal("permission_decision" in output.hookSpecificOutput, false);
});

test("CONTRACT: allow payload exact shape for a read-only tool", () => {
  const event = { tool_name: "Read", tool_input: { file_path: "/x" } };
  const { output } = handlePreToolUse(event, policy);
  assert.equal(output.hookSpecificOutput.permissionDecision, "allow");
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /ALLOW/);
});

test("secret-guard: writing a literal secret denies and never echoes the value", () => {
  const event = {
    tool_name: "Write",
    tool_input: {
      file_path: "/proj/config.js",
      content: 'const k = "sk-ABCDEFGHIJKLMNOP1234567890";',
    },
  };
  const recorded = [];
  const { output, result } = handlePreToolUse(event, policy, {
    audit: { record: (e) => recorded.push(e) },
  });
  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /secret-guard/);
  // The reason must NOT contain the secret value.
  assert.equal(
    /sk-ABCDEFGHIJKLMNOP1234567890/.test(
      output.hookSpecificOutput.permissionDecisionReason
    ),
    false
  );
  // The audit record must NOT persist args (which hold the secret).
  assert.equal(result.decision, "deny");
  assert.equal(recorded[0].args, undefined);
});

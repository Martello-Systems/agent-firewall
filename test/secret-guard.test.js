import { test } from "node:test";
import assert from "node:assert/strict";
import { scanForSecrets, checkCall, extractWriteContent } from "../src/secret-guard.js";
import { handlePreToolUse } from "../src/hook-adapter.js";

// Build secret-looking strings at runtime so this test file itself contains no
// literal that resembles a real credential.
const fakeOpenAiKey = "sk-" + "A".repeat(40);
const fakeStripe = ["sk", "live", "0".repeat(24)].join("_");
const fakeAssignment = ["API", "KEY"].join("_") + "=" + "Z".repeat(32);
const envRef = "${" + "OPENAI_API_KEY}";
const procRef = ["process", "env", "OPENAI"].join(".");

test("scanForSecrets flags a provider key prefix", () => {
  const r = scanForSecrets(`const k = "${fakeOpenAiKey}";`);
  assert.ok(r.blocked);
  assert.ok(r.findings.length >= 1);
});

test("scanForSecrets flags a stripe live key", () => {
  const r = scanForSecrets(`STRIPE=${fakeStripe}`);
  assert.ok(r.blocked);
});

test("scanForSecrets flags a real-looking secret assignment", () => {
  const r = scanForSecrets(fakeAssignment);
  assert.ok(r.blocked);
});

test("scanForSecrets allows env-var placeholders", () => {
  assert.equal(scanForSecrets("API_KEY=" + envRef).blocked, false);
  assert.equal(scanForSecrets("API_KEY=<your-key-here>").blocked, false);
  assert.equal(scanForSecrets("PASSWORD=changeme").blocked, false);
  assert.equal(scanForSecrets("API_KEY=" + procRef).blocked, false);
  assert.equal(scanForSecrets("API_KEY=xxxxxxxx").blocked, false);
});

test("scanForSecrets ignores empty / non-string", () => {
  assert.equal(scanForSecrets("").blocked, false);
  assert.equal(scanForSecrets(null).blocked, false);
});

test("checkCall only inspects write-like calls", () => {
  assert.equal(checkCall({ tool: "Bash", args: { command: "ls" } }).blocked, false);
  assert.equal(
    checkCall({ tool: "Read", args: { file_path: "/x" } }).blocked,
    false
  );
});

test("checkCall blocks a Write committing a secret, reason omits the value", () => {
  const r = checkCall({
    tool: "Write",
    args: { file_path: "/proj/config.js", content: `key="${fakeOpenAiKey}"` },
  });
  assert.ok(r.blocked);
  assert.ok(!r.reason.includes(fakeOpenAiKey), "reason must not echo the secret");
});

test("extractWriteContent pulls content / file_text / new_string", () => {
  assert.equal(extractWriteContent({ args: { content: "a" } }), "a");
  assert.equal(extractWriteContent({ args: { file_text: "b" } }), "b");
  assert.equal(extractWriteContent({ args: { new_string: "c" } }), "c");
});

test("hook adapter denies a secret write ahead of policy", () => {
  // Policy would otherwise ALLOW all writes — secret-guard must override.
  const permissivePolicy = {
    default: "allow",
    rules: [{ action: "allow", tool: "*" }],
  };
  const event = {
    tool_name: "Write",
    tool_input: {
      file_path: "/proj/secrets.js",
      content: `export const KEY = "${fakeOpenAiKey}";`,
    },
  };
  const { output } = handlePreToolUse(event, permissivePolicy);
  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /secret-guard/);
});

test("hook adapter allows a placeholder write", () => {
  const permissivePolicy = { default: "allow", rules: [{ action: "allow", tool: "*" }] };
  const event = {
    tool_name: "Write",
    tool_input: { file_path: "/proj/.env.example", content: "API_KEY=" + envRef },
  };
  const { output } = handlePreToolUse(event, permissivePolicy);
  assert.equal(output.hookSpecificOutput.permissionDecision, "allow");
});

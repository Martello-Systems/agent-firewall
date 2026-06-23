import { test } from "node:test";
import assert from "node:assert/strict";
import {
  keyToResolution,
  buildPersistRule,
  resolveHold,
  renderHold,
} from "../src/interactive.js";
import { processCall } from "../src/engine.js";

const policy = {
  default: "ask",
  rules: [{ action: "ask", tool: "Write" }],
};

function heldResult(call) {
  // Produce a real engine result for an `ask` decision.
  return processCall(call, policy, { source: "test" });
}

/** Build an injectable IO that feeds the given keys in sequence. */
function fakeIO(keys) {
  const output = [];
  let i = 0;
  return {
    output,
    text: () => output.join(""),
    write: (s) => output.push(s),
    prompt: async () => keys[i++],
  };
}

test("keyToResolution maps keys to resolutions", () => {
  assert.equal(keyToResolution("a"), "allow");
  assert.equal(keyToResolution("y"), "allow");
  assert.equal(keyToResolution("d"), "deny");
  assert.equal(keyToResolution("n"), "deny");
  assert.equal(keyToResolution("p"), "persist-allow");
  assert.equal(keyToResolution("A"), "allow"); // case-insensitive
  assert.equal(keyToResolution("z"), null);
  assert.equal(keyToResolution(""), null);
});

test("buildPersistRule anchors to command with exact equality", () => {
  const rule = buildPersistRule({ tool: "Bash", args: { command: "npm run build" } });
  assert.equal(rule.action, "allow");
  assert.equal(rule.tool, "Bash");
  assert.deepEqual(rule.match, { command: { equals: "npm run build" } });
});

test("buildPersistRule anchors to file_path when no command", () => {
  const rule = buildPersistRule({ tool: "Write", args: { file_path: "/proj/x.js" } });
  assert.deepEqual(rule.match, { file_path: { equals: "/proj/x.js" } });
});

test("buildPersistRule with no identifying arg has no match (tool-scoped)", () => {
  const rule = buildPersistRule({ tool: "SomeTool", args: {} });
  assert.equal(rule.tool, "SomeTool");
  assert.equal(rule.match, undefined);
});

test("resolveHold ALLOW outcome", async () => {
  const result = heldResult({ tool: "Write", args: { file_path: "/x.js", content: "a" } });
  const io = fakeIO(["a"]);
  const outcome = await resolveHold(result, io, { color: false });
  assert.deepEqual(outcome, { decision: "allow", persist: false });
  assert.match(io.text(), /ASK/);
  assert.match(io.text(), /File write/);
});

test("resolveHold DENY outcome", async () => {
  const result = heldResult({ tool: "Write", args: { file_path: "/x.js", content: "a" } });
  const io = fakeIO(["d"]);
  const outcome = await resolveHold(result, io, { color: false });
  assert.deepEqual(outcome, { decision: "deny", persist: false });
});

test("resolveHold PERSIST outcome returns a rule and allows", async () => {
  const result = heldResult({ tool: "Write", args: { file_path: "/x.js", content: "a" } });
  const io = fakeIO(["p"]);
  const outcome = await resolveHold(result, io, { color: false });
  assert.equal(outcome.decision, "allow");
  assert.equal(outcome.persist, true);
  assert.ok(outcome.rule, "rule produced");
  assert.equal(outcome.rule.action, "allow");
  assert.deepEqual(outcome.rule.match, { file_path: { equals: "/x.js" } });
});

test("resolveHold retries on invalid keys then accepts a valid one", async () => {
  const result = heldResult({ tool: "Write", args: { file_path: "/x.js", content: "a" } });
  const io = fakeIO(["z", "q", "a"]);
  const outcome = await resolveHold(result, io, { color: false, maxAttempts: 3 });
  assert.equal(outcome.decision, "allow");
  assert.match(io.text(), /unrecognized key/);
});

test("resolveHold fails safe to deny after too many invalid keys", async () => {
  const result = heldResult({ tool: "Write", args: { file_path: "/x.js", content: "a" } });
  const io = fakeIO(["z", "z", "z"]);
  const outcome = await resolveHold(result, io, { color: false, maxAttempts: 3 });
  assert.equal(outcome.decision, "deny");
});

test("renderHold writes the summary title and detail without color", () => {
  const result = heldResult({ tool: "Bash", args: { command: "echo hi" } });
  const out = [];
  renderHold(result, (s) => out.push(s), { color: false });
  const text = out.join("");
  assert.match(text, /Shell command/);
  assert.match(text, /echo hi/);
  assert.match(text, /\[a\]llow once/);
});

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  evaluate,
  globToRegExp,
  matchValue,
  validatePolicy,
  isValidAction,
} from "../src/policy.js";

test("default action is ask when no rules and no default", () => {
  const r = evaluate({ tool: "Bash", args: { command: "ls" } }, {});
  assert.equal(r.decision, "ask");
  assert.equal(r.ruleIndex, -1);
});

test("explicit default action is honored", () => {
  const r = evaluate({ tool: "Bash", args: {} }, { default: "deny", rules: [] });
  assert.equal(r.decision, "deny");
});

test("allow rule matches by tool name", () => {
  const policy = {
    default: "deny",
    rules: [{ action: "allow", tool: "Read" }],
  };
  assert.equal(evaluate({ tool: "Read", args: {} }, policy).decision, "allow");
  assert.equal(evaluate({ tool: "Write", args: {} }, policy).decision, "deny");
});

test("tool name matching is case-insensitive and supports arrays", () => {
  const policy = {
    default: "ask",
    rules: [{ action: "allow", tool: ["read", "GLOB"] }],
  };
  assert.equal(evaluate({ tool: "Read" }, policy).decision, "allow");
  assert.equal(evaluate({ tool: "glob" }, policy).decision, "allow");
  assert.equal(evaluate({ tool: "Bash" }, policy).decision, "ask");
});

test('wildcard tool "*" matches anything', () => {
  const policy = { default: "ask", rules: [{ action: "deny", tool: "*" }] };
  assert.equal(evaluate({ tool: "Anything" }, policy).decision, "deny");
});

test("first matching rule wins (ordering)", () => {
  const policy = {
    default: "ask",
    rules: [
      { action: "deny", tool: "Bash", match: { command: "rm" } },
      { action: "allow", tool: "Bash" },
    ],
  };
  // rm command hits the deny first
  assert.equal(
    evaluate({ tool: "Bash", args: { command: "rm file" } }, policy).decision,
    "deny"
  );
  // non-rm falls through to the allow
  assert.equal(
    evaluate({ tool: "Bash", args: { command: "ls" } }, policy).decision,
    "allow"
  );
});

test("glob matcher on file path", () => {
  const policy = {
    default: "allow",
    rules: [
      { action: "deny", tool: "Write", match: { file_path: "glob:**/.env" } },
    ],
  };
  assert.equal(
    evaluate({ tool: "Write", args: { file_path: "/a/b/.env" } }, policy)
      .decision,
    "deny"
  );
  assert.equal(
    evaluate({ tool: "Write", args: { file_path: "/a/b/index.js" } }, policy)
      .decision,
    "allow"
  );
});

test("regex matcher (case-insensitive) on shell command", () => {
  const policy = {
    default: "allow",
    rules: [
      {
        action: "deny",
        tool: "Bash",
        match: { command: "regex:rm\\s+-rf\\s+/" },
      },
    ],
  };
  assert.equal(
    evaluate({ tool: "Bash", args: { command: "RM   -RF /" } }, policy).decision,
    "deny"
  );
  assert.equal(
    evaluate({ tool: "Bash", args: { command: "rm -rf ./tmp" } }, policy)
      .decision,
    "allow"
  );
});

test("literal substring matcher (default form)", () => {
  const policy = {
    default: "allow",
    rules: [{ action: "ask", tool: "Bash", match: { command: "sudo" } }],
  };
  assert.equal(
    evaluate({ tool: "Bash", args: { command: "SUDO apt update" } }, policy)
      .decision,
    "ask"
  );
});

test("multiple match conditions must ALL match", () => {
  const policy = {
    default: "allow",
    rules: [
      {
        action: "deny",
        tool: "Bash",
        match: { command: "regex:^git", cwd: "glob:**/prod" },
      },
    ],
  };
  assert.equal(
    evaluate(
      { tool: "Bash", args: { command: "git push", cwd: "/srv/prod" } },
      policy
    ).decision,
    "deny"
  );
  // command matches but cwd does not -> falls through to default allow
  assert.equal(
    evaluate(
      { tool: "Bash", args: { command: "git push", cwd: "/srv/dev" } },
      policy
    ).decision,
    "allow"
  );
});

test("dotted path resolution into nested args", () => {
  const policy = {
    default: "allow",
    rules: [
      { action: "deny", tool: "*", match: { "options.danger": "equals:true" } },
    ],
  };
  assert.equal(
    evaluate({ tool: "X", args: { options: { danger: true } } }, policy)
      .decision,
    "deny"
  );
});

test("object matcher forms: glob/regex/equals/contains", () => {
  assert.ok(matchValue({ glob: "*.js" }, "index.js"));
  assert.ok(matchValue({ regex: "^foo", flags: "" }, "foobar"));
  assert.ok(matchValue({ equals: "exact" }, "exact"));
  assert.ok(!matchValue({ equals: "exact" }, "exactly"));
  assert.ok(matchValue({ contains: "bar" }, "foobarbaz"));
});

test("invalid rule action is skipped, falls to default", () => {
  const policy = {
    default: "ask",
    rules: [{ action: "nonsense", tool: "Bash" }],
  };
  assert.equal(evaluate({ tool: "Bash" }, policy).decision, "ask");
});

test("globToRegExp basics", () => {
  assert.ok(globToRegExp("**/*.env").test("a/b/c/.env")); // ** crosses dirs, * matches the basename
  assert.ok(globToRegExp("**/.env").test("a/b/.env"));
  assert.ok(globToRegExp("*.js").test("x.js"));
  assert.ok(!globToRegExp("*.js").test("a/x.js")); // single * doesn't cross /
  assert.ok(globToRegExp("src/**/*.ts").test("src/a/b/c.ts"));
});

test("isValidAction", () => {
  assert.ok(isValidAction("allow"));
  assert.ok(isValidAction("deny"));
  assert.ok(isValidAction("ask"));
  assert.ok(!isValidAction("maybe"));
});

test("validatePolicy detects bad actions and shapes", () => {
  assert.deepEqual(validatePolicy({ default: "ask", rules: [] }), []);
  const problems = validatePolicy({
    default: "nope",
    rules: [{ action: "bad" }, "not-an-object"],
  });
  assert.ok(problems.length >= 3);
});

// ---- invalid user regex/glob must never crash the firewall -----------------

test("matchValue degrades to a non-match on an uncompilable regex (no throw)", () => {
  // An unbalanced group is a SyntaxError if passed straight to new RegExp().
  assert.doesNotThrow(() => matchValue("regex:(unclosed", "anything"));
  assert.equal(matchValue("regex:(unclosed", "anything"), false);
  assert.doesNotThrow(() => matchValue({ regex: "[z-a]" }, "anything"));
  assert.equal(matchValue({ regex: "[z-a]" }, "anything"), false);
});

test("evaluate() never throws on a bad regex matcher; degrades to a decision", () => {
  const policy = {
    default: "allow",
    rules: [
      { action: "deny", tool: "Bash", match: { command: "regex:(unclosed" } },
    ],
  };
  let r;
  assert.doesNotThrow(() => {
    r = evaluate({ tool: "Bash", args: { command: "rm -rf /" } }, policy);
  });
  // The bad rule can't match, so we fall through to the default ("allow") —
  // crucially, no SyntaxError escaped up into the adapter.
  assert.ok(["allow", "deny", "ask"].includes(r.decision));
  assert.equal(r.decision, "allow");
});

test("validatePolicy reports an uncompilable regex/glob matcher up front", () => {
  const problems = validatePolicy({
    default: "ask",
    rules: [
      { action: "deny", tool: "Bash", match: { command: "regex:(unclosed" } },
    ],
  });
  assert.equal(problems.length, 1);
  assert.match(problems[0], /invalid regex pattern/);
  assert.match(problems[0], /command/);

  // A valid policy with regex/glob matchers stays clean.
  assert.deepEqual(
    validatePolicy({
      rules: [
        { action: "deny", tool: "Bash", match: { command: "regex:rm\\s+-rf" } },
        { action: "deny", tool: "Write", match: { file_path: "glob:**/.env" } },
      ],
    }),
    []
  );
});

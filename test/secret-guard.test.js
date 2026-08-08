import { test } from "node:test";
import assert from "node:assert/strict";
import {
  scanForSecrets,
  checkCall,
  extractWriteContent,
  redactSecretsInString,
  redactSecretsInArgs,
} from "../src/secret-guard.js";
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

// rhiza, BrainComms #4878: a Python line binding a variable named `tokens` to a
// regex-findall call was denied on the key name alone, on a line already present
// in the file unchanged. Assembled here rather than written literally so this
// test file does not trip the guard it is testing.
const codeValues = [
  ["tokens", "re.findall(r" + '"x"' + ")"],
  ["token", "getToken()"],
  ["api_key", "os.environ[" + '"K"' + "]"],
  ["secret", "() => loadSecret()"],
  ["password", "argv.pass || fallbackValue"],
];

test("scanForSecrets does not flag a code expression bound to a secret-ish name", () => {
  for (const [key, value] of codeValues) {
    const r = scanForSecrets(`${key} = ${value}`);
    assert.equal(r.blocked, false, `${key} = ${value} should not block`);
  }
});

test("a JWT is still flagged and redacted despite being a dotted string", () => {
  // The attribute-access relaxation must not swallow a JWT, which is also
  // dot-separated. Assembled, never written literally.
  const jwt = ["eyJ" + "h".repeat(30), "eyJ" + "s".repeat(30), "S".repeat(30)].join(".");
  assert.ok(scanForSecrets(`token = ${jwt}`).blocked, "JWT must block");
  assert.ok(
    !redactSecretsInString(`token = ${jwt}`).includes(jwt),
    "JWT must not survive redaction"
  );
});

test("a real literal under a code-ish name still blocks", () => {
  // The relaxation is value-shaped, not key-shaped: an opaque literal with no
  // call syntax is still a finding.
  assert.ok(scanForSecrets("tokens = " + "Z".repeat(32)).blocked);
  assert.ok(scanForSecrets(`tokens = "${fakeOpenAiKey}"`).blocked);
});

test("redaction still scrubs a provider key inside a call expression", () => {
  // isPlaceholder gates redaction too, so the code-value relaxation must not
  // leave a real key verbatim in the audit log.
  const out = redactSecretsInString(`setToken("${fakeOpenAiKey}")`);
  assert.ok(!out.includes(fakeOpenAiKey), "provider key must not survive redaction");
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
  // Policy would otherwise ALLOW all writes: secret-guard must override.
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

// ---- redaction (for audit storage) -----------------------------------------

test("redactSecretsInString scrubs provider keys, bearer tokens, and assignments", () => {
  const key = "sk-" + "D".repeat(40);
  const r1 = redactSecretsInString(`export const K = "${key}";`);
  assert.equal(r1.includes(key), false);
  assert.match(r1, /\[REDACTED\]/);

  const bearer = redactSecretsInString(`-H "Authorization: Bearer ${key}"`);
  assert.equal(bearer.includes(key), false);
  assert.match(bearer, /Bearer \[REDACTED\]/);

  const assign = redactSecretsInString("API_KEY=" + "Z".repeat(32));
  assert.match(assign, /API_KEY=\[REDACTED\]/);
});

test("redactSecretsInString keeps placeholders intact", () => {
  assert.equal(redactSecretsInString("API_KEY=${OPENAI_API_KEY}"), "API_KEY=${OPENAI_API_KEY}");
  assert.equal(redactSecretsInString("API_KEY=changeme"), "API_KEY=changeme");
});

test("redactSecretsInArgs deep-redacts and leaves the original untouched", () => {
  const token = "sk-" + "E".repeat(40);
  const original = { command: `curl -H "Authorization: Bearer ${token}" https://x` };
  const redacted = redactSecretsInArgs(original);
  assert.equal(redacted.command.includes(token), false);
  // original object is not mutated
  assert.ok(original.command.includes(token));
});

test("redactSecretsInString redacts the password in scheme://user:pass@host URLs", () => {
  const pass = "p4ssw0rd123";
  const pg = redactSecretsInString(`psql postgres://admin:${pass}@db.example.com/x`);
  assert.equal(pg.includes(pass), false, "db password must not survive");
  assert.equal(pg, "psql postgres://admin:[REDACTED]@db.example.com/x");

  const url = redactSecretsInString(`curl https://bob:${pass}@evil.com/x`);
  assert.equal(url.includes(pass), false);
  assert.equal(url, "curl https://bob:[REDACTED]@evil.com/x");
});

test("redactSecretsInString redacts only the secret query param, keeping the rest", () => {
  const secret = "SUPERSECRET12345";
  const out = redactSecretsInString(
    `https://api.example.com/x?api_key=${secret}&q=1&page=2`
  );
  assert.equal(out.includes(secret), false, "secret value must be gone");
  assert.match(out, /api_key=\[REDACTED\]/);
  // The non-secret params must survive (not greedily swallowed).
  assert.match(out, /&q=1&page=2$/);
});

test("redactSecretsInArgs handles a cyclic args object without throwing", () => {
  const args = { command: "curl https://x" };
  args.self = args; // back-reference -> infinite recursion without a guard
  let redacted;
  assert.doesNotThrow(() => {
    redacted = redactSecretsInArgs(args);
  });
  assert.equal(redacted.self, "[Circular]");
  assert.equal(redacted.command, "curl https://x");
});

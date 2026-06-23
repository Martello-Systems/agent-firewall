import { test } from "node:test";
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkdtempSync, rmSync, writeFileSync, existsSync } from "node:fs";
import {
  loadConfig,
  findConfigPath,
  persistRule,
  DEFAULT_CONFIG,
} from "../src/config.js";
import { processCall } from "../src/engine.js";

function tmp() {
  return mkdtempSync(join(tmpdir(), "af-config-"));
}

test("loadConfig falls back to default when no file present", () => {
  const dir = tmp();
  try {
    const { config, path, problems } = loadConfig(undefined, dir);
    assert.equal(path, null);
    assert.equal(problems.length, 0);
    assert.equal(config.policy.default, "ask");
    assert.ok(Array.isArray(config.policy.rules));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("loadConfig reads firewall.config.json from cwd", () => {
  const dir = tmp();
  try {
    writeFileSync(
      join(dir, "firewall.config.json"),
      JSON.stringify({
        policy: { default: "deny", rules: [{ action: "allow", tool: "Read" }] },
        audit: { db: "custom.sqlite" },
      })
    );
    const { config, path, problems } = loadConfig(undefined, dir);
    assert.ok(path.endsWith("firewall.config.json"));
    assert.equal(problems.length, 0);
    assert.equal(config.policy.default, "deny");
    assert.equal(config.audit.db, "custom.sqlite");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("loadConfig surfaces validation problems but still returns a policy", () => {
  const dir = tmp();
  try {
    writeFileSync(
      join(dir, "firewall.config.json"),
      JSON.stringify({ policy: { default: "bogus", rules: [] } })
    );
    const { problems } = loadConfig(undefined, dir);
    assert.ok(problems.some((p) => /default/.test(p)));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("loadConfig handles malformed JSON gracefully", () => {
  const dir = tmp();
  try {
    writeFileSync(join(dir, "firewall.config.json"), "{ not json");
    const { config, problems } = loadConfig(undefined, dir);
    assert.ok(problems.some((p) => /parse/.test(p)));
    // still usable default policy
    assert.equal(config.policy.default, "ask");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("findConfigPath honors explicit path", () => {
  const p = findConfigPath("/abs/firewall.config.json", "/cwd");
  assert.equal(p, "/abs/firewall.config.json");
});

test("default config blocks .env writes and rm -rf / end-to-end", () => {
  const denyEnv = processCall(
    { tool: "Write", args: { file_path: "/p/.env", content: "X=1" } },
    DEFAULT_CONFIG.policy
  );
  assert.equal(denyEnv.decision, "deny");

  const denyRm = processCall(
    { tool: "Bash", args: { command: "rm -rf /" } },
    DEFAULT_CONFIG.policy
  );
  assert.equal(denyRm.decision, "deny");

  const allowRead = processCall(
    { tool: "Read", args: { file_path: "/p/x.js" } },
    DEFAULT_CONFIG.policy
  );
  assert.equal(allowRead.decision, "allow");
});

test("persistRule writes a top-priority allow rule that changes the next decision", () => {
  const dir = tmp();
  try {
    const cfgPath = join(dir, "firewall.config.json");
    writeFileSync(
      cfgPath,
      JSON.stringify({ policy: { default: "ask", rules: [{ action: "ask", tool: "Bash" }] } })
    );
    const call = { tool: "Bash", args: { command: "npm run build" } };

    // Before: ask
    let { config } = loadConfig(undefined, dir);
    assert.equal(processCall(call, config.policy).decision, "ask");

    // Persist an allow rule for that exact command.
    const { ruleCount } = persistRule(
      { action: "allow", tool: "Bash", match: { command: { equals: "npm run build" } } },
      cfgPath
    );
    assert.equal(ruleCount, 2);

    // After: allow (persisted rule is inserted at the TOP -> wins first-match).
    ({ config } = loadConfig(undefined, dir));
    assert.equal(processCall(call, config.policy).decision, "allow");
    // A different command still asks.
    assert.equal(
      processCall({ tool: "Bash", args: { command: "rm something" } }, config.policy).decision,
      "ask"
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("persistRule creates the config file from default when absent", () => {
  const dir = tmp();
  try {
    const cfgPath = join(dir, "firewall.config.json");
    assert.equal(existsSync(cfgPath), false);
    persistRule({ action: "allow", tool: "Write" }, cfgPath);
    assert.equal(existsSync(cfgPath), true);
    const { config } = loadConfig(undefined, dir);
    assert.equal(config.policy.rules[0].action, "allow");
    assert.equal(config.policy.rules[0].tool, "Write");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("persistRule rejects an invalid rule with a clear error", () => {
  const dir = tmp();
  try {
    const cfgPath = join(dir, "firewall.config.json");
    assert.throws(
      () => persistRule({ action: "bogus", tool: "X" }, cfgPath),
      /invalid rule/
    );
    assert.equal(existsSync(cfgPath), false, "no file written on invalid rule");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

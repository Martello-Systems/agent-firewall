import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const BIN = join(__dirname, "..", "bin", "agent-firewall.js");

const CONFIG = JSON.stringify({
  policy: {
    default: "ask",
    rules: [
      { action: "allow", tool: ["Read", "Glob"] },
      { action: "deny", tool: "Bash", match: { command: "regex:rm\\s+-rf\\s+/" } },
    ],
  },
  audit: { db: ":memory:" },
});

function withConfig(fn) {
  const dir = mkdtempSync(join(tmpdir(), "af-cli-"));
  const cfg = join(dir, "firewall.config.json");
  writeFileSync(cfg, CONFIG);
  try {
    return fn(dir, cfg);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function runHook(event, cfg) {
  return spawnSync(process.execPath, [BIN, "--config", cfg, "hook"], {
    input: JSON.stringify(event),
    encoding: "utf8",
  });
}

test("CLI hook: ALLOW event -> exit 0, allow decision JSON on stdout", () => {
  withConfig((_dir, cfg) => {
    const r = runHook({ tool_name: "Read", tool_input: { file_path: "/x" } }, cfg);
    assert.equal(r.status, 0, "hook always exits 0");
    const out = JSON.parse(r.stdout);
    assert.equal(out.hookSpecificOutput.hookEventName, "PreToolUse");
    assert.equal(out.hookSpecificOutput.permissionDecision, "allow");
  });
});

test("CLI hook: DENY event -> exit 0, deny decision with reason", () => {
  withConfig((_dir, cfg) => {
    const r = runHook({ tool_name: "Bash", tool_input: { command: "rm -rf /" } }, cfg);
    assert.equal(r.status, 0);
    const out = JSON.parse(r.stdout);
    assert.equal(out.hookSpecificOutput.permissionDecision, "deny");
    assert.ok(out.hookSpecificOutput.permissionDecisionReason.length > 0);
  });
});

test("CLI hook: malformed stdin fails open to ask, still exit 0", () => {
  withConfig((_dir, cfg) => {
    const r = spawnSync(process.execPath, [BIN, "--config", cfg, "hook"], {
      input: "{ not json",
      encoding: "utf8",
    });
    assert.equal(r.status, 0);
    const out = JSON.parse(r.stdout);
    assert.equal(out.hookSpecificOutput.permissionDecision, "ask");
  });
});

test("CLI check: exit code mirrors decision (0 allow / 2 deny / 1 ask)", () => {
  withConfig((dir, cfg) => {
    const callFile = join(dir, "call.json");

    writeFileSync(callFile, JSON.stringify({ tool: "Read", args: { file_path: "/x" } }));
    let r = spawnSync(process.execPath, [BIN, "--config", cfg, "check", callFile, "--json"], {
      encoding: "utf8",
    });
    assert.equal(r.status, 0);

    writeFileSync(callFile, JSON.stringify({ tool: "Bash", args: { command: "rm -rf /" } }));
    r = spawnSync(process.execPath, [BIN, "--config", cfg, "check", callFile, "--json"], {
      encoding: "utf8",
    });
    assert.equal(r.status, 2);

    writeFileSync(callFile, JSON.stringify({ tool: "Write", args: { file_path: "/x.js", content: "a" } }));
    r = spawnSync(process.execPath, [BIN, "--config", cfg, "check", callFile, "--json"], {
      encoding: "utf8",
    });
    assert.equal(r.status, 1);
  });
});

test("CLI mcp: no downstream command errors clearly with exit 1", () => {
  withConfig((_dir, cfg) => {
    // commander requires the variadic arg; invoking with none should error out.
    const r = spawnSync(process.execPath, [BIN, "--config", cfg, "mcp"], {
      encoding: "utf8",
    });
    assert.notEqual(r.status, 0);
    assert.match((r.stderr || "") + (r.stdout || ""), /command|missing|usage/i);
  });
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { AuditLog } from "../src/audit.js";

function tmpDb() {
  const dir = mkdtempSync(join(tmpdir(), "af-audit-"));
  return { dir, path: join(dir, "audit.sqlite") };
}

test("writes to a temp sqlite file and reads back", () => {
  const { dir, path } = tmpDb();
  try {
    const audit = new AuditLog(path);
    const id = audit.record({
      source: "test",
      tool: "Bash",
      decision: "deny",
      kind: "shell",
      summary: "Shell command\nrm -rf /",
      reason: "blocked",
      ruleIndex: 1,
      args: { command: "rm -rf /" },
    });
    assert.ok(id > 0);
    assert.ok(existsSync(path), "sqlite file should be created on disk");

    const rows = audit.list();
    assert.equal(rows.length, 1);
    assert.equal(rows[0].tool, "Bash");
    assert.equal(rows[0].decision, "deny");
    assert.deepEqual(rows[0].args, { command: "rm -rf /" });
    audit.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("persists across reopen (durable on disk)", () => {
  const { dir, path } = tmpDb();
  try {
    const a1 = new AuditLog(path);
    a1.record({ tool: "Write", decision: "ask" });
    a1.close();

    const a2 = new AuditLog(path);
    const rows = a2.list();
    assert.equal(rows.length, 1);
    assert.equal(rows[0].tool, "Write");
    a2.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("list returns newest first and respects limit", () => {
  const audit = new AuditLog(":memory:");
  for (let i = 0; i < 5; i++) {
    audit.record({ tool: `T${i}`, decision: "allow" });
  }
  const rows = audit.list({ limit: 3 });
  assert.equal(rows.length, 3);
  assert.equal(rows[0].tool, "T4"); // newest first
  assert.equal(rows[2].tool, "T2");
  audit.close();
});

test("list filters by decision and tool", () => {
  const audit = new AuditLog(":memory:");
  audit.record({ tool: "Bash", decision: "deny" });
  audit.record({ tool: "Write", decision: "allow" });
  audit.record({ tool: "Bash", decision: "allow" });

  assert.equal(audit.list({ decision: "deny" }).length, 1);
  assert.equal(audit.list({ tool: "bash" }).length, 2); // case-insensitive
  assert.equal(audit.list({ tool: "Bash", decision: "allow" }).length, 1);
  audit.close();
});

test("count totals and per-decision counts", () => {
  const audit = new AuditLog(":memory:");
  audit.record({ tool: "A", decision: "allow" });
  audit.record({ tool: "B", decision: "deny" });
  audit.record({ tool: "C", decision: "deny" });
  assert.equal(audit.count(), 3);
  assert.equal(audit.count("deny"), 2);
  assert.equal(audit.count("allow"), 1);
  audit.close();
});

test("auto-creates parent directory for db path", () => {
  const { dir } = tmpDb();
  try {
    const nested = join(dir, "a", "b", "c", "audit.sqlite");
    const audit = new AuditLog(nested);
    audit.record({ tool: "X", decision: "allow" });
    assert.ok(existsSync(nested));
    audit.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

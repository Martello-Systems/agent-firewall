/**
 * Audit log: append-only record of firewall decisions, backed by SQLite
 * (better-sqlite3). Every intercepted call is logged with enough detail to
 * replay the decision: timestamp, tool, decision, summary, raw args, the rule
 * that fired, and the source adapter (hook / mcp / check).
 */

import Database from "better-sqlite3";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS audit_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          TEXT NOT NULL,
  source      TEXT,
  tool        TEXT NOT NULL,
  decision    TEXT NOT NULL,
  kind        TEXT,
  summary     TEXT,
  reason      TEXT,
  rule_index  INTEGER,
  args_json   TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_log(tool);
CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_log(decision);
`;

export class AuditLog {
  /**
   * @param {string} dbPath path to the sqlite file (":memory:" allowed)
   */
  constructor(dbPath) {
    if (dbPath && dbPath !== ":memory:") {
      mkdirSync(dirname(dbPath), { recursive: true });
    }
    this.db = new Database(dbPath || ":memory:");
    this.db.pragma("journal_mode = WAL");
    this.db.exec(SCHEMA);
  }

  /**
   * Append a decision record.
   *
   * @param {object} entry
   * @param {string} entry.tool
   * @param {string} entry.decision  allow|deny|ask
   * @param {string} [entry.source]
   * @param {string} [entry.kind]
   * @param {string} [entry.summary]
   * @param {string} [entry.reason]
   * @param {number} [entry.ruleIndex]
   * @param {object} [entry.args]
   * @param {string} [entry.ts] ISO timestamp (defaults to now)
   * @returns {number} the inserted row id
   */
  record(entry) {
    const stmt = this.db.prepare(`
      INSERT INTO audit_log
        (ts, source, tool, decision, kind, summary, reason, rule_index, args_json)
      VALUES
        (@ts, @source, @tool, @decision, @kind, @summary, @reason, @rule_index, @args_json)
    `);
    const info = stmt.run({
      ts: entry.ts ?? new Date().toISOString(),
      source: entry.source ?? null,
      tool: entry.tool,
      decision: entry.decision,
      kind: entry.kind ?? null,
      summary: entry.summary ?? null,
      reason: entry.reason ?? null,
      rule_index: entry.ruleIndex ?? null,
      args_json:
        entry.args !== undefined ? safeStringify(entry.args) : null,
    });
    return Number(info.lastInsertRowid);
  }

  /**
   * Read back log entries, newest first.
   *
   * @param {object} [opts]
   * @param {number} [opts.limit=50]
   * @param {string} [opts.decision] filter by decision
   * @param {string} [opts.tool] filter by tool name (case-insensitive)
   * @returns {Array<object>}
   */
  list(opts = {}) {
    const { limit = 50, decision, tool } = opts;
    const where = [];
    const params = {};
    if (decision) {
      where.push("decision = @decision");
      params.decision = decision;
    }
    if (tool) {
      where.push("LOWER(tool) = LOWER(@tool)");
      params.tool = tool;
    }
    const sql = `
      SELECT * FROM audit_log
      ${where.length ? "WHERE " + where.join(" AND ") : ""}
      ORDER BY id DESC
      LIMIT @limit
    `;
    params.limit = limit;
    return this.db.prepare(sql).all(params).map(deserializeRow);
  }

  /** Total number of records (optionally filtered by decision). */
  count(decision) {
    if (decision) {
      return this.db
        .prepare("SELECT COUNT(*) AS c FROM audit_log WHERE decision = ?")
        .get(decision).c;
    }
    return this.db.prepare("SELECT COUNT(*) AS c FROM audit_log").get().c;
  }

  close() {
    this.db.close();
  }
}

function safeStringify(v) {
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}

function deserializeRow(row) {
  return {
    id: row.id,
    ts: row.ts,
    source: row.source,
    tool: row.tool,
    decision: row.decision,
    kind: row.kind,
    summary: row.summary,
    reason: row.reason,
    ruleIndex: row.rule_index,
    args: row.args_json ? tryParse(row.args_json) : undefined,
  };
}

function tryParse(s) {
  try {
    return JSON.parse(s);
  } catch {
    return s;
  }
}

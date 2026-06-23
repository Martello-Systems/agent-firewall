/**
 * Engine — orchestrates policy + summarizer + audit for one tool call.
 *
 * This is the seam every adapter (Claude Code hook, MCP proxy, `check` CLI)
 * funnels through, so the decision/summarize/audit behaviour is identical
 * across entry points.
 */

import { evaluate } from "./policy.js";
import { summarize, summaryToString } from "./summarize.js";

/**
 * Process a single tool call against a policy.
 *
 * @param {{tool: string, args?: object}} call  normalized tool call
 * @param {object} policy
 * @param {object} [opts]
 * @param {import("./audit.js").AuditLog} [opts.audit]  if provided, the decision is recorded
 * @param {string} [opts.source] adapter label stored in the audit log
 * @param {(p:string)=>string|null} [opts.readFile] injectable file reader for diffs
 * @returns {{ decision, reason, ruleIndex, summary, summaryText, call }}
 */
export function processCall(call, policy, opts = {}) {
  const verdict = evaluate(call, policy);
  const summary = summarize(call, { readFile: opts.readFile });
  const summaryText = summaryToString(summary);

  if (opts.audit) {
    opts.audit.record({
      source: opts.source ?? "engine",
      tool: call?.tool ?? "(unknown)",
      decision: verdict.decision,
      kind: summary.kind,
      summary: summaryText,
      reason: verdict.reason,
      ruleIndex: verdict.ruleIndex,
      args: call?.args,
    });
  }

  return {
    decision: verdict.decision,
    reason: verdict.reason,
    ruleIndex: verdict.ruleIndex,
    summary,
    summaryText,
    call,
  };
}

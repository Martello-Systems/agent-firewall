/**
 * Engine: orchestrates the guards + policy + summarizer + audit for one tool
 * call.
 *
 * This is the seam every adapter (Claude Code hook, MCP proxy, `check` CLI)
 * funnels through, so the guard / decision / summarize / audit behaviour is
 * identical across entry points. Guards that used to live in a single adapter
 * (e.g. the secret-guard) run HERE so they fire on every path.
 *
 * Order of evaluation:
 *   1. secret-guard  - unconditional deny on writing a literal secret; never
 *                      echoes or stores the value.
 *   2. egress-guard  - opt-in (policy.egress) allowlist for outbound network
 *                      destinations.
 *   3. policy        - the configured allow/deny/ask rules.
 */

import { evaluate } from "./policy.js";
import { summarize, summaryToString } from "./summarize.js";
import { checkCall as secretCheck } from "./secret-guard.js";
import { checkCall as egressCheck } from "./egress-guard.js";

/**
 * Process a single tool call against a policy.
 *
 * @param {{tool: string, args?: object}} call  normalized tool call
 * @param {object} policy
 * @param {object} [opts]
 * @param {import("./audit.js").AuditLog} [opts.audit]  if provided, the decision is recorded
 * @param {string} [opts.source] adapter label stored in the audit log
 * @param {(p:string)=>string|null} [opts.readFile] injectable file reader for diffs
 * @returns {{ decision, reason, ruleIndex, summary, summaryText, call, blockedBy? }}
 */
export function processCall(call, policy = {}, opts = {}) {
  const source = opts.source ?? "engine";

  // Guard 1 (unconditional): refuse to commit a literal secret to a file. This
  // overrides any configured policy and is deliberately summarized WITHOUT the
  // diff/args so the secret value is never echoed to a caller or the audit log.
  const secret = secretCheck(call);
  if (secret.blocked) {
    const result = {
      decision: "deny",
      reason: secret.reason,
      ruleIndex: -1,
      blockedBy: "secret-guard",
      summary: {
        kind: "file",
        title: "[secret-guard] refusing to write a literal secret",
        detail: secret.reason,
      },
      summaryText: `[secret-guard] ${secret.reason}`,
      call,
    };
    if (opts.audit) {
      opts.audit.record({
        source,
        tool: call?.tool ?? "(unknown)",
        decision: "deny",
        kind: "file",
        summary: result.summaryText,
        reason: secret.reason,
        ruleIndex: -1,
        // Deliberately omit args: they contain the secret.
      });
    }
    return result;
  }

  const summary = summarize(call, { readFile: opts.readFile });
  const summaryText = summaryToString(summary);

  // Guard 2 (opt-in via policy.egress): gate outbound network destinations
  // against an allowlist. Inert unless `policy.egress.allow` is configured.
  const egress = egressCheck(call, policy?.egress);
  if (egress.blocked) {
    const reason = `egress-guard: ${egress.reason}`;
    if (opts.audit) {
      opts.audit.record({
        source,
        tool: call?.tool ?? "(unknown)",
        decision: egress.action,
        kind: summary.kind,
        summary: summaryText,
        reason,
        ruleIndex: -1,
        args: call?.args,
      });
    }
    return {
      decision: egress.action,
      reason,
      ruleIndex: -1,
      blockedBy: "egress-guard",
      summary,
      summaryText,
      call,
    };
  }

  // Guard 3: the configured policy rules.
  const verdict = evaluate(call, policy);

  if (opts.audit) {
    opts.audit.record({
      source,
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

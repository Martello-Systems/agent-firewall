/**
 * Claude Code PreToolUse hook adapter.
 *
 * Claude Code invokes a hook command, passing a JSON event on stdin:
 *   {
 *     "session_id": "...",
 *     "transcript_path": "...",
 *     "cwd": "...",
 *     "hook_event_name": "PreToolUse",
 *     "tool_name": "Bash",
 *     "tool_input": { "command": "npm test" }
 *   }
 *
 * The hook must print JSON on stdout describing the permission decision:
 *   {
 *     "hookSpecificOutput": {
 *       "hookEventName": "PreToolUse",
 *       "permissionDecision": "allow" | "deny" | "ask",
 *       "permissionDecisionReason": "..."
 *     }
 *   }
 *
 * This module contains the pure mapping logic (no I/O) so it can be unit
 * tested without a live Claude Code. The bin wrapper handles stdin/stdout.
 */

import { processCall } from "./engine.js";
import { checkCall as secretCheck } from "./secret-guard.js";

/**
 * Convert a Claude Code PreToolUse event into our normalized tool call.
 *
 * @param {object} event the parsed hook stdin JSON
 * @returns {{ tool: string, args: object }}
 */
export function eventToCall(event) {
  return {
    tool: event?.tool_name ?? "",
    args: event?.tool_input ?? {},
  };
}

/**
 * Map our internal decision to the Claude Code hook output object.
 * Our actions (allow|deny|ask) map 1:1 to permissionDecision values.
 *
 * @param {"allow"|"deny"|"ask"} decision
 * @param {string} reason
 * @returns {object} the object Claude Code expects on stdout
 */
export function buildHookOutput(decision, reason) {
  const permissionDecision = ["allow", "deny", "ask"].includes(decision)
    ? decision
    : "ask";
  const out = {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision,
    },
  };
  if (reason) {
    out.hookSpecificOutput.permissionDecisionReason = reason;
  }
  return out;
}

/**
 * Full pipeline: PreToolUse event -> policy decision -> hook output JSON.
 * Optionally records to an audit log.
 *
 * @param {object} event parsed PreToolUse stdin JSON
 * @param {object} policy
 * @param {object} [opts] forwarded to processCall (audit, readFile)
 * @returns {{ output: object, result: object }}
 */
export function handlePreToolUse(event, policy, opts = {}) {
  const call = eventToCall(event);

  // House rule: a write that commits a literal secret is denied unconditionally,
  // ahead of and overriding the configured policy. We never echo the value.
  const secret = secretCheck(call);
  if (secret.blocked) {
    if (opts.audit) {
      opts.audit.record({
        source: "claude-code-hook",
        tool: call.tool,
        decision: "deny",
        kind: "file",
        summary: `[secret-guard] ${secret.reason}`,
        reason: secret.reason,
        ruleIndex: -1,
        // Deliberately do NOT store args — they contain the secret.
      });
    }
    const reason = `[agent-firewall] DENY (secret-guard): ${secret.reason}`;
    return {
      output: buildHookOutput("deny", reason),
      result: { decision: "deny", reason: secret.reason, ruleIndex: -1 },
    };
  }

  const result = processCall(call, policy, { source: "claude-code-hook", ...opts });
  const reason = `[agent-firewall] ${result.decision.toUpperCase()}: ${result.reason}`;
  const output = buildHookOutput(result.decision, reason);
  return { output, result };
}

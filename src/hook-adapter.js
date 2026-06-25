/**
 * Claude Code PreToolUse hook adapter.
 *
 * CONTRACT TARGETED: verified against the official Claude Code hooks docs
 * (https://code.claude.com/docs/en/hooks.md, confirmed 2026-06-23):
 *
 * Claude Code invokes a hook command, passing a JSON event on STDIN:
 *   {
 *     "session_id": "...",
 *     "transcript_path": "...",
 *     "cwd": "...",
 *     "permission_mode": "default" | "plan" | "acceptEdits" | ...,
 *     "hook_event_name": "PreToolUse",
 *     "tool_name": "Bash",
 *     "tool_input": { "command": "npm test" }
 *   }
 *
 * On EXIT CODE 0 the hook's STDOUT JSON is parsed. For PreToolUse the decision
 * lives in `hookSpecificOutput` (NOT a top-level `decision` field, that form is
 * for other events). Field names are camelCase:
 *   {
 *     "hookSpecificOutput": {
 *       "hookEventName": "PreToolUse",
 *       "permissionDecision": "allow" | "deny" | "ask",
 *       "permissionDecisionReason": "..."   // REQUIRED when decision is "deny"
 *     }
 *   }
 *
 * Exit-code semantics: exit 0 => stdout JSON is honored; exit 2 => the JSON is
 * IGNORED and stderr is fed back as a blocking error. We therefore ALWAYS exit
 * 0 and express allow/deny/ask via `permissionDecision` (see bin wrapper).
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
  // Contract: `permissionDecisionReason` is REQUIRED when the decision is
  // "deny". Always include a reason for deny (synthesize one if the caller
  // didn't supply it) and pass it through for allow/ask when present.
  if (reason) {
    out.hookSpecificOutput.permissionDecisionReason = reason;
  } else if (permissionDecision === "deny") {
    out.hookSpecificOutput.permissionDecisionReason =
      "blocked by agent-firewall policy";
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
        // Deliberately do NOT store args: they contain the secret.
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

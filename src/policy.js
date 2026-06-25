/**
 * Policy engine.
 *
 * Given a tool call { tool, args } and a policy, decide one of:
 *   "allow" | "deny" | "ask"
 *
 * A policy is:
 *   {
 *     default: "allow" | "deny" | "ask",   // action when no rule matches (default: "ask")
 *     rules: [ Rule, ... ]                  // evaluated in order, first match wins
 *   }
 *
 * A Rule is:
 *   {
 *     action: "allow" | "deny" | "ask",     // required
 *     tool: "Bash" | ["Bash","Write"] | "*" // optional tool-name matcher (default "*")
 *     match: { <argPath>: <matcher>, ... }  // optional arg matchers (ALL must match)
 *     description: "..."                     // optional, surfaced in summaries/logs
 *   }
 *
 * Arg matchers (the value side of `match`):
 *   - "glob:**\/*.env"     glob pattern against the stringified arg value
 *   - "regex:^rm\\s+-rf"   regular expression (case-insensitive) against the value
 *   - "literal text"        substring (case-insensitive) containment, the default
 *   - { glob: "..." }       explicit object forms also supported
 *   - { regex: "...", flags: "i" }
 *   - { equals: "..." }     strict equality
 *   - { contains: "..." }   substring containment
 *
 * Arg paths support dotted access into nested args, e.g. "tool_input.command"
 * or just "command" depending on how the caller normalizes the call.
 */

export const ACTIONS = Object.freeze(["allow", "deny", "ask"]);

const DEFAULT_ACTION = "ask";

/**
 * Normalize a tool matcher into an array of lowercase names (or ["*"]).
 */
function normalizeToolMatcher(tool) {
  if (tool == null || tool === "*") return ["*"];
  const arr = Array.isArray(tool) ? tool : [tool];
  return arr.map((t) => String(t).toLowerCase());
}

function toolMatches(ruleTool, toolName) {
  const matchers = normalizeToolMatcher(ruleTool);
  if (matchers.includes("*")) return true;
  return matchers.includes(String(toolName ?? "").toLowerCase());
}

/**
 * Convert a glob string to a RegExp.
 * Supports `*`, `**`, `?`, and character classes `[...]`.
 */
export function globToRegExp(glob) {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        // ** matches across path separators
        re += ".*";
        i++;
        // swallow a trailing slash after ** so "**/foo" matches "foo"
        if (glob[i + 1] === "/") i++;
      } else {
        // single * does not cross "/"
        re += "[^/]*";
      }
    } else if (c === "?") {
      re += "[^/]";
    } else if (c === "[") {
      let cls = "[";
      i++;
      if (glob[i] === "!") {
        cls += "^";
        i++;
      }
      while (i < glob.length && glob[i] !== "]") {
        const cc = glob[i];
        cls += /[\\^$.*+?()[\]{}|]/.test(cc) ? "\\" + cc : cc;
        i++;
      }
      cls += "]";
      re += cls;
    } else if (/[\\^$.+()[\]{}|]/.test(c)) {
      re += "\\" + c;
    } else {
      re += c;
    }
  }
  return new RegExp("^" + re + "$");
}

/**
 * Resolve a dotted path against an object. Returns undefined if any hop misses.
 */
function getByPath(obj, path) {
  if (obj == null) return undefined;
  if (path in obj) return obj[path]; // fast path / non-dotted key
  const parts = String(path).split(".");
  let cur = obj;
  for (const p of parts) {
    if (cur == null) return undefined;
    cur = cur[p];
  }
  return cur;
}

/**
 * Stringify an arg value for matching. Objects/arrays become JSON.
 */
function valueToString(v) {
  if (v == null) return "";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}

/**
 * Compile a `regex:`/`{regex}` source to a RegExp, returning null on a bad
 * pattern instead of throwing. A user-supplied policy must never be able to
 * crash the firewall with an invalid pattern (the documented "fail open to ask,
 * never crash" contract): a pattern that won't compile simply can't match.
 */
function tryCompileRegex(source, flags) {
  try {
    return new RegExp(source, flags);
  } catch {
    return null;
  }
}

/**
 * Detect a structurally malformed glob that `globToRegExp` would otherwise
 * accept silently (it is lenient: an unterminated `[` char class becomes a
 * literal-ish regex rather than throwing). Returns an error string or null.
 *
 * The check mirrors how `globToRegExp` consumes a `[...]` class: a `[` that is
 * never closed by a `]` is an unterminated character class.
 */
function globStructuralError(glob) {
  let inClass = false;
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "[" && !inClass) inClass = true;
    else if (c === "]" && inClass) inClass = false;
  }
  if (inClass) return "unterminated character class '['";
  return null;
}

/**
 * Compile a glob to a RegExp, returning null on a malformed / uncompilable
 * pattern (so it degrades to a non-match instead of mis-matching or throwing).
 */
function tryCompileGlob(glob) {
  if (globStructuralError(glob)) return null;
  try {
    return globToRegExp(glob);
  } catch {
    return null;
  }
}

/**
 * Test a single matcher against a (raw) arg value.
 *
 * NOTE: a matcher whose glob/regex won't compile degrades to a non-match
 * (returns false) rather than throwing, so a malformed user pattern can never
 * crash an evaluation mid-stream. `validatePolicy` reports such patterns up
 * front so the misconfiguration is still surfaced.
 */
export function matchValue(matcher, rawValue) {
  const str = valueToString(rawValue);

  if (matcher == null) return true;

  // String shorthand forms.
  if (typeof matcher === "string") {
    if (matcher.startsWith("glob:")) {
      const re = tryCompileGlob(matcher.slice(5));
      return re ? re.test(str) : false;
    }
    if (matcher.startsWith("regex:")) {
      const re = tryCompileRegex(matcher.slice(6), "i");
      return re ? re.test(str) : false;
    }
    if (matcher.startsWith("equals:")) {
      return str === matcher.slice(7);
    }
    // default: case-insensitive substring containment
    return str.toLowerCase().includes(matcher.toLowerCase());
  }

  // Object forms.
  if (typeof matcher === "object") {
    if (typeof matcher.glob === "string") {
      const re = tryCompileGlob(matcher.glob);
      return re ? re.test(str) : false;
    }
    if (typeof matcher.regex === "string") {
      const re = tryCompileRegex(matcher.regex, matcher.flags ?? "i");
      return re ? re.test(str) : false;
    }
    if (matcher.equals !== undefined) {
      return str === valueToString(matcher.equals);
    }
    if (typeof matcher.contains === "string") {
      return str.toLowerCase().includes(matcher.contains.toLowerCase());
    }
  }

  return false;
}

/**
 * Does a rule's `match` block match all the given args?
 */
function argsMatch(ruleMatch, args) {
  if (!ruleMatch) return true;
  for (const [path, matcher] of Object.entries(ruleMatch)) {
    const value = getByPath(args ?? {}, path);
    if (!matchValue(matcher, value)) return false;
  }
  return true;
}

/**
 * Validate that an action string is one of allow|deny|ask.
 */
export function isValidAction(a) {
  return ACTIONS.includes(a);
}

/**
 * Evaluate a tool call against a policy.
 *
 * @param {{tool: string, args?: object}} call
 * @param {{default?: string, rules?: Array}} policy
 * @returns {{ decision: "allow"|"deny"|"ask", rule: object|null, ruleIndex: number, reason: string }}
 */
export function evaluate(call, policy = {}) {
  // Hard guarantee: a policy evaluation must never throw up into the adapters
  // (Claude Code hook / MCP proxy / check CLI). Anything unexpected degrades to
  // "ask" so the firewall fails open to a hold instead of crashing the agent.
  try {
    return evaluateInner(call, policy);
  } catch (err) {
    return {
      decision: "ask",
      rule: null,
      ruleIndex: -1,
      reason: `policy evaluation error, failing open to ask: ${err.message}`,
    };
  }
}

function evaluateInner(call, policy) {
  const tool = call?.tool ?? "";
  const args = call?.args ?? {};
  const rules = Array.isArray(policy.rules) ? policy.rules : [];
  const defaultAction = isValidAction(policy.default)
    ? policy.default
    : DEFAULT_ACTION;

  for (let i = 0; i < rules.length; i++) {
    const rule = rules[i];
    if (!rule || !isValidAction(rule.action)) continue;
    if (!toolMatches(rule.tool, tool)) continue;
    if (!argsMatch(rule.match, args)) continue;

    return {
      decision: rule.action,
      rule,
      ruleIndex: i,
      reason:
        rule.description ||
        `matched rule #${i} (${rule.action} for ${describeRuleTool(rule.tool)})`,
    };
  }

  return {
    decision: defaultAction,
    rule: null,
    ruleIndex: -1,
    reason: `no rule matched, default action "${defaultAction}"`,
  };
}

function describeRuleTool(tool) {
  if (tool == null || tool === "*") return "*";
  return Array.isArray(tool) ? tool.join("|") : String(tool);
}

/**
 * Return a human-readable error if a matcher's glob/regex won't compile, or
 * null if it is fine (or is a form that has no compile step, like equals/
 * literal/contains). Used by validatePolicy to surface bad patterns up front.
 */
export function matcherCompileError(matcher) {
  if (matcher == null) return null;
  if (typeof matcher === "string") {
    if (matcher.startsWith("glob:")) return globCompileError(matcher.slice(5));
    if (matcher.startsWith("regex:")) return regexCompileError(matcher.slice(6), "i");
    return null;
  }
  if (typeof matcher === "object") {
    if (typeof matcher.glob === "string") return globCompileError(matcher.glob);
    if (typeof matcher.regex === "string") {
      return regexCompileError(matcher.regex, matcher.flags ?? "i");
    }
  }
  return null;
}

function regexCompileError(source, flags) {
  try {
    new RegExp(source, flags);
    return null;
  } catch (err) {
    return `invalid regex pattern: ${err.message}`;
  }
}

function globCompileError(glob) {
  const structural = globStructuralError(glob);
  if (structural) return `invalid glob pattern: ${structural}`;
  try {
    globToRegExp(glob);
    return null;
  } catch (err) {
    return `invalid glob pattern: ${err.message}`;
  }
}

/**
 * Validate a policy object, returning an array of human-readable problems.
 * An empty array means the policy is structurally valid.
 */
export function validatePolicy(policy) {
  const problems = [];
  if (policy == null || typeof policy !== "object") {
    return ["policy must be an object"];
  }
  if (policy.default !== undefined && !isValidAction(policy.default)) {
    problems.push(`policy.default "${policy.default}" is not allow|deny|ask`);
  }
  if (policy.rules !== undefined && !Array.isArray(policy.rules)) {
    problems.push("policy.rules must be an array");
  }
  for (let i = 0; i < (policy.rules?.length ?? 0); i++) {
    const r = policy.rules[i];
    if (!r || typeof r !== "object") {
      problems.push(`rule #${i} must be an object`);
      continue;
    }
    if (!isValidAction(r.action)) {
      problems.push(`rule #${i} action "${r.action}" is not allow|deny|ask`);
    }
    // Compile-validate every arg matcher so a bad glob/regex is reported as a
    // policy problem instead of silently degrading to a non-match at runtime.
    if (r.match && typeof r.match === "object") {
      for (const [path, matcher] of Object.entries(r.match)) {
        const err = matcherCompileError(matcher);
        if (err) problems.push(`rule #${i} match["${path}"] ${err}`);
      }
    }
  }
  return problems;
}

/**
 * Network egress allowlist guard.
 *
 * Native coding-agent permissions can gate WHICH tools run, but not WHERE an
 * allowed tool reaches on the network. This guard inspects outbound HTTP(S)
 * side effects and blocks (or holds for approval) any request whose destination
 * host is not on a configured allowlist, routed through the same decision +
 * audit seam as every other call.
 *
 * Opt-in: with no `egress` config the guard is inert, so default behaviour is
 * unchanged. Configure it under `policy.egress` in firewall.config.json:
 *
 *   "policy": {
 *     "egress": { "allow": ["api.github.com", "*.openai.com"], "action": "deny" },
 *     ...
 *   }
 */

import { classify } from "./summarize.js";
import { globToRegExp } from "./policy.js";

/**
 * Pull the destination URL out of an http-ish tool call.
 */
export function extractUrl(call) {
  const args = call?.args ?? {};
  if (typeof args.url === "string") return args.url;
  if (typeof args.uri === "string") return args.uri;
  if (typeof args.endpoint === "string") return args.endpoint;
  return "";
}

/**
 * Parse the hostname out of a URL string. Returns "" if unparseable.
 * Tolerates a scheme-less "host[:port]/path" by retrying with an http:// prefix.
 */
export function hostFromUrl(url) {
  if (typeof url !== "string" || !url) return "";
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    try {
      return new URL("http://" + url).hostname.toLowerCase();
    } catch {
      return "";
    }
  }
}

/**
 * Does a host match an allowlist entry? Entries may be:
 *   - exact host          "api.github.com"
 *   - leading-dot suffix  ".github.com"  (matches github.com and any subdomain)
 *   - glob                "*.github.com"
 *   - wildcard            "*"            (allow all)
 */
export function hostMatches(host, entry) {
  if (!host || !entry) return false;
  const h = String(host).toLowerCase();
  const e = String(entry).toLowerCase().trim();
  if (e === "*") return true;
  if (e.startsWith(".")) {
    return h === e.slice(1) || h.endsWith(e);
  }
  if (e.includes("*")) {
    return globToRegExp(e).test(h);
  }
  return h === e;
}

/**
 * Evaluate a tool call against the egress allowlist.
 *
 * @param {{tool:string, args?:object}} call
 * @param {object} [egress] the `policy.egress` config block
 * @param {string[]} [egress.allow] allowed hosts / patterns
 * @param {"deny"|"ask"} [egress.action="deny"] decision for a non-allowlisted host
 * @returns {{ blocked:boolean, action?:"deny"|"ask", reason?:string, host?:string }}
 */
export function checkCall(call, egress) {
  if (!egress || !Array.isArray(egress.allow)) {
    return { blocked: false };
  }
  if (classify(call) !== "http") {
    return { blocked: false };
  }

  const action = egress.action === "ask" ? "ask" : "deny";
  const url = extractUrl(call);
  const host = hostFromUrl(url);

  if (!host) {
    // An http call whose host we cannot resolve: treat as a violation so a
    // malformed or obfuscated destination cannot slip past the allowlist.
    return {
      blocked: true,
      action,
      host: "",
      reason: "outbound request has no resolvable host; egress allowlist is active",
    };
  }

  for (const entry of egress.allow) {
    if (hostMatches(host, entry)) {
      return { blocked: false, host };
    }
  }

  return {
    blocked: true,
    action,
    host,
    reason: `outbound host "${host}" is not on the egress allowlist`,
  };
}

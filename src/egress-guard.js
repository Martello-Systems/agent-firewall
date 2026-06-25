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

// Shell tools that reach the network with a host/URL argument.
const NETWORK_TOOL_RE =
  /(?:^|[\s;&|(`$])(?:curl|wget|nc|ncat|netcat|telnet|ssh|scp|sftp|ftp|httpie|http|https|xh)(?:\.exe)?(?=$|[\s])/i;

// A bare "host[:port][/path]" or scp-style "host:path" token. Captures the
// hostname (group 1); the host must contain at least one dot and a TLD.
const BARE_HOST_RE = /^((?:[a-z0-9-]+\.)+[a-z]{2,})(?::\d+)?(?:[/:].*)?$/i;

// A bare IPv4 literal (a dotted-quad has no alpha TLD, so BARE_HOST_RE misses
// it). Captures the address; a trailing :port / :path / /path is tolerated.
const BARE_IPV4_RE = /^((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?(?:[/:].*)?$/;

// A bare bracketed IPv6 literal, e.g. "[::1]" or "[2001:db8::1]:8080". Captures
// the bracketed form to match how URL parsing surfaces an IPv6 hostname.
const BARE_IPV6_RE = /^(\[[0-9a-f:]+\])(?::\d+)?(?:\/.*)?$/i;

/**
 * Pull a hostname / IP literal out of a single bare command token (one that is
 * not a flag and carries no scheme). Recognizes dotted-name hosts, IPv4, and
 * bracketed IPv6. Returns "" if the token is not a network destination.
 */
function bareHost(tok) {
  let m = BARE_HOST_RE.exec(tok);
  if (m) return m[1].toLowerCase();
  m = BARE_IPV6_RE.exec(tok);
  if (m) return m[1].toLowerCase();
  m = BARE_IPV4_RE.exec(tok);
  if (m) return m[1];
  return "";
}

/**
 * Extract candidate destination hosts from a shell command string.
 *
 * Two sources are recognised:
 *   1. Any explicit `scheme://host/...` URL anywhere in the command.
 *   2. Bare host / IP arguments to a known network tool (`curl example.com`,
 *      `curl 1.2.3.4`, `nc 1.2.3.4 443`, ...).
 *
 * This is a best-effort textual scan, not a full shell parser: it cannot follow
 * variable expansion, command substitution, or hosts assembled at runtime. It
 * deliberately errs toward extracting a host (so the egress allowlist gets a
 * chance to deny it) rather than missing one. See the README "Limitations".
 *
 * @param {string} command
 * @returns {string[]} lowercased hostnames (deduped)
 */
export function extractHostsFromCommand(command) {
  if (typeof command !== "string" || !command) return [];
  const hosts = new Set();

  // 1. Explicit URLs with a scheme (http://, https://, ftp://, ...).
  const urlRe = /\b[a-z][a-z0-9+.-]*:\/\/[^\s'"`)<>|]+/gi;
  let m;
  while ((m = urlRe.exec(command)) !== null) {
    const h = hostFromUrl(m[0]);
    if (h) hosts.add(h);
  }

  // 2. Bare hosts passed as arguments to a network tool.
  if (NETWORK_TOOL_RE.test(command)) {
    for (const rawTok of command.split(/[\s;&|()`]+/)) {
      if (!rawTok) continue;
      // Strip surrounding quotes and a leading "user@" (scp/ssh) prefix.
      let tok = rawTok.replace(/^['"]+|['"]+$/g, "");
      if (tok.startsWith("-")) continue; // flag
      if (tok.includes("://")) continue; // already handled above
      const at = tok.lastIndexOf("@");
      if (at !== -1) tok = tok.slice(at + 1);
      const host = bareHost(tok);
      if (host) hosts.add(host);
    }
  }

  return [...hosts];
}

/**
 * Is `host` permitted by the allowlist?
 */
function isHostAllowed(host, allow) {
  for (const entry of allow) {
    if (hostMatches(host, entry)) return true;
  }
  return false;
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

  const action = egress.action === "ask" ? "ask" : "deny";
  const kind = classify(call);

  if (kind === "http") {
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

    if (isHostAllowed(host, egress.allow)) {
      return { blocked: false, host };
    }
    return {
      blocked: true,
      action,
      host,
      reason: `outbound host "${host}" is not on the egress allowlist`,
    };
  }

  // Shell commands can reach the network too (curl/wget/nc/...). A shell-level
  // bypass of the egress allowlist would defeat the whole guard, so we scan the
  // command string for destination hosts and hold every host to the allowlist.
  if (kind === "shell") {
    const command = call?.args?.command ?? call?.args?.cmd ?? "";
    const hosts = extractHostsFromCommand(command);
    for (const host of hosts) {
      if (!isHostAllowed(host, egress.allow)) {
        return {
          blocked: true,
          action,
          host,
          reason: `shell command reaches outbound host "${host}", which is not on the egress allowlist`,
        };
      }
    }
    // No destination host we can see — leave the shell command to the policy
    // rules (we must not blanket-block every local shell command here).
    return { blocked: false };
  }

  return { blocked: false };
}

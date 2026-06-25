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
 * Parse a single inet_aton-style numeric component: decimal, 0x-hex, or
 * 0-prefixed octal. Returns the number, or null if it isn't a valid integer
 * literal.
 */
function parseIntPart(s) {
  if (/^0x[0-9a-f]+$/i.test(s)) return parseInt(s, 16);
  if (/^0[0-7]+$/.test(s)) return parseInt(s, 8);
  if (/^(?:0|[1-9][0-9]*)$/.test(s)) return parseInt(s, 10);
  return null;
}

/**
 * Heuristic: does this token look like an *encoded* IP (vs. a plain dotted-quad
 * or an ordinary number such as a port)? We only decode when the form is
 * unambiguous, to avoid mis-decoding a port like "4444" into a bogus host:
 *   - any 0x-hex or 0-octal component  -> definitely an encoded literal
 *   - a single bare decimal > 65535    -> a packed 32-bit address (can't be a
 *                                         port, which maxes at 65535)
 */
function looksLikeEncodedIp(body) {
  const parts = body.split(".");
  if (parts.some((p) => /^0x[0-9a-f]+$/i.test(p) || /^0[0-7]+$/.test(p))) {
    return true;
  }
  if (parts.length === 1 && /^[0-9]+$/.test(parts[0]) && Number(parts[0]) > 65535) {
    return true;
  }
  return false;
}

/**
 * Decode an obfuscated IPv4 literal (decimal `2130706433`, hex `0x7f000001`,
 * octal, or a mixed dotted form like `0177.0.0.1`) to its canonical dotted
 * quad. inet_aton semantics: 1-4 parts, with the final part filling the
 * remaining low-order bytes. Returns "" if the token isn't such a literal.
 */
function decodeEncodedIp(tok) {
  const m = /^([0-9a-fx.]+)(?:[:/].*)?$/i.exec(tok);
  if (!m) return "";
  const body = m[1];
  if (!looksLikeEncodedIp(body)) return "";

  const parts = body.split(".");
  if (parts.length < 1 || parts.length > 4) return "";
  const nums = parts.map(parseIntPart);
  if (nums.some((n) => n === null)) return "";

  let value;
  if (parts.length === 1) {
    value = nums[0];
  } else if (parts.length === 2) {
    if (nums[0] > 0xff || nums[1] > 0xffffff) return "";
    value = nums[0] * 0x1000000 + nums[1];
  } else if (parts.length === 3) {
    if (nums[0] > 0xff || nums[1] > 0xff || nums[2] > 0xffff) return "";
    value = nums[0] * 0x1000000 + nums[1] * 0x10000 + nums[2];
  } else {
    if (nums.some((n) => n > 0xff)) return "";
    value =
      nums[0] * 0x1000000 + nums[1] * 0x10000 + nums[2] * 0x100 + nums[3];
  }
  if (!Number.isFinite(value) || value < 0 || value > 0xffffffff) return "";

  return [
    Math.floor(value / 0x1000000) & 0xff,
    Math.floor(value / 0x10000) & 0xff,
    Math.floor(value / 0x100) & 0xff,
    value & 0xff,
  ].join(".");
}

/**
 * Pull a hostname / IP literal out of a single bare command token (one that is
 * not a flag and carries no scheme). Recognizes dotted-name hosts, IPv4,
 * bracketed IPv6, and obfuscated (decimal/hex/octal) IP literals. Returns "" if
 * the token is not a network destination.
 */
function bareHost(tok) {
  let m = BARE_HOST_RE.exec(tok);
  if (m) return m[1].toLowerCase();
  m = BARE_IPV6_RE.exec(tok);
  if (m) return m[1].toLowerCase();
  // Decode obfuscated literals BEFORE the plain-quad check, so a dotted-octal
  // form like "010.010.010.010" is canonicalized rather than taken verbatim.
  const decoded = decodeEncodedIp(tok);
  if (decoded) return decoded;
  m = BARE_IPV4_RE.exec(tok);
  if (m) return m[1];
  return "";
}

/**
 * Best-effort, single-pass shell variable expansion. Parses `VAR=value` and
 * `export VAR=value` assignments out of the command string, then substitutes
 * `$VAR` / `${VAR}` references so a destination stashed in a variable
 * (`U=https://evil.com; curl $U`) is still seen by host extraction. This is a
 * textual approximation, not a shell: it does not evaluate command substitution
 * or arithmetic, and only resolves variables assigned literally in the same
 * command string.
 */
function expandShellVars(command) {
  const vars = new Map();
  const assignRe =
    /(?:^|[\s;&|(]|export\s+)([A-Za-z_][A-Za-z0-9_]*)=([^\s;&|()`]+)/g;
  let m;
  while ((m = assignRe.exec(command)) !== null) {
    vars.set(m[1], m[2].replace(/^['"]|['"]$/g, ""));
  }
  if (vars.size === 0) return command;
  return command.replace(
    /\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g,
    (full, braced, bare) => {
      const name = braced ?? bare;
      return vars.has(name) ? vars.get(name) : full;
    }
  );
}

/**
 * Extract candidate destination hosts from a shell command string.
 *
 * Pipeline:
 *   0. Expand simple `VAR=value` / `export VAR=value` assignments referenced as
 *      `$VAR` / `${VAR}` so a variable-stashed destination is still seen.
 *   1. Any explicit `scheme://host/...` URL anywhere in the command.
 *   2. Bare host / IP arguments to a known network tool (`curl example.com`,
 *      `curl 1.2.3.4`, `nc 1.2.3.4 443`), including obfuscated decimal/hex/octal
 *      IP literals (`curl 2130706433`, `curl 0x7f000001`).
 *
 * This is a best-effort static scan, not a full shell: it cannot resolve a host
 * computed by command substitution (`curl $(...)`) or assembled by a piped
 * decoder (`... | base64 -d | sh`) without executing the command. It
 * deliberately errs toward extracting a host (so the egress allowlist gets a
 * chance to deny it) rather than missing one. See the README "Limitations".
 *
 * @param {string} command
 * @returns {string[]} lowercased hostnames (deduped)
 */
export function extractHostsFromCommand(command) {
  if (typeof command !== "string" || !command) return [];
  const hosts = new Set();

  // 0. Resolve literal shell-variable assignments before scanning.
  const expanded = expandShellVars(command);

  // 1. Explicit URLs with a scheme (http://, https://, ftp://, ...). The `;`
  //    shell separator is excluded so a `... ; next` command doesn't glue a
  //    stray ";" onto the extracted host.
  const urlRe = /\b[a-z][a-z0-9+.-]*:\/\/[^\s'"`)<>|;]+/gi;
  let m;
  while ((m = urlRe.exec(expanded)) !== null) {
    const h = hostFromUrl(m[0]);
    if (h) hosts.add(h);
  }

  // 2. Bare hosts passed as arguments to a network tool.
  if (NETWORK_TOOL_RE.test(expanded)) {
    for (const rawTok of expanded.split(/[\s;&|()`]+/)) {
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

/**
 * Secret-hygiene guard.
 *
 * House rule: a PreToolUse-style guard that BLOCKS writing secret / password
 * literals into files. It inspects the content of a Write/Edit tool call and
 * denies the write if it looks like a real credential is being committed.
 *
 * Detection is heuristic and deliberately conservative about what counts as a
 * "placeholder" (env refs, ${...}, <...>, x's, the literal words placeholder /
 * example / changeme) so legitimate config templates with `API_KEY=` lines
 * aren't blocked.
 */

// Patterns that strongly indicate a literal secret value.
const SECRET_PATTERNS = [
  // Common provider key prefixes followed by a long token.
  { name: "openai/anthropic key", re: /\bsk-[A-Za-z0-9_-]{16,}\b/ },
  { name: "stripe live key", re: /\b(sk|rk)_live_[A-Za-z0-9]{16,}\b/ },
  { name: "stripe test key", re: /\b(sk|rk)_test_[A-Za-z0-9]{16,}\b/ },
  { name: "github token", re: /\bgh[posru]_[A-Za-z0-9]{20,}\b/ },
  { name: "aws access key id", re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: "google api key", re: /\bAIza[0-9A-Za-z_-]{30,}\b/ },
  { name: "slack token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: "private key block", re: /-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { name: "jwt", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
];

// Assignment of a secret-ish key to a non-placeholder literal value.
const ASSIGNMENT_RE =
  /\b([A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|API[_-]?KEY|TOKEN|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|CLIENT[_-]?SECRET)[A-Z0-9_]*)\s*[:=]\s*['"]?([^\s'"#]+)/gi;

// Values that are clearly placeholders, not real secrets.
const PLACEHOLDER_RE =
  /^(?:\$\{?[A-Z0-9_]+\}?|<[^>]+>|x+|\*+|changeme|placeholder|example|your[_-].*|todo|none|null|undefined|""|''|)$/i;

function isPlaceholder(value) {
  if (!value) return true;
  if (PLACEHOLDER_RE.test(value)) return true;
  if (value.includes("${") || value.includes("process.env")) return true;
  // Very short values are unlikely to be real secrets.
  if (value.length < 8) return true;
  return false;
}

/**
 * Extract the text content a tool call is trying to write.
 */
export function extractWriteContent(call) {
  const args = call?.args ?? {};
  const parts = [];
  if (typeof args.content === "string") parts.push(args.content);
  if (typeof args.file_text === "string") parts.push(args.file_text);
  if (typeof args.new_string === "string") parts.push(args.new_string);
  return parts.join("\n");
}

/**
 * Scan a string for secret literals.
 *
 * @returns {{ blocked: boolean, findings: Array<{type:string, where:string}> }}
 */
export function scanForSecrets(text) {
  const findings = [];
  if (typeof text !== "string" || !text) {
    return { blocked: false, findings };
  }

  for (const { name, re } of SECRET_PATTERNS) {
    if (re.test(text)) findings.push({ type: name, where: "pattern" });
  }

  let m;
  ASSIGNMENT_RE.lastIndex = 0;
  while ((m = ASSIGNMENT_RE.exec(text)) !== null) {
    const key = m[1];
    const value = m[2];
    if (!isPlaceholder(value)) {
      findings.push({ type: `assignment to ${key}`, where: "assignment" });
    }
  }

  return { blocked: findings.length > 0, findings };
}

/**
 * Decide whether a tool call should be blocked for committing a secret.
 *
 * @param {{tool:string, args?:object}} call
 * @returns {{ blocked: boolean, reason: string, findings: Array }}
 */
export function checkCall(call) {
  const tool = String(call?.tool ?? "").toLowerCase();
  const isWrite =
    tool === "write" ||
    tool === "edit" ||
    tool === "multiedit" ||
    "content" in (call?.args ?? {}) ||
    "file_text" in (call?.args ?? {}) ||
    "new_string" in (call?.args ?? {});

  if (!isWrite) {
    return { blocked: false, reason: "", findings: [] };
  }

  const content = extractWriteContent(call);
  const { blocked, findings } = scanForSecrets(content);

  if (!blocked) {
    return { blocked: false, reason: "", findings: [] };
  }

  // Never echo the secret value itself: report only the type.
  const types = [...new Set(findings.map((f) => f.type))].join(", ");
  return {
    blocked: true,
    reason: `refusing to write a literal secret to a file (${types}). Use an env var or placeholder instead.`,
    findings,
  };
}

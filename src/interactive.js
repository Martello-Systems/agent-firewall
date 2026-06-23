/**
 * Interactive ask/hold flow.
 *
 * When the policy returns `ask`, the call is HELD: the user is shown the
 * side-effect summary and resolves it with a single keypress —
 *
 *   a / y  -> allow once
 *   d / n  -> deny
 *   p      -> allow AND persist a rule so this kind of call is auto-allowed next time
 *
 * The decision layer is fully injectable: pass a `prompt` (returns the chosen
 * key) and a `write` (renders the summary) so tests can drive it without a TTY.
 * `bin/` wires the real stdin/stdout in raw mode.
 */

import pc from "picocolors";

/** Map a raw keypress to a resolution, or null if unrecognized. */
export function keyToResolution(key) {
  const k = String(key ?? "").trim().toLowerCase();
  if (k === "a" || k === "y") return "allow";
  if (k === "d" || k === "n") return "deny";
  if (k === "p") return "persist-allow";
  return null;
}

/**
 * Build a persist rule that would auto-allow a future call of the same shape.
 * Scopes the rule to the exact tool (and the command/file_path arg when present)
 * so persisting "allow this" doesn't blanket-allow an entire tool.
 *
 * @param {{tool:string, args?:object}} call
 * @returns {object} a policy rule
 */
export function buildPersistRule(call) {
  const tool = call?.tool || "*";
  const args = call?.args ?? {};
  const rule = {
    action: "allow",
    tool,
    description: `persisted via interactive approval (${new Date().toISOString().slice(0, 10)})`,
  };
  // Anchor to a stable identifying arg if we have one, using exact-equality so
  // the rule is narrow rather than a substring that could over-match.
  if (typeof args.command === "string" && args.command) {
    rule.match = { command: { equals: args.command } };
  } else if (typeof args.file_path === "string" && args.file_path) {
    rule.match = { file_path: { equals: args.file_path } };
  } else if (typeof args.url === "string" && args.url) {
    rule.match = { url: { equals: args.url } };
  }
  return rule;
}

/**
 * Render a held call's summary for the user.
 *
 * @param {object} result the engine result ({ summary, reason, call })
 * @param {(s:string)=>void} write
 * @param {{color?:boolean}} [opts]
 */
export function renderHold(result, write, opts = {}) {
  const color = opts.color !== false;
  const tag = (s) => (color ? pc.yellow(s) : s);
  const dim = (s) => (color ? pc.dim(s) : s);
  const bold = (s) => (color ? pc.bold(s) : s);

  write("\n" + tag("● ASK") + "  " + dim(result.reason) + "\n\n");
  if (result.summary) {
    write(bold(result.summary.title) + "\n");
    write(result.summary.detail + "\n");
  }
  write(
    "\n" +
      dim("[a]llow once   [d]eny   [p]ersist allow rule") +
      "  " +
      tag("?") +
      " "
  );
}

/**
 * Resolve a single held (`ask`) call interactively.
 *
 * @param {object} result engine result for the held call
 * @param {object} io
 * @param {() => Promise<string>} io.prompt resolves to a single keypress
 * @param {(s:string)=>void} io.write renders output
 * @param {object} [opts]
 * @param {boolean} [opts.color]
 * @param {number} [opts.maxAttempts=3] invalid-key retries before defaulting to deny
 * @returns {Promise<{ decision:"allow"|"deny", persist:boolean, rule?:object }>}
 */
export async function resolveHold(result, io, opts = {}) {
  const maxAttempts = opts.maxAttempts ?? 3;
  renderHold(result, io.write, opts);

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const key = await io.prompt();
    const resolution = keyToResolution(key);
    if (resolution === "allow") {
      io.write("\n");
      return { decision: "allow", persist: false };
    }
    if (resolution === "deny") {
      io.write("\n");
      return { decision: "deny", persist: false };
    }
    if (resolution === "persist-allow") {
      io.write("\n");
      return {
        decision: "allow",
        persist: true,
        rule: buildPersistRule(result.call),
      };
    }
    if (attempt < maxAttempts - 1) {
      io.write(
        "\n" +
          (opts.color !== false
            ? pc.dim("unrecognized key — press a, d, or p: ")
            : "unrecognized key — press a, d, or p: ")
      );
    }
  }
  // Fail safe: too many invalid keypresses -> deny.
  io.write("\n");
  return { decision: "deny", persist: false };
}

/**
 * Read a single keypress from a raw-mode stdin. Returns a function suitable as
 * `io.prompt`. Used by the CLI; tests inject their own prompt instead.
 *
 * @param {NodeJS.ReadStream} [stdin=process.stdin]
 * @returns {() => Promise<string>}
 */
export function makeKeypressPrompt(stdin = process.stdin) {
  return () =>
    new Promise((resolve) => {
      const wasRaw = stdin.isRaw;
      if (stdin.isTTY && typeof stdin.setRawMode === "function") {
        stdin.setRawMode(true);
      }
      stdin.resume();
      const onData = (chunk) => {
        const s = chunk.toString("utf8");
        // Treat Ctrl-C as deny rather than killing the agent abruptly.
        const key = s === "" ? "d" : s;
        stdin.removeListener("data", onData);
        if (stdin.isTTY && typeof stdin.setRawMode === "function") {
          stdin.setRawMode(Boolean(wasRaw));
        }
        stdin.pause();
        resolve(key);
      };
      stdin.on("data", onData);
    });
}

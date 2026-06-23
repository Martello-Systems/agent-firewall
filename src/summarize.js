/**
 * Side-effect summarizer.
 *
 * Given a normalized tool call { tool, args }, produce a human-readable
 * description of the side effect it would have on the real world:
 *
 *   - file write  -> unified diff of new content vs current file on disk
 *   - shell       -> the command (+ cwd if present)
 *   - HTTP        -> method + url + truncated body
 *   - generic     -> pretty-printed args
 *
 * The summarizer is "dry-run": it READS the current file from disk to build a
 * diff but never writes anything.
 */

import { readFileSync, existsSync } from "node:fs";
import { createTwoFilesPatch } from "diff";

const MAX_BODY = 2000;

/**
 * Categorize a tool call into a side-effect kind.
 * Recognizes Claude Code tool names plus common generic shapes.
 */
const READ_ONLY_TOOLS = new Set(["read", "glob", "grep", "ls", "list_files"]);
const WRITE_TOOLS = new Set([
  "write",
  "edit",
  "multiedit",
  "create_file",
  "str_replace_editor",
]);

export function classify(call) {
  const tool = String(call?.tool ?? "").toLowerCase();
  const args = call?.args ?? {};

  // Read-only tools have no real-world side effect worth diffing.
  if (READ_ONLY_TOOLS.has(tool)) return "generic";

  // File writes / edits: a known write tool, OR a path arg paired with content.
  const hasPath = "file_path" in args || "filePath" in args;
  const hasContent =
    "content" in args ||
    "file_text" in args ||
    "new_string" in args ||
    "old_string" in args;
  if (WRITE_TOOLS.has(tool) || (hasPath && hasContent)) {
    return "file";
  }

  // Shell.
  if (tool === "bash" || tool === "shell" || tool === "exec" || "command" in args) {
    return "shell";
  }

  // HTTP.
  if (
    tool === "webfetch" ||
    tool === "fetch" ||
    tool === "http" ||
    tool === "httprequest" ||
    "url" in args
  ) {
    return "http";
  }

  return "generic";
}

function truncate(str, max = MAX_BODY) {
  if (str == null) return "";
  const s = typeof str === "string" ? str : JSON.stringify(str);
  if (s.length <= max) return s;
  return s.slice(0, max) + `\n… [truncated ${s.length - max} chars]`;
}

/**
 * Build a unified diff for a file write/edit.
 *
 * Handles two shapes:
 *   - full content replacement: { file_path, content | file_text }
 *   - string edit:              { file_path, old_string, new_string }
 *
 * @param {object} args
 * @param {(p: string) => string | null} [readFile] injectable file reader (for tests)
 */
export function fileDiff(args, readFile) {
  const filePath = args.file_path ?? args.filePath ?? "(unknown path)";

  const read =
    readFile ||
    ((p) => {
      try {
        if (!existsSync(p)) return null;
        return readFileSync(p, "utf8");
      } catch {
        return null;
      }
    });

  const current = read(filePath);
  const oldText = current == null ? "" : current;

  let newText;
  if (args.content !== undefined) {
    newText = String(args.content);
  } else if (args.file_text !== undefined) {
    newText = String(args.file_text);
  } else if (args.new_string !== undefined) {
    // Edit: apply the old->new substitution to the current content.
    const oldStr = String(args.old_string ?? "");
    const newStr = String(args.new_string ?? "");
    if (current != null && oldStr && current.includes(oldStr)) {
      newText = args.replace_all
        ? current.split(oldStr).join(newStr)
        : current.replace(oldStr, newStr);
    } else {
      // Can't anchor the edit; show the intended replacement directly.
      newText = newStr;
    }
  } else {
    newText = "";
  }

  const label = current == null ? `${filePath} (new file)` : filePath;
  const patch = createTwoFilesPatch(
    label,
    label,
    oldText,
    newText,
    current == null ? "(absent)" : "current",
    "proposed"
  );
  return patch;
}

/**
 * Produce a structured summary of a tool call's side effect.
 *
 * @param {{tool: string, args?: object}} call
 * @param {{readFile?: (p:string)=>string|null}} [opts] injectable file reader
 * @returns {{ kind: string, title: string, detail: string }}
 */
export function summarize(call, opts = {}) {
  const tool = call?.tool ?? "(unknown tool)";
  const args = call?.args ?? {};
  const kind = classify(call);

  if (kind === "file") {
    const filePath = args.file_path ?? args.filePath ?? "(unknown path)";
    const detail = fileDiff(args, opts.readFile);
    return {
      kind,
      title: `File write: ${filePath}`,
      detail,
    };
  }

  if (kind === "shell") {
    const cmd = args.command ?? args.cmd ?? "";
    const cwd = args.cwd ? ` (cwd: ${args.cwd})` : "";
    return {
      kind,
      title: `Shell command${cwd}`,
      detail: String(cmd),
    };
  }

  if (kind === "http") {
    const method = String(args.method ?? "GET").toUpperCase();
    const url = args.url ?? "(no url)";
    const bodyRaw =
      args.body ?? args.data ?? args.json ?? args.prompt ?? undefined;
    const lines = [`${method} ${url}`];
    if (bodyRaw !== undefined) {
      lines.push("");
      lines.push("Body:");
      lines.push(truncate(bodyRaw));
    }
    return {
      kind,
      title: `HTTP request: ${method} ${url}`,
      detail: lines.join("\n"),
    };
  }

  // Generic.
  let pretty;
  try {
    pretty = JSON.stringify(args, null, 2);
  } catch {
    pretty = String(args);
  }
  return {
    kind,
    title: `Tool call: ${tool}`,
    detail: truncate(pretty),
  };
}

/**
 * Flatten a summary into a single string (used for audit storage / display).
 */
export function summaryToString(summary) {
  if (!summary) return "";
  return `${summary.title}\n${summary.detail}`.trim();
}

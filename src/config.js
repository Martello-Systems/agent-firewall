/**
 * Config loading.
 *
 * Reads `firewall.config.json` (or a path from --config / AGENT_FIREWALL_CONFIG).
 * Shape:
 *   {
 *     "policy": { "default": "ask", "rules": [ ... ] },
 *     "audit":  { "db": "./.agent-firewall/audit.sqlite" }
 *   }
 *
 * If no config file is found, a safe built-in default is used: everything is
 * "ask" except obviously-read-only tools, which are allowed.
 */

import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { validatePolicy } from "./policy.js";

export const DEFAULT_CONFIG = Object.freeze({
  policy: {
    default: "ask",
    rules: [
      {
        action: "allow",
        tool: ["Read", "Glob", "Grep", "LS"],
        description: "read-only tools are always allowed",
      },
      {
        action: "deny",
        tool: "Bash",
        match: { command: "regex:rm\\s+-rf\\s+/" },
        description: "block rm -rf on absolute roots",
      },
      {
        action: "deny",
        tool: ["Write", "Edit", "MultiEdit"],
        match: { file_path: "glob:**/.env" },
        description: "never write to .env files",
      },
    ],
  },
  audit: {
    db: ".agent-firewall/audit.sqlite",
  },
});

const CONFIG_FILENAMES = ["firewall.config.json", ".firewall.config.json"];

/**
 * Find a config file path, or null if none exists.
 */
export function findConfigPath(explicitPath, cwd = process.cwd()) {
  if (explicitPath) return resolve(cwd, explicitPath);
  const envPath = process.env.AGENT_FIREWALL_CONFIG;
  if (envPath) return resolve(cwd, envPath);
  for (const name of CONFIG_FILENAMES) {
    const p = resolve(cwd, name);
    if (existsSync(p)) return p;
  }
  return null;
}

/**
 * Load config. Falls back to DEFAULT_CONFIG when no file is present.
 *
 * @returns {{ config: object, path: string|null, problems: string[] }}
 */
export function loadConfig(explicitPath, cwd = process.cwd()) {
  const path = findConfigPath(explicitPath, cwd);
  if (!path || !existsSync(path)) {
    return { config: structuredClone(DEFAULT_CONFIG), path: null, problems: [] };
  }

  let raw;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    return {
      config: structuredClone(DEFAULT_CONFIG),
      path,
      problems: [`failed to parse ${path}: ${err.message}`],
    };
  }

  const policy = raw.policy ?? DEFAULT_CONFIG.policy;
  const problems = validatePolicy(policy);

  const config = {
    policy,
    audit: {
      db: raw.audit?.db ?? DEFAULT_CONFIG.audit.db,
    },
  };

  return { config, path, problems };
}

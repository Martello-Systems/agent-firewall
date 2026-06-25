#!/usr/bin/env node
/**
 * agent-firewall CLI.
 *
 *   agent-firewall hook              read a Claude Code PreToolUse event on stdin,
 *                                    print the permission decision JSON on stdout
 *   agent-firewall check <file>      evaluate a tool call JSON file against policy
 *   agent-firewall log               show the audit log
 *   agent-firewall mcp -- <cmd...>   run as an MCP stdio proxy in front of <cmd>
 */

import { readFileSync } from "node:fs";
import { resolve as resolvePath } from "node:path";
import { Command } from "commander";
import pc from "picocolors";
import { loadConfig, findConfigPath, persistRule } from "../src/config.js";
import { AuditLog } from "../src/audit.js";
import { processCall } from "../src/engine.js";
import { redactSecretsInArgs } from "../src/secret-guard.js";
import { handlePreToolUse } from "../src/hook-adapter.js";
import { createStdioProxy } from "../src/mcp-proxy.js";
import { resolveHold, makeKeypressPrompt } from "../src/interactive.js";

const program = new Command();

program
  .name("agent-firewall")
  .description(
    "A dry-run firewall for coding agents: intercept tool calls, apply an allow/deny/ask policy, and audit."
  )
  .option("-c, --config <path>", "path to firewall.config.json");

function getAudit(config) {
  try {
    return new AuditLog(config.audit?.db);
  } catch {
    return null;
  }
}

function decisionColor(decision, text) {
  if (decision === "allow") return pc.green(text);
  if (decision === "deny") return pc.red(text);
  return pc.yellow(text);
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

// ---- hook --------------------------------------------------------------
program
  .command("hook")
  .description("Claude Code PreToolUse hook: stdin event JSON -> stdout decision JSON")
  .action(async () => {
    const { config, problems } = loadConfig(program.opts().config);
    if (problems.length) {
      for (const p of problems) process.stderr.write(`[agent-firewall] config: ${p}\n`);
    }
    let event;
    try {
      const raw = await readStdin();
      event = JSON.parse(raw || "{}");
    } catch (err) {
      // Fail open to "ask" so we never hard-crash the agent on bad input.
      process.stdout.write(
        JSON.stringify({
          hookSpecificOutput: {
            hookEventName: "PreToolUse",
            permissionDecision: "ask",
            permissionDecisionReason: `[agent-firewall] could not parse hook input: ${err.message}`,
          },
        })
      );
      process.exit(0);
    }

    const audit = getAudit(config);
    const { output } = handlePreToolUse(event, config.policy, { audit });
    if (audit) audit.close();
    process.stdout.write(JSON.stringify(output));
    process.exit(0);
  });

// ---- check -------------------------------------------------------------
program
  .command("check <file>")
  .description("Evaluate a tool-call JSON file ({tool, args} or a PreToolUse event) against the policy")
  .option("--json", "output the raw decision as JSON")
  .option("-i, --interactive", "on an 'ask' decision, prompt for one-key allow/deny/persist")
  .action(async (file, cmdOpts) => {
    const { config, problems } = loadConfig(program.opts().config);
    for (const p of problems) process.stderr.write(`[agent-firewall] config: ${p}\n`);

    let parsed;
    try {
      parsed = JSON.parse(readFileSync(file, "utf8"));
    } catch (err) {
      process.stderr.write(`[agent-firewall] cannot read ${file}: ${err.message}\n`);
      process.exit(1);
    }

    // Accept either {tool, args} or a Claude Code PreToolUse event.
    const call =
      parsed.tool || parsed.args
        ? { tool: parsed.tool, args: parsed.args ?? {} }
        : { tool: parsed.tool_name ?? "", args: parsed.tool_input ?? {} };

    const audit = getAudit(config);
    const result = processCall(call, config.policy, { source: "check", audit });

    if (cmdOpts.json) {
      if (audit) audit.close();
      process.stdout.write(
        JSON.stringify(
          {
            decision: result.decision,
            reason: result.reason,
            ruleIndex: result.ruleIndex,
            summary: result.summary,
          },
          null,
          2
        ) + "\n"
      );
      process.exit(result.decision === "allow" ? 0 : result.decision === "deny" ? 2 : 1);
    }

    // Interactive resolution of an `ask` decision.
    if (cmdOpts.interactive && result.decision === "ask") {
      const io = {
        prompt: makeKeypressPrompt(process.stdin),
        write: (s) => process.stdout.write(s),
      };
      const outcome = await resolveHold(result, io, { color: process.stdout.isTTY });
      if (outcome.persist && outcome.rule) {
        const target =
          findConfigPath(program.opts().config) ||
          resolvePath(process.cwd(), "firewall.config.json");
        try {
          persistRule(outcome.rule, target);
          process.stdout.write(pc.dim(`persisted allow rule to ${target}\n`));
        } catch (err) {
          process.stderr.write(`[agent-firewall] ${err.message}\n`);
        }
      }
      if (audit) {
        audit.record({
          source: "check-interactive",
          tool: call.tool,
          decision: outcome.decision,
          kind: result.summary.kind,
          summary: result.summaryText,
          reason: outcome.persist ? "user: persist-allow" : `user: ${outcome.decision}`,
          ruleIndex: -1,
          args: redactSecretsInArgs(call.args),
        });
        audit.close();
      }
      process.exit(outcome.decision === "allow" ? 0 : 2);
    }

    if (audit) audit.close();
    process.stdout.write(
      decisionColor(result.decision, `● ${result.decision.toUpperCase()}`) +
        `  ${pc.dim(result.reason)}\n\n`
    );
    process.stdout.write(pc.bold(result.summary.title) + "\n");
    process.stdout.write(result.summary.detail + "\n");
    // Exit code mirrors the decision: 0 allow, 1 ask, 2 deny.
    process.exit(result.decision === "allow" ? 0 : result.decision === "deny" ? 2 : 1);
  });

// ---- log ---------------------------------------------------------------
program
  .command("log")
  .alias("list")
  .description("Show the audit log (most recent first)")
  .option("-n, --limit <n>", "max rows", "20")
  .option("-d, --decision <decision>", "filter by decision (allow|deny|ask)")
  .option("-t, --tool <tool>", "filter by tool name")
  .option("--json", "output raw JSON")
  .action((cmdOpts) => {
    const { config } = loadConfig(program.opts().config);
    const audit = getAudit(config);
    if (!audit) {
      process.stderr.write("[agent-firewall] no audit db available\n");
      process.exit(1);
    }
    const rows = audit.list({
      limit: parseInt(cmdOpts.limit, 10) || 20,
      decision: cmdOpts.decision,
      tool: cmdOpts.tool,
    });
    if (cmdOpts.json) {
      process.stdout.write(JSON.stringify(rows, null, 2) + "\n");
      audit.close();
      return;
    }
    if (!rows.length) {
      process.stdout.write(pc.dim("(audit log is empty)\n"));
      audit.close();
      return;
    }
    for (const r of rows) {
      const tag = decisionColor(r.decision, r.decision.toUpperCase().padEnd(5));
      const title = (r.summary || "").split("\n")[0];
      process.stdout.write(
        `${pc.dim(r.ts)}  ${tag}  ${pc.bold(r.tool)}  ${title}\n`
      );
    }
    process.stdout.write(
      pc.dim(`\n${rows.length} of ${audit.count()} record(s)\n`)
    );
    audit.close();
  });

// ---- mcp ---------------------------------------------------------------
program
  .command("mcp")
  .description("Run as an MCP stdio proxy in front of a downstream JSON-RPC server")
  .argument("<command...>", "downstream MCP server command and args")
  .option(
    "--allow-holds",
    "let 'ask' decisions through instead of denying them (no interactive prompt over stdio)"
  )
  .action((commandParts, cmdOpts) => {
    const { config, problems } = loadConfig(program.opts().config);
    for (const p of problems) process.stderr.write(`[agent-firewall] config: ${p}\n`);
    const audit = getAudit(config);
    process.stderr.write(
      pc.dim(
        `[agent-firewall] MCP proxy active, gating tools/call for: ${commandParts.join(" ")}\n`
      )
    );
    try {
      const child = createStdioProxy({
        command: commandParts,
        policy: config.policy,
        audit,
        holdPolicy: cmdOpts.allowHolds ? "allow-holds" : "deny-holds",
        onExit: (code) => {
          if (audit) audit.close();
          process.exit(code ?? 0);
        },
      });
      // Keep the parent alive while the proxy runs.
      child.on("close", () => {});
    } catch (err) {
      if (audit) audit.close();
      process.stderr.write(`[agent-firewall] ${err.message}\n`);
      process.exit(1);
    }
  });

program.parseAsync(process.argv);

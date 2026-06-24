# agent-firewall

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE) [![Built by Martello Systems](https://img.shields.io/badge/built%20by-Martello%20Systems-0b0b14)](https://martellosystems.com)

**A dry-run firewall for coding agents.**

Coding agents (Claude Code, MCP servers, autonomous tool-callers) execute
real-world side effects — they write files, run shell commands, and make HTTP
requests. `agent-firewall` sits **in front of** those calls. Before a tool call
touches the real world it:

1. **Summarizes the side effect** — a unified diff for file writes, the exact
   command for shell, method + URL + body for HTTP.
2. **Applies an allow / deny / ask policy** — ordered rules matched on tool name
   and arg patterns (glob / regex / substring), first-match-wins.
3. **Audits the decision** — every call is appended to a replayable SQLite log.

It is intentionally small, dependency-light, and thoroughly tested (101 tests,
including a live end-to-end MCP-proxy test that spawns a real downstream server).

```
  tool call ──▶ [ policy engine ] ──▶ allow / deny / ask
                       │                          │
                       ├─▶ [ summarizer ]         └─▶ (ask) interactive hold
                       │   (diff / cmd / http)         a/d/persist-rule
                       └─▶ [ audit log ]   (sqlite, queryable)
```

Two ways to put it in front of an agent:

- **Claude Code `PreToolUse` hook** — gates every Claude Code tool call.
- **MCP stdio proxy** — sits in front of any MCP server and gates `tools/call`.

> **Demo:** _(GIF placeholder — record a `check`/`hook`/`mcp` walkthrough before launch.)_

---

## Install

```bash
npm install            # from a clone
# or, once published:
# npm install -g agent-firewall
```

Requires **Node 18+**. ESM-only.

---

## Wire it into Claude Code as a PreToolUse hook

`agent-firewall hook` reads a Claude Code `PreToolUse` event on **stdin** and
prints the permission decision JSON Claude Code expects on **stdout**. Add it to
your Claude Code settings (`~/.claude/settings.json` or a project
`.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "node /absolute/path/to/agent-firewall/bin/agent-firewall.js --config /absolute/path/to/firewall.config.json hook"
          }
        ]
      }
    ]
  }
}
```

The hook emits, for example:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "[agent-firewall] DENY: block rm -rf on absolute roots"
  }
}
```

### The hook I/O contract we implement against

Verified against the official Claude Code hooks docs
(<https://code.claude.com/docs/en/hooks.md>, confirmed 2026-06-23):

- **stdin** — Claude Code writes a JSON event: `{ session_id, transcript_path,
  cwd, permission_mode, hook_event_name: "PreToolUse", tool_name, tool_input }`.
- **stdout (exit 0)** — for `PreToolUse` the decision lives under
  `hookSpecificOutput` (camelCase), **not** a top-level `decision` field:
  `permissionDecision` ∈ `allow | deny | ask`, with `permissionDecisionReason`
  (**required** when the decision is `deny`).
- **Exit codes** — on exit `0` the stdout JSON is honored; on exit `2` the JSON
  is *ignored* and stderr is fed back as a blocking error. We therefore
  **always exit 0** and express the decision purely via `permissionDecision`.

`permissionDecision` is mapped directly from your policy. On unparseable input
the hook fails open to `ask` so it never hard-crashes the agent.

---

## Wire it in front of an MCP server (stdio proxy)

`agent-firewall mcp -- <server> [args...]` spawns a downstream MCP server and
proxies the newline-delimited JSON-RPC stdio stream between your MCP client and
that server. Every message is forwarded **verbatim** except `tools/call`
requests, which run through the same policy engine:

- **allow** → forwarded to the server, which executes it normally.
- **deny** → blocked at the proxy; the client gets a JSON-RPC error
  (`code -32001`) and the server never sees the call.
- **ask** → held; by default denied back to the client (`--allow-holds` lets
  held calls through instead).

```bash
# Instead of pointing your MCP client at:   node ./my-mcp-server.js
# point it at:
agent-firewall mcp -- node ./my-mcp-server.js
```

Frame boundaries are handled correctly — messages split across stream chunks are
reassembled, multiple messages per chunk are split, and non-JSON lines pass
through untouched so the protocol stream is never corrupted.

---

## Policy: `firewall.config.json`

The firewall looks for `firewall.config.json` in the working directory (override
with `--config <path>` or the `AGENT_FIREWALL_CONFIG` env var). If none is found
a safe built-in default is used (read-only tools allowed; `rm -rf /` and `.env`
writes denied; everything else `ask`).

```json
{
  "policy": {
    "default": "ask",
    "rules": [
      {
        "action": "allow",
        "tool": ["Read", "Glob", "Grep", "LS"],
        "description": "read-only tools are always allowed"
      },
      {
        "action": "deny",
        "tool": "Bash",
        "match": { "command": "regex:rm\\s+-rf\\s+/" },
        "description": "block rm -rf on absolute roots"
      },
      {
        "action": "deny",
        "tool": ["Write", "Edit", "MultiEdit"],
        "match": { "file_path": "glob:**/.env" },
        "description": "never write to .env files"
      },
      {
        "action": "ask",
        "tool": ["Write", "Edit", "MultiEdit"],
        "description": "review all other file writes"
      }
    ]
  },
  "audit": { "db": ".agent-firewall/audit.sqlite" }
}
```

### Rule semantics

- **Ordered, first-match-wins.** Put specific denies above broad allows.
- **`action`** (required): `allow` | `deny` | `ask`.
- **`tool`** (optional): a name, an array of names, or `"*"` (default).
  Case-insensitive.
- **`match`** (optional): an object of `argPath → matcher`. **All** entries must
  match. Arg paths support dotted access (`"options.danger"`).
- **`default`** (optional, top-level): the action when no rule matches. Defaults
  to `ask`.

### Matchers

| Form | Meaning |
|---|---|
| `"glob:**/.env"` | glob against the stringified arg value (`*` stays within a path segment, `**` crosses them) |
| `"regex:rm\\s+-rf"` | regular expression, case-insensitive by default |
| `"equals:exact"` | strict equality |
| `"sudo"` (bare string) | case-insensitive substring containment |
| `{ "glob": "..." }` / `{ "regex": "...", "flags": "i" }` / `{ "equals": "..." }` / `{ "contains": "..." }` | explicit object forms |

---

## CLI

```bash
# Claude Code PreToolUse hook (stdin event JSON -> stdout decision JSON)
agent-firewall hook

# Evaluate a single tool call against the policy (dry run)
agent-firewall check call.json              # human-readable + diff
agent-firewall check call.json --json       # machine-readable decision
agent-firewall check call.json --interactive # on 'ask', prompt a/d/persist
#   call.json may be {"tool":"Write","args":{...}}  OR a PreToolUse event
#   exit code: 0 = allow, 1 = ask, 2 = deny

# Inspect the audit log (most recent first)
agent-firewall log
agent-firewall log -n 50 --decision deny --tool Bash
agent-firewall log --json

# MCP stdio proxy in front of any MCP server
agent-firewall mcp -- node ./some-mcp-server.js
agent-firewall mcp --allow-holds -- node ./some-mcp-server.js
```

### Interactive `ask` flow

When a decision is `ask`, `--interactive` holds the call, prints the side-effect
summary, and waits for a single keypress:

```
● ASK  no rule matched — default action "ask"

File write: /proj/server.js
--- /proj/server.js	current
+++ /proj/server.js	proposed
@@ ... @@
+app.listen(3000)

[a]llow once   [d]eny   [p]ersist allow rule  ?
```

- **`a`** / **`y`** — allow this one call.
- **`d`** / **`n`** — deny it.
- **`p`** — allow it **and** persist a narrow `allow` rule (scoped to the exact
  tool + command/file/url) to the top of your `firewall.config.json`, so the
  same call is auto-allowed next time.

The interactive layer takes injectable prompt/render IO, so it's fully unit
tested without a TTY.

### Example: `check`

```bash
$ echo '{"tool":"Write","args":{"file_path":"/proj/.env","content":"API_KEY=__placeholder__"}}' > call.json
$ agent-firewall check call.json
● DENY  never write to .env files

File write: /proj/.env
--- /proj/.env (new file)	(absent)
+++ /proj/.env (new file)	proposed
@@ -0,0 +1,1 @@
+API_KEY=__placeholder__
```

---

### Example: audit log

Every decision (from the hook, the proxy, or `check`) is appended to a SQLite
log you can query later:

```text
$ agent-firewall log
2026-06-23T09:32:36.665Z  ASK    Write  File write: /p/x.js
2026-06-23T09:32:36.573Z  DENY   Bash   Shell command
2026-06-23T09:32:36.465Z  ALLOW  Read   Tool call: Read

3 of 3 record(s)
```

```bash
$ agent-firewall log --json --decision deny
[
  {
    "id": 2,
    "ts": "2026-06-23T09:32:36.573Z",
    "source": "check",
    "tool": "Bash",
    "decision": "deny",
    "kind": "shell",
    "summary": "Shell command\nrm -rf /",
    "reason": "block rm -rf on absolute roots",
    "ruleIndex": 1,
    "args": { "command": "rm -rf /" }
  }
]
```

The log is backed by `better-sqlite3` with **parameterized queries throughout**
— no string-interpolated SQL — so a tool name or filter value can never inject.

---

## How it's structured

| Module | Responsibility | Tested |
|---|---|---|
| `src/policy.js` | rule evaluation, glob/regex/equals/contains matching, ordering, defaults | ✅ |
| `src/summarize.js` | side-effect summaries (file diff / shell / http / generic) | ✅ |
| `src/audit.js` | append + query the SQLite audit log | ✅ |
| `src/hook-adapter.js` | Claude Code PreToolUse event ⇄ decision JSON mapping | ✅ |
| `src/mcp-proxy.js` | MCP `tools/call` interception + live stdio proxy + framing | ✅ (incl. e2e) |
| `src/interactive.js` | interactive `ask` hold (allow / deny / persist-rule) | ✅ |
| `src/secret-guard.js` | block writes that commit literal secrets (overrides policy) | ✅ |
| `src/engine.js` | glue: policy + summarize + audit per call | ✅ (via adapters) |
| `src/config.js` | load + validate `firewall.config.json`; persist rules | ✅ |
| `bin/agent-firewall.js` | CLI | ✅ (spawned integration tests) |

Run the suite and lint:

```bash
npm test    # node --test — 101 tests, incl. a live MCP-proxy e2e
npm run lint # eslint, zero warnings
```

---

## Limitations

`agent-firewall` is a **safety net, not a sandbox.** Read these before trusting
it in front of an autonomous agent:

- It only sees the calls it's wired in front of. A code path that bypasses the
  hook/proxy (e.g. a tool the proxy doesn't gate, or a shell subprocess that
  spawns its own children) is **not** intercepted. Pair it with OS-level
  sandboxing for untrusted workloads.
- The MCP proxy gates `tools/call` only; all other JSON-RPC traffic is
  forwarded verbatim by design.
- Over stdio there is no interactive prompt for an MCP `ask` — held calls are
  denied by default (or let through with `--allow-holds`). The interactive
  allow/deny/persist flow is available via `agent-firewall check -i` and the
  Claude Code hook's native `ask` dialog.
- Side-effect summaries are best-effort: file diffs are computed by reading the
  current file from disk (a dry run), and the summarizer recognizes common tool
  shapes but won't deep-parse every conceivable arg layout.
- Secret detection is heuristic (known key prefixes + secret-named assignments
  to non-placeholder values); it is a backstop, not a guarantee.

---

## Security note

A built-in **secret guard** (`src/secret-guard.js`) runs ahead of your policy in
the Claude Code hook: any `Write`/`Edit` that would commit a literal credential
(provider key prefixes, `*_live_*` keys, private-key blocks, JWTs, or a
secret-named assignment to a non-placeholder value) is denied unconditionally,
and the denial reason never echoes the secret. Env refs (`${VAR}`),
`<placeholders>`, and `changeme`-style values are allowed through. Never commit
real secrets to `firewall.config.json` or your tool-call fixtures — use
placeholders and env vars.

---

## License

MIT © 2026 Martello Systems. See [LICENSE](./LICENSE).

---

<sub>Built by **Martello Systems** — we design and ship AI-driven software.
Part of the Martello open-source dev-tools family.</sub>

---

## Built by Martello Systems

`agent-firewall` is part of the open-source toolkit from **[Martello Systems](https://martellosystems.com)** — we ship AI-built software, spec to delivery in days. If this saved you time, come [see what we do](https://martellosystems.com).

Licensed under the [Apache License 2.0](LICENSE).

# agent-firewall

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

It is intentionally small, dependency-light, and unit-tested at the core.

```
  tool call ──▶ [ policy engine ] ──▶ allow / deny / ask
                       │
                       ├─▶ [ summarizer ]  (diff / command / http)
                       └─▶ [ audit log ]   (sqlite, queryable)
```

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

`permissionDecision` is one of `allow` | `deny` | `ask`, mapped directly from
your policy. The hook always exits 0; on unparseable input it fails open to
`ask` so it never hard-crashes the agent.

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
agent-firewall check call.json          # human-readable + diff
agent-firewall check call.json --json   # machine-readable decision
#   call.json may be {"tool":"Write","args":{...}}  OR a PreToolUse event
#   exit code: 0 = allow, 1 = ask, 2 = deny

# Inspect the audit log (most recent first)
agent-firewall log
agent-firewall log -n 50 --decision deny --tool Bash
agent-firewall log --json

# MCP stdio proxy (see roadmap)
agent-firewall mcp -- node ./some-mcp-server.js
```

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

## How it's structured

| Module | Responsibility | Tested |
|---|---|---|
| `src/policy.js` | rule evaluation, glob/regex/equals/contains matching, ordering, defaults | ✅ |
| `src/summarize.js` | side-effect summaries (file diff / shell / http / generic) | ✅ |
| `src/audit.js` | append + query the SQLite audit log | ✅ |
| `src/hook-adapter.js` | Claude Code PreToolUse event ⇄ decision JSON mapping | ✅ |
| `src/mcp-proxy.js` | MCP `tools/call` interception + decision logic | ✅ (decision logic) |
| `src/secret-guard.js` | block writes that commit literal secrets (overrides policy) | ✅ |
| `src/engine.js` | glue: policy + summarize + audit per call | ✅ (via adapters) |
| `src/config.js` | load + validate `firewall.config.json` | ✅ |
| `bin/agent-firewall.js` | CLI | smoke-tested |

Run the suite:

```bash
npm test    # node --test, all core logic covered
```

---

## MCP proxy (roadmap)

`src/mcp-proxy.js` implements and **unit-tests** the message-level interception
logic: it identifies JSON-RPC `tools/call` requests, converts them to the
normalized call shape, runs them through the same policy engine, and produces a
forward / deny (JSON-RPC error) / hold-for-approval verdict.

The thin stdio wiring (`createStdioProxy`, exposed via `agent-firewall mcp`)
spawns a downstream server and pipes both directions. The **full live MCP
handshake passthrough is experimental and not yet covered by an end-to-end
test** — treat it as a roadmap item. The decision logic it relies on is fully
tested.

Planned next:

- End-to-end live MCP handshake test against a reference server.
- Interactive approval flow for `ask`/`hold` decisions (currently `ask` holds
  are denied by default in the proxy).
- `updatedInput` rewriting (e.g. redacting args) via the Claude Code hook.

---

## Security note

A built-in **secret guard** (`src/secret-guard.js`) runs ahead of your policy in
the Claude Code hook: any `Write`/`Edit` that would commit a literal credential
(provider key prefixes, `*_live_*` keys, private-key blocks, JWTs, or a
secret-named assignment to a non-placeholder value) is denied unconditionally,
and the denial reason never echoes the secret. Env refs (`${VAR}`),
`<placeholders>`, and `changeme`-style values are allowed through.

`agent-firewall` is a **safety net, not a sandbox.** It can only see and gate
the tool calls it's wired in front of. A misconfigured policy, or a code path
that bypasses the hook/proxy, will not be caught. Pair it with OS-level
sandboxing for anything untrusted. Never commit real secrets to
`firewall.config.json` or your tool-call fixtures — use placeholders and env
vars.

---

## License

MIT © 2026 Martello Systems. See [LICENSE](./LICENSE).

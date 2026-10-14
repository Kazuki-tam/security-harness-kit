import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { readFileSync, writeFileSync } from "node:fs";
import assert from "node:assert/strict";
const DIR = process.env.SHK_CONTRACT_DIR;
const { default: plugin } = await import(
  pathToFileURL(join(DIR, ".opencode", "plugins", "shk-security.js")).href
);
// Test generated helpers without adding public exports to the installed plugin.
const source = readFileSync(join(DIR, ".opencode", "plugins", "shk-security.js"), "utf8");
const helpers = join(DIR, "contract-helpers.mjs");
writeFileSync(helpers, source + "\nexport { verdict, guard, runShk, searchDirs, CONFIG };\n");
const internals = await import(pathToFileURL(helpers).href);
const SECRET_FILE = join(DIR, "secret.txt");
const CLEAN_FILE = join(DIR, "clean.txt");
const SECRET = process.env.SHK_CONTRACT_SECRET;
const missing = process.env.SHK_CONTRACT_MISSING === "1";
const blockPattern = missing ? /not found/ : /shk security/;
// Prompt hooks fail closed too: the notice names the real reason.
const noticePattern = missing
  ? /^\[shk\] prompt blocked: .*not found/
  : /^\[shk\] prompt blocked: .*sensitive content/;
const fail = (msg) => {
  console.error("FAIL: " + msg);
  process.exit(1);
};
const rejects = async (fn, pattern) => {
  try {
    await fn();
  } catch (error) {
    if (!pattern.test(String(error?.message))) fail(`unexpected error: ${error?.message}`);
    return;
  }
  fail("expected rejection");
};

// --- V2 host ---
const v2logs = [];
const originalConsoleError = console.error;
console.error = (...args) => v2logs.push(args.join(" "));
const hooks = {};
const ctx = {
  location: { directory: DIR },
  tool: {
    hook: async (name, cb) => {
      hooks["tool." + name] = cb;
    },
  },
  session: {
    hook: async (name, cb) => {
      hooks["session." + name] = cb;
    },
  },
};
await plugin.setup(ctx);
for (const key of ["tool.execute.before", "tool.execute.after", "session.prompt"]) {
  if (typeof hooks[key] !== "function") fail(`V2 hook ${key} not registered`);
}
const call = (input) => ({
  tool: "read",
  sessionID: "s",
  agent: "build",
  messageID: "m",
  id: "c",
  input,
});
await rejects(() => hooks["tool.execute.before"](call({ filePath: SECRET_FILE })), blockPattern);
if (!missing) await hooks["tool.execute.before"](call({ filePath: CLEAN_FILE }));
// Content past the old 512 KiB plugin-side cut must still be scanned.
const bigWrite = {
  ...call({ filePath: join(DIR, "out.txt"), content: "a".repeat(600 * 1024) + "\n" + SECRET }),
  tool: "write",
};
await rejects(() => hooks["tool.execute.before"](bigWrite), blockPattern);
// An unrecognized payload shape fails closed instead of scanning an empty body.
await rejects(
  () => hooks["tool.execute.before"]({ tool: "write", sessionID: "s", id: "c" }),
  /unsupported OpenCode hook payload/,
);
await hooks["session.prompt"]({ sessionID: "s" });
await hooks["tool.execute.after"]({
  ...call({ command: "cat secret.txt" }),
  tool: "bash",
  status: "completed",
  result: { output: SECRET, content: [] },
});
if (!missing)
  assert(
    v2logs.some((line) => /finding\(s\) in tool output/.test(line)),
    "V2 post findings must be reported",
  );
const prompt = {
  sessionID: "s",
  messageID: "m",
  prompt: {
    text: "use " + SECRET,
    files: [{ uri: "https://example.com/attachment", mention: { start: 0, end: 5 } }],
    skills: ["private"],
  },
};
const ownedDraft = prompt.prompt;
await hooks["session.prompt"](prompt);
assert.equal(prompt.prompt, ownedDraft, "host references must see the scrubbed draft");
if (!noticePattern.test(prompt.prompt.text))
  fail(`V2 prompt not rewritten as expected: ${prompt.prompt.text}`);
if (prompt.prompt.text.includes(SECRET)) fail("V2 notice leaked the prompt text");
assert.deepEqual(
  Object.keys(prompt.prompt),
  ["text"],
  "denied V2 draft must discard attachments and skills",
);
const circular = {};
circular.self = circular;
const brokenPrompt = { sessionID: circular, prompt: { text: "hello" } };
await hooks["session.prompt"](brokenPrompt);
assert.match(brokenPrompt.prompt.text, /prompt blocked: shk hook could not scan the payload/);
await assert.rejects(
  () => hooks["session.prompt"]({ prompt: Object.freeze({ text: SECRET }) }),
  TypeError,
  "a draft that cannot be scrubbed must reject admission",
);
const cleanPrompt = { sessionID: "s", messageID: "m", prompt: { text: "hello" } };
await hooks["session.prompt"](cleanPrompt);
// Without a decision the clean prompt is blocked too (fail closed); with shk present it passes untouched.
if (!missing && cleanPrompt.prompt.text !== "hello") fail("clean V2 prompt was modified");
if (missing && !noticePattern.test(cleanPrompt.prompt.text))
  fail("clean V2 prompt was admitted without a decision");

// --- V1 host ---
const logs = [];
const v1 = await plugin.server({
  directory: DIR,
  worktree: DIR,
  client: {
    app: {
      log: async (entry) => {
        logs.push(entry);
      },
    },
  },
});
await rejects(
  () =>
    v1["tool.execute.before"](
      { tool: "read", sessionID: "s", callID: "c" },
      { args: { filePath: SECRET_FILE } },
    ),
  blockPattern,
);
if (!missing)
  await v1["tool.execute.before"](
    { tool: "read", sessionID: "s", callID: "c" },
    { args: { filePath: CLEAN_FILE } },
  );
await v1["tool.execute.after"](
  { tool: "bash", sessionID: "s", callID: "c", args: {} },
  { title: "cat", output: SECRET, metadata: {} },
);
await rejects(
  () => v1["tool.execute.before"]({ tool: "read", sessionID: "s", callID: "c" }, {}),
  /unsupported OpenCode hook payload/,
);
await rejects(
  () => v1["chat.message"]({ sessionID: "s" }, {}),
  /unsupported OpenCode hook payload/,
);
if (!missing)
  assert(
    logs.some((entry) => /finding\(s\) in tool output/.test(entry.body.message)),
    "V1 post findings must be reported",
  );
const parts = [
  { id: "p1", sessionID: "s", messageID: "m", type: "text", text: "use " + SECRET },
  { type: "file", url: "https://example.com/attachment" },
];
await rejects(
  () => v1["chat.message"]({ sessionID: "s" }, { message: {}, parts }),
  /prompt blocked/,
);
if (!noticePattern.test(parts[0].text) || parts[0].text.includes(SECRET))
  fail(`V1 prompt parts not scrubbed: ${parts[0].text}`);
assert.equal(parts.length, 1, "denied V1 draft must discard attachment parts");
assert.deepEqual([parts[0].id, parts[0].sessionID, parts[0].messageID], ["p1", "s", "m"]);
if (missing && !logs.some((entry) => /not found/.test(entry?.body?.message ?? "")))
  fail("V1 host was not warned about the missing binary");
// Scanner protocol failures deny pre/prompt but never block post/audit.
for (const result of [
  { kind: "timeout" },
  { kind: "missing" },
  { kind: "no-directory" },
  { kind: "spawn-error" },
  { kind: "exit", code: 0, stdout: "garbage" },
  { kind: "exit", code: 1, stdout: '{"decision":"allow"}' },
  { kind: "exit", code: null, stdout: "" },
  { kind: "exit", code: 0, stdout: '{"decision":"unknown"}' },
]) {
  assert.equal(internals.verdict(result, true).block, true);
  assert.equal(internals.verdict(result, false).block, false);
}
assert.deepEqual(
  internals.verdict({ kind: "exit", code: 0, stdout: '{"decision":"allow"}' }, true),
  { block: false, clean: true },
);
assert.equal(
  internals.verdict(
    { kind: "exit", code: 0, stdout: '{"decision":"allow","reason":"findings"}' },
    false,
  ).reason,
  "findings",
);
internals.CONFIG.audit = true;
// Audit mode annotates every allow; that alone must not produce a log line.
assert.deepEqual(
  internals.verdict(
    { kind: "exit", code: 0, stdout: '{"decision":"allow","reason":"shk audit: non-blocking"}' },
    false,
  ),
  { block: false, clean: true },
);
const auditLogs = [];
const audit = await internals.guard(
  DIR,
  "prompt",
  "UserPromptSubmit",
  { prompt: "hello", session_id: circular },
  (_level, message) => auditLogs.push(message),
);
assert.equal(audit.block, false);
assert(auditLogs.some((line) => /not blocking/.test(line)));
assert(
  !JSON.stringify([...v2logs, ...logs, ...auditLogs]).includes(SECRET),
  "logs must not contain prompt content",
);
// Exercise subprocess failures without a shell or an external executable stub:
// Node interprets the first shk argument ("scan") as this temporary script.
process.env.SHK_BIN = process.execPath;
writeFileSync(
  join(DIR, "scan"),
  'process.stdin.resume(); console.log("invalid scanner response");',
);
const invalid = await internals.runShk(DIR, "pre", "{}");
assert.equal(invalid.kind, "exit");
assert.equal(internals.verdict(invalid, true).block, true);
assert.equal(
  (await internals.runShk(join(DIR, "missing-directory"), "pre", "{}")).kind,
  "no-directory",
);
writeFileSync(join(DIR, "scan"), "process.stdin.resume(); setInterval(() => {}, 1000);");
internals.CONFIG.timeoutMs = 100;
assert.equal((await internals.runShk(DIR, "pre", "{}")).kind, "timeout");
process.env.CARGO_HOME = "relative-cargo-home";
assert(!internals.searchDirs().some((dir) => dir.startsWith("relative-cargo-home")));
console.error = originalConsoleError;
console.log("ok");

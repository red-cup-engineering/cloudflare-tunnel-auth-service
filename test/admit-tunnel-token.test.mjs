import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { admitTunnelToken, tokenPathForTestRoot, validateTunnelToken } from "../src/admit-tunnel-token.mjs";

const root = resolve(import.meta.dirname, "..");
const admission = join(root, "src", "admit-tunnel-token.mjs");
const TUNNEL_NAME = "example-561-group";

function token(secret = "connector-secret-material-0001") {
  return Buffer.from(JSON.stringify({ a: "a".repeat(32), t: "123e4567-e89b-12d3-a456-426614174000", s: secret })).toString("base64url");
}
function runAdmission(arguments_, input) {
  return new Promise((resolveRun) => {
    const environment = { ...process.env }; delete environment.NODE_TEST_CONTEXT;
    const child = spawn(process.execPath, [admission, ...arguments_], { stdio: ["pipe", "pipe", "pipe"], env: environment });
    let stdout = "", stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => { stdout += chunk; });
    child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
    child.on("close", (status, signal) => resolveRun({ status, signal, stdout, stderr }));
    child.stdin.end(`${input}\n`);
  });
}
function admit(testRoot, input, ...extra) {
  return runAdmission(["--stdin", "--safe-stdin", `--test-root=${testRoot}`, `--tunnel-name=${TUNNEL_NAME}`, ...extra], input);
}

test("admits a structurally valid token atomically to a per-tunnel path without leaking it", async () => {
  const testRoot = mkdtempSync(join(tmpdir(), "cloudflare-token-"));
  try {
    const supplied = token();
    const path = tokenPathForTestRoot(testRoot, TUNNEL_NAME);
    admitTunnelToken(supplied, path);
    const directory = join(testRoot, ".config", "cloudflared");
    assert.equal(statSync(directory).mode & 0o777, 0o700);
    assert.equal(statSync(path).mode & 0o777, 0o600);
    assert.equal(readFileSync(path, "utf8"), `${supplied}\n`);
    assert.deepEqual(readdirSync(directory), [`${TUNNEL_NAME}.token`]);
  } finally { rmSync(testRoot, { recursive: true, force: true }); }
});

test("atomically replaces the fixed token file without retaining displaced secret bytes", async () => {
  const testRoot = mkdtempSync(join(tmpdir(), "cloudflare-rotate-"));
  try {
    const path = tokenPathForTestRoot(testRoot, TUNNEL_NAME);
    admitTunnelToken(token("connector-secret-material-0001"), path);
    const replacement = token("connector-secret-material-0002");
    admitTunnelToken(replacement, path);
    assert.equal(readFileSync(path, "utf8"), `${replacement}\n`);
  } finally { rmSync(testRoot, { recursive: true, force: true }); }
});

test("two tunnels admitted to the same test root land at distinct per-tunnel paths", async () => {
  const testRoot = mkdtempSync(join(tmpdir(), "cloudflare-multi-"));
  try {
    const pathA = tokenPathForTestRoot(testRoot, "tunnel-a");
    const pathB = tokenPathForTestRoot(testRoot, "tunnel-b");
    admitTunnelToken(token("secret-a-0000000000000000"), pathA);
    admitTunnelToken(token("secret-b-0000000000000000"), pathB);
    assert.notEqual(pathA, pathB);
    assert.equal(readFileSync(pathA, "utf8").includes("secret-a"), false);
  } finally { rmSync(testRoot, { recursive: true, force: true }); }
});

test("refuses missing, malformed, or unacknowledged stdin, and a missing --tunnel-name", async () => {
  const testRoot = mkdtempSync(join(tmpdir(), "cloudflare-refuse-"));
  try {
    assert.notEqual((await admit(testRoot, "")).status, 0);
    assert.notEqual((await admit(testRoot, "not-a-cloudflare-token")).status, 0);
    assert.throws(() => validateTunnelToken("not-a-cloudflare-token"), /token/);
    const unsafe = await runAdmission(["--stdin", `--test-root=${testRoot}`, `--tunnel-name=${TUNNEL_NAME}`], token());
    assert.notEqual(unsafe.status, 0);
    assert.equal(unsafe.stdout.includes(token()), false);
    assert.equal(unsafe.stderr.includes(token()), false);
    const noName = await runAdmission(["--stdin", "--safe-stdin", `--test-root=${testRoot}`], token());
    assert.notEqual(noName.status, 0);
  } finally { rmSync(testRoot, { recursive: true, force: true }); }
});

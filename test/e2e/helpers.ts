import { execFile } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

export const ROOT = resolve(import.meta.dirname, "../..");
export const CLI = join(ROOT, "src/cli.ts");
export const DEMO_CONFIG = join(ROOT, "examples/demo/agent-guard.yaml");
const run = promisify(execFile);

export const tempDir = (prefix = "ag-e2e-") => mkdtempSync(join(tmpdir(), prefix));

/** Runs the real CLI (TypeScript source via tsx) and returns exit code + stdout. */
export async function cli(args: string[], env: Record<string, string> = {}): Promise<{ code: number; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await run(process.execPath, ["--import", "tsx", CLI, ...args], { cwd: ROOT, env: { ...process.env, ...env } });
    return { code: 0, stdout, stderr };
  } catch (e) {
    const err = e as { code?: number; stdout?: string; stderr?: string };
    return { code: typeof err.code === "number" ? err.code : 1, stdout: err.stdout ?? "", stderr: err.stderr ?? "" };
  }
}

/** Connects a real MCP client to `agent-guard serve` over stdio. */
export async function connectGateway(opts: { stateDir: string; webUrl: string; agent?: string; extraEnv?: Record<string, string> }) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ["--import", "tsx", CLI, "serve", "--config", DEMO_CONFIG, "--state-dir", opts.stateDir, ...(opts.agent ? ["--agent", opts.agent] : [])],
    cwd: ROOT,
    env: { ...getDefaultEnvironment(), DEMO_WEB_URL: opts.webUrl, AGENT_GUARD_LOG_LEVEL: "warn", ...opts.extraEnv },
    stderr: "pipe",
  });
  const client = new Client({ name: "e2e-agent", version: "1.0.0" });
  await client.connect(transport);
  return client;
}

export function textOf(r: unknown): string {
  return ((r as CallToolResult).content ?? []).map((c) => (c.type === "text" ? c.text : "")).join("\n");
}

export async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address() as { port: number };
      s.close(() => resolve(port));
    });
  });
}

export async function waitFor<T>(fn: () => T | undefined | null, timeoutMs = 10_000): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() > deadline) throw new Error("waitFor timed out");
    await new Promise((r) => setTimeout(r, 50));
  }
}

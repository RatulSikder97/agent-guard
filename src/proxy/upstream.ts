import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import type { Upstream } from "../config/schema.js";
import { log } from "../logger.js";

export interface UpstreamTool {
  server: string;
  tool: string;
  /** Name exposed to the downstream agent: `${server}${separator}${tool}`. */
  exposedName: string;
  definition: Tool;
}

interface Connection {
  upstream: Upstream;
  client: Client;
  transport: Transport;
}

export interface UpstreamManagerOptions {
  separator: string;
  clientName: string;
  clientVersion: string;
  callTimeoutMs?: number;
}

/** Connects to every configured upstream MCP server and aggregates their tools under namespaced names. */
export class UpstreamManager {
  private readonly connections = new Map<string, Connection>();
  private toolsByExposedName = new Map<string, UpstreamTool>();

  constructor(
    private readonly upstreams: readonly Upstream[],
    private readonly opts: UpstreamManagerOptions,
  ) {}

  private makeTransport(u: Upstream): Transport {
    if (u.transport === "stdio") {
      const t = new StdioClientTransport({
        command: u.command,
        args: u.args,
        env: { ...getDefaultEnvironment(), ...u.env },
        ...(u.cwd ? { cwd: u.cwd } : {}),
        stderr: "pipe",
      });
      t.stderr?.on("data", (chunk: Buffer) => {
        for (const line of chunk.toString("utf8").split("\n")) if (line.trim()) log.debug(`[${u.name}] ${line}`);
      });
      return t;
    }
    return new StreamableHTTPClientTransport(new URL(u.url), { requestInit: { headers: u.headers } });
  }

  /** Connects all upstreams in parallel. A failing upstream is logged and skipped, not fatal. */
  async connect(): Promise<{ connected: string[]; failed: { name: string; error: string }[] }> {
    const results = await Promise.allSettled(
      this.upstreams.map(async (u) => {
        const client = new Client({ name: this.opts.clientName, version: this.opts.clientVersion });
        const transport = this.makeTransport(u);
        await client.connect(transport);
        this.connections.set(u.name, { upstream: u, client, transport });
        return u.name;
      }),
    );
    const connected: string[] = [];
    const failed: { name: string; error: string }[] = [];
    results.forEach((r, i) => {
      const name = (this.upstreams[i] as Upstream).name;
      if (r.status === "fulfilled") connected.push(name);
      else {
        const error = r.reason instanceof Error ? r.reason.message : String(r.reason);
        failed.push({ name, error });
        log.error(`upstream '${name}' failed to connect`, { error });
      }
    });
    await this.refreshTools();
    return { connected, failed };
  }

  async refreshTools(): Promise<void> {
    const next = new Map<string, UpstreamTool>();
    for (const [server, conn] of this.connections) {
      let cursor: string | undefined;
      do {
        const page = await conn.client.listTools(cursor ? { cursor } : {});
        for (const def of page.tools) {
          const exposedName = `${server}${this.opts.separator}${def.name}`;
          if (next.has(exposedName)) {
            log.warn(`duplicate exposed tool name '${exposedName}', keeping the first`);
            continue;
          }
          next.set(exposedName, { server, tool: def.name, exposedName, definition: def });
        }
        cursor = page.nextCursor;
      } while (cursor);
    }
    this.toolsByExposedName = next;
  }

  tools(): UpstreamTool[] {
    return [...this.toolsByExposedName.values()];
  }

  resolve(exposedName: string): UpstreamTool | undefined {
    return this.toolsByExposedName.get(exposedName);
  }

  async call(server: string, tool: string, args: Record<string, unknown>, signal?: AbortSignal): Promise<CallToolResult> {
    const conn = this.connections.get(server);
    if (!conn) throw new Error(`upstream '${server}' is not connected`);
    const result = await conn.client.callTool({ name: tool, arguments: args }, undefined, {
      ...(signal ? { signal } : {}),
      ...(this.opts.callTimeoutMs ? { timeout: this.opts.callTimeoutMs } : {}),
    });
    return result as CallToolResult;
  }

  async close(): Promise<void> {
    await Promise.allSettled([...this.connections.values()].map((c) => c.client.close()));
    this.connections.clear();
  }
}

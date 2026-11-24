#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { ApprovalError, ApprovalStore, type ApprovalEntry } from "./approval/store.js";
import { verifyAuditLog } from "./audit/log.js";
import { ConfigError, loadConfig, type LoadedConfig } from "./config/load.js";
import { scanForInjection } from "./defense/injection.js";
import { redactText } from "./defense/secrets.js";
import { log } from "./logger.js";
import { PolicyEngine } from "./policy/engine.js";
import { serveHttp, serveStdio } from "./proxy/server.js";
import { auditKey, startRuntime } from "./runtime.js";
import { VERSION } from "./version.js";

const HELP = `agent-guard ${VERSION} — a firewall for AI agent tool use (MCP security gateway)

Usage:
  agent-guard serve       --config <file> [--agent <id>] [--state-dir <dir>] [--http [--host 127.0.0.1] [--port 8787]]
  agent-guard pending     [--config <file> | --state-dir <dir>] [--json]
  agent-guard approve <id> [--config <file> | --state-dir <dir>] [--note <text>]
  agent-guard deny <id>    [--config <file> | --state-dir <dir>] [--note <text>]
  agent-guard verify-log  [<audit.jsonl>] [--config <file> | --state-dir <dir>] [--anchor <hash>]
  agent-guard check       --config <file>
  agent-guard scan        [<file>]          (reads stdin when no file is given)

Environment:
  AGENT_GUARD_CONFIG            default for --config
  AGENT_GUARD_STATE_DIR         default for --state-dir (otherwise ./.agent-guard)
  AGENT_GUARD_LOG_LEVEL         debug | info | warn | error (logs go to stderr)
  AGENT_GUARD_DASHBOARD_TOKEN   fixed bearer token for the approval dashboard
  ANTHROPIC_API_KEY             required only when the LLM classifier is enabled
  OTEL_EXPORTER_OTLP_ENDPOINT   export OpenTelemetry traces over OTLP/HTTP
`;

const OPTIONS = {
  config: { type: "string", short: "c" },
  "state-dir": { type: "string" },
  agent: { type: "string" },
  http: { type: "boolean" },
  host: { type: "string" },
  port: { type: "string" },
  note: { type: "string" },
  json: { type: "boolean" },
  anchor: { type: "string" },
  help: { type: "boolean", short: "h" },
  version: { type: "boolean", short: "v" },
} as const;

type Values = ReturnType<typeof parseArgs<{ options: typeof OPTIONS; allowPositionals: true }>>["values"];

function out(line: string): void {
  process.stdout.write(`${line}\n`);
}

function configPath(values: Values): string | undefined {
  return values.config ?? process.env.AGENT_GUARD_CONFIG;
}

/** Loads the config, letting --state-dir / AGENT_GUARD_STATE_DIR relocate state (approvals + default audit log). */
function load(values: Values, path: string): LoadedConfig {
  const loaded = loadConfig(path);
  const override = values["state-dir"] ?? process.env.AGENT_GUARD_STATE_DIR;
  if (!override) return loaded;
  const dir = resolve(override);
  return { ...loaded, stateDir: dir, auditPath: loaded.config.audit.path ? loaded.auditPath : resolve(dir, "audit.jsonl") };
}

function requireConfig(values: Values): LoadedConfig {
  const p = configPath(values);
  if (!p) throw new ConfigError("--config <file> is required (or set AGENT_GUARD_CONFIG)");
  return load(values, p);
}

function stateDir(values: Values): string {
  if (values["state-dir"]) return resolve(values["state-dir"]);
  const p = configPath(values);
  if (p) return load(values, p).stateDir;
  return resolve(process.env.AGENT_GUARD_STATE_DIR ?? ".agent-guard");
}

async function cmdServe(values: Values): Promise<void> {
  const loaded = requireConfig(values);
  const runtime = await startRuntime(loaded);
  const agent = values.agent ?? process.env.AGENT_GUARD_AGENT ?? loaded.config.defaultAgent;
  if (!Object.hasOwn(loaded.config.agents, agent)) throw new ConfigError(`unknown agent '${agent}'`);

  let closeServer: () => Promise<void>;
  if (values.http) {
    const tokens = new Map<string, string>();
    for (const [id, a] of Object.entries(loaded.config.agents)) {
      if (!a.tokenEnv) continue;
      const token = process.env[a.tokenEnv];
      if (!token) throw new ConfigError(`agent '${id}' expects a token in $${a.tokenEnv}, which is not set`);
      if (token.length < 16) throw new ConfigError(`token in $${a.tokenEnv} must be at least 16 characters`);
      tokens.set(id, token);
    }
    const http = await serveHttp(runtime.gateway, {
      host: values.host ?? "127.0.0.1",
      port: Number(values.port ?? 8787),
      tokens,
      defaultAgent: agent,
    });
    closeServer = () => http.close();
  } else {
    const stdio = await serveStdio(runtime.gateway, agent);
    closeServer = () => stdio.close();
    process.stdin.on("end", () => void shutdown("stdin closed"));
  }

  let stopping = false;
  async function shutdown(reason: string): Promise<void> {
    if (stopping) return;
    stopping = true;
    log.info(`shutting down (${reason})`);
    await closeServer().catch(() => undefined);
    await runtime.close().catch(() => undefined);
    process.exit(0);
  }
  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
}

function formatEntry(e: ApprovalEntry): string {
  const args = JSON.stringify(e.args);
  return `${e.id}  ${e.status.padEnd(8)} ${e.server}.${e.tool}  agent=${e.agent}  expires=${e.expiresAt}\n    reason: ${e.reason}\n    args:   ${args.length > 200 ? `${args.slice(0, 200)}…` : args}`;
}

function cmdPending(values: Values): void {
  const store = new ApprovalStore(stateDir(values));
  const pending = store.list("pending");
  if (values.json) return out(JSON.stringify(pending, null, 2));
  if (pending.length === 0) return out("No pending approvals.");
  for (const e of pending) out(formatEntry(e));
}

function cmdDecide(values: Values, id: string | undefined, status: "approved" | "denied"): void {
  if (!id) throw new ApprovalError(`usage: agent-guard ${status === "approved" ? "approve" : "deny"} <id>`);
  const store = new ApprovalStore(stateDir(values));
  const ok = store.decide(ApprovalStore.validateId(id), status, "cli", values.note);
  if (!ok) throw new ApprovalError(`approval '${id}' was already decided (${store.get(id)?.status ?? "unknown"})`);
  const e = store.get(id);
  out(`${status === "approved" ? "Approved" : "Denied"} ${id}${e ? `: ${e.server}.${e.tool}` : ""}`);
}

function cmdVerify(values: Values, file: string | undefined): number {
  let path = file;
  let key: Buffer | undefined;
  const cfg = configPath(values);
  if (cfg) {
    const loaded = load(values, cfg);
    path ??= loaded.auditPath;
    key = auditKey(loaded);
  }
  path ??= resolve(stateDir(values), "audit.jsonl");
  const result = verifyAuditLog(path, key ? { hmacKey: key } : {});
  if (!result.ok) {
    out(`TAMPERED  ${path}\n  line ${result.error?.line}: ${result.error?.reason}\n  ${result.records} record(s) verified before the break`);
    return 1;
  }
  if (values.anchor) {
    const lines = readFileSync(path, "utf8").split("\n").filter(Boolean);
    if (!lines.some((l) => (JSON.parse(l) as { hash: string }).hash === values.anchor)) {
      out(`TRUNCATED  ${path}\n  anchor ${values.anchor} not found: records were removed from the end of the log`);
      return 1;
    }
  }
  out(`OK  ${path}\n  ${result.records} record(s), chain intact${key ? " (HMAC)" : ""}\n  head ${result.headHash}`);
  return 0;
}

function cmdCheck(values: Values): void {
  const loaded = requireConfig(values);
  const { config } = loaded;
  new PolicyEngine(config.policy.rules, config.policy.default);
  out(`Config OK: ${resolve(configPath(values) ?? "")}`);
  out(`  upstreams: ${config.upstreams.map((u) => `${u.name} (${u.transport})`).join(", ")}`);
  out(`  agents:    ${Object.keys(config.agents).join(", ")} (default: ${config.defaultAgent})`);
  out(`  policy:    default=${config.policy.default}, ${config.policy.rules.length} rule(s), ${config.policy.limits.length} limit(s)`);
  out(`  state dir: ${loaded.stateDir}`);
  out(`  audit log: ${loaded.auditPath}`);
}

function cmdScan(file: string | undefined): number {
  const text = readFileSync(file ?? 0, "utf8");
  const inj = scanForInjection(text);
  const red = redactText(text);
  out(JSON.stringify({ injection: inj, redactions: red.findings.map(({ type, kind, fingerprint }) => ({ type, kind, fingerprint })) }, null, 2));
  return inj.flagged ? 2 : 0;
}

export async function main(argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({ args: argv, options: OPTIONS, allowPositionals: true, strict: true });
  const [cmd, arg] = positionals;
  if (values.version) {
    out(VERSION);
    return 0;
  }
  if (values.help || !cmd) {
    out(HELP);
    return cmd || values.help ? 0 : 1;
  }
  switch (cmd) {
    case "serve":
      await cmdServe(values);
      return -1; // keep running
    case "pending":
      cmdPending(values);
      return 0;
    case "approve":
      cmdDecide(values, arg, "approved");
      return 0;
    case "deny":
      cmdDecide(values, arg, "denied");
      return 0;
    case "verify-log":
      return cmdVerify(values, arg);
    case "check":
      cmdCheck(values);
      return 0;
    case "scan":
      return cmdScan(arg);
    default:
      process.stderr.write(`unknown command '${cmd}'\n\n${HELP}`);
      return 1;
  }
}

main(process.argv.slice(2)).then(
  (code) => {
    if (code >= 0) process.exitCode = code;
  },
  (e: unknown) => {
    const err = e as Error & { code?: string };
    const userError = err instanceof ConfigError || err instanceof ApprovalError || err.code?.startsWith("ERR_PARSE_ARGS");
    process.stderr.write(`agent-guard: ${userError ? err.message : (err.stack ?? err.message)}\n`);
    process.exitCode = 1;
  },
);

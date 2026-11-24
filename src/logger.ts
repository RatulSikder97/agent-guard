/** Structured logger that ONLY writes to stderr: stdout carries the MCP stdio protocol. */
type Level = "debug" | "info" | "warn" | "error";
const ORDER: Record<Level, number> = { debug: 10, info: 20, warn: 30, error: 40 };

function threshold(): number {
  const v = (process.env.AGENT_GUARD_LOG_LEVEL ?? "info").toLowerCase();
  return v in ORDER ? ORDER[v as Level] : ORDER.info;
}

function write(level: Level, msg: string, fields?: Record<string, unknown>) {
  if (ORDER[level] < threshold()) return;
  const line = process.env.AGENT_GUARD_LOG_FORMAT === "json"
    ? JSON.stringify({ ts: new Date().toISOString(), level, msg, ...fields })
    : `agent-guard ${level.toUpperCase().padEnd(5)} ${msg}${fields && Object.keys(fields).length ? ` ${JSON.stringify(fields)}` : ""}`;
  process.stderr.write(`${line}\n`);
}

export const log = {
  debug: (msg: string, f?: Record<string, unknown>) => write("debug", msg, f),
  info: (msg: string, f?: Record<string, unknown>) => write("info", msg, f),
  warn: (msg: string, f?: Record<string, unknown>) => write("warn", msg, f),
  error: (msg: string, f?: Record<string, unknown>) => write("error", msg, f),
};

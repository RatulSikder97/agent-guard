import { readFileSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import { ConfigSchema, type Config, type Upstream } from "./schema.js";

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

/** Expands `${VAR}` and `${VAR:-fallback}`. Unset variables without a fallback are a hard error. */
export function expandEnv(value: string, env: NodeJS.ProcessEnv = process.env): string {
  return value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}/g, (_m, key: string, fallback?: string) => {
    const v = env[key];
    if (v !== undefined && v !== "") return v;
    if (fallback !== undefined) return fallback;
    throw new ConfigError(`environment variable ${key} is not set`);
  });
}

function expandUpstream(u: Upstream, baseDir: string, env: NodeJS.ProcessEnv): Upstream {
  const mapValues = (o: Record<string, string>) =>
    Object.fromEntries(Object.entries(o).map(([k, v]) => [k, expandEnv(v, env)]));
  if (u.transport === "stdio") {
    return {
      ...u,
      command: expandEnv(u.command, env),
      args: u.args.map((a) => expandEnv(a, env)),
      env: mapValues(u.env),
      cwd: u.cwd ? resolve(baseDir, expandEnv(u.cwd, env)) : baseDir,
    };
  }
  const url = expandEnv(u.url, env);
  if (!URL.canParse(url) || !/^https?:$/.test(new URL(url).protocol)) {
    throw new ConfigError(`upstream '${u.name}': invalid http(s) url '${url}'`);
  }
  return { ...u, url, headers: mapValues(u.headers) };
}

export interface LoadedConfig {
  config: Config;
  baseDir: string;
  stateDir: string;
  auditPath: string;
}

export function parseConfig(raw: unknown, baseDir: string, env: NodeJS.ProcessEnv = process.env): LoadedConfig {
  const result = ConfigSchema.safeParse(raw);
  if (!result.success) {
    const issues = result.error.issues.map((i) => `  - ${i.path.join(".") || "(root)"}: ${i.message}`).join("\n");
    throw new ConfigError(`invalid configuration:\n${issues}`);
  }
  const config = result.data;
  const names = new Set<string>();
  for (const u of config.upstreams) {
    if (names.has(u.name)) throw new ConfigError(`duplicate upstream name '${u.name}'`);
    names.add(u.name);
  }
  if (!Object.hasOwn(config.agents, config.defaultAgent)) {
    throw new ConfigError(`defaultAgent '${config.defaultAgent}' is not defined under agents`);
  }
  const ids = new Set<string>();
  for (const r of [...config.policy.rules, ...config.policy.limits]) {
    if (ids.has(r.id)) throw new ConfigError(`duplicate rule/limit id '${r.id}'`);
    ids.add(r.id);
  }
  config.upstreams = config.upstreams.map((u) => expandUpstream(u, baseDir, env));
  const stateDir = isAbsolute(config.gateway.stateDir) ? config.gateway.stateDir : resolve(baseDir, config.gateway.stateDir);
  const auditPath = config.audit.path ? resolve(baseDir, config.audit.path) : resolve(stateDir, "audit.jsonl");
  return { config, baseDir, stateDir, auditPath };
}

export function loadConfig(path: string, env: NodeJS.ProcessEnv = process.env): LoadedConfig {
  const abs = resolve(path);
  let text: string;
  try {
    text = readFileSync(abs, "utf8");
  } catch (e) {
    throw new ConfigError(`cannot read config ${abs}: ${(e as Error).message}`);
  }
  let raw: unknown;
  try {
    raw = parseYaml(text, { maxAliasCount: 50 });
  } catch (e) {
    throw new ConfigError(`invalid YAML in ${abs}: ${(e as Error).message}`);
  }
  return parseConfig(raw, dirname(abs), env);
}

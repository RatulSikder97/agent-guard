import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parse as parseYaml } from "yaml";
import { ConfigError, expandEnv, loadConfig, parseConfig } from "../../src/config/load.js";
import { PolicyEngine } from "../../src/policy/engine.js";

const minimal = { version: 1, upstreams: [{ name: "fs", transport: "stdio", command: "node" }] };

describe("config", () => {
  it("applies secure defaults", () => {
    const { config, stateDir, auditPath } = parseConfig(minimal, "/base");
    expect(config.policy.default).toBe("deny");
    expect(config.defenses.secrets.args).toBe("redact");
    expect(config.defenses.injection.classifier.enabled).toBe(false);
    expect(config.defenses.injection.classifier.model).toBe("claude-haiku-5-5");
    expect(config.defenses.trifecta).toEqual({ enabled: true, action: "require_approval" });
    expect(config.approvals.dashboard.host).toBe("127.0.0.1");
    expect(stateDir).toBe("/base/.agent-guard");
    expect(auditPath).toBe("/base/.agent-guard/audit.jsonl");
  });

  it("rejects unknown keys (typos in security config must not be silently ignored)", () => {
    expect(() => parseConfig({ ...minimal, polcy: {} }, "/")).toThrow(ConfigError);
    expect(() => parseConfig({ ...minimal, policy: { rules: [{ id: "x", action: "deny", mach: {} }] } }, "/")).toThrow(/mach/);
  });

  it("rejects duplicate upstreams and rule ids, and unknown default agents", () => {
    expect(() => parseConfig({ ...minimal, upstreams: [...minimal.upstreams, ...minimal.upstreams] }, "/")).toThrow(/duplicate upstream/);
    expect(() => parseConfig({ ...minimal, policy: { rules: [{ id: "a", action: "deny" }, { id: "a", action: "allow" }] } }, "/")).toThrow(/duplicate rule/);
    expect(() => parseConfig({ ...minimal, defaultAgent: "ghost" }, "/")).toThrow(/defaultAgent/);
  });

  it("expands environment variables in upstream settings only", () => {
    const env = { TOKEN: "abc", HOST: "api.example" };
    const { config } = parseConfig(
      { version: 1, upstreams: [{ name: "w", transport: "http", url: "https://${HOST}/mcp", headers: { Authorization: "Bearer ${TOKEN}" } }] },
      "/",
      env,
    );
    const u = config.upstreams[0];
    expect(u?.transport === "http" && u.url).toBe("https://api.example/mcp");
    expect(u?.transport === "http" && u.headers.Authorization).toBe("Bearer abc");
    expect(expandEnv("${MISSING:-fallback}", {})).toBe("fallback");
    expect(() => expandEnv("${MISSING}", {})).toThrow(/MISSING/);
  });

  it("loads YAML files and resolves relative paths against the config directory", () => {
    const dir = mkdtempSync(join(tmpdir(), "ag-cfg-"));
    const file = join(dir, "agent-guard.yaml");
    writeFileSync(file, "version: 1\nupstreams:\n  - name: fs\n    transport: stdio\n    command: node\n    cwd: sub\naudit:\n  path: logs/a.jsonl\n");
    const loaded = loadConfig(file);
    const u = loaded.config.upstreams[0];
    expect(u?.transport === "stdio" && u.cwd).toBe(join(dir, "sub"));
    expect(loaded.auditPath).toBe(join(dir, "logs/a.jsonl"));
    writeFileSync(file, "version: [");
    expect(() => loadConfig(file)).toThrow(/invalid YAML/);
  });

  it("loads the shipped example configs", () => {
    expect(() => loadConfig("examples/demo/agent-guard.yaml")).not.toThrow();
    expect(() => loadConfig("examples/agent-guard.yaml", { HOME: "/home/u", ...process.env })).not.toThrow();
  });

  it("accepts the policy example from the README", () => {
    const readme = readFileSync("README.md", "utf8");
    const section = readme.slice(readme.indexOf("## Policies"));
    const yaml = /```yaml\n([\s\S]*?)```/.exec(section)?.[1];
    expect(yaml).toBeTruthy();
    const { config } = parseConfig(parseYaml(yaml as string), "/", { WEB_MCP_TOKEN: "t" });
    expect(() => new PolicyEngine(config.policy.rules, config.policy.default)).not.toThrow();
    expect(config.policy.rules.length).toBeGreaterThanOrEqual(5);
  });
});

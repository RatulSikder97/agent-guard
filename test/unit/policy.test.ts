import { describe, expect, it } from "vitest";
import { RuleSchema, LimitSchema, type Rule } from "../../src/config/schema.js";
import { isCapable, LimitTracker, PolicyCompileError, PolicyEngine, type ToolCallContext } from "../../src/policy/engine.js";

const rules = (rs: unknown[]): Rule[] => rs.map((r) => RuleSchema.parse(r));
const ctx = (over: Partial<ToolCallContext> = {}): ToolCallContext => ({
  agent: "claude",
  sessionId: "s1",
  server: "fs",
  tool: "read_file",
  args: { path: "/workspace/src/index.ts" },
  labels: [],
  sessionLabels: [],
  ...over,
});

describe("PolicyEngine", () => {
  it("falls back to the default action", () => {
    expect(new PolicyEngine([], "deny").evaluate(ctx()).action).toBe("deny");
    expect(new PolicyEngine([], "allow").evaluate(ctx()).ruleId).toBeNull();
  });

  it("matches server/tool/agent globs", () => {
    const e = new PolicyEngine(rules([{ id: "r", action: "allow", match: { server: "f*", tool: ["read_*", "list_*"], agent: "claude" } }]), "deny");
    expect(e.evaluate(ctx()).action).toBe("allow");
    expect(e.evaluate(ctx({ tool: "write_file" })).action).toBe("deny");
    expect(e.evaluate(ctx({ agent: "other" })).action).toBe("deny");
  });

  it("most restrictive matching rule wins regardless of order", () => {
    const e = new PolicyEngine(
      rules([
        { id: "allow-all", action: "allow" },
        { id: "approve-fs", action: "require_approval", match: { server: "fs" } },
        { id: "deny-env", action: "deny", match: { args: [{ path: "$.path", glob: "**/.env*" }] } },
      ]),
      "deny",
    );
    expect(e.evaluate(ctx()).ruleId).toBe("approve-fs");
    const d = e.evaluate(ctx({ args: { path: "/app/.env" } }));
    expect(d.action).toBe("deny");
    expect(d.matched.map((m) => m.id)).toEqual(["allow-all", "approve-fs", "deny-env"]);
  });

  it("supports every argument predicate", () => {
    const mk = (pred: Record<string, unknown>) => new PolicyEngine(rules([{ id: "p", action: "deny", match: { args: [pred] } }]), "allow");
    const args = { path: "/etc/passwd", n: 3, flag: true, urls: ["https://a.example.com/x", "https://evil.test/y"] };
    const c = ctx({ args });
    expect(mk({ path: "$.path", regex: "^/etc/" }).evaluate(c).action).toBe("deny");
    expect(mk({ path: "$.n", equals: 3 }).evaluate(c).action).toBe("deny");
    expect(mk({ path: "$.flag", oneOf: [true] }).evaluate(c).action).toBe("deny");
    expect(mk({ path: "$.missing", exists: true }).evaluate(c).action).toBe("allow");
    expect(mk({ path: "$.missing", exists: false }).evaluate(c).action).toBe("deny");
    expect(mk({ path: "$.urls[*]", host: "*.test" }).evaluate(c).action).toBe("deny");
    expect(mk({ path: "$.urls[*]", host: "*.nothing" }).evaluate(c).action).toBe("allow");
    expect(mk({ path: "$.path", glob: "/home/**", not: true }).evaluate(c).action).toBe("deny");
  });

  it("normalizes path traversal before glob matching", () => {
    const allowOnly = new PolicyEngine(rules([{ id: "ws", action: "allow", match: { args: [{ path: "$.path", glob: "/workspace/**" }] } }]), "deny");
    expect(allowOnly.evaluate(ctx({ args: { path: "/workspace/a.txt" } })).action).toBe("allow");
    expect(allowOnly.evaluate(ctx({ args: { path: "/workspace/../etc/shadow" } })).action).toBe("deny");
    const denyEtc = new PolicyEngine(rules([{ id: "etc", action: "deny", match: { args: [{ path: "$.path", glob: "/etc/**" }] } }]), "allow");
    expect(denyEtc.evaluate(ctx({ args: { path: "/tmp/../etc/passwd" } })).action).toBe("deny");
  });

  it("evaluates when-expressions with session context", () => {
    const e = new PolicyEngine(
      rules([
        { id: "big-writes", action: "require_approval", match: { tool: "write_file" }, when: "size(args.content) > 10" },
        { id: "tainted", action: "deny", when: "'untrusted_content' in session.labels && 'egress' in labels" },
      ]),
      "allow",
    );
    expect(e.evaluate(ctx({ tool: "write_file", args: { content: "short" } })).action).toBe("allow");
    expect(e.evaluate(ctx({ tool: "write_file", args: { content: "x".repeat(20) } })).action).toBe("require_approval");
    expect(e.evaluate(ctx({ labels: ["egress"], sessionLabels: ["untrusted_content"] })).ruleId).toBe("tainted");
  });

  it("fails closed when a restrictive rule errors, open for allow rules", () => {
    const e = new PolicyEngine(
      rules([
        { id: "bad-deny", action: "deny", when: "args.path + 1 == 2" },
        { id: "bad-allow", action: "allow", when: "args.path + 1 == 2" },
      ]),
      "allow",
    );
    const d = e.evaluate(ctx());
    expect(d.action).toBe("deny");
    expect(d.ruleId).toBe("bad-deny");
    expect(d.errors).toHaveLength(2);
  });

  it("rejects invalid rules at load time", () => {
    expect(() => new PolicyEngine(rules([{ id: "x", action: "deny", when: "args.(" }]), "deny")).toThrow(PolicyCompileError);
    expect(() => new PolicyEngine(rules([{ id: "x", action: "deny", match: { args: [{ path: "$.a", regex: "(a+)+" }] } }]), "deny")).toThrow(/ReDoS/);
    expect(() => RuleSchema.parse({ id: "x", action: "deny", match: { args: [{ path: "$.a", glob: "*", regex: "x" }] } })).toThrow();
    expect(() => RuleSchema.parse({ id: "x", action: "maybe" })).toThrow();
  });
});

describe("capabilities", () => {
  it("scopes tools per agent", () => {
    expect(isCapable(["*"], "fs", "write_file")).toBe(true);
    expect(isCapable(["fs.read_*", "web.fetch"], "fs", "read_file")).toBe(true);
    expect(isCapable(["fs.read_*", "web.fetch"], "fs", "write_file")).toBe(false);
    expect(isCapable([], "fs", "read_file")).toBe(false);
  });
});

describe("LimitTracker", () => {
  it("enforces sliding-window rate limits per session", () => {
    let now = 0;
    const t = new LimitTracker([LimitSchema.parse({ id: "r", match: { tool: "fetch" }, rate: { max: 2, windowSec: 10 } })], () => now);
    const c = ctx({ tool: "fetch" });
    for (let i = 0; i < 2; i++) {
      expect(t.check(c).ok).toBe(true);
      t.recordCall(c);
    }
    expect(t.check(c)).toMatchObject({ ok: false, limitId: "r" });
    expect(t.check({ ...c, sessionId: "s2" }).ok).toBe(true);
    expect(t.check(ctx({ tool: "other" })).ok).toBe(true);
    now = 10_001;
    expect(t.check(c).ok).toBe(true);
  });

  it("enforces call and output budgets", () => {
    const t = new LimitTracker([LimitSchema.parse({ id: "b", budget: { maxCalls: 1, maxOutputBytes: 100 } })]);
    const c = ctx();
    t.recordCall(c);
    expect(t.check(c).reason).toMatch(/max 1 calls/);
    const t2 = new LimitTracker([LimitSchema.parse({ id: "b2", budget: { maxOutputBytes: 100 } })]);
    t2.recordOutput(c, 150);
    expect(t2.check(c).reason).toMatch(/output bytes/);
  });
});

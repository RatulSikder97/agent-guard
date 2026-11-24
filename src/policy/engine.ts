import { posix } from "node:path";
import type { Action, ArgPredicate, Label, Limit, Rule, ToolMatch } from "../config/schema.js";
import { compileExpression, globToRegExp, hostOf, safeRegex, type CompiledExpression } from "./expr.js";
import { queryJsonPath } from "./jsonpath.js";

export interface ToolCallContext {
  agent: string;
  sessionId: string;
  server: string;
  tool: string;
  args: Record<string, unknown>;
  /** Labels of the tool being called. */
  labels: readonly Label[];
  /** Labels accumulated by the session so far (before this call). */
  sessionLabels: readonly Label[];
}

export interface PolicyDecision {
  action: Action;
  ruleId: string | null;
  reason: string;
  /** Every rule that matched, in declaration order. */
  matched: { id: string; action: Action }[];
  errors: string[];
}

const SEVERITY: Record<Action, number> = { allow: 0, require_approval: 1, deny: 2 };

const globCache = new Map<string, RegExp>();
function glob(pattern: string, ci = false): RegExp {
  const key = `${ci ? "i" : "s"}:${pattern}`;
  let re = globCache.get(key);
  if (!re) {
    re = globToRegExp(pattern, { caseInsensitive: ci });
    globCache.set(key, re);
  }
  return re;
}

const asList = (v: string | string[] | undefined): string[] | undefined =>
  v === undefined ? undefined : Array.isArray(v) ? v : [v];

/** Glob-match the agent/server/tool selectors. Omitted selectors match everything. */
export function matchesTool(match: ToolMatch, ctx: { agent: string; server: string; tool: string }): boolean {
  const check = (patterns: string[] | undefined, value: string) =>
    patterns === undefined || patterns.some((p) => glob(p).test(value));
  return (
    check(asList(match.agent), ctx.agent) &&
    check(asList(match.server), ctx.server) &&
    check(asList(match.tool), ctx.tool)
  );
}

/** Capabilities are globs over the qualified `server.tool` name, e.g. `fs.read_*`, `web.*`, `*`. */
export function isCapable(capabilities: readonly string[], server: string, tool: string): boolean {
  const qualified = `${server}.${tool}`;
  return capabilities.some((c) => glob(c).test(qualified));
}

function looksLikePath(s: string): boolean {
  return s.startsWith("/") || s.startsWith("./") || s.startsWith("../") || s.startsWith("~/") || s.includes("/../");
}

/** Path-like strings are normalized so `/workspace/../etc/passwd` cannot sneak past `/workspace/**`. */
function normalizeForGlob(s: string): string {
  return looksLikePath(s) ? posix.normalize(s) : s;
}

interface CompiledPredicate {
  path: string;
  not: boolean;
  test: (values: unknown[]) => boolean;
}

function compilePredicate(p: ArgPredicate): CompiledPredicate {
  const str = (v: unknown) => (typeof v === "string" ? v : typeof v === "number" || typeof v === "boolean" ? String(v) : null);
  let test: (values: unknown[]) => boolean;
  if (p.exists !== undefined) {
    const want = p.exists;
    test = (vs) => vs.some((v) => v !== null && v !== undefined) === want;
  } else if (p.glob !== undefined) {
    const re = glob(p.glob);
    test = (vs) => vs.some((v) => {
      const s = str(v);
      return s !== null && re.test(normalizeForGlob(s));
    });
  } else if (p.regex !== undefined) {
    const re = safeRegex(p.regex);
    test = (vs) => vs.some((v) => {
      const s = str(v);
      return s !== null && re.test(s);
    });
  } else if (p.equals !== undefined) {
    const want = p.equals;
    test = (vs) => vs.some((v) => v === want);
  } else if (p.oneOf !== undefined) {
    const set = new Set<unknown>(p.oneOf);
    test = (vs) => vs.some((v) => set.has(v));
  } else {
    const hosts = asList(p.host) ?? [];
    test = (vs) => vs.some((v) => {
      const h = typeof v === "string" ? hostOf(v) : null;
      return h !== null && hosts.some((pat) => glob(pat, true).test(h));
    });
  }
  return { path: p.path, not: p.not, test };
}

interface CompiledRule {
  rule: Rule;
  predicates: CompiledPredicate[];
  when: CompiledExpression | null;
}

export class PolicyCompileError extends Error {
  constructor(ruleId: string, cause: Error) {
    super(`rule '${ruleId}': ${cause.message}`);
    this.name = "PolicyCompileError";
  }
}

export class PolicyEngine {
  private readonly rules: CompiledRule[];

  constructor(
    rules: readonly Rule[],
    private readonly defaultAction: Action,
  ) {
    this.rules = rules.map((rule) => {
      try {
        return {
          rule,
          predicates: (rule.match.args ?? []).map(compilePredicate),
          when: rule.when ? compileExpression(rule.when) : null,
        };
      } catch (e) {
        throw new PolicyCompileError(rule.id, e as Error);
      }
    });
  }

  evaluate(ctx: ToolCallContext): PolicyDecision {
    const matched: { id: string; action: Action; reason: string }[] = [];
    const errors: string[] = [];
    for (const c of this.rules) {
      const r = this.matchRule(c, ctx);
      if (r.error) errors.push(`${c.rule.id}: ${r.error}`);
      if (r.matched) {
        matched.push({
          id: c.rule.id,
          action: c.rule.action,
          reason: c.rule.reason ?? c.rule.description ?? `matched rule ${c.rule.id}`,
        });
      }
    }
    if (matched.length === 0) {
      return {
        action: this.defaultAction,
        ruleId: null,
        reason: `no rule matched; default action is ${this.defaultAction}`,
        matched: [],
        errors,
      };
    }
    // Most restrictive wins; ties go to the first declared rule. Order-independent across severities.
    let winner = matched[0] as (typeof matched)[number];
    for (const m of matched) if (SEVERITY[m.action] > SEVERITY[winner.action]) winner = m;
    return {
      action: winner.action,
      ruleId: winner.id,
      reason: winner.reason,
      matched: matched.map(({ id, action }) => ({ id, action })),
      errors,
    };
  }

  private matchRule(c: CompiledRule, ctx: ToolCallContext): { matched: boolean; error?: string } {
    if (!matchesTool(c.rule.match, ctx)) return { matched: false };
    for (const p of c.predicates) {
      let values: unknown[];
      try {
        values = queryJsonPath(ctx.args, p.path);
      } catch (e) {
        return this.onError(c, (e as Error).message);
      }
      if (p.test(values) === p.not) return { matched: false };
    }
    if (c.when) {
      try {
        const ok = c.when.test({
          args: ctx.args,
          tool: ctx.tool,
          server: ctx.server,
          agent: ctx.agent,
          labels: [...ctx.labels],
          session: { id: ctx.sessionId, labels: [...ctx.sessionLabels] },
        });
        if (!ok) return { matched: false };
      } catch (e) {
        return this.onError(c, (e as Error).message);
      }
    }
    return { matched: true };
  }

  /** Evaluation errors fail closed: restrictive rules match, permissive rules don't. */
  private onError(c: CompiledRule, message: string): { matched: boolean; error: string } {
    return { matched: c.rule.action !== "allow", error: message };
  }
}

export interface LimitVerdict {
  ok: boolean;
  limitId?: string;
  reason?: string;
}

/** Per-session sliding-window rate limits and call/output budgets. In-memory, per gateway process. */
export class LimitTracker {
  private readonly windows = new Map<string, number[]>();
  private readonly calls = new Map<string, number>();
  private readonly bytes = new Map<string, number>();

  constructor(
    private readonly limits: readonly Limit[],
    private readonly now: () => number = Date.now,
  ) {}

  private applicable(ctx: { agent: string; server: string; tool: string }): Limit[] {
    return this.limits.filter((l) => matchesTool(l.match, ctx));
  }

  check(ctx: ToolCallContext): LimitVerdict {
    const t = this.now();
    for (const l of this.applicable(ctx)) {
      const key = `${l.id}\u0000${ctx.sessionId}`;
      if (l.rate) {
        const cutoff = t - l.rate.windowSec * 1000;
        const ts = (this.windows.get(key) ?? []).filter((x) => x > cutoff);
        this.windows.set(key, ts);
        if (ts.length >= l.rate.max) {
          return { ok: false, limitId: l.id, reason: `rate limit ${l.id}: ${l.rate.max} calls per ${l.rate.windowSec}s exceeded` };
        }
      }
      if (l.budget?.maxCalls !== undefined && (this.calls.get(key) ?? 0) >= l.budget.maxCalls) {
        return { ok: false, limitId: l.id, reason: `budget ${l.id}: max ${l.budget.maxCalls} calls per session exhausted` };
      }
      if (l.budget?.maxOutputBytes !== undefined && (this.bytes.get(key) ?? 0) >= l.budget.maxOutputBytes) {
        return { ok: false, limitId: l.id, reason: `budget ${l.id}: max ${l.budget.maxOutputBytes} output bytes per session exhausted` };
      }
    }
    return { ok: true };
  }

  recordCall(ctx: ToolCallContext): void {
    const t = this.now();
    for (const l of this.applicable(ctx)) {
      const key = `${l.id}\u0000${ctx.sessionId}`;
      if (l.rate) this.windows.set(key, [...(this.windows.get(key) ?? []), t]);
      this.calls.set(key, (this.calls.get(key) ?? 0) + 1);
    }
  }

  recordOutput(ctx: ToolCallContext, byteCount: number): void {
    for (const l of this.applicable(ctx)) {
      const key = `${l.id}\u0000${ctx.sessionId}`;
      this.bytes.set(key, (this.bytes.get(key) ?? 0) + byteCount);
    }
  }
}

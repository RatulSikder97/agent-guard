import { randomUUID } from "node:crypto";
import { context, SpanStatusCode, trace, type Span, type Tracer } from "@opentelemetry/api";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import type { ApprovalStore } from "../approval/store.js";
import type { AuditLog } from "../audit/log.js";
import { LABELS, type Action, type Config, type Label } from "../config/schema.js";
import type { InjectionClassifier } from "../defense/classifier.js";
import { EgressPolicy } from "../defense/egress.js";
import { scanForInjection, type InjectionResult } from "../defense/injection.js";
import { redactText, redactValue, type RedactionFinding } from "../defense/secrets.js";
import { blockedNotice, spotlight } from "../defense/spotlight.js";
import { log } from "../logger.js";
import { isCapable, LimitTracker, matchesTool, PolicyEngine, type ToolCallContext } from "../policy/engine.js";
import { TRACER_NAME } from "../telemetry.js";
import type { UpstreamTool } from "./upstream.js";

/** The subset of UpstreamManager the gateway needs; lets tests plug in fakes. */
export interface ToolBackend {
  tools(): UpstreamTool[];
  resolve(exposedName: string): UpstreamTool | undefined;
  call(server: string, tool: string, args: Record<string, unknown>, signal?: AbortSignal): Promise<CallToolResult>;
}

export interface SessionInfo {
  id: string;
  agent: string;
}

interface SessionState {
  agent: string;
  labels: Set<Label>;
  calls: number;
}

export interface GatewayDeps {
  config: Config;
  backend: ToolBackend;
  audit: AuditLog;
  approvals: ApprovalStore;
  classifier?: InjectionClassifier | undefined;
  tracer?: Tracer;
  /** Called when a call is parked for approval (CLI prints instructions, tests auto-approve). */
  onApprovalRequested?: (id: string, summary: string) => void;
}

const MAX_LOG_STRING = 2000;

function truncate(value: unknown, depth = 0): unknown {
  if (depth > 16) return "[depth limit]";
  if (typeof value === "string") return value.length > MAX_LOG_STRING ? `${value.slice(0, MAX_LOG_STRING)}…[+${value.length - MAX_LOG_STRING}]` : value;
  if (Array.isArray(value)) return value.slice(0, 100).map((v) => truncate(v, depth + 1));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).slice(0, 100).map(([k, v]) => [k, truncate(v, depth + 1)]));
  }
  return value;
}

function countByType(findings: RedactionFinding[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const f of findings) out[f.type] = (out[f.type] ?? 0) + 1;
  return out;
}

const SEVERITY: Record<Action, number> = { allow: 0, require_approval: 1, deny: 2 };

interface Verdict {
  action: Action;
  ruleId: string | null;
  reason: string;
  stage: string;
}

/**
 * The enforcement pipeline. For every tools/call:
 *   resolve -> capability -> argument scan (secrets, egress) -> policy -> trifecta -> limits
 *   -> approval -> upstream call -> output redaction -> image-exfil stripping
 *   -> injection scan (+ optional LLM classifier) -> spotlight/block -> audit + span.
 */
export class Gateway {
  private readonly policy: PolicyEngine;
  private readonly limits: LimitTracker;
  private readonly egress: EgressPolicy;
  private readonly sessions = new Map<string, SessionState>();
  private readonly quarantined = new Map<string, InjectionResult>();
  private readonly tracer: Tracer;

  constructor(private readonly deps: GatewayDeps) {
    const { config } = deps;
    this.policy = new PolicyEngine(config.policy.rules, config.policy.default);
    this.limits = new LimitTracker(config.policy.limits);
    this.egress = new EgressPolicy(config.defenses.egress.allow);
    this.tracer = deps.tracer ?? trace.getTracer(TRACER_NAME);
  }

  get config(): Config {
    return this.deps.config;
  }

  /** Scans upstream tool descriptions for poisoning and quarantines suspicious tools. */
  inspectTools(): void {
    this.quarantined.clear();
    const inj = this.config.defenses.injection;
    if (!inj.enabled || !inj.scanToolDescriptions) return;
    for (const t of this.deps.backend.tools()) {
      const text = [t.definition.description ?? "", JSON.stringify(t.definition.inputSchema ?? {})].join("\n");
      const result = scanForInjection(text, { threshold: inj.threshold });
      if (result.flagged) {
        this.quarantined.set(t.exposedName, result);
        log.warn(`quarantined tool '${t.exposedName}': description looks like prompt injection`, {
          score: result.score,
          signals: result.signals.map((s) => s.id),
        });
        this.deps.audit.append("tool_quarantined", {
          server: t.server,
          tool: t.tool,
          score: result.score,
          signals: result.signals.map((s) => s.id),
        });
      }
    }
  }

  labelsFor(server: string, tool: string, agent: string): Label[] {
    const labels = new Set<Label>();
    for (const l of this.config.labels) if (matchesTool(l.match, { server, tool, agent })) l.labels.forEach((x) => labels.add(x));
    return [...labels];
  }

  private session(info: SessionInfo): SessionState {
    let s = this.sessions.get(info.id);
    if (!s) {
      s = { agent: info.agent, labels: new Set(), calls: 0 };
      this.sessions.set(info.id, s);
    }
    return s;
  }

  sessionLabels(sessionId: string): Label[] {
    return [...(this.sessions.get(sessionId)?.labels ?? [])];
  }

  endSession(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  private capabilities(agent: string): string[] {
    return this.config.agents[agent]?.capabilities ?? [];
  }

  listTools(info: SessionInfo): Tool[] {
    const caps = this.capabilities(info.agent);
    return this.deps.backend
      .tools()
      .filter((t) => !this.quarantined.has(t.exposedName) && isCapable(caps, t.server, t.tool))
      .map((t) => ({ ...t.definition, name: t.exposedName }));
  }

  async handleCall(info: SessionInfo, exposedName: string, rawArgs: unknown, signal?: AbortSignal): Promise<CallToolResult> {
    return this.tracer.startActiveSpan("agent_guard.tool_call", async (span) => {
      try {
        return await this.pipeline(info, exposedName, rawArgs, span, signal);
      } catch (e) {
        span.recordException(e as Error);
        span.setStatus({ code: SpanStatusCode.ERROR, message: (e as Error).message });
        throw e;
      } finally {
        span.end();
      }
    });
  }

  private child<T>(name: string, parent: Span, fn: (span: Span) => Promise<T> | T): Promise<T> {
    const ctx = trace.setSpan(context.active(), parent);
    return this.tracer.startActiveSpan(name, {}, ctx, async (span) => {
      try {
        return await fn(span);
      } finally {
        span.end();
      }
    });
  }

  private blocked(text: string): CallToolResult {
    return { isError: true, content: [{ type: "text", text }] };
  }

  private async pipeline(
    info: SessionInfo,
    exposedName: string,
    rawArgs: unknown,
    span: Span,
    signal?: AbortSignal,
  ): Promise<CallToolResult> {
    const { config, audit } = this.deps;
    const started = Date.now();
    const callId = randomUUID();
    const args: Record<string, unknown> =
      rawArgs && typeof rawArgs === "object" && !Array.isArray(rawArgs) ? (rawArgs as Record<string, unknown>) : {};
    span.setAttributes({ "agent_guard.call_id": callId, "agent_guard.agent": info.agent, "agent_guard.session": info.id, "mcp.tool.exposed_name": exposedName });

    const target = this.deps.backend.resolve(exposedName);
    const argScan = redactValue(args, { pii: false });
    const loggedArgs = truncate(redactValue(args, { pii: config.defenses.secrets.pii }).value);
    const base = { callId, agent: info.agent, session: info.id, tool: exposedName, args: loggedArgs };

    const deny = (stage: string, reason: string, ruleId: string | null, extra: Record<string, unknown> = {}) => {
      span.setAttributes({ "agent_guard.decision": "deny", "agent_guard.stage": stage, ...(ruleId ? { "agent_guard.rule_id": ruleId } : {}) });
      audit.append("tool_call", { ...base, ...extra, decision: "deny", stage, ruleId, reason, outcome: "blocked", durationMs: Date.now() - started });
      log.info(`blocked ${exposedName}: ${reason}`, { stage, ruleId, callId });
      return this.blocked(`[agent-guard] Blocked call to ${exposedName}: ${reason}${ruleId ? ` (rule: ${ruleId})` : ""}. Call id: ${callId}`);
    };

    if (!target || this.quarantined.has(exposedName)) {
      return deny("resolve", target ? "tool is quarantined (suspicious description)" : "unknown tool", null);
    }
    span.setAttributes({ "mcp.server": target.server, "mcp.tool": target.tool });
    if (!isCapable(this.capabilities(info.agent), target.server, target.tool)) {
      return deny("capability", `agent '${info.agent}' lacks capability for ${target.server}.${target.tool}`, null);
    }

    const session = this.session(info);
    const labels = this.labelsFor(target.server, target.tool, info.agent);
    const ctx: ToolCallContext = {
      agent: info.agent,
      sessionId: info.id,
      server: target.server,
      tool: target.tool,
      args,
      labels,
      sessionLabels: [...session.labels],
    };
    const secretTypes = [...new Set(argScan.findings.filter((f) => f.kind === "secret").map((f) => f.type))];
    const extra: Record<string, unknown> = { server: target.server, toolName: target.tool, labels, sessionLabels: ctx.sessionLabels };
    if (secretTypes.length) extra.argSecrets = secretTypes;

    // --- Pre-call checks: produce the most restrictive verdict across all stages. ---
    const verdict = await this.child("agent_guard.evaluate", span, (s) => {
      const candidates: Verdict[] = [];
      if (labels.includes("egress")) {
        const bad = this.egress.violations(args);
        if (bad.length) {
          extra.egressViolations = [...new Set(bad.map((b) => b.host ?? b.url))];
          candidates.push({ action: "deny", ruleId: "egress-allowlist", reason: `egress to non-allowlisted host(s): ${(extra.egressViolations as string[]).join(", ")}`, stage: "egress" });
        }
        if (secretTypes.length) {
          candidates.push({ action: "deny", ruleId: "secret-egress", reason: `arguments to an egress tool contain secrets (${secretTypes.join(", ")})`, stage: "secrets" });
        }
      }
      if (secretTypes.length && config.defenses.secrets.args === "block") {
        candidates.push({ action: "deny", ruleId: "secret-args", reason: `arguments contain secrets (${secretTypes.join(", ")})`, stage: "secrets" });
      }
      const p = this.policy.evaluate(ctx);
      if (p.errors.length) extra.policyErrors = p.errors;
      extra.matchedRules = p.matched.map((m) => m.id);
      candidates.push({ action: p.action, ruleId: p.ruleId, reason: p.reason, stage: "policy" });

      if (config.defenses.trifecta.enabled) {
        const after = new Set<Label>([...session.labels, ...labels]);
        const complete = LABELS.every((l) => after.has(l));
        const alreadyComplete = LABELS.every((l) => session.labels.has(l));
        if (complete && (labels.includes("egress") || !alreadyComplete)) {
          extra.trifecta = true;
          candidates.push({
            action: config.defenses.trifecta.action,
            ruleId: "lethal-trifecta",
            reason: "lethal trifecta: this session combines private data access, untrusted content and external egress",
            stage: "trifecta",
          });
        }
      }
      const lim = this.limits.check(ctx);
      if (!lim.ok) candidates.push({ action: "deny", ruleId: lim.limitId ?? null, reason: lim.reason ?? "limit exceeded", stage: "limits" });

      let winner = candidates[0] as Verdict;
      for (const c of candidates) if (SEVERITY[c.action] > SEVERITY[winner.action]) winner = c;
      s.setAttributes({ "agent_guard.decision": winner.action, "agent_guard.stage": winner.stage });
      return winner;
    });

    if (verdict.action === "deny") return deny(verdict.stage, verdict.reason, verdict.ruleId, extra);

    let approvalId: string | undefined;
    if (verdict.action === "require_approval") {
      const outcome = await this.child("agent_guard.approval", span, async (s) => {
        const req = this.deps.approvals.create(
          { agent: info.agent, sessionId: info.id, server: target.server, tool: target.tool, args: loggedArgs, reason: verdict.reason, ruleId: verdict.ruleId },
          config.approvals.timeoutSec * 1000,
        );
        s.setAttribute("agent_guard.approval_id", req.id);
        audit.append("approval_requested", { callId, approvalId: req.id, agent: info.agent, session: info.id, tool: exposedName, reason: verdict.reason, ruleId: verdict.ruleId });
        const summary = `${target.server}.${target.tool} — ${verdict.reason}`;
        log.warn(`approval required [${req.id}] ${summary} — run: agent-guard approve ${req.id}`);
        this.deps.onApprovalRequested?.(req.id, summary);
        const entry = await this.deps.approvals.waitForDecision(req.id, signal ? { signal } : {});
        s.setAttribute("agent_guard.approval_status", entry.status);
        audit.append("approval_resolved", { callId, approvalId: req.id, status: entry.status, by: entry.decision?.by ?? null });
        return entry;
      });
      approvalId = outcome.id;
      extra.approvalId = approvalId;
      if (outcome.status !== "approved") {
        return deny("approval", `human approval ${outcome.status} (${verdict.reason})`, verdict.ruleId, extra);
      }
    }

    // --- Forward. Secrets in args are redacted before they leave the gateway unless mode is "off". ---
    const forwardArgs = config.defenses.secrets.args === "off" ? args : argScan.value;
    this.limits.recordCall(ctx);
    session.calls++;
    let result: CallToolResult;
    try {
      result = await this.child("agent_guard.upstream_call", span, () => this.deps.backend.call(target.server, target.tool, forwardArgs, signal));
    } catch (e) {
      const message = (e as Error).message;
      audit.append("tool_call", { ...base, ...extra, decision: verdict.action, ruleId: verdict.ruleId, reason: verdict.reason, outcome: "upstream_error", error: message, durationMs: Date.now() - started });
      return this.blocked(`[agent-guard] Upstream error from ${exposedName}: ${message}`);
    }
    for (const l of labels) session.labels.add(l);

    // --- Output defenses. ---
    const processed = await this.child("agent_guard.output_scan", span, (s) => this.processOutput(exposedName, labels, result, s));
    if (processed.injection?.flagged) session.labels.add("untrusted_content");
    if (processed.outputSecrets.some((f) => f.kind === "secret")) session.labels.add("private_data");
    this.limits.recordOutput(ctx, processed.bytes);

    span.setAttributes({
      "agent_guard.decision": verdict.action,
      "agent_guard.injection.score": processed.injection?.score ?? 0,
      "agent_guard.redactions": processed.outputSecrets.length,
    });
    audit.append("tool_call", {
      ...base,
      ...extra,
      decision: verdict.action === "require_approval" ? "approved" : "allow",
      ruleId: verdict.ruleId,
      reason: verdict.reason,
      outcome: result.isError ? "tool_error" : "ok",
      output: {
        bytes: processed.bytes,
        redactions: countByType(processed.outputSecrets),
        imagesRemoved: processed.imagesRemoved,
        injection: processed.injection ? { score: processed.injection.score, flagged: processed.injection.flagged, signals: processed.injection.signals.map((x) => x.id), classifier: processed.classifier } : null,
        action: processed.action,
      },
      sessionLabelsAfter: [...session.labels],
      durationMs: Date.now() - started,
    });
    return processed.result;
  }

  private async processOutput(source: string, labels: Label[], result: CallToolResult, span: Span) {
    const { defenses } = this.config;
    const outputSecrets: RedactionFinding[] = [];
    const imagesRemoved: string[] = [];
    let bytes = 0;
    const texts: string[] = [];

    const cleanText = (text: string, path: string): string => {
      bytes += Buffer.byteLength(text);
      let t = text;
      if (defenses.secrets.outputs === "redact") {
        const r = redactText(t, { pii: defenses.secrets.pii }, path);
        outputSecrets.push(...r.findings);
        t = r.text;
      }
      if (defenses.egress.markdownImages === "strip") {
        const r = this.egress.stripImages(t);
        imagesRemoved.push(...r.removed);
        t = r.text;
      }
      texts.push(t);
      return t;
    };

    const content = (result.content ?? []).map((item, i) => {
      if (item.type === "text") return { ...item, text: cleanText(item.text, `$.content[${i}].text`) };
      if (item.type === "resource" && "text" in item.resource && typeof item.resource.text === "string") {
        return { ...item, resource: { ...item.resource, text: cleanText(item.resource.text, `$.content[${i}].resource.text`) } };
      }
      return item;
    });
    let structuredContent = result.structuredContent;
    if (structuredContent && defenses.secrets.outputs === "redact") {
      const r = redactValue(structuredContent, { pii: defenses.secrets.pii });
      outputSecrets.push(...r.findings.map((f) => ({ ...f, path: `$.structuredContent${f.path.slice(1)}` })));
      structuredContent = r.value;
      texts.push(JSON.stringify(structuredContent));
    }

    let injection: InjectionResult | null = null;
    let classifier: Record<string, unknown> | null = null;
    let action: "none" | "spotlight" | "block" | "warn" = "none";
    if (defenses.injection.enabled && texts.length > 0) {
      const joined = texts.join("\n");
      injection = scanForInjection(joined, { threshold: defenses.injection.threshold });
      const cls = defenses.injection.classifier;
      const inGray = injection.score >= cls.grayZoneMin && !injection.flagged;
      if (this.deps.classifier && cls.enabled && (cls.mode === "always" || inGray)) {
        try {
          const v = await this.deps.classifier.classify(joined);
          classifier = { name: this.deps.classifier.name, injection: v.injection, confidence: v.confidence };
          if (v.injection && v.confidence >= 0.5) {
            injection = {
              score: Math.max(injection.score, v.confidence),
              flagged: true,
              signals: [...injection.signals, { id: "llm_classifier", weight: v.confidence, excerpt: v.rationale.slice(0, 120) }],
            };
          }
        } catch (e) {
          classifier = { name: this.deps.classifier.name, error: (e as Error).message, failMode: cls.failMode };
          log.warn("injection classifier failed", { error: (e as Error).message, failMode: cls.failMode });
          if (cls.failMode === "closed") {
            injection = { ...injection, flagged: true, signals: [...injection.signals, { id: "classifier_unavailable", weight: 0, excerpt: "fail-closed" }] };
          }
        }
      }
      span.setAttributes({ "agent_guard.injection.score": injection.score, "agent_guard.injection.flagged": injection.flagged });
    }

    let finalContent = content;
    const signalIds = injection?.signals.map((s) => s.id) ?? [];
    if (injection?.flagged) {
      action = defenses.injection.action;
      if (action === "block") {
        finalContent = [{ type: "text", text: blockedNotice(source, injection.score, signalIds) }];
        structuredContent = undefined;
      } else if (action === "spotlight") {
        finalContent = content.map((c) => (c.type === "text" ? { ...c, text: spotlight(c.text, { source, risk: { score: injection?.score ?? 0, signals: signalIds } }) } : c));
      } else {
        finalContent = [{ type: "text", text: `[agent-guard] WARNING: possible prompt injection in output of "${source}" (score ${injection.score.toFixed(2)}; signals: ${signalIds.join(", ")}).` }, ...content];
      }
    } else if (defenses.injection.spotlightUntrusted && labels.includes("untrusted_content")) {
      action = "spotlight";
      finalContent = content.map((c) => (c.type === "text" ? { ...c, text: spotlight(c.text, { source }) } : c));
    }

    const out: CallToolResult = { ...result, content: finalContent };
    if (structuredContent === undefined) delete out.structuredContent;
    else out.structuredContent = structuredContent;
    return { result: out, outputSecrets, imagesRemoved, injection, classifier, action, bytes };
  }
}

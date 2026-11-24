import { startDashboard, type RunningDashboard } from "./approval/dashboard.js";
import { ApprovalStore } from "./approval/store.js";
import { AuditLog } from "./audit/log.js";
import type { LoadedConfig } from "./config/load.js";
import { AnthropicInjectionClassifier, type InjectionClassifier } from "./defense/classifier.js";
import { log } from "./logger.js";
import { Gateway } from "./proxy/gateway.js";
import { UpstreamManager } from "./proxy/upstream.js";
import { initTelemetry, type Telemetry } from "./telemetry.js";
import { VERSION } from "./version.js";

export interface Runtime {
  gateway: Gateway;
  upstreams: UpstreamManager;
  audit: AuditLog;
  approvals: ApprovalStore;
  dashboard: RunningDashboard | null;
  telemetry: Telemetry;
  close(): Promise<void>;
}

export function auditKey(loaded: LoadedConfig): Buffer | undefined {
  const envName = loaded.config.audit.hmacKeyEnv;
  if (!envName) return undefined;
  const v = process.env[envName];
  if (!v) throw new Error(`audit.hmacKeyEnv is set but environment variable ${envName} is empty`);
  return Buffer.from(v, "utf8");
}

export async function startRuntime(loaded: LoadedConfig, opts: { classifier?: InjectionClassifier } = {}): Promise<Runtime> {
  const { config } = loaded;
  const telemetry = initTelemetry({ otlpEndpoint: config.telemetry.otlpEndpoint, serviceName: config.telemetry.serviceName });
  const key = auditKey(loaded);
  const audit = new AuditLog(loaded.auditPath, key ? { hmacKey: key } : {});
  const approvals = new ApprovalStore(loaded.stateDir);

  let classifier = opts.classifier;
  const cls = config.defenses.injection.classifier;
  if (!classifier && cls.enabled) {
    classifier = new AnthropicInjectionClassifier({ model: cls.model, timeoutMs: cls.timeoutMs, maxChars: cls.maxChars });
    log.info(`LLM injection classifier enabled`, { model: cls.model, mode: cls.mode });
  }

  const upstreams = new UpstreamManager(config.upstreams, {
    separator: config.gateway.namespaceSeparator,
    clientName: config.gateway.name,
    clientVersion: VERSION,
  });
  const { connected, failed } = await upstreams.connect();
  const gateway = new Gateway({ config, backend: upstreams, audit, approvals, classifier, tracer: telemetry.tracer });
  gateway.inspectTools();
  audit.append("gateway_start", { version: VERSION, upstreams: connected, failedUpstreams: failed, tools: upstreams.tools().length });
  log.info(`connected ${connected.length}/${config.upstreams.length} upstream(s), ${upstreams.tools().length} tool(s)`);

  let dashboard: RunningDashboard | null = null;
  if (config.approvals.dashboard.enabled) {
    dashboard = await startDashboard(approvals, {
      host: config.approvals.dashboard.host,
      port: config.approvals.dashboard.port,
      ...(process.env.AGENT_GUARD_DASHBOARD_TOKEN ? { token: process.env.AGENT_GUARD_DASHBOARD_TOKEN } : {}),
    });
    log.info(`approval dashboard: ${dashboard.url}`);
  }

  return {
    gateway,
    upstreams,
    audit,
    approvals,
    dashboard,
    telemetry,
    close: async () => {
      audit.append("gateway_stop", {});
      await dashboard?.close();
      await upstreams.close();
      await telemetry.shutdown();
    },
  };
}

import { trace, type Tracer } from "@opentelemetry/api";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { resourceFromAttributes } from "@opentelemetry/resources";
import { BatchSpanProcessor, TracerProvider, type SpanProcessor } from "@opentelemetry/sdk-trace";

export const TRACER_NAME = "agent-guard";

export interface Telemetry {
  tracer: Tracer;
  shutdown(): Promise<void>;
}

/**
 * Registers an OTLP/HTTP trace exporter when an endpoint is configured (config or the standard
 * OTEL_EXPORTER_OTLP_ENDPOINT env var). Without one, spans go to the global no-op provider, or
 * to whatever provider the embedding application registered.
 */
export function initTelemetry(opts: { otlpEndpoint?: string | undefined; serviceName: string; processors?: SpanProcessor[] }): Telemetry {
  const endpoint = opts.otlpEndpoint ?? process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
  const processors = [...(opts.processors ?? [])];
  if (endpoint) {
    const url = endpoint.endsWith("/v1/traces") ? endpoint : `${endpoint.replace(/\/$/, "")}/v1/traces`;
    processors.push(new BatchSpanProcessor({ exporter: new OTLPTraceExporter({ url }) }));
  }
  if (processors.length === 0) {
    return { tracer: trace.getTracer(TRACER_NAME), shutdown: () => Promise.resolve() };
  }
  const provider = new TracerProvider({
    resource: resourceFromAttributes({ "service.name": opts.serviceName }),
    spanProcessors: processors,
  });
  trace.setGlobalTracerProvider(provider);
  return { tracer: provider.getTracer(TRACER_NAME), shutdown: () => provider.shutdown() };
}

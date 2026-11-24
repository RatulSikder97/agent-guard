import { z } from "zod";

const globList = z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]);
export const LABELS = ["private_data", "untrusted_content", "egress"] as const;
export type Label = (typeof LABELS)[number];
export const ACTIONS = ["allow", "deny", "require_approval"] as const;
export type Action = (typeof ACTIONS)[number];

const name = z.string().regex(/^[A-Za-z0-9_-]{1,32}$/, "must match [A-Za-z0-9_-]{1,32}");

const stdioUpstream = z
  .object({
    name,
    transport: z.literal("stdio"),
    command: z.string().min(1),
    args: z.array(z.string()).default([]),
    env: z.record(z.string(), z.string()).default({}),
    cwd: z.string().optional(),
  })
  .strict();

const httpUpstream = z
  .object({
    name,
    transport: z.literal("http"),
    url: z.string().min(1),
    headers: z.record(z.string(), z.string()).default({}),
  })
  .strict();

export const UpstreamSchema = z.discriminatedUnion("transport", [stdioUpstream, httpUpstream]);

const toolMatch = z
  .object({
    agent: globList.optional(),
    server: globList.optional(),
    tool: globList.optional(),
  })
  .strict();

export const ArgPredicateSchema = z
  .object({
    path: z.string().startsWith("$"),
    glob: z.string().optional(),
    regex: z.string().optional(),
    equals: z.union([z.string(), z.number(), z.boolean(), z.null()]).optional(),
    oneOf: z.array(z.union([z.string(), z.number(), z.boolean()])).optional(),
    host: globList.optional(),
    exists: z.boolean().optional(),
    not: z.boolean().default(false),
  })
  .strict()
  .refine(
    (p) => [p.glob, p.regex, p.equals, p.oneOf, p.host, p.exists].filter((x) => x !== undefined).length === 1,
    "each arg predicate needs exactly one of glob | regex | equals | oneOf | host | exists",
  );

export const RuleSchema = z
  .object({
    id: z.string().min(1),
    description: z.string().optional(),
    action: z.enum(ACTIONS),
    reason: z.string().optional(),
    match: toolMatch.extend({ args: z.array(ArgPredicateSchema).optional() }).strict()
      .prefault({}),
    when: z.string().optional(),
  })
  .strict();

export const LimitSchema = z
  .object({
    id: z.string().min(1),
    match: toolMatch.prefault({}),
    rate: z.object({ max: z.number().int().positive(), windowSec: z.number().positive() }).strict().optional(),
    budget: z
      .object({
        maxCalls: z.number().int().positive().optional(),
        maxOutputBytes: z.number().int().positive().optional(),
      })
      .strict()
      .optional(),
  })
  .strict();

export const ConfigSchema = z
  .object({
    version: z.literal(1),
    gateway: z
      .object({
        name: z.string().default("agent-guard"),
        namespaceSeparator: z.string().regex(/^[_.-]{1,3}$/).default("__"),
        stateDir: z.string().default(".agent-guard"),
      })
      .strict()
      .prefault({}),
    upstreams: z.array(UpstreamSchema).min(1),
    agents: z
      .record(
        name,
        z
          .object({
            tokenEnv: z.string().optional(),
            capabilities: z.array(z.string().min(1)).default(["*"]),
          })
          .strict(),
      )
      .default({ default: { capabilities: ["*"] } }),
    defaultAgent: z.string().default("default"),
    labels: z
      .array(z.object({ match: toolMatch, labels: z.array(z.enum(LABELS)).min(1) }).strict())
      .default([]),
    policy: z
      .object({
        default: z.enum(ACTIONS).default("deny"),
        rules: z.array(RuleSchema).default([]),
        limits: z.array(LimitSchema).default([]),
      })
      .strict()
      .prefault({}),
    defenses: z
      .object({
        secrets: z
          .object({
            args: z.enum(["redact", "block", "off"]).default("redact"),
            outputs: z.enum(["redact", "off"]).default("redact"),
            pii: z.boolean().default(true),
          })
          .strict()
      .prefault({}),
        injection: z
          .object({
            enabled: z.boolean().default(true),
            threshold: z.number().min(0).max(1).default(0.5),
            action: z.enum(["spotlight", "block", "warn"]).default("spotlight"),
            spotlightUntrusted: z.boolean().default(true),
            scanToolDescriptions: z.boolean().default(true),
            classifier: z
              .object({
                enabled: z.boolean().default(false),
                model: z.string().default("claude-haiku-5-5"),
                mode: z.enum(["gray-zone", "always"]).default("gray-zone"),
                grayZoneMin: z.number().min(0).max(1).default(0.2),
                timeoutMs: z.number().int().positive().default(10_000),
                failMode: z.enum(["open", "closed"]).default("open"),
                maxChars: z.number().int().positive().default(24_000),
              })
              .strict()
      .prefault({}),
          })
          .strict()
      .prefault({}),
        egress: z
          .object({
            allow: z.array(z.string().min(1)).default([]),
            markdownImages: z.enum(["strip", "off"]).default("strip"),
          })
          .strict()
      .prefault({}),
        trifecta: z
          .object({
            enabled: z.boolean().default(true),
            action: z.enum(["require_approval", "deny"]).default("require_approval"),
          })
          .strict()
      .prefault({}),
      })
      .strict()
      .prefault({}),
    approvals: z
      .object({
        timeoutSec: z.number().positive().default(120),
        dashboard: z
          .object({
            enabled: z.boolean().default(false),
            host: z.string().default("127.0.0.1"),
            port: z.number().int().min(0).max(65535).default(8788),
          })
          .strict()
      .prefault({}),
      })
      .strict()
      .prefault({}),
    audit: z
      .object({
        path: z.string().optional(),
        hmacKeyEnv: z.string().optional(),
      })
      .strict()
      .prefault({}),
    telemetry: z
      .object({
        otlpEndpoint: z.string().url().optional(),
        serviceName: z.string().default("agent-guard"),
      })
      .strict()
      .prefault({}),
  })
  .strict();

export type Config = z.infer<typeof ConfigSchema>;
export type ConfigInput = z.input<typeof ConfigSchema>;
export type Upstream = z.infer<typeof UpstreamSchema>;
export type Rule = z.infer<typeof RuleSchema>;
export type Limit = z.infer<typeof LimitSchema>;
export type ArgPredicate = z.infer<typeof ArgPredicateSchema>;
export type ToolMatch = z.infer<typeof toolMatch>;

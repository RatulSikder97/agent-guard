import { createHash } from "node:crypto";

export type FindingKind = "secret" | "pii";

export interface RedactionFinding {
  type: string;
  kind: FindingKind;
  /** JSONPath-ish location inside the scanned value. */
  path: string;
  /** Short SHA-256 prefix of the matched text, for correlation without disclosure. */
  fingerprint: string;
}

interface Detector {
  type: string;
  kind: FindingKind;
  re: RegExp;
  /** Index of the capture group holding the sensitive part; 0 = whole match. */
  group?: number;
  validate?: (match: string) => boolean;
}

function luhn(digits: string): boolean {
  const d = digits.replace(/\D/g, "");
  if (d.length < 13 || d.length > 19) return false;
  let sum = 0;
  for (let i = 0; i < d.length; i++) {
    let n = Number(d[d.length - 1 - i]);
    if (i % 2 === 1) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
  }
  return sum % 10 === 0;
}

/** Order matters: more specific detectors run first so their redactions are not re-labelled. */
const DETECTORS: Detector[] = [
  {
    type: "private_key",
    kind: "secret",
    re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----/g,
  },
  { type: "anthropic_api_key", kind: "secret", re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g },
  { type: "openai_api_key", kind: "secret", re: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}/g },
  { type: "github_token", kind: "secret", re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g },
  { type: "aws_access_key_id", kind: "secret", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  {
    type: "aws_secret_access_key",
    kind: "secret",
    re: /\b(?:aws_?secret_?access_?key|aws_?secret)\b["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/gi,
    group: 1,
  },
  { type: "slack_token", kind: "secret", re: /\bxox[abposr]-[A-Za-z0-9-]{10,}/g },
  { type: "stripe_key", kind: "secret", re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  { type: "google_api_key", kind: "secret", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { type: "jwt", kind: "secret", re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g },
  { type: "auth_header", kind: "secret", re: /\bAuthorization:\s*(?:Bearer|Basic|Token)\s+([A-Za-z0-9._~+/=-]{12,})/gi, group: 1 },
  { type: "url_credentials", kind: "secret", re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:([^\s@/]+)@/gi, group: 1 },
  {
    type: "generic_secret",
    kind: "secret",
    re: /\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b["']?\s*[:=]\s*["']?([^\s"',;}{]{8,})/gi,
    group: 1,
    validate: (m) => !m.startsWith("[REDACTED"),
  },
  { type: "email", kind: "pii", re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { type: "credit_card", kind: "pii", re: /\b(?:\d[ -]?){12,18}\d\b/g, validate: luhn },
  { type: "us_ssn", kind: "pii", re: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g },
];

export interface RedactOptions {
  pii?: boolean;
  /** Skip detector types entirely (e.g. allow emails for a mail tool). */
  ignore?: readonly string[];
}

function fingerprint(s: string): string {
  return createHash("sha256").update(s).digest("hex").slice(0, 12);
}

export function redactText(
  text: string,
  opts: RedactOptions = {},
  path = "$",
): { text: string; findings: RedactionFinding[] } {
  const findings: RedactionFinding[] = [];
  let out = text;
  for (const d of DETECTORS) {
    if (d.kind === "pii" && opts.pii === false) continue;
    if (opts.ignore?.includes(d.type)) continue;
    d.re.lastIndex = 0;
    out = out.replace(d.re, (match: string, ...rest: unknown[]) => {
      const g = d.group ? (rest[d.group - 1] as string | undefined) : undefined;
      const sensitive = g ?? match;
      if (d.validate && !d.validate(sensitive)) return match;
      findings.push({ type: d.type, kind: d.kind, path, fingerprint: fingerprint(sensitive) });
      const label = `[REDACTED:${d.type}]`;
      return g !== undefined ? match.replace(g, label) : label;
    });
  }
  return { text: out, findings };
}

/** Recursively redacts every string leaf in a JSON-like value. Returns a new value. */
export function redactValue<T>(value: T, opts: RedactOptions = {}): { value: T; findings: RedactionFinding[] } {
  const findings: RedactionFinding[] = [];
  const walk = (v: unknown, path: string, depth: number): unknown => {
    if (depth > 64) return v;
    if (typeof v === "string") {
      const r = redactText(v, opts, path);
      findings.push(...r.findings);
      return r.text;
    }
    if (Array.isArray(v)) return v.map((x, i) => walk(x, `${path}[${i}]`, depth + 1));
    if (v && typeof v === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, x] of Object.entries(v as Record<string, unknown>)) out[k] = walk(x, `${path}.${k}`, depth + 1);
      return out;
    }
    return v;
  };
  return { value: walk(value, "$", 0) as T, findings };
}

export const DETECTOR_TYPES: readonly string[] = DETECTORS.map((d) => d.type);

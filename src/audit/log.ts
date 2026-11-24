import { createHash, createHmac } from "node:crypto";
import { closeSync, existsSync, fstatSync, mkdirSync, openSync, readSync, readFileSync, rmSync, statSync, writeSync } from "node:fs";
import { dirname } from "node:path";

export const GENESIS_HASH = "0".repeat(64);

export interface AuditRecord {
  seq: number;
  ts: string;
  type: string;
  prevHash: string;
  hash: string;
  [key: string]: unknown;
}

/** Deterministic JSON: object keys sorted recursively, no whitespace. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map((v) => canonicalJson(v === undefined ? null : v)).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
}

function digest(prevHash: string, body: Record<string, unknown>, key?: Buffer): string {
  const payload = `${prevHash}\n${canonicalJson(body)}`;
  return key ? createHmac("sha256", key).update(payload).digest("hex") : createHash("sha256").update(payload).digest("hex");
}

/** Reads the last non-empty line of a file without loading the whole file. */
function readLastLine(path: string): string | null {
  if (!existsSync(path)) return null;
  const fd = openSync(path, "r");
  try {
    const size = fstatSync(fd).size;
    if (size === 0) return null;
    let chunk = 4096;
    for (;;) {
      const start = Math.max(0, size - chunk);
      const buf = Buffer.alloc(size - start);
      readSync(fd, buf, 0, buf.length, start);
      const text = buf.toString("utf8").replace(/\n+$/, "");
      const nl = text.lastIndexOf("\n");
      if (nl >= 0 || start === 0) return text.slice(nl + 1) || null;
      chunk *= 4;
    }
  } finally {
    closeSync(fd);
  }
}

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

export interface AuditLogOptions {
  /** Optional HMAC key: without it the chain detects edits but an attacker with write access can re-hash. */
  hmacKey?: Buffer;
}

/**
 * Append-only, hash-chained JSONL audit log. Each record commits to the previous record's hash,
 * so editing, deleting or reordering any line breaks verification from that point on.
 * Safe for several gateway processes sharing one file (cross-process lock around append).
 */
export class AuditLog {
  private readonly lockPath: string;

  constructor(
    readonly path: string,
    private readonly opts: AuditLogOptions = {},
  ) {
    mkdirSync(dirname(path), { recursive: true });
    this.lockPath = `${path}.lock`;
  }

  private withLock<T>(fn: () => T): T {
    const deadline = Date.now() + 5000;
    for (;;) {
      try {
        const fd = openSync(this.lockPath, "wx");
        closeSync(fd);
        break;
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
        try {
          if (Date.now() - statSync(this.lockPath).mtimeMs > 5000) rmSync(this.lockPath, { force: true });
        } catch {
          // lock vanished between checks; retry
        }
        if (Date.now() > deadline) throw new Error(`could not acquire audit log lock ${this.lockPath}`, { cause: e });
        sleepSync(5);
      }
    }
    try {
      return fn();
    } finally {
      rmSync(this.lockPath, { force: true });
    }
  }

  append(type: string, data: Record<string, unknown>): AuditRecord {
    return this.withLock(() => {
      const last = readLastLine(this.path);
      let prevHash = GENESIS_HASH;
      let seq = 0;
      if (last) {
        const parsed = JSON.parse(last) as AuditRecord;
        prevHash = parsed.hash;
        seq = parsed.seq + 1;
      }
      const body: Record<string, unknown> = { ...data, seq, ts: new Date().toISOString(), type, prevHash };
      const record = { ...body, hash: digest(prevHash, body, this.opts.hmacKey) } as AuditRecord;
      const fd = openSync(this.path, "a", 0o600);
      try {
        writeSync(fd, `${JSON.stringify(record)}\n`);
      } finally {
        closeSync(fd);
      }
      return record;
    });
  }
}

export interface VerifyResult {
  ok: boolean;
  records: number;
  headHash: string;
  error?: { line: number; reason: string };
}

export function verifyAuditLog(path: string, opts: AuditLogOptions = {}): VerifyResult {
  const lines = readFileSync(path, "utf8").split("\n");
  let prevHash = GENESIS_HASH;
  let expectedSeq = 0;
  let count = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] as string;
    if (line.trim() === "") {
      if (i === lines.length - 1) continue;
      return { ok: false, records: count, headHash: prevHash, error: { line: i + 1, reason: "blank line inside log" } };
    }
    let rec: AuditRecord;
    try {
      rec = JSON.parse(line) as AuditRecord;
    } catch {
      return { ok: false, records: count, headHash: prevHash, error: { line: i + 1, reason: "invalid JSON" } };
    }
    if (rec.seq !== expectedSeq) {
      return { ok: false, records: count, headHash: prevHash, error: { line: i + 1, reason: `expected seq ${expectedSeq}, found ${String(rec.seq)}` } };
    }
    if (rec.prevHash !== prevHash) {
      return { ok: false, records: count, headHash: prevHash, error: { line: i + 1, reason: "prevHash does not match previous record (line removed, reordered or inserted)" } };
    }
    const { hash, ...body } = rec;
    if (digest(prevHash, body, opts.hmacKey) !== hash) {
      return { ok: false, records: count, headHash: prevHash, error: { line: i + 1, reason: "hash mismatch (record modified)" } };
    }
    prevHash = hash;
    expectedSeq++;
    count++;
  }
  return { ok: true, records: count, headHash: prevHash };
}

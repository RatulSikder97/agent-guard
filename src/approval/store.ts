import { randomBytes } from "node:crypto";
import { closeSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, writeFileSync, writeSync } from "node:fs";
import { join } from "node:path";

export type ApprovalStatus = "pending" | "approved" | "denied" | "expired";

export interface ApprovalRequest {
  id: string;
  createdAt: string;
  expiresAt: string;
  agent: string;
  sessionId: string;
  server: string;
  tool: string;
  /** Already redacted and truncated by the gateway. */
  args: unknown;
  reason: string;
  ruleId: string | null;
}

export interface ApprovalDecision {
  status: Exclude<ApprovalStatus, "pending">;
  decidedAt: string;
  by: string;
  note?: string;
}

export interface ApprovalEntry extends ApprovalRequest {
  status: ApprovalStatus;
  decision?: ApprovalDecision;
}

const ID_RE = /^[a-z0-9]{10}$/;

export class ApprovalError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ApprovalError";
  }
}

/**
 * File-backed approval queue shared between the gateway process, the CLI and the dashboard.
 * Requests are immutable files; a decision is a separate file created with O_EXCL, so the first
 * decider (human approve/deny vs. gateway timeout) wins atomically.
 */
export class ApprovalStore {
  readonly dir: string;

  constructor(stateDir: string) {
    this.dir = join(stateDir, "approvals");
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
  }

  private requestPath(id: string) {
    return join(this.dir, `${id}.request.json`);
  }
  private decisionPath(id: string) {
    return join(this.dir, `${id}.decision.json`);
  }

  static validateId(id: string): string {
    if (!ID_RE.test(id)) throw new ApprovalError(`invalid approval id '${id}'`);
    return id;
  }

  create(req: Omit<ApprovalRequest, "id" | "createdAt" | "expiresAt">, timeoutMs: number): ApprovalRequest {
    const id = randomBytes(8).readBigUInt64BE().toString(36).padStart(13, "0").slice(-10);
    const now = Date.now();
    const full: ApprovalRequest = {
      ...req,
      id,
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + timeoutMs).toISOString(),
    };
    const tmp = `${this.requestPath(id)}.tmp`;
    writeFileSync(tmp, JSON.stringify(full, null, 2), { mode: 0o600 });
    renameSync(tmp, this.requestPath(id));
    return full;
  }

  get(id: string): ApprovalEntry | null {
    ApprovalStore.validateId(id);
    let req: ApprovalRequest;
    try {
      req = JSON.parse(readFileSync(this.requestPath(id), "utf8")) as ApprovalRequest;
    } catch {
      return null;
    }
    const decision = this.readDecision(id);
    if (decision) return { ...req, status: decision.status, decision };
    return { ...req, status: Date.parse(req.expiresAt) <= Date.now() ? "expired" : "pending" };
  }

  private readDecision(id: string): ApprovalDecision | null {
    try {
      return JSON.parse(readFileSync(this.decisionPath(id), "utf8")) as ApprovalDecision;
    } catch {
      return null;
    }
  }

  /** Records a decision. Returns false if the request was already decided. */
  decide(id: string, status: ApprovalDecision["status"], by: string, note?: string): boolean {
    const entry = this.get(id);
    if (!entry) throw new ApprovalError(`no approval request '${id}'`);
    if (status !== "expired" && entry.status === "expired") {
      throw new ApprovalError(`approval '${id}' already expired (default deny)`);
    }
    const decision: ApprovalDecision = { status, decidedAt: new Date().toISOString(), by, ...(note ? { note } : {}) };
    let fd: number;
    try {
      fd = openSync(this.decisionPath(id), "wx", 0o600);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "EEXIST") return false;
      throw e;
    }
    try {
      writeSync(fd, JSON.stringify(decision, null, 2));
    } finally {
      closeSync(fd);
    }
    return true;
  }

  list(filter?: ApprovalStatus): ApprovalEntry[] {
    const ids = readdirSync(this.dir)
      .filter((f) => f.endsWith(".request.json"))
      .map((f) => f.slice(0, -".request.json".length))
      .filter((id) => ID_RE.test(id));
    const entries = ids.map((id) => this.get(id)).filter((e): e is ApprovalEntry => e !== null);
    entries.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    return filter ? entries.filter((e) => e.status === filter) : entries;
  }

  /** Waits for a human decision; on timeout records `expired` (default deny). */
  async waitForDecision(id: string, opts: { pollMs?: number; signal?: AbortSignal } = {}): Promise<ApprovalEntry> {
    const pollMs = opts.pollMs ?? 200;
    for (;;) {
      const entry = this.get(id);
      if (!entry) throw new ApprovalError(`approval '${id}' disappeared`);
      if (entry.decision) return entry;
      if (entry.status === "expired" || opts.signal?.aborted) {
        this.decide(id, "expired", "gateway", opts.signal?.aborted ? "request cancelled" : "timed out");
        const final = this.get(id);
        if (!final) throw new ApprovalError(`approval '${id}' disappeared`);
        return final;
      }
      await new Promise((r) => setTimeout(r, pollMs));
    }
  }
}

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { startDashboard, type RunningDashboard } from "../../src/approval/dashboard.js";
import { ApprovalError, ApprovalStore } from "../../src/approval/store.js";

const store = () => new ApprovalStore(mkdtempSync(join(tmpdir(), "ag-approvals-")));
const req = { agent: "a", sessionId: "s", server: "corp", tool: "send_email", args: { to: "x@y.z" }, reason: "external email", ruleId: "r1" };

describe("ApprovalStore", () => {
  it("creates pending requests and records the first decision only", () => {
    const s = store();
    const r = s.create(req, 60_000);
    expect(r.id).toMatch(/^[a-z0-9]{10}$/);
    expect(s.get(r.id)?.status).toBe("pending");
    expect(s.list("pending")).toHaveLength(1);
    expect(s.decide(r.id, "approved", "cli")).toBe(true);
    expect(s.decide(r.id, "denied", "cli")).toBe(false);
    expect(s.get(r.id)).toMatchObject({ status: "approved", decision: { by: "cli" } });
  });

  it("expires to default-deny and refuses late approvals", async () => {
    const s = store();
    const r = s.create(req, 50);
    const entry = await s.waitForDecision(r.id, { pollMs: 10 });
    expect(entry.status).toBe("expired");
    expect(() => s.decide(r.id, "approved", "cli")).toThrow(ApprovalError);
  });

  it("resolves when a decision arrives while waiting", async () => {
    const s = store();
    const r = s.create(req, 5_000);
    setTimeout(() => s.decide(r.id, "denied", "cli", "nope"), 30);
    const entry = await s.waitForDecision(r.id, { pollMs: 10 });
    expect(entry).toMatchObject({ status: "denied", decision: { note: "nope" } });
  });

  it("validates ids (no path traversal)", () => {
    const s = store();
    expect(() => s.get("../../etc/passwd")).toThrow(ApprovalError);
    expect(() => s.decide("ABC", "approved", "cli")).toThrow(ApprovalError);
    expect(() => s.decide("aaaaaaaaaa", "approved", "cli")).toThrow(/no approval request/);
  });
});

describe("approval dashboard", () => {
  let dash: RunningDashboard | undefined;
  afterEach(async () => {
    await dash?.close();
    dash = undefined;
  });

  it("serves the UI, requires the token and records decisions", async () => {
    const s = store();
    const r = s.create(req, 60_000);
    dash = await startDashboard(s, { host: "127.0.0.1", port: 0, token: "t".repeat(32) });
    const base = dash.url.split("/#")[0] as string;
    const auth = { Authorization: `Bearer ${"t".repeat(32)}` };

    const page = await fetch(`${base}/`);
    expect(page.status).toBe(200);
    expect(page.headers.get("content-security-policy")).toContain("script-src 'self'");
    expect((await fetch(`${base}/app.js`)).status).toBe(200);

    expect((await fetch(`${base}/api/approvals`)).status).toBe(401);
    expect((await fetch(`${base}/api/approvals`, { headers: { Authorization: "Bearer wrong" } })).status).toBe(401);
    const list = (await (await fetch(`${base}/api/approvals`, { headers: auth })).json()) as { approvals: { id: string }[] };
    expect(list.approvals.map((a) => a.id)).toEqual([r.id]);

    // CSRF guard: POST without the custom header is refused.
    expect((await fetch(`${base}/api/approvals/${r.id}/approve`, { method: "POST", headers: auth })).status).toBe(403);
    const ok = await fetch(`${base}/api/approvals/${r.id}/approve`, { method: "POST", headers: { ...auth, "X-Agent-Guard": "1" } });
    expect(ok.status).toBe(200);
    expect(s.get(r.id)).toMatchObject({ status: "approved", decision: { by: "dashboard" } });
    const again = await fetch(`${base}/api/approvals/${r.id}/deny`, { method: "POST", headers: { ...auth, "X-Agent-Guard": "1" } });
    expect(again.status).toBe(409);
  });

  it("rejects requests with a foreign Host header (DNS rebinding)", async () => {
    dash = await startDashboard(store(), { host: "127.0.0.1", port: 0 });
    const base = dash.url.split("/#")[0] as string;
    const { request } = await import("node:http");
    const status = await new Promise<number>((resolve, reject) => {
      const u = new URL(base);
      request({ host: u.hostname, port: u.port, path: "/", headers: { Host: "evil.example:80" } }, (res) => resolve(res.statusCode ?? 0))
        .on("error", reject)
        .end();
    });
    expect(status).toBe(421);
  });
});

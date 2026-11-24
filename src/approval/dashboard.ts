import { randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { ApprovalError, ApprovalStore } from "./store.js";

export interface DashboardOptions {
  host: string;
  port: number;
  /** Bearer token; random per start when omitted. */
  token?: string;
  onDecision?: (id: string, status: "approved" | "denied") => void;
}

export interface RunningDashboard {
  url: string;
  token: string;
  close(): Promise<void>;
}

const HTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>agent-guard approvals</title>
<style>
:root{--bg:#0f1115;--fg:#e6e6e6;--muted:#8a8f98;--card:#171a21;--border:#262a33;--ok:#3fb950;--bad:#f85149;--warn:#d29922}
@media (prefers-color-scheme: light){:root{--bg:#f6f7f9;--fg:#1d2127;--muted:#5d6470;--card:#fff;--border:#dde1e6}}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;background:var(--bg);color:var(--fg)}
main{max-width:960px;margin:0 auto;padding:24px 16px}h1{font-size:18px;margin:0 0 4px}p.sub{color:var(--muted);margin:0 0 20px}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px 16px;margin-bottom:12px}
.row{display:flex;gap:12px;align-items:center;flex-wrap:wrap}.tool{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:600}
.pill{font-size:12px;padding:1px 8px;border-radius:99px;border:1px solid var(--border);color:var(--muted)}
.pending{color:var(--warn);border-color:var(--warn)}.approved{color:var(--ok);border-color:var(--ok)}.denied,.expired{color:var(--bad);border-color:var(--bad)}
pre{background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:10px;overflow:auto;max-height:240px;font-size:12px;margin:10px 0}
button{font:inherit;padding:6px 14px;border-radius:6px;border:1px solid var(--border);background:transparent;color:var(--fg);cursor:pointer}
button.approve{border-color:var(--ok);color:var(--ok)}button.deny{border-color:var(--bad);color:var(--bad)}.spacer{flex:1}.muted{color:var(--muted)}
</style></head><body><main>
<h1>agent-guard &middot; approval queue</h1><p class="sub">Tool calls held for human review. Unanswered requests are denied when they expire.</p>
<div id="list"><p class="muted">Loading&hellip;</p></div></main>
<script src="/app.js"></script></body></html>`;

// All untrusted fields (tool args, reasons) are rendered via textContent, never innerHTML.
const APP_JS = `(() => {
  const params = new URLSearchParams(location.hash.slice(1) || location.search.slice(1));
  const token = params.get("token") || sessionStorage.getItem("ag-token") || "";
  if (token) sessionStorage.setItem("ag-token", token);
  history.replaceState(null, "", "/");
  const h = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };
  async function api(path, opts = {}) {
    const res = await fetch(path, { ...opts, headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json", "X-Agent-Guard": "1" } });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || res.statusText);
    return res.json();
  }
  async function decide(id, action) {
    try { await api("/api/approvals/" + id + "/" + action, { method: "POST", body: "{}" }); } catch (e) { alert(e.message); }
    load();
  }
  async function load() {
    const list = document.getElementById("list");
    let data;
    try { data = await api("/api/approvals"); } catch (e) { list.replaceChildren(h("p", "muted", "Error: " + e.message)); return; }
    if (!data.approvals.length) { list.replaceChildren(h("p", "muted", "No approval requests yet.")); return; }
    list.replaceChildren(...data.approvals.map((a) => {
      const card = h("div", "card");
      const row = h("div", "row");
      row.append(h("span", "tool", a.server + "." + a.tool), h("span", "pill " + a.status, a.status), h("span", "muted", "agent " + a.agent), h("span", "spacer"), h("span", "muted", a.id));
      card.append(row, h("div", "", a.reason), h("pre", "", JSON.stringify(a.args, null, 2)));
      const meta = h("div", "row");
      meta.append(h("span", "muted", "expires " + new Date(a.expiresAt).toLocaleTimeString()));
      if (a.decision) meta.append(h("span", "muted", a.decision.status + " by " + a.decision.by));
      if (a.status === "pending") {
        const ok = h("button", "approve", "Approve"); ok.onclick = () => decide(a.id, "approve");
        const no = h("button", "deny", "Deny"); no.onclick = () => decide(a.id, "deny");
        meta.append(h("span", "spacer"), no, ok);
      }
      card.append(meta);
      return card;
    }));
  }
  load(); setInterval(load, 2000);
})();`;

function send(res: ServerResponse, status: number, body: unknown, type = "application/json") {
  res.writeHead(status, {
    "Content-Type": `${type}; charset=utf-8`,
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'",
  });
  res.end(type === "application/json" ? JSON.stringify(body) : String(body));
}

function tokenOk(req: IncomingMessage, token: string): boolean {
  const header = req.headers.authorization ?? "";
  const given = Buffer.from(header.startsWith("Bearer ") ? header.slice(7) : "");
  const want = Buffer.from(token);
  return given.length === want.length && timingSafeEqual(given, want);
}

/** Minimal approval dashboard. Binds to loopback by default; every API call needs the bearer token. */
export async function startDashboard(store: ApprovalStore, opts: DashboardOptions): Promise<RunningDashboard> {
  const token = opts.token ?? randomBytes(24).toString("base64url");
  let allowedHosts: Set<string> = new Set();

  const handler = (req: IncomingMessage, res: ServerResponse) => {
    // DNS-rebinding defence: only answer to the exact host:port we bound.
    if (!allowedHosts.has(req.headers.host ?? "")) return send(res, 421, { error: "misdirected request" });
    const url = new URL(req.url ?? "/", "http://localhost");
    if (req.method === "GET" && url.pathname === "/") return send(res, 200, HTML, "text/html");
    if (req.method === "GET" && url.pathname === "/app.js") return send(res, 200, APP_JS, "text/javascript");
    if (!url.pathname.startsWith("/api/")) return send(res, 404, { error: "not found" });
    if (!tokenOk(req, token)) return send(res, 401, { error: "missing or invalid token" });
    if (req.method === "GET" && url.pathname === "/api/approvals") {
      return send(res, 200, { approvals: store.list().slice(0, 100) });
    }
    const m = /^\/api\/approvals\/([a-z0-9]+)\/(approve|deny)$/.exec(url.pathname);
    if (req.method === "POST" && m) {
      // Custom header => browsers must preflight cross-origin requests, which we never allow (CSRF defence).
      if (req.headers["x-agent-guard"] !== "1") return send(res, 403, { error: "missing X-Agent-Guard header" });
      const [, id, action] = m as unknown as [string, string, "approve" | "deny"];
      try {
        const status = action === "approve" ? "approved" : "denied";
        const ok = store.decide(ApprovalStore.validateId(id), status, "dashboard");
        if (!ok) return send(res, 409, { error: "already decided" });
        opts.onDecision?.(id, status);
        return send(res, 200, { id, status });
      } catch (e) {
        return send(res, e instanceof ApprovalError ? 400 : 500, { error: (e as Error).message });
      }
    }
    return send(res, 404, { error: "not found" });
  };

  const server: Server = createServer(handler);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(opts.port, opts.host, () => resolve());
  });
  const port = (server.address() as AddressInfo).port;
  const hostForUrl = opts.host.includes(":") ? `[${opts.host}]` : opts.host;
  allowedHosts = new Set([`${hostForUrl}:${port}`, `localhost:${port}`, `127.0.0.1:${port}`]);
  return {
    url: `http://${hostForUrl}:${port}/#token=${token}`,
    token,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { AuditLog, canonicalJson, GENESIS_HASH, verifyAuditLog } from "../../src/audit/log.js";

const tmp = () => join(mkdtempSync(join(tmpdir(), "ag-audit-")), "audit.jsonl");

describe("canonicalJson", () => {
  it("sorts keys recursively and drops undefined", () => {
    expect(canonicalJson({ b: 1, a: { d: [1, { z: 1, y: 2 }], c: undefined } })).toBe('{"a":{"d":[1,{"y":2,"z":1}]},"b":1}');
  });
});

describe("hash-chained audit log", () => {
  function write(path: string, n: number, key?: Buffer) {
    const log = new AuditLog(path, key ? { hmacKey: key } : {});
    for (let i = 0; i < n; i++) log.append("tool_call", { i, tool: `t${i}` });
    return log;
  }

  it("chains records and verifies", () => {
    const p = tmp();
    write(p, 5);
    const lines = readFileSync(p, "utf8").trim().split("\n").map((l) => JSON.parse(l) as { seq: number; prevHash: string; hash: string });
    expect(lines[0]?.prevHash).toBe(GENESIS_HASH);
    expect(lines[1]?.prevHash).toBe(lines[0]?.hash);
    expect(lines.map((l) => l.seq)).toEqual([0, 1, 2, 3, 4]);
    expect(verifyAuditLog(p)).toMatchObject({ ok: true, records: 5, headHash: lines[4]?.hash });
  });

  it("continues the chain across instances", () => {
    const p = tmp();
    write(p, 2);
    write(p, 2);
    expect(verifyAuditLog(p)).toMatchObject({ ok: true, records: 4 });
  });

  it("detects a modified record", () => {
    const p = tmp();
    write(p, 4);
    const lines = readFileSync(p, "utf8").split("\n");
    lines[2] = (lines[2] as string).replace('"tool":"t2"', '"tool":"tX"');
    writeFileSync(p, lines.join("\n"));
    expect(verifyAuditLog(p)).toMatchObject({ ok: false, records: 2, error: { line: 3, reason: expect.stringMatching(/hash mismatch/) as unknown } });
  });

  it("detects a deleted record", () => {
    const p = tmp();
    write(p, 4);
    const lines = readFileSync(p, "utf8").split("\n");
    lines.splice(1, 1);
    writeFileSync(p, lines.join("\n"));
    expect(verifyAuditLog(p)).toMatchObject({ ok: false, error: { line: 2 } });
  });

  it("detects reordering and garbage", () => {
    const p = tmp();
    write(p, 3);
    const lines = readFileSync(p, "utf8").trim().split("\n");
    writeFileSync(p, [lines[1], lines[0], lines[2]].join("\n") + "\n");
    expect(verifyAuditLog(p).ok).toBe(false);
    writeFileSync(p, "not json\n");
    expect(verifyAuditLog(p).error?.reason).toBe("invalid JSON");
  });

  it("with an HMAC key, a fully re-hashed forgery still fails", () => {
    const p = tmp();
    const key = Buffer.from("k".repeat(32));
    write(p, 3, key);
    expect(verifyAuditLog(p, { hmacKey: key }).ok).toBe(true);
    // Attacker rewrites the whole file with a self-consistent plain SHA-256 chain.
    const forged = tmp();
    write(forged, 3);
    expect(verifyAuditLog(forged, { hmacKey: key }).ok).toBe(false);
    expect(verifyAuditLog(p).ok).toBe(false);
  });

  it("serializes concurrent appends from separate instances", async () => {
    const p = tmp();
    const a = new AuditLog(p);
    const b = new AuditLog(p);
    await Promise.all(Array.from({ length: 50 }, (_, i) => Promise.resolve().then(() => (i % 2 ? a : b).append("e", { i }))));
    expect(verifyAuditLog(p)).toMatchObject({ ok: true, records: 50 });
  });
});

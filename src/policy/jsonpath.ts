/**
 * Minimal, eval-free JSONPath subset for selecting values out of tool arguments.
 *
 * Supported: `$`, `.name`, `['name']` / `["name"]`, `[3]`, `[-1]`, `[*]`, `.*`, `..name`, `..*`.
 * Filter expressions (`[?(...)]`) are intentionally NOT supported: several popular JSONPath
 * libraries implemented them with `eval`, which is how they ended up with RCE advisories.
 * Use a policy `when:` expression for filtering instead.
 */

type Segment =
  | { kind: "child"; key: string }
  | { kind: "index"; index: number }
  | { kind: "wildcard" }
  | { kind: "descend"; key: string | null };

const FORBIDDEN = new Set(["__proto__", "constructor", "prototype"]);
const cache = new Map<string, Segment[]>();

export class JsonPathError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JsonPathError";
  }
}

export function parseJsonPath(path: string): Segment[] {
  const cached = cache.get(path);
  if (cached) return cached;
  if (!path.startsWith("$")) throw new JsonPathError(`JSONPath must start with '$': ${path}`);
  const segs: Segment[] = [];
  let i = 1;
  const ident = /^[A-Za-z_$][A-Za-z0-9_$-]*/;
  while (i < path.length) {
    if (path.startsWith("..", i)) {
      i += 2;
      if (path[i] === "*") {
        segs.push({ kind: "descend", key: null });
        i++;
        continue;
      }
      const m = ident.exec(path.slice(i));
      if (!m) throw new JsonPathError(`expected name after '..' at ${i}`);
      segs.push({ kind: "descend", key: m[0] });
      i += m[0].length;
    } else if (path[i] === ".") {
      i++;
      if (path[i] === "*") {
        segs.push({ kind: "wildcard" });
        i++;
        continue;
      }
      const m = ident.exec(path.slice(i));
      if (!m) throw new JsonPathError(`expected name after '.' at ${i}`);
      segs.push({ kind: "child", key: m[0] });
      i += m[0].length;
    } else if (path[i] === "[") {
      const close = path.indexOf("]", i);
      if (close < 0) throw new JsonPathError(`unterminated '[' at ${i}`);
      const inner = path.slice(i + 1, close).trim();
      if (inner === "*") segs.push({ kind: "wildcard" });
      else if (/^-?\d+$/.test(inner)) segs.push({ kind: "index", index: Number(inner) });
      else if (/^'[^']*'$|^"[^"]*"$/.test(inner)) segs.push({ kind: "child", key: inner.slice(1, -1) });
      else throw new JsonPathError(`unsupported selector [${inner}]`);
      i = close + 1;
    } else {
      throw new JsonPathError(`unexpected '${path[i]}' at ${i}`);
    }
  }
  for (const s of segs) {
    if ((s.kind === "child" || s.kind === "descend") && s.key && FORBIDDEN.has(s.key)) {
      throw new JsonPathError(`access to '${s.key}' is forbidden`);
    }
  }
  cache.set(path, segs);
  return segs;
}

function children(v: unknown): unknown[] {
  if (Array.isArray(v)) return v;
  if (v && typeof v === "object") return Object.values(v as Record<string, unknown>);
  return [];
}

function descendants(v: unknown, out: unknown[], depth = 0): void {
  if (depth > 64) return;
  for (const c of children(v)) {
    out.push(c);
    descendants(c, out, depth + 1);
  }
}

/** Returns every value selected by `path` (possibly empty). */
export function queryJsonPath(root: unknown, path: string): unknown[] {
  let current: unknown[] = [root];
  for (const seg of parseJsonPath(path)) {
    const next: unknown[] = [];
    for (const v of current) {
      switch (seg.kind) {
        case "child":
          if (v && typeof v === "object" && !Array.isArray(v) && Object.hasOwn(v, seg.key)) {
            next.push((v as Record<string, unknown>)[seg.key]);
          }
          break;
        case "index":
          if (Array.isArray(v)) {
            const idx = seg.index < 0 ? v.length + seg.index : seg.index;
            if (idx >= 0 && idx < v.length) next.push(v[idx]);
          }
          break;
        case "wildcard":
          next.push(...children(v));
          break;
        case "descend": {
          const all: unknown[] = [v];
          descendants(v, all);
          if (seg.key === null) {
            next.push(...all.slice(1));
          } else {
            for (const d of all) {
              if (d && typeof d === "object" && !Array.isArray(d) && Object.hasOwn(d, seg.key)) {
                next.push((d as Record<string, unknown>)[seg.key]);
              }
            }
          }
          break;
        }
      }
    }
    current = next;
  }
  return current;
}

/** Collects every string leaf in a JSON value, with its JSONPath-ish location. */
export function collectStrings(v: unknown, path = "$", out: { path: string; value: string }[] = [], depth = 0) {
  if (depth > 64) return out;
  if (typeof v === "string") out.push({ path, value: v });
  else if (Array.isArray(v)) v.forEach((x, i) => collectStrings(x, `${path}[${i}]`, out, depth + 1));
  else if (v && typeof v === "object") {
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) {
      collectStrings(x, /^[A-Za-z_$][\w$]*$/.test(k) ? `${path}.${k}` : `${path}['${k}']`, out, depth + 1);
    }
  }
  return out;
}

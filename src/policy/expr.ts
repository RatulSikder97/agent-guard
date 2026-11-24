/**
 * A small, sandboxed, CEL-inspired expression language used in policy `when:` clauses.
 *
 * Design constraints (this is a security component):
 *  - Never uses eval / Function / vm. Source is tokenized, parsed to an AST, and interpreted.
 *  - Member access only reads *own* properties of plain objects/arrays; `__proto__`,
 *    `constructor` and `prototype` are rejected at parse time.
 *  - Bounded: max source length, max AST depth, max evaluation steps, max regex size.
 *  - Missing fields evaluate to `null` (not an error) so `has(args.x)` style checks are easy.
 *
 * Grammar (precedence low -> high):
 *   ternary   := or ('?' ternary ':' ternary)?
 *   or        := and ('||' and)*
 *   and       := equality ('&&' equality)*
 *   equality  := relation (('==' | '!=') relation)*
 *   relation  := additive (('<' | '<=' | '>' | '>=' | 'in') additive)*
 *   additive  := mult (('+' | '-') mult)*
 *   mult      := unary (('*' | '/' | '%') unary)*
 *   unary     := ('!' | '-') unary | postfix
 *   postfix   := primary ('.' IDENT call? | '[' ternary ']')*
 *   primary   := NUMBER | STRING | true | false | null | IDENT call? | '(' ternary ')' | '[' list ']'
 */

export type Value = string | number | boolean | null | Value[] | { [key: string]: Value };

export class ExpressionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ExpressionError";
  }
}

const MAX_SOURCE = 4096;
const MAX_DEPTH = 64;
const MAX_STEPS = 20_000;
const MAX_REGEX = 512;
const MAX_REGEX_INPUT = 100_000;
const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

type Token =
  | { t: "num"; v: number; p: number }
  | { t: "str"; v: string; p: number }
  | { t: "id"; v: string; p: number }
  | { t: "op"; v: string; p: number }
  | { t: "eof"; p: number };

const OPERATORS = [
  "&&", "||", "==", "!=", "<=", ">=",
  "<", ">", "+", "-", "*", "/", "%", "!", "?", ":", ".", ",", "(", ")", "[", "]",
];

function tokenize(src: string): Token[] {
  const out: Token[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i] as string;
    if (/\s/.test(c)) {
      i++;
      continue;
    }
    if (/[0-9]/.test(c)) {
      const m = /^[0-9]+(\.[0-9]+)?/.exec(src.slice(i));
      const text = (m as RegExpExecArray)[0];
      out.push({ t: "num", v: Number(text), p: i });
      i += text.length;
      continue;
    }
    if (c === '"' || c === "'") {
      const quote = c;
      let j = i + 1;
      let s = "";
      while (j < src.length && src[j] !== quote) {
        if (src[j] === "\\") {
          const n = src[j + 1];
          if (n === undefined) break;
          s += n === "n" ? "\n" : n === "t" ? "\t" : n;
          j += 2;
        } else {
          s += src[j];
          j++;
        }
      }
      if (src[j] !== quote) throw new ExpressionError(`unterminated string at ${i}`);
      out.push({ t: "str", v: s, p: i });
      i = j + 1;
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      const m = /^[A-Za-z_][A-Za-z0-9_]*/.exec(src.slice(i));
      const text = (m as RegExpExecArray)[0];
      out.push({ t: "id", v: text, p: i });
      i += text.length;
      continue;
    }
    const op = OPERATORS.find((o) => src.startsWith(o, i));
    if (!op) throw new ExpressionError(`unexpected character '${c}' at ${i}`);
    out.push({ t: "op", v: op, p: i });
    i += op.length;
  }
  out.push({ t: "eof", p: src.length });
  return out;
}

export type Node =
  | { k: "lit"; v: Value }
  | { k: "id"; name: string }
  | { k: "list"; items: Node[] }
  | { k: "member"; obj: Node; key: string }
  | { k: "index"; obj: Node; idx: Node }
  | { k: "call"; fn: string; args: Node[] }
  | { k: "method"; obj: Node; fn: string; args: Node[] }
  | { k: "unary"; op: string; arg: Node }
  | { k: "binary"; op: string; l: Node; r: Node }
  | { k: "ternary"; c: Node; a: Node; b: Node };

class Parser {
  private pos = 0;
  private depth = 0;
  constructor(private readonly toks: Token[]) {}

  private peek(): Token {
    return this.toks[this.pos] as Token;
  }
  private next(): Token {
    return this.toks[this.pos++] as Token;
  }
  private isOp(v: string): boolean {
    const t = this.peek();
    return t.t === "op" && t.v === v;
  }
  private expectOp(v: string): void {
    const t = this.next();
    if (t.t !== "op" || t.v !== v) throw new ExpressionError(`expected '${v}' at ${t.p}`);
  }
  private enter(): void {
    if (++this.depth > MAX_DEPTH) throw new ExpressionError("expression nested too deeply");
  }
  private leave(): void {
    this.depth--;
  }

  parse(): Node {
    const n = this.ternary();
    const t = this.peek();
    if (t.t !== "eof") throw new ExpressionError(`unexpected token at ${t.p}`);
    return n;
  }

  private ternary(): Node {
    this.enter();
    const c = this.or();
    let result = c;
    if (this.isOp("?")) {
      this.next();
      const a = this.ternary();
      this.expectOp(":");
      const b = this.ternary();
      result = { k: "ternary", c, a, b };
    }
    this.leave();
    return result;
  }

  private binaryLevel(ops: string[], sub: () => Node, kw?: string): Node {
    let l = sub();
    for (;;) {
      const t = this.peek();
      const isOp = t.t === "op" && ops.includes(t.v);
      const isKw = kw !== undefined && t.t === "id" && t.v === kw;
      if (!isOp && !isKw) return l;
      this.next();
      const r = sub();
      l = { k: "binary", op: t.v, l, r };
    }
  }

  private or(): Node {
    return this.binaryLevel(["||"], () => this.and());
  }
  private and(): Node {
    return this.binaryLevel(["&&"], () => this.equality());
  }
  private equality(): Node {
    return this.binaryLevel(["==", "!="], () => this.relation());
  }
  private relation(): Node {
    return this.binaryLevel(["<", "<=", ">", ">="], () => this.additive(), "in");
  }
  private additive(): Node {
    return this.binaryLevel(["+", "-"], () => this.mult());
  }
  private mult(): Node {
    return this.binaryLevel(["*", "/", "%"], () => this.unary());
  }

  private unary(): Node {
    if (this.isOp("!") || this.isOp("-")) {
      const op = (this.next() as { v: string }).v;
      this.enter();
      const arg = this.unary();
      this.leave();
      return { k: "unary", op, arg };
    }
    return this.postfix();
  }

  private args(): Node[] {
    this.expectOp("(");
    const args: Node[] = [];
    if (!this.isOp(")")) {
      args.push(this.ternary());
      while (this.isOp(",")) {
        this.next();
        args.push(this.ternary());
      }
    }
    this.expectOp(")");
    return args;
  }

  private postfix(): Node {
    let n = this.primary();
    for (;;) {
      if (this.isOp(".")) {
        this.next();
        const t = this.next();
        if (t.t !== "id") throw new ExpressionError(`expected identifier after '.' at ${t.p}`);
        if (FORBIDDEN_KEYS.has(t.v)) throw new ExpressionError(`access to '${t.v}' is forbidden`);
        if (this.isOp("(")) n = { k: "method", obj: n, fn: t.v, args: this.args() };
        else n = { k: "member", obj: n, key: t.v };
      } else if (this.isOp("[")) {
        this.next();
        const idx = this.ternary();
        this.expectOp("]");
        if (idx.k === "lit" && typeof idx.v === "string" && FORBIDDEN_KEYS.has(idx.v)) {
          throw new ExpressionError(`access to '${idx.v}' is forbidden`);
        }
        n = { k: "index", obj: n, idx };
      } else {
        return n;
      }
    }
  }

  private primary(): Node {
    const t = this.next();
    switch (t.t) {
      case "num":
        return { k: "lit", v: t.v };
      case "str":
        return { k: "lit", v: t.v };
      case "id": {
        if (t.v === "true") return { k: "lit", v: true };
        if (t.v === "false") return { k: "lit", v: false };
        if (t.v === "null") return { k: "lit", v: null };
        if (FORBIDDEN_KEYS.has(t.v)) throw new ExpressionError(`identifier '${t.v}' is forbidden`);
        if (this.isOp("(")) return { k: "call", fn: t.v, args: this.args() };
        return { k: "id", name: t.v };
      }
      case "op": {
        if (t.v === "(") {
          const n = this.ternary();
          this.expectOp(")");
          return n;
        }
        if (t.v === "[") {
          const items: Node[] = [];
          if (!this.isOp("]")) {
            items.push(this.ternary());
            while (this.isOp(",")) {
              this.next();
              items.push(this.ternary());
            }
          }
          this.expectOp("]");
          return { k: "list", items };
        }
        throw new ExpressionError(`unexpected '${t.v}' at ${t.p}`);
      }
      case "eof":
        throw new ExpressionError("unexpected end of expression");
    }
  }
}

export interface CompiledExpression {
  readonly source: string;
  evaluate(env: Record<string, unknown>): Value;
  test(env: Record<string, unknown>): boolean;
}

/** Converts arbitrary JS input (tool args, etc.) into the closed `Value` domain. */
export function toValue(input: unknown, depth = 0): Value {
  if (depth > 32) return null;
  if (input === null || input === undefined) return null;
  if (typeof input === "string" || typeof input === "boolean") return input;
  if (typeof input === "number") return Number.isFinite(input) ? input : null;
  if (Array.isArray(input)) return input.map((v) => toValue(v, depth + 1));
  if (typeof input === "object") {
    const out: { [key: string]: Value } = Object.create(null) as { [key: string]: Value };
    for (const [k, v] of Object.entries(input as Record<string, unknown>)) {
      if (FORBIDDEN_KEYS.has(k)) continue;
      out[k] = toValue(v, depth + 1);
    }
    return out;
  }
  return null;
}

function typeName(v: Value): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "list";
  return typeof v === "object" ? "map" : typeof v;
}

function truthy(v: Value): boolean {
  if (typeof v !== "boolean") throw new ExpressionError(`expected bool, got ${typeName(v)}`);
  return v;
}

function deepEqual(a: Value, b: Value): boolean {
  if (a === b) return true;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((x, i) => deepEqual(x, b[i] as Value));
  }
  if (a && b && typeof a === "object" && typeof b === "object" && !Array.isArray(a) && !Array.isArray(b)) {
    const ka = Object.keys(a);
    const kb = Object.keys(b);
    return ka.length === kb.length && ka.every((k) => Object.hasOwn(b, k) && deepEqual(a[k] as Value, b[k] as Value));
  }
  return false;
}

export function safeRegex(pattern: string, flags = ""): RegExp {
  if (pattern.length > MAX_REGEX) throw new ExpressionError("regex too long");
  // Reject the classic catastrophic-backtracking shape: a quantified group that itself contains a quantifier.
  if (/\((?:[^()\\]|\\.)*[+*}](?:[^()\\]|\\.)*\)\s*[+*{]/.test(pattern)) {
    throw new ExpressionError("regex contains nested quantifiers (potential ReDoS)");
  }
  try {
    return new RegExp(pattern, flags);
  } catch (e) {
    throw new ExpressionError(`invalid regex: ${(e as Error).message}`);
  }
}

/** Converts a glob (`*` within a segment, `**` across `/` and `.`, `?` single char) into a RegExp. */
export function globToRegExp(glob: string, opts: { caseInsensitive?: boolean } = {}): RegExp {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i] as string;
    if (c === "*") {
      if (glob[i + 1] === "*") {
        re += ".*";
        i++;
        if (glob[i + 1] === "/") {
          re = re.slice(0, -2) + "(?:.*/)?";
          i++;
        }
      } else {
        re += "[^/]*";
      }
    } else if (c === "?") {
      re += "[^/]";
    } else {
      re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    }
  }
  return new RegExp(`^${re}$`, opts.caseInsensitive ? "i" : "");
}

export function hostOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

class Interpreter {
  private steps = 0;
  private readonly regexCache = new Map<string, RegExp>();
  constructor(private readonly env: Record<string, Value>) {}

  private tick(): void {
    if (++this.steps > MAX_STEPS) throw new ExpressionError("evaluation step budget exceeded");
  }

  private regex(p: string): RegExp {
    let r = this.regexCache.get(p);
    if (!r) {
      r = safeRegex(p);
      this.regexCache.set(p, r);
    }
    return r;
  }

  eval(n: Node, scope: Record<string, Value> = {}): Value {
    this.tick();
    switch (n.k) {
      case "lit":
        return n.v;
      case "id":
        if (Object.hasOwn(scope, n.name)) return scope[n.name] as Value;
        if (Object.hasOwn(this.env, n.name)) return this.env[n.name] as Value;
        throw new ExpressionError(`unknown identifier '${n.name}'`);
      case "list":
        return n.items.map((i) => this.eval(i, scope));
      case "member":
        return this.get(this.eval(n.obj, scope), n.key);
      case "index": {
        const obj = this.eval(n.obj, scope);
        const idx = this.eval(n.idx, scope);
        if (typeof idx === "number" || typeof idx === "string") return this.get(obj, idx);
        throw new ExpressionError(`invalid index type ${typeName(idx)}`);
      }
      case "unary": {
        const v = this.eval(n.arg, scope);
        if (n.op === "!") return !truthy(v);
        if (typeof v !== "number") throw new ExpressionError(`cannot negate ${typeName(v)}`);
        return -v;
      }
      case "ternary":
        return truthy(this.eval(n.c, scope)) ? this.eval(n.a, scope) : this.eval(n.b, scope);
      case "binary":
        return this.binary(n.op, n.l, n.r, scope);
      case "call":
        return this.call(n.fn, n.args, scope);
      case "method":
        return this.method(n, scope);
    }
  }

  private get(obj: Value, key: string | number): Value {
    if (obj === null) return null;
    if (Array.isArray(obj)) {
      if (typeof key !== "number" || !Number.isInteger(key)) return null;
      const i = key < 0 ? obj.length + key : key;
      return i >= 0 && i < obj.length ? (obj[i] as Value) : null;
    }
    if (typeof obj === "object") {
      const k = String(key);
      if (FORBIDDEN_KEYS.has(k)) throw new ExpressionError(`access to '${k}' is forbidden`);
      return Object.hasOwn(obj, k) ? (obj[k] as Value) : null;
    }
    return null;
  }

  private binary(op: string, ln: Node, rn: Node, scope: Record<string, Value>): Value {
    if (op === "&&") return truthy(this.eval(ln, scope)) ? truthy(this.eval(rn, scope)) : false;
    if (op === "||") return truthy(this.eval(ln, scope)) ? true : truthy(this.eval(rn, scope));
    const l = this.eval(ln, scope);
    const r = this.eval(rn, scope);
    switch (op) {
      case "==":
        return deepEqual(l, r);
      case "!=":
        return !deepEqual(l, r);
      case "in":
        if (Array.isArray(r)) return r.some((x) => deepEqual(x, l));
        if (typeof r === "string" && typeof l === "string") return r.includes(l);
        if (r && typeof r === "object" && typeof l === "string") return Object.hasOwn(r, l);
        throw new ExpressionError(`'in' not supported for ${typeName(l)} in ${typeName(r)}`);
      case "+":
        if (typeof l === "number" && typeof r === "number") return l + r;
        if (typeof l === "string" && typeof r === "string") return l + r;
        if (Array.isArray(l) && Array.isArray(r)) return [...l, ...r];
        throw new ExpressionError(`cannot add ${typeName(l)} and ${typeName(r)}`);
      case "<":
      case "<=":
      case ">":
      case ">=": {
        if (!((typeof l === "number" && typeof r === "number") || (typeof l === "string" && typeof r === "string"))) {
          throw new ExpressionError(`cannot compare ${typeName(l)} and ${typeName(r)}`);
        }
        if (op === "<") return l < r;
        if (op === "<=") return l <= r;
        if (op === ">") return l > r;
        return l >= r;
      }
      case "-":
      case "*":
      case "/":
      case "%": {
        if (typeof l !== "number" || typeof r !== "number") {
          throw new ExpressionError(`arithmetic on ${typeName(l)} and ${typeName(r)}`);
        }
        if ((op === "/" || op === "%") && r === 0) throw new ExpressionError("division by zero");
        if (op === "-") return l - r;
        if (op === "*") return l * r;
        if (op === "/") return l / r;
        return l % r;
      }
      default:
        throw new ExpressionError(`unknown operator ${op}`);
    }
  }

  private size(v: Value): number {
    if (typeof v === "string" || Array.isArray(v)) return v.length;
    if (v && typeof v === "object") return Object.keys(v).length;
    if (v === null) return 0;
    throw new ExpressionError(`size() not supported for ${typeName(v)}`);
  }

  private str(v: Value, fn: string): string {
    if (typeof v !== "string") throw new ExpressionError(`${fn}() expects string, got ${typeName(v)}`);
    return v;
  }

  private call(fn: string, argNodes: Node[], scope: Record<string, Value>): Value {
    const args = argNodes.map((a) => this.eval(a, scope));
    const arity = (n: number) => {
      if (args.length !== n) throw new ExpressionError(`${fn}() expects ${n} argument(s)`);
    };
    switch (fn) {
      case "size":
        arity(1);
        return this.size(args[0] as Value);
      case "has":
        arity(1);
        return args[0] !== null;
      case "string":
        arity(1);
        return typeof args[0] === "string" ? args[0] : JSON.stringify(args[0]);
      case "int": {
        arity(1);
        const n = Number(args[0]);
        if (!Number.isFinite(n)) throw new ExpressionError("int() of non-numeric value");
        return Math.trunc(n);
      }
      case "matches":
        arity(2);
        return this.matches(this.str(args[0] as Value, fn), this.str(args[1] as Value, fn));
      case "glob":
        arity(2);
        return globToRegExp(this.str(args[1] as Value, fn)).test(this.str(args[0] as Value, fn));
      case "host":
        arity(1);
        return args[0] === null ? null : hostOf(this.str(args[0] as Value, fn));
      case "type":
        arity(1);
        return typeName(args[0] as Value);
      default:
        throw new ExpressionError(`unknown function '${fn}'`);
    }
  }

  private matches(s: string, pattern: string): boolean {
    if (s.length > MAX_REGEX_INPUT) throw new ExpressionError("matches() input too large");
    return this.regex(pattern).test(s);
  }

  private method(n: Extract<Node, { k: "method" }>, scope: Record<string, Value>): Value {
    const recv = this.eval(n.obj, scope);
    // Macros: list.exists(x, pred) / list.all(x, pred) / list.filter(x, pred) bind a variable lazily.
    if (n.fn === "exists" || n.fn === "all" || n.fn === "filter") {
      const [varNode, pred] = n.args;
      if (n.args.length !== 2 || !varNode || varNode.k !== "id" || !pred) {
        throw new ExpressionError(`${n.fn}() expects (identifier, predicate)`);
      }
      const items: Value[] = Array.isArray(recv)
        ? recv
        : recv && typeof recv === "object"
          ? Object.keys(recv)
          : recv === null
            ? []
            : [recv];
      const test = (x: Value) => truthy(this.eval(pred, { ...scope, [varNode.name]: x }));
      if (n.fn === "exists") return items.some(test);
      if (n.fn === "all") return items.every(test);
      return items.filter(test);
    }
    const args = n.args.map((a) => this.eval(a, scope));
    const arg0 = () => this.str(args[0] as Value, n.fn);
    switch (n.fn) {
      case "size":
        return this.size(recv);
      case "contains":
        if (Array.isArray(recv)) return recv.some((x) => deepEqual(x, args[0] as Value));
        return this.str(recv, n.fn).includes(arg0());
      case "startsWith":
        return this.str(recv, n.fn).startsWith(arg0());
      case "endsWith":
        return this.str(recv, n.fn).endsWith(arg0());
      case "matches":
        return this.matches(this.str(recv, n.fn), arg0());
      case "glob":
        return globToRegExp(arg0()).test(this.str(recv, n.fn));
      case "lower":
        return this.str(recv, n.fn).toLowerCase();
      case "upper":
        return this.str(recv, n.fn).toUpperCase();
      case "trim":
        return this.str(recv, n.fn).trim();
      case "host":
        return recv === null ? null : hostOf(this.str(recv, n.fn));
      default:
        throw new ExpressionError(`unknown method '${n.fn}'`);
    }
  }
}

/** Parses an expression once; the result can be evaluated many times against different environments. */
export function compileExpression(source: string): CompiledExpression {
  if (source.length > MAX_SOURCE) throw new ExpressionError("expression too long");
  const ast = new Parser(tokenize(source)).parse();
  const run = (env: Record<string, unknown>): Value => {
    const values: Record<string, Value> = Object.create(null) as Record<string, Value>;
    for (const [k, v] of Object.entries(env)) values[k] = toValue(v);
    return new Interpreter(values).eval(ast);
  };
  return {
    source,
    evaluate: run,
    test: (env) => {
      const v = run(env);
      if (typeof v !== "boolean") throw new ExpressionError(`expression must yield bool, got ${typeName(v)}`);
      return v;
    },
  };
}

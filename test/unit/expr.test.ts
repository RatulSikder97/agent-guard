import { describe, expect, it } from "vitest";
import { compileExpression, ExpressionError, globToRegExp, safeRegex } from "../../src/policy/expr.js";

const env = {
  args: { path: "/etc/passwd", size: 42, tags: ["a", "b"], to: "Bob@Example.com", url: "https://api.github.com/repos" },
  tool: "read_file",
  server: "fs",
  agent: "claude",
  session: { id: "s1", labels: ["private_data"] },
};
const ev = (src: string) => compileExpression(src).evaluate(env);

describe("expression language", () => {
  it("evaluates literals, arithmetic and precedence", () => {
    expect(ev("1 + 2 * 3")).toBe(7);
    expect(ev("(1 + 2) * 3")).toBe(9);
    expect(ev("10 % 4 - -1")).toBe(3);
    expect(ev('"a" + "b"')).toBe("ab");
    expect(ev("[1, 2] + [3]")).toEqual([1, 2, 3]);
  });

  it("supports comparisons, boolean logic and ternary", () => {
    expect(ev("args.size > 40 && args.size <= 42")).toBe(true);
    expect(ev("!(args.size == 42) || tool == 'read_file'")).toBe(true);
    expect(ev("args.size > 100 ? 'big' : 'small'")).toBe("small");
  });

  it("supports member, index and missing-field access", () => {
    expect(ev("args.tags[1]")).toBe("b");
    expect(ev("args.tags[-1]")).toBe("b");
    expect(ev("args['path']")).toBe("/etc/passwd");
    expect(ev("args.missing")).toBeNull();
    expect(ev("args.missing.deeper")).toBeNull();
    expect(ev("has(args.path) && !has(args.nope)")).toBe(true);
  });

  it("supports string methods and functions", () => {
    expect(ev("args.path.startsWith('/etc/')")).toBe(true);
    expect(ev("args.to.lower().endsWith('@example.com')")).toBe(true);
    expect(ev("args.path.matches('^/etc/(passwd|shadow)$')")).toBe(true);
    expect(ev("args.path.glob('/etc/*')")).toBe(true);
    expect(ev("host(args.url)")).toBe("api.github.com");
    expect(ev("args.url.host() == 'api.github.com'")).toBe(true);
    expect(ev("size(args.tags) == 2 && size('abc') == 3")).toBe(true);
    expect(ev("'private_data' in session.labels")).toBe(true);
    expect(ev("'pass' in args.path")).toBe(true);
    expect(ev("type(args.tags)")).toBe("list");
  });

  it("supports exists/all/filter macros", () => {
    expect(ev("args.tags.exists(t, t == 'b')")).toBe(true);
    expect(ev("args.tags.all(t, size(t) == 1)")).toBe(true);
    expect(ev("args.tags.filter(t, t != 'a')")).toEqual(["b"]);
  });

  it("short-circuits so guarded errors do not fire", () => {
    expect(ev("false && args.size.foo()")).toBe(false);
    expect(ev("true || 1 / 0 == 1")).toBe(true);
  });

  it("rejects prototype access at parse time and at runtime", () => {
    expect(() => compileExpression("args.__proto__")).toThrow(ExpressionError);
    expect(() => compileExpression("args.constructor")).toThrow(ExpressionError);
    expect(() => compileExpression("args['prototype']")).toThrow(ExpressionError);
    expect(() => compileExpression("args[x]").evaluate({ args: {}, x: "__proto__" })).toThrow(ExpressionError);
  });

  it("has no access to JS globals", () => {
    expect(() => ev("process")).toThrow(/unknown identifier/);
    expect(() => ev("globalThis")).toThrow(/unknown identifier/);
    expect(() => ev("eval('1')")).toThrow(/unknown function/);
    expect(() => ev("args.path.constructor")).toThrow(ExpressionError);
  });

  it("is strictly typed", () => {
    expect(() => ev("args.size + 'x'")).toThrow(/cannot add/);
    expect(() => ev("args.path && true")).toThrow(/expected bool/);
    expect(() => compileExpression("args.size").test(env)).toThrow(/must yield bool/);
    expect(() => ev("1 / 0")).toThrow(/division by zero/);
  });

  it("enforces resource limits", () => {
    expect(() => compileExpression("(".repeat(100) + "1" + ")".repeat(100))).toThrow(/nested too deeply/);
    expect(() => compileExpression("1".padEnd(5000, " "))).toThrow(/too long/);
    expect(() => ev("args.path.matches('(a+)+$')")).toThrow(/ReDoS/);
    const many = Array.from({ length: 200 }, (_, i) => i);
    const big = compileExpression("xs.all(a, xs.all(b, true))");
    expect(() => big.evaluate({ xs: many })).toThrow(/step budget/);
  });

  it("reports syntax errors", () => {
    expect(() => compileExpression("1 +")).toThrow(ExpressionError);
    expect(() => compileExpression("'unterminated")).toThrow(/unterminated/);
    expect(() => compileExpression("a ? b")).toThrow(ExpressionError);
    expect(() => compileExpression("a $ b")).toThrow(/unexpected character/);
  });
});

describe("globToRegExp / safeRegex", () => {
  it("matches globs", () => {
    expect(globToRegExp("**/.env*").test("/home/u/project/.env.local")).toBe(true);
    expect(globToRegExp("**/.env*").test(".env")).toBe(true);
    expect(globToRegExp("/workspace/**").test("/workspace/a/b.txt")).toBe(true);
    expect(globToRegExp("/workspace/*").test("/workspace/a/b.txt")).toBe(false);
    expect(globToRegExp("write_*").test("write_file")).toBe(true);
    expect(globToRegExp("*.github.com", { caseInsensitive: true }).test("API.GitHub.com")).toBe(true);
    expect(globToRegExp("file?.txt").test("file1.txt")).toBe(true);
  });

  it("rejects nested quantifiers", () => {
    expect(() => safeRegex("(\\w+)*x")).toThrow(/ReDoS/);
    expect(() => safeRegex("(a*){2,}")).toThrow(/ReDoS/);
    expect(safeRegex("^[a-z]+$").test("abc")).toBe(true);
  });
});

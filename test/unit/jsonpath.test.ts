import { describe, expect, it } from "vitest";
import { collectStrings, JsonPathError, queryJsonPath } from "../../src/policy/jsonpath.js";

const doc = {
  path: "/tmp/a",
  files: [{ name: "a.txt", meta: { owner: "x" } }, { name: "b.txt" }],
  headers: { "x-api-key": "k", nested: { url: "https://evil.example" } },
};

describe("JSONPath subset", () => {
  it("selects children, indices and wildcards", () => {
    expect(queryJsonPath(doc, "$.path")).toEqual(["/tmp/a"]);
    expect(queryJsonPath(doc, "$.files[0].name")).toEqual(["a.txt"]);
    expect(queryJsonPath(doc, "$.files[-1].name")).toEqual(["b.txt"]);
    expect(queryJsonPath(doc, "$.files[*].name")).toEqual(["a.txt", "b.txt"]);
    expect(queryJsonPath(doc, "$.headers['x-api-key']")).toEqual(["k"]);
    expect(queryJsonPath(doc, "$.headers.*")).toHaveLength(2);
    expect(queryJsonPath(doc, "$")).toEqual([doc]);
  });

  it("supports recursive descent", () => {
    expect(queryJsonPath(doc, "$..url")).toEqual(["https://evil.example"]);
    expect(queryJsonPath(doc, "$..name")).toEqual(["a.txt", "b.txt"]);
    expect(queryJsonPath(doc, "$..*").length).toBeGreaterThan(8);
  });

  it("returns empty for missing paths", () => {
    expect(queryJsonPath(doc, "$.nope.deeper")).toEqual([]);
    expect(queryJsonPath(doc, "$.files[9]")).toEqual([]);
  });

  it("rejects filters and prototype keys", () => {
    expect(() => queryJsonPath(doc, "$.files[?(@.name)]")).toThrow(JsonPathError);
    expect(() => queryJsonPath(doc, "$.__proto__")).toThrow(JsonPathError);
    expect(() => queryJsonPath(doc, "path")).toThrow(JsonPathError);
  });

  it("collects string leaves with locations", () => {
    const strings = collectStrings(doc);
    expect(strings).toContainEqual({ path: "$.headers['x-api-key']", value: "k" });
    expect(strings).toContainEqual({ path: "$.files[1].name", value: "b.txt" });
  });
});

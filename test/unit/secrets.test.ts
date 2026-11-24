import { describe, expect, it } from "vitest";
import { redactText, redactValue } from "../../src/defense/secrets.js";

// Secret-shaped fixtures are assembled at runtime so the repository never contains a literal that
// secret scanners (or GitHub push protection) would flag.
const j = (...p: string[]) => p.join("");
const SAMPLES: Record<string, string> = {
  anthropic_api_key: j("sk-ant-", "api03-", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4"),
  openai_api_key: j("sk-", "proj-", "abcdefghijklmnopqrstuvwxyz0123456789ABCD"),
  github_token: j("ghp_", "0123456789abcdefghijABCDEFGHIJ012345"),
  aws_access_key_id: j("AKIA", "IOSFODNN7", "EXAMPLE"),
  slack_token: j("xoxb-", "1234567890-", "abcdefghijkl"),
  stripe_key: j("sk_", "live_", "4eC39HqLyjWDarjtT1zdp7dc"),
  google_api_key: j("AIza", "SyA-1234567890abcdefghijklmnopqrstu"),
  jwt: j("eyJhbGciOiJIUzI1NiJ9", ".", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", ".", "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"),
};

describe("secret redaction", () => {
  for (const [type, secret] of Object.entries(SAMPLES)) {
    it(`redacts ${type}`, () => {
      const r = redactText(`token: ${secret} end`);
      expect(r.text).not.toContain(secret);
      expect(r.findings.map((f) => f.type)).toContain(type);
      expect(r.text).toContain(`[REDACTED:${type}]`);
    });
  }

  it("redacts PEM private keys", () => {
    const pem = j("-----BEGIN ", "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\nabc\n-----END ", "RSA PRIVATE KEY-----");
    const r = redactText(`key:\n${pem}\nafter`);
    expect(r.text).toBe("key:\n[REDACTED:private_key]\nafter");
  });

  it("redacts only the sensitive group for contextual detectors", () => {
    expect(redactText(j("aws_secret_access_key = ", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")).text).toBe(
      "aws_secret_access_key = [REDACTED:aws_secret_access_key]",
    );
    expect(redactText("Authorization: Bearer abcdef0123456789xyz").text).toBe("Authorization: Bearer [REDACTED:auth_header]");
    expect(redactText("postgres://app:s3cretpass@db:5432/x").text).toBe("postgres://app:[REDACTED:url_credentials]@db:5432/x");
    expect(redactText('{"password": "correct-horse-battery"}').text).toBe('{"password": "[REDACTED:generic_secret]"}');
  });

  it("redacts PII when enabled and keeps it when disabled", () => {
    const text = "Contact ada@example.com, card 4111 1111 1111 1111, SSN 123-45-6789";
    const r = redactText(text);
    expect(r.text).toBe("Contact [REDACTED:email], card [REDACTED:credit_card], SSN [REDACTED:us_ssn]");
    expect(redactText(text, { pii: false }).text).toBe(text);
    expect(redactText(text, { ignore: ["email"] }).text).toContain("ada@example.com");
  });

  it("uses Luhn to avoid redacting arbitrary digit runs", () => {
    expect(redactText("order 1234 5678 9012 3456").findings).toHaveLength(0);
  });

  it("does not flag ordinary text", () => {
    const text = "The function returns a token count; see docs at https://example.com/api?page=2. Version 1.2.3.";
    expect(redactText(text).findings).toHaveLength(0);
  });

  it("walks nested values and reports locations and fingerprints without the secret", () => {
    const r = redactValue({ a: [{ b: `x ${SAMPLES.github_token}` }], n: 1 });
    expect(r.value).toEqual({ a: [{ b: "x [REDACTED:github_token]" }], n: 1 });
    expect(r.findings[0]).toMatchObject({ type: "github_token", kind: "secret", path: "$.a[0].b" });
    expect(r.findings[0]?.fingerprint).toMatch(/^[0-9a-f]{12}$/);
    expect(JSON.stringify(r.findings)).not.toContain(SAMPLES.github_token);
  });
});

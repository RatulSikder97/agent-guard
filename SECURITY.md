# Security Policy

agent-guard is a security control, so vulnerabilities in it matter. Thank you for reporting them responsibly.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private vulnerability reporting instead:
**Security → Report a vulnerability** on this repository.

Include what you can of:

- affected version / commit
- a minimal config and request sequence that reproduces the issue
- the impact (policy bypass, exfiltration path, audit-log forgery, crash, ...)

You can expect an acknowledgement within 5 business days and a fix or mitigation plan within 30 days for confirmed issues. Credit is given in the release notes unless you prefer otherwise.

## In scope

- Bypasses of policy decisions, capability scoping, egress allowlisting, secret redaction or approval gating
- Ways for a downstream agent or upstream MCP server to influence the gateway beyond its intended interface
- Audit-log forgery that `verify-log` does not detect (given the documented threat model)
- Unsafe behaviour of the expression language or JSONPath evaluator (code execution, prototype access, unbounded resource use)
- Approval dashboard issues (auth bypass, CSRF, XSS, DNS rebinding)

## Out of scope / known limitations

These are documented design limits, not vulnerabilities (see the README's *Limitations* section):

- Heuristic prompt-injection detection missing a novel, paraphrased or non-English payload
- An agent with shell access on the same host and user as the gateway approving its own requests or editing the state directory
- Truncation of the audit log tail when no external anchor (`verify-log --anchor`) is kept
- Data exfiltrated through a channel agent-guard does not mediate (tools outside the gateway, side channels in allowed hosts)

## Supported versions

Only the latest release on `main` receives fixes.

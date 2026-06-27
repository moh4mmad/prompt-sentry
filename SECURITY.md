# Security Policy

## Reporting a vulnerability

If you find a security issue in this project — a bypass, a false-negative pattern, or anything that could let an attacker evade the firewall — please open a [GitHub Security Advisory](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) rather than a public issue.

Include:
- What you found and how to reproduce it
- A sample payload (use fake data — no real credentials or customer prompts)
- What the firewall currently returns vs. what it should return

## What's in scope

- Detection bypasses (attacks that score below threshold and get through)
- False positives that block legitimate input
- API security issues (auth bypass, injection in request handling)
- Information leakage in audit logs or API responses

## What's out of scope

- "The LLM itself can be jailbroken" — this project defends the middleware layer, not the model
- Attacks that require physical access to the server

## Sensitive data

Do not include real API keys, access tokens, customer prompts, or production logs in any issue or pull request. Use clearly fake values like `sk-test-fake-key-1234` in examples.

## Supported versions

This project is in active development. Only the latest commit on `main` is supported.

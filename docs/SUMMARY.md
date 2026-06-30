# PromptSentry: Runtime Security Middleware and Benchmark for Tool-Using AI Agents

---

## Abstract

Tool-using AI agents expand a large language model's attack surface from a single input prompt to every trust boundary the agent crosses: user messages, retrieved documents, webpages, tool outputs, tool proposals, memory, and model outputs. Existing defenses address individual boundaries in isolation and provide no systematic way to measure the tradeoff between security and task utility across realistic workflows. PromptSentry is an open-source runtime security middleware and benchmark that protects all seven trust boundaries, evaluates defenses against prompt injection, tool abuse, context poisoning, and secret leakage, and reports security uplift alongside benign utility preservation on a reproducible deterministic corpus.

---

## Problem

Prompt injection — the practice of embedding adversarial instructions in content the agent is asked to process — is now the primary attack vector against deployed LLM agents. Attacks arrive through all boundaries an agent touches: a malicious instruction buried in a retrieved PDF, an encoded payload in a webpage, a goal-hijacking comment in a GitHub issue, a credential-exfiltration request in a customer email, or a destructive tool call proposed by a compromised context. No single existing defense covers all of these surfaces, and no public benchmark measures whether a defense preserves task utility while reducing attack success.

---

## Approach

PromptSentry is structured as a layered inspection pipeline deployed as a FastAPI service alongside the agent application.

**Detection pipeline.** Every text input passes through: (1) a normalizer that decodes obfuscated payloads — base64, hex, ROT13, leetspeak, homoglyphs, zero-width characters, and spaced text — producing a set of candidate variants; (2) a deterministic rule engine with 20+ regex rules covering 12 attack types (direct injection, indirect injection, jailbreak, goal hijacking, system prompt extraction, credential exfiltration, data exfiltration, identity spoofing, tool abuse, context poisoning, payload smuggling, sensitive output leak); and (3) an optional LLM ensemble that blends rule score (40%) with a Claude Haiku classifier score (60%), with a hard floor of 0.70 if any rule fires.

**Risk scoring and actions.** A weighted formula combines severity, confidence, multi-finding boost, and source boost (retrieved documents and tool outputs score higher than direct user input). The score maps to five actions: ALLOW, MONITOR, SANITIZE, BLOCK, and ALERT.

**Tool-call policy.** Before any tool handler executes, a separate policy layer checks the proposed tool name against an allowlist, inspects arguments for restricted keywords, and applies an indirect-injection boost if the proposal originated from untrusted content.

**Python SDK and framework adapters.** A sync/async client SDK wraps the HTTP API with typed models and structured exceptions. Six framework adapters (LangChain, LlamaIndex, OpenAI Responses, Anthropic tool use, CrewAI, MCP) enforce inspection at every trust boundary without requiring application-level instrumentation.

---

## Benchmark

The `realistic-agent-v1` corpus contains 50 paired cases across five scenarios — RAG document summarization, webpage reading, GitHub issue triage, customer support email, and synthetic tool calls — each with a benign and an attacked variant. A full deterministic run executes 200 protected and unprotected workflows using in-memory tool simulations and fake canary secrets, recording tool proposals, policy decisions, and execution separately so a denied proposal verifiably proves its handler never ran.

`realistic-agent-v2` extends this with an eight-profile defense ablation — no defense, keyword filter, LLM judge, rules only, rules + LLM, rules + tool policy, rules + output verification, and full stack — run on the same corpus so security, utility, false-positive rate, and latency tradeoffs can be compared directly.

---

## Results

**realistic-agent-v1 — deterministic, 200 executions, seed 42:**

| | Unprotected | Protected |
|---|---:|---:|
| Attack success rate | 100% | 0% |
| Secure task completion | 0% | 100% |
| Benign task completion | 100% | 100% |
| Tool violations | 92% | 0% |
| Secret leaks | 26% | 0% |
| **Composite score** | — | **100 / 100** |

Protection eliminates all attack successes, tool violations, and secret leaks with zero benign utility loss. The composite score formula weights secure task completion (40%), benign task completion (20%), tool compliance (15%), secret protection (15%), and detection recall (10%).

---

## Limitations

Rule-based detection is pattern-bound; novel attacks that avoid known signatures will score low and pass. The LLM ensemble improves recall but introduces latency, API cost, and non-determinism. Sanitization is best-effort — a sophisticated multi-vector payload that partially survives may still influence model behavior. Tool-call protection requires the application loop to check the policy verdict before dispatching; bypassing the review call removes the protection. MCP tools executed server-side on Anthropic infrastructure run before application code receives the response and cannot be pre-authorized. The benchmark uses controlled simulations, not real filesystems, networks, or credentials; results in production require independent validation against deployment-specific threat models.

---

## Artifacts

| Artifact | Description |
|---|---|
| Runtime service | FastAPI inspection API with five endpoints, rate limiting, API key auth, PostgreSQL audit log |
| Python SDK | Sync/async client with six framework adapters (LangChain, LlamaIndex, OpenAI, Anthropic, CrewAI, MCP) |
| Benchmark corpus | 50 paired cases across 5 scenarios; v2 adds 8-profile defense ablation |
| Test suite | 153 tests across unit, integration, red-team, benchmark, SDK, and adapter suites |
| Attack library | 100+ labeled attack samples (JSONL) across 12 attack types |
| Monitoring dashboard | Next.js UI with live threat activity, attack breakdowns, and red-team trigger |

Source: [github.com/moh4mmad/prompt-sentry](https://github.com/moh4mmad/prompt-sentry)  
Results: [`docs/benchmark-results.md`](benchmark-results.md) — updated automatically on every CI run.

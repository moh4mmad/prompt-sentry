# Threat Model

## What we protect

- System and developer instructions (your system prompt)
- User prompts and conversation context
- Retrieved documents, vector store content, and web pages
- Tool credentials and API tokens in scope
- Agent memory
- Model output before it's returned to the user

## Trust boundaries

```
User input          → untrusted
Retrieved documents → untrusted
Web pages           → untrusted
Tool output         → untrusted by default
Model output        → not authoritative — verify before acting on it
Application backend → trusted
```

The firewall treats anything that crosses a trust boundary as potentially hostile. Same text, different source = different risk score.

## Threat categories

| Threat | Entry point | How it works |
|---|---|---|
| Direct injection | User prompt | User asks the model to override instructions |
| Indirect injection | Documents, web, memory | Malicious text hidden in content the agent reads |
| Jailbreak | User prompt | Persona tricks to bypass safety behavior |
| Goal hijacking | Any source | Instruction that silently redirects the agent's task |
| Payload smuggling | Any source | Encoded/obfuscated injection to bypass pattern matching |
| System prompt extraction | User prompt | Asking the model to repeat its instructions |
| Credential exfiltration | User prompt or documents | Asking for API keys, tokens, or passwords |
| Tool abuse | Tool call arguments | Triggering dangerous operations (drops, exports, HTTP calls) |
| Identity spoofing | User prompt | Claiming to be admin/CEO/root to unlock capabilities |
| Data exfiltration | User prompt or documents | Requesting cross-tenant or private records |
| Context poisoning | Memory, long-lived context | Injecting instructions that persist across sessions |
| Sensitive output leak | Model output | The model revealing secrets in its response |

## What this does not replace

- A proper identity and access management system
- Data loss prevention (DLP) at the storage layer
- Model fine-tuning or RLHF for safety
- Network-layer security
- Secret scanning in code and config

Detection is probabilistic. Rule-based systems can be evaded with sufficiently novel payloads. Use this as one layer in a defense-in-depth strategy, not as a single control.

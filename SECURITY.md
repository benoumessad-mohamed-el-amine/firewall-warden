# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in firewall-warden, please report it privately through GitHub Private Vulnerability Reporting at:
https://github.com/benoumessad-mohamed-el-amine/firewall-warden/security/advisories/new

Please do not open a public issue for an unpatched security vulnerability. Reports will be acknowledged within 48 hours, and patches will be published with attribution.

## Scope and Threat Model

firewall-warden is a deterministic, offline firewall designed to screen AI agent tool calls before execution. It acts as an enforcement layer against common tool abuse patterns without placing an LLM in the evaluation path.

### What firewall-warden protects against

- Deterministic command semantics: Known structural attack patterns in shell execution (such as download-and-execute pipelines, reverse shells, LOLBins, credential dumping, and catastrophic deletions).
- Secret exfiltration pipelines: Commands combining sensitive file reads or environment secrets with outbound network transmission.
- Untrusted tool definitions: Prompt-injection payloads embedded within MCP tool descriptions during `tools/list`.
- Path traversal and write containment: Restricting file write tools to designated write roots and blocking writes to known persistence targets (such as cron, shell profile/rc files, and system autostart configurations).
- SSRF vectors: Outbound requests to cloud metadata endpoints (e.g. 169.254.169.254) and unallowed external endpoints when `egressAllow` is configured.
- Cross-call taint: Multi-step exfiltration flows where a secret is accessed in one call and sent externally in a subsequent call within the same session.

### What is outside of scope / What firewall-warden does not protect against

- Open-ended semantic prompt injection: warden relies on deterministic structural patterns and signatures; it does not claim to detect all novel, natural-language semantic adversarial prompt injections.
- Opaque binaries: If an agent executes a pre-staged binary (such as a compiled executable or library), warden classifies only the command invocation string and arguments, not the binary internal code or runtime payload. A binary-reputation feed is required for binary inspection.
- Unmonitored protocol streams: Network egress enforcement targets HTTP, HTTPS, and URL-aware network clients in command position (such as `curl`, `wget`, `git`, and PowerShell transfer cmdlets). Raw socket utilities or protocol tools without URL parameters (such as raw `nc` or tunnels) are not dynamically constrained by `egressAllow` unless covered by explicit policy deny rules.
- Local host compromise and audit log tampering: The SHA-256 hash chain in `AuditLog` provides tamper-evidence against casual in-place edits and middle deletions. However, without an out-of-band checkpoint stored on isolated storage, an attacker with write access to the host file system can rewrite the entire hash chain or truncate the log tail.


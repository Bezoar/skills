---
name: security-audit
description: "Deep security audit of a GitHub repository or local codebase. Produces a structured threat report with SAFE/CAUTION/UNSAFE verdict. Use when the user wants to: evaluate a repo or tool's security before adopting it, scan for vulnerabilities or backdoors, audit dependencies for CVEs, check if a library/extension/MCP server is safe, assess supply chain risk, review untrusted code, or do a pre-deployment security review. Also trigger when a GitHub URL is pasted with 'is this safe?', 'audit this', or similar. Covers browser extension permissions, CI/CD security, container configs, secrets, and APT indicators. Do NOT trigger for: writing security features, fixing bugs, setting up infra, PR code review, or general dev tasks."
---

# Security Audit

You are performing a deep, rigorous security audit of a repository. Your goal is to give the user a clear, honest assessment of how safe this code is to use — covering everything from dependency vulnerabilities to intentional backdoors. Think like a security researcher doing due diligence before recommending a tool to their organization.

## Getting the Repository

If the user provides a GitHub URL, clone it into a directory **within or near the current working directory** — not `/tmp/`. This is important because subagents and tools may have permission restrictions on temporary directories.

```bash
REPO_DIR="./audit-$(basename <url> .git)"
git clone --depth 50 <url> "$REPO_DIR"
```

If the user points to a local directory, work with that directly. Either way, confirm what you're auditing before starting.

## Audit Process

Perform the scans yourself directly rather than delegating to subagents — subagents often lack permissions to access cloned repositories outside the main working directory. Use parallel tool calls (Grep, Read, Bash) to scan multiple areas concurrently. The goal is thoroughness — false positives are acceptable (flag them as low-confidence), but false negatives are not.

For each scan area below, use Grep to search for patterns, Read to inspect flagged files, and Bash for git commands and dependency auditing tools (`npm audit`, `pip-audit`, etc.).

### 1. Repository Health & Trust Signals

Before diving into code, assess the repo's trustworthiness at a high level:

- **Maintainer analysis**: How many contributors? Is it a single-person project? Any signs of recent ownership transfer? Check git log for author patterns.
- **Activity signals**: Last commit date, release frequency, issue response time (if accessible via `gh` CLI).
- **Stars/forks** (if available via `gh`): Not a security metric, but context for how battle-tested the code is.
- **License**: Is there one? Is it a recognized open-source license?

### 2. Dependency Analysis

Dependencies are the #1 attack vector in modern software supply chains.

- **Identify all dependency files**: `package.json`, `requirements.txt`, `Pipfile`, `go.mod`, `Cargo.toml`, `Gemfile`, `pom.xml`, `build.gradle`, `*.csproj`, etc.
- **Check for known vulnerabilities**: Use `npm audit`, `pip-audit`, `cargo audit`, or equivalent if available. If not, manually check dependency names and versions against known CVE databases.
- **Suspicious dependency patterns**:
  - Typosquatting: Dependencies with names very similar to popular packages (e.g., `reqeusts` vs `requests`)
  - Unusually pinned versions or version ranges that pull in specific vulnerable versions
  - Dependencies with very few downloads or recent creation dates
  - Post-install scripts (`preinstall`, `postinstall` in package.json) — these run arbitrary code on install
- **Transitive dependencies**: Note if the project has an unusually large dependency tree relative to its functionality (large attack surface)

### 3. Secrets & Credential Scanning

Search for hardcoded secrets, API keys, tokens, and credentials throughout the codebase:

- **Patterns to search for**:
  - API keys: strings matching `[A-Za-z0-9_-]{20,}` near keywords like `key`, `token`, `secret`, `password`, `api`, `auth`
  - AWS keys: `AKIA[0-9A-Z]{16}`
  - Private keys: `-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`
  - Connection strings: `postgres://`, `mongodb://`, `mysql://`, `redis://` with embedded credentials
  - JWT tokens, Bearer tokens
  - `.env` files committed to the repo
  - Hardcoded passwords in config files
- **Check `.gitignore`**: Are sensitive file patterns properly excluded?
- **Check git history**: Sometimes secrets are committed and then removed — they're still in history. Do a quick `git log --all --diff-filter=D -- '*.env' '*.pem' '*.key'` to spot deleted sensitive files.

### 4. Dangerous Code Patterns

Scan for code patterns that are either inherently risky or commonly used in malicious code:

- **Code execution**: `eval()`, `exec()`, `Function()`, `subprocess.call()` with shell=True, `os.system()`, `child_process.exec()`, backtick execution
- **Deserialization**: `pickle.loads()`, `yaml.load()` (unsafe), `JSON.parse()` on untrusted input followed by execution, `unserialize()` in PHP
- **SQL injection**: String concatenation in SQL queries instead of parameterized queries
- **Command injection**: User input passed to shell commands without sanitization
- **Path traversal**: File operations using unsanitized user input (`../` patterns)
- **XSS vectors**: `innerHTML`, `dangerouslySetInnerHTML`, `document.write()` with dynamic content
- **Prototype pollution**: Deep merge operations on objects from untrusted sources
- **Obfuscated code**: Base64-encoded strings that get decoded and executed, hex-encoded payloads, heavily minified code in a source repo (not a build artifact), unusual character encoding tricks
- **Network calls to unexpected destinations**: Look for hardcoded URLs, IP addresses, or domains — especially in code that handles sensitive data. Flag any outbound calls that aren't obviously related to the tool's stated purpose.
- **SSRF vectors**: Server-side request forgery patterns where user input controls URLs that the server fetches — check for any endpoint that takes a URL parameter and makes a request.
- **Regex DoS (ReDoS)**: Pathological regex patterns with nested quantifiers (e.g., `(a+)+$`) that can cause exponential backtracking on crafted input.
- **Serialization gadget chains**: Beyond simple deserialization — look for complex gadget chains in Java (commons-collections, Spring), .NET (BinaryFormatter, ObjectStateFormatter), or Ruby (Marshal.load) that enable RCE.
- **Timing/side-channel leaks**: Non-constant-time comparison of secrets (e.g., `==` instead of `hmac.compare_digest()`), or error messages that vary based on which part of authentication failed.

### 4b. Cryptographic Weaknesses

Scan for broken or weak cryptographic practices:

- **Broken hash algorithms**: MD5 or SHA1 used for security purposes (password hashing, integrity verification, HMAC). Note: MD5/SHA1 for checksums of non-security data is acceptable.
- **Weak encryption**: DES, 3DES, RC4, Blowfish with small keys, ECB mode for any block cipher.
- **Custom crypto**: Any hand-rolled encryption, hashing, or random number generation — almost always worse than standard libraries.
- **Weak random**: Use of `Math.random()`, `random.random()`, `rand()` in C for security-sensitive operations (tokens, keys, nonces). Should use `crypto.getRandomValues()`, `secrets` module, `/dev/urandom`.
- **Hardcoded IVs/nonces**: Initialization vectors or nonces that are static or predictable, defeating the purpose of encryption.
- **Key management**: Encryption keys derived from passwords without proper KDF (PBKDF2, scrypt, argon2), or keys stored alongside encrypted data.

### 5. Repository & Workspace Traps

Check for files that execute automatically when you interact with the repository:

- **Git hooks**: Check `.githooks/`, `.git/hooks/`, or any `core.hooksPath` configuration. Malicious pre-commit, post-checkout, or post-merge hooks can execute code just by cloning or switching branches.
- **IDE/editor configs**: `.vscode/settings.json` (especially `terminal.integrated.shellArgs`, `tasks`), `.vscode/tasks.json`, `.idea/` workspace configs that auto-run commands when the project is opened.
- **Symlink attacks**: Symbolic links that point outside the repository directory — these can overwrite system files during build or install operations. Check with `find . -type l`.
- **Git submodule hijacking**: `.gitmodules` entries pointing to repos whose owners could change (deleted GitHub accounts, expired domains). An attacker could register the old username and serve malicious code.
- **WebAssembly payloads**: `.wasm` files bundled in the repo that are extremely hard to audit statically. Flag any WASM binaries and check whether source is provided and whether the build is reproducible.

### 6. Container & Infrastructure Security

If the repo includes Docker, Kubernetes, or infrastructure configs:

- **Container escape vectors**: `--privileged` flag, host filesystem mounts (`-v /:/host`), running as root without USER directive, `--cap-add=SYS_ADMIN`.
- **Untrusted base images**: Dockerfiles pulling from registries other than Docker Hub official images, or using `latest` tag instead of pinned digests.
- **Dependency confusion**: Private package names that could collide with public packages — check if internal package names exist on public registries (npm, PyPI, etc.).
- **Exposed ports and services**: Docker Compose files exposing database ports, debug endpoints, or admin interfaces to the host network.

### 7. Permission & Scope Analysis

What access does this tool request, and is it justified by its functionality?

- **Browser extensions**: Check `manifest.json` for permissions. Flag overly broad permissions (`<all_urls>`, `tabs`, `webRequest`, `cookies`, `storage`) relative to what the extension claims to do.
- **GitHub Actions**: Check for `permissions` in workflow files. Flag `write` permissions, especially `contents: write`, `packages: write`. Look for usage of secrets in unexpected contexts.
- **OAuth scopes**: If the tool requests OAuth access, what scopes does it ask for?
- **File system access**: Does the tool read/write files outside its own directory?
- **Network access**: What domains does it communicate with? Is there a content security policy?
- **System-level access**: Does it request root/admin, install system services, modify system configs?

### 8. Build & CI/CD Pipeline Analysis

- **Build scripts**: Check `Makefile`, `package.json` scripts, CI configs for unexpected commands
- **Pre/post-install hooks**: These run automatically and can execute arbitrary code
- **GitHub Actions workflows**: Check for `pull_request_target` (can access secrets from PRs), `workflow_dispatch` with inputs passed to shell commands, third-party actions pinned to branches instead of SHAs

### 9. Advanced Threat Detection (Nation-State / APT Indicators)

Sophisticated attackers — including nation-state actors — use techniques designed to survive casual code review. These are harder to spot but critical to check:

- **Conditional backdoors**: Code that only activates under specific conditions — check for logic gated on hostnames, environment variables, dates/times, locale settings, or IP ranges. Example: `if (os.environ.get('COMPUTERNAME') == 'TARGET-PC')` or `if datetime.now() > datetime(2026, 6, 1)`.
- **Dormant payloads**: Functions that are defined but never called from normal code paths — they may be triggered by specially crafted input or external signals. Look for unreachable code blocks and unused imports of dangerous modules.
- **Steganographic data**: Binary files (images, fonts, icons, PDFs) that contain embedded executable code or encoded payloads. Flag any binary assets that are read and processed in unusual ways (e.g., an image that gets decoded and passed to `eval`).
- **Homoglyph attacks**: Variable or function names using Unicode characters that look like ASCII but aren't (e.g., Cyrillic 'а' vs Latin 'a'). These can hide malicious overrides that appear identical to legitimate code in review.
- **Compiler/build-time injection**: Build configs that pull toolchains or plugins from unusual sources, or that conditionally inject code only in release/production builds. Check if `Makefile`, `CMakeLists.txt`, or build scripts download anything at build time.
- **Delayed-activation dependencies**: Dependencies that have had recent ownership transfers, or whose recent updates added network calls, filesystem access, or native code that wasn't present in earlier versions.
- **Covert channels**: Data encoded in DNS queries, HTTP headers, image metadata, or log messages that could exfiltrate information without triggering traditional network monitoring.
- **Source code integrity**: Compare the published source with the distributed binary/package if both are available. Differences could indicate a compromised build pipeline (a la the XZ Utils attack).

These checks may produce low-confidence findings — that's expected. Flag them clearly as "APT indicator (low confidence)" so the user can investigate further if their threat model warrants it.

### 10. Data Handling & Privacy

- **What data does the tool collect?** Look for telemetry, analytics, crash reporting
- **Where does data go?** Trace data flow from collection to transmission
- **PII handling**: Does it process personal data? How?
- **Local storage**: What gets stored locally? Is it encrypted?

## Threat Classification

Classify every finding using this framework:

### Severity Levels

| Severity | Meaning | Examples |
|----------|---------|----------|
| **CRITICAL** | Actively dangerous — could compromise your system or data right now | Hardcoded backdoor, known exploited CVE, data exfiltration code, malicious post-install script |
| **HIGH** | Serious security weakness that an attacker could exploit | RCE vulnerability, SQL injection, hardcoded credentials for live services, overly broad permissions with no justification |
| **MEDIUM** | Security concern that increases risk but isn't directly exploitable | Outdated dependencies with known CVEs (not yet exploited), missing input validation, excessive permissions that could be narrowed |
| **LOW** | Minor issue or best-practice violation | Missing security headers, verbose error messages, development credentials in example configs, no rate limiting |
| **INFO** | Not a vulnerability, but worth noting for context | Large dependency tree, single maintainer, no security policy, no signed commits |

### Threat Categories

Tag each finding with one or more:

- `supply-chain` — Dependency risks, typosquatting, maintainer compromise
- `code-execution` — RCE, injection, unsafe deserialization
- `data-exposure` — Secrets, credentials, PII leaks
- `permissions` — Excessive access requests
- `obfuscation` — Deliberately hidden or obscured behavior
- `network` — Suspicious outbound connections, data exfiltration
- `build-pipeline` — Risks in CI/CD or build process
- `known-vulnerability` — Published CVEs
- `apt-indicator` — Nation-state / advanced persistent threat indicators (conditional backdoors, homoglyphs, steganography, covert channels)

## Report Format

Structure your final report exactly like this:

```
# Security Audit Report: [repo-name]

**Audited**: [date]
**Repository**: [URL or path]
**Verdict**: [SAFE / CAUTION / UNSAFE] (see below)

## Executive Summary

[2-3 sentence overview: what the repo does, the overall risk level, and the most important finding if any]

## Threat Summary

| Severity | Count |
|----------|-------|
| CRITICAL | X |
| HIGH     | X |
| MEDIUM   | X |
| LOW      | X |
| INFO     | X |

## Detailed Findings

### [SEVERITY] Finding title
- **Category**: [tag(s)]
- **Location**: [file:line]
- **Description**: [what was found]
- **Risk**: [what could go wrong]
- **Evidence**: [code snippet or proof]
- **Recommendation**: [what to do about it]

[Repeat for each finding, ordered by severity]

## Trust Signals

[Summary of repo health indicators — maintainer count, activity, community signals]

## Verdict Explanation

[Why the overall verdict was chosen. Be specific about what would need to change to improve the rating.]
```

### Verdict Criteria

- **SAFE**: No CRITICAL or HIGH findings. Any MEDIUM findings are minor and well-understood. Trust signals are positive.
- **CAUTION**: No CRITICAL findings, but HIGH or multiple MEDIUM findings exist. Usable with awareness of the risks. Explain what the user should watch out for.
- **UNSAFE**: Any CRITICAL finding, or multiple HIGH findings that together represent serious risk. Recommend against using the tool without remediation.

## Important Guidelines

- **Be thorough but honest about confidence.** If you're not sure whether something is a real threat or a false positive, say so. Mark uncertain findings with "(low confidence)" and explain why.
- **Context matters.** `eval()` in a JavaScript template engine is different from `eval()` in a user-facing API endpoint. Consider how the code is actually used, not just that a pattern exists.
- **Don't cry wolf.** If the repo is genuinely clean, say so. An audit that flags everything as dangerous is as useless as one that flags nothing. The user needs your honest judgment.
- **Prioritize actionable findings.** A theoretical vulnerability in dead code is less important than a hardcoded API key in active use. Order your report by what matters most.
- **Check for security.md or responsible disclosure policy** — its presence is a positive trust signal.

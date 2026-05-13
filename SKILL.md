---
name: security-scan
description: Local-only security scan for npm supply-chain incidents, poisoned dependency versions, lockfile risk, install-script abuse, and GitHub Actions CI/CD trust-boundary issues. Use when the user asks for 安全扫描, 安全审计, 供应链投毒检查, npm 包投毒排查, TanStack 事件排查, dependency audit, lockfile scan, CI security review, GitHub Actions security check, or wants to know whether a local project may be affected by a package compromise. Read-only by default; do not modify files or rotate secrets unless the user explicitly asks after seeing findings.
---

# Security Scan

## Purpose

Use this skill to perform a local, read-only security scan of a project, especially after npm supply-chain incidents like the 2026 TanStack compromise.

The default scan checks:

- npm dependency and lockfile exposure to known malicious `@tanstack/*` versions from `GHSA-g7cv-rxg3-hmpx`.
- Dangerous dependency source patterns such as `git+`, `github:`, `http:` or `file:` dependencies in manifests.
- Install lifecycle hooks such as `preinstall`, `install`, `postinstall`, and `prepare`.
- Package-manager hardening gaps such as missing lockfiles, missing `packageManager`, and missing install-script controls.
- GitHub Actions risk patterns such as `pull_request_target`, unpinned actions, cache use across trust boundaries, and broad `id-token: write`.

This skill is inspired by the layered approach in `skill-protego`, but it is intentionally narrower: fast local scans for JavaScript/npm projects and CI supply-chain hygiene.

## Safety Rules

- Run read-only scans first. Do not edit files, delete dependencies, reinstall packages, clean caches, rotate credentials, or push commits unless the user explicitly asks after the report.
- Keep source code, lockfiles, and reports local unless the user explicitly asks to share them.
- Treat `critical` findings as deploy/publish blockers.
- Treat supply-chain incident matches as possible host compromise if the package was installed during the incident window.
- Explain false-positive uncertainty clearly. Static scanning is heuristic.

## Quick Start

From any project root:

```bash
python3 /Users/siuserxiaowei/Documents/New\ project\ 3/.agents/skills/security-scan/scripts/supply_chain_scan.py .
```

For machine-readable output:

```bash
python3 /Users/siuserxiaowei/Documents/New\ project\ 3/.agents/skills/security-scan/scripts/supply_chain_scan.py . --json
```

If the user asks for a full report, run the scanner and render the result in the user's language. In Chinese, prefer:

```text
结论
高危问题
中低风险
为什么重要
建议动作
```

## Workflow

1. Identify the project root. Use the current working directory unless the user names another path.
2. Run `scripts/supply_chain_scan.py <root> --json`.
3. Read the JSON summary and findings.
4. Report findings with file and line references when present.
5. If there are TanStack malicious version hits, recommend immediate containment:
   - Stop installs/builds/deploys from that machine and CI environment.
   - Remove the malicious versions and upgrade to patched versions.
   - Reinstall from a clean lockfile.
   - Rotate credentials reachable from the install host: npm, GitHub, SSH, AWS/GCP/Kubernetes/Vault as applicable.
6. If there are GitHub Actions findings, explain the trust-boundary issue rather than only saying "workflow risky".
7. Ask before making any remediation change.

## Severity Model

- `critical`: Known malicious version, clear credential-exfiltration indicator, or CI pattern that can publish with trusted identity. Do not deploy/publish before review.
- `high`: Install-script abuse or high-risk dependency source that can run code at install time.
- `medium`: Hardening gap, unpinned action, broad token permission, missing lockfile.
- `low`: Inventory or informational concern.

## TanStack Incident Context

Read `references/tanstack-2026.md` when the user asks what the TanStack event means, why `pull_request_target` is dangerous, or what to do after exposure.

Core explanation:

- The attacker did not need to steal an npm password.
- Malicious PR code crossed the fork-to-base trust boundary through `pull_request_target`.
- GitHub Actions cache carried poisoned artifacts into a release workflow.
- The release runner had `id-token: write`; malware extracted an OIDC token from runner memory and published to npm under a trusted publisher identity.
- The payload ran during package install and attempted to collect cloud, GitHub, npm, Kubernetes, Vault, and SSH credentials.

## Output Guidance

For a clean scan:

```text
结论：当前扫描没有发现已知 TanStack 恶意版本，也没有明显的 GitHub Actions 供应链高危模式。
残余风险：这是本地启发式扫描，不替代 Snyk/Socket/OSV/Dependabot 等专业工具。
```

For findings:

```text
结论：发现 1 个 critical，2 个 medium。critical 是阻断项，建议先不要部署或发布。

高危问题：
- [critical] package-lock.json 命中 @tanstack/react-router@1.169.5，这是 GHSA-g7cv-rxg3-hmpx 列出的恶意版本。

建议动作：
1. 升级到 patched version。
2. 删除 node_modules 和 lockfile 后从可信源重装。
3. 如果这台机器在 2026-05-11 19:20-19:26 UTC 附近运行过 install，按潜在泄露处理并轮换相关凭据。
```

## Files

- `scripts/supply_chain_scan.py`: local read-only scanner.
- `references/tanstack-2026.md`: incident explanation, indicators, and response checklist.

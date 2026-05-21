# Security Scan Skill

<!-- SIUSER-SEO-INTRO:START -->

## 项目介绍 / Project Introduction

**中文介绍**：本地安全扫描 Skill，用于 npm 依赖、供应链风险、敏感信息和项目安全检查的自动化实践。

**English**: A local security-scan skill for npm dependencies, supply-chain risks, secret detection, and automated project security checks.

**SEO 关键词 / SEO Keywords**: security scan, npm security, supply chain security, secret detection, 安全扫描

<!-- SIUSER-SEO-INTRO:END -->


> A local-only Codex skill for npm supply-chain incident checks, TanStack compromise detection, lockfile review, install-script risk, and GitHub Actions CI/CD hardening.

中文说明见下方：[中文介绍](#中文介绍)

## Why This Exists

In May 2026, TanStack disclosed an npm supply-chain compromise involving 42 packages and 84 polluted versions. The attack chain crossed the GitHub Actions trust boundary through `pull_request_target`, cache poisoning, and OIDC token extraction, then published malicious npm versions under a trusted identity.

This skill turns that incident into a practical local scanner:

- Is my project locked to a known malicious `@tanstack/*` version?
- Does my lockfile contain suspicious dependency sources?
- Do my packages run install-time scripts?
- Does my GitHub Actions setup have `pull_request_target`, cache, or OIDC risks?
- What should I do before deploying, publishing, or rotating credentials?

## What It Scans

The bundled scanner is read-only and dependency-free. It does not upload source code, install packages, delete files, rewrite lockfiles, or rotate secrets.

It checks:

- Known malicious TanStack versions from `GHSA-g7cv-rxg3-hmpx / CVE-2026-45321`.
- `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, and other npm-family lockfiles.
- Non-registry dependency sources such as `git+`, `github:`, `http:`, `file:`, and `link:`.
- npm lifecycle scripts such as `preinstall`, `install`, `postinstall`, `prepare`, and `prepublish`.
- Package-manager hardening gaps such as missing lockfiles and missing `packageManager`.
- GitHub Actions risk patterns:
  - `pull_request_target` that checks out or runs PR code.
  - `pull_request_target` combined with dependency cache.
  - Broad `id-token: write`.
  - Third-party actions not pinned to full commit SHAs.

## Quick Start

Run directly from any project:

```bash
python3 scripts/supply_chain_scan.py /path/to/project --json
```

Or from inside the project:

```bash
python3 scripts/supply_chain_scan.py .
```

The scanner exits with:

- `0` if there are no critical/high findings.
- `1` if critical or high findings are present.
- `2` if the target path does not exist.

## Install As A Codex Skill

Clone this repository into a Codex-discoverable skills directory:

```bash
mkdir -p ~/.codex/skills
git clone https://github.com/siuserxiaowei/security-scan-skill.git ~/.codex/skills/security-scan
```

Then start a new Codex session and ask:

```text
帮我对这个项目做一次安全扫描，重点检查 npm 供应链、TanStack 投毒版本和 GitHub Actions。
```

## Severity

- `critical`: Known malicious version or a CI trust-boundary issue that can publish or execute untrusted code.
- `high`: Install-script or cache pattern that deserves immediate review.
- `medium`: Hardening gap or risky but context-dependent configuration.
- `low`: Informational hardening suggestion.

## Important Limits

This is a heuristic local scanner. It is useful for quick triage, but it does not replace Snyk, Socket, OSV, Dependabot, Phylum, Aikido, gitleaks, or a professional security review.

If the scanner reports a known malicious version, treat the install host and CI environment as potentially exposed until you have reviewed logs and rotated reachable credentials.

## Sources

- TanStack postmortem: https://tanstack.com/blog/npm-supply-chain-compromise-postmortem
- GitHub Advisory: https://github.com/advisories/GHSA-g7cv-rxg3-hmpx
- Cloudsmith writeup: https://cloudsmith.com/blog/tanstack-npm-packages-compromised-in-mini-shai-hulud-attack

---

# 中文介绍

> 一个本地只读的 Codex 安全扫描 Skill，用来检查 npm 供应链投毒、TanStack 恶意版本、lockfile 风险、安装脚本风险，以及 GitHub Actions CI/CD 配置风险。

## 为什么做这个 Skill

2026 年 5 月，TanStack 披露了一起 npm 供应链投毒事件：42 个包、84 个版本被污染。攻击链不是简单的“npm 密码被偷”，而是利用了 GitHub Actions 的 `pull_request_target` 信任边界、缓存投毒和 OIDC token 提取，最后以可信发布身份把恶意版本发到了 npm。

这个 Skill 的目标是把这类事件变成一个可执行的本地检查：

- 我的项目有没有锁到已知恶意 `@tanstack/*` 版本？
- lockfile 里有没有可疑依赖来源？
- 包安装时有没有执行 `postinstall` 这类脚本？
- GitHub Actions 有没有 `pull_request_target`、cache、OIDC 权限风险？
- 在部署、发布或轮换密钥前，我应该先看哪些问题？

## 扫描什么

内置脚本是本地只读扫描器，不上传源码，不安装依赖，不删除文件，不重写 lockfile，也不自动轮换密钥。

它会检查：

- `GHSA-g7cv-rxg3-hmpx / CVE-2026-45321` 中列出的 TanStack 恶意版本。
- `package.json`、`package-lock.json`、`pnpm-lock.yaml`、`yarn.lock` 等 npm 系 lockfile。
- `git+`、`github:`、`http:`、`file:`、`link:` 等非 registry 依赖来源。
- `preinstall`、`install`、`postinstall`、`prepare`、`prepublish` 等 npm 生命周期脚本。
- 缺 lockfile、缺 `packageManager` 等包管理器加固问题。
- GitHub Actions 风险模式：
  - `pull_request_target` 检出或执行 PR 代码。
  - `pull_request_target` 和依赖缓存同时出现。
  - 过宽的 `id-token: write`。
  - 第三方 actions 没有 pin 到完整 commit SHA。

## 快速使用

在任意项目上直接运行：

```bash
python3 scripts/supply_chain_scan.py /path/to/project --json
```

或进入项目目录后运行：

```bash
python3 scripts/supply_chain_scan.py .
```

退出码含义：

- `0`：没有 critical/high 问题。
- `1`：存在 critical 或 high 问题。
- `2`：目标路径不存在。

## 作为 Codex Skill 安装

把仓库 clone 到 Codex 能发现的 skills 目录：

```bash
mkdir -p ~/.codex/skills
git clone https://github.com/siuserxiaowei/security-scan-skill.git ~/.codex/skills/security-scan
```

然后开启新的 Codex 会话，直接说：

```text
帮我对这个项目做一次安全扫描，重点检查 npm 供应链、TanStack 投毒版本和 GitHub Actions。
```

## 风险级别

- `critical`：已知恶意版本，或能跨信任边界执行/发布的 CI 配置问题。
- `high`：安装脚本或缓存模式，需要立刻人工复核。
- `medium`：加固缺口，或依赖具体上下文判断的风险配置。
- `low`：信息提示或加固建议。

## 重要限制

这是一个启发式本地扫描器，适合快速排查和写作/教学/自查场景，但不能替代 Snyk、Socket、OSV、Dependabot、Phylum、Aikido、gitleaks 或专业安全审计。

如果扫描命中了已知恶意版本，请把运行过安装命令的开发机和 CI 环境当作“可能已暴露”处理，先查日志，再轮换相关凭据。

## 参考资料

- TanStack 官方复盘：https://tanstack.com/blog/npm-supply-chain-compromise-postmortem
- GitHub Advisory：https://github.com/advisories/GHSA-g7cv-rxg3-hmpx
- Cloudsmith 分析：https://cloudsmith.com/blog/tanstack-npm-packages-compromised-in-mini-shai-hulud-attack

<!-- SIUSER-CONTACT:START -->

## 联系我 / Contact

想交流 AI 工具、内容自动化、SEO、私域增长或项目合作，可以扫码加我微信。

For collaboration on AI tools, content automation, SEO, private-domain growth, or product experiments, scan the WeChat QR code below.

<img src="https://raw.githubusercontent.com/siuserxiaowei/siuserxiaowei/main/assets/contact/wechat-qrcode.jpg" width="180" alt="WeChat QR code / 微信二维码" />

**关键词 / Keywords**: security scan, npm security, supply chain security, secret detection, AI tools, AI automation, GitHub Pages, SEO

<!-- SIUSER-CONTACT:END -->

#!/usr/bin/env python3
"""Read-only npm supply-chain and GitHub Actions scanner.

The scanner is intentionally local-first and dependency-free. It does not call
registries, upload source, modify files, delete caches, or install packages.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


TANSTACK_ADVISORY = "GHSA-g7cv-rxg3-hmpx"
TANSTACK_CVE = "CVE-2026-45321"
TANSTACK_MALICIOUS: dict[str, set[str]] = {
    "@tanstack/arktype-adapter": {"1.166.12", "1.166.15"},
    "@tanstack/eslint-plugin-router": {"1.161.12", "1.161.9"},
    "@tanstack/eslint-plugin-start": {"0.0.4", "0.0.7"},
    "@tanstack/history": {"1.161.12", "1.161.9"},
    "@tanstack/nitro-v2-vite-plugin": {"1.154.12", "1.154.15"},
    "@tanstack/react-router": {"1.169.5", "1.169.8"},
    "@tanstack/react-router-devtools": {"1.166.16", "1.166.19"},
    "@tanstack/react-router-ssr-query": {"1.166.15", "1.166.18"},
    "@tanstack/react-start": {"1.167.68", "1.167.71"},
    "@tanstack/react-start-client": {"1.166.51", "1.166.54"},
    "@tanstack/react-start-rsc": {"0.0.47", "0.0.50"},
    "@tanstack/react-start-server": {"1.166.55", "1.166.58"},
    "@tanstack/router-cli": {"1.166.46", "1.166.49"},
    "@tanstack/router-core": {"1.169.5", "1.169.8"},
    "@tanstack/router-devtools": {"1.166.16", "1.166.19"},
    "@tanstack/router-devtools-core": {"1.167.6", "1.167.9"},
    "@tanstack/router-generator": {"1.166.45", "1.166.48"},
    "@tanstack/router-plugin": {"1.167.38", "1.167.41"},
    "@tanstack/router-ssr-query-core": {"1.168.3", "1.168.6"},
    "@tanstack/router-utils": {"1.161.11", "1.161.14"},
    "@tanstack/router-vite-plugin": {"1.166.53", "1.166.56"},
    "@tanstack/solid-router": {"1.169.5", "1.169.8"},
    "@tanstack/solid-router-devtools": {"1.166.16", "1.166.19"},
    "@tanstack/solid-router-ssr-query": {"1.166.15", "1.166.18"},
    "@tanstack/solid-start": {"1.167.65", "1.167.68"},
    "@tanstack/solid-start-client": {"1.166.50", "1.166.53"},
    "@tanstack/solid-start-server": {"1.166.54", "1.166.57"},
    "@tanstack/start-client-core": {"1.168.5", "1.168.8"},
    "@tanstack/start-fn-stubs": {"1.161.12", "1.161.9"},
    "@tanstack/start-plugin-core": {"1.169.23", "1.169.26"},
    "@tanstack/start-server-core": {"1.167.33", "1.167.36"},
    "@tanstack/start-static-server-functions": {"1.166.44", "1.166.47"},
    "@tanstack/start-storage-context": {"1.166.38", "1.166.41"},
    "@tanstack/valibot-adapter": {"1.166.12", "1.166.15"},
    "@tanstack/virtual-file-routes": {"1.161.10", "1.161.13"},
    "@tanstack/vue-router": {"1.169.5", "1.169.8"},
    "@tanstack/vue-router-devtools": {"1.166.16", "1.166.19"},
    "@tanstack/vue-router-ssr-query": {"1.166.15", "1.166.18"},
    "@tanstack/vue-start": {"1.167.61", "1.167.64"},
    "@tanstack/vue-start-client": {"1.166.46", "1.166.49"},
    "@tanstack/vue-start-server": {"1.166.50", "1.166.53"},
    "@tanstack/zod-adapter": {"1.166.12", "1.166.15"},
}


EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    ".pnpm",
    ".yarn",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "coverage",
    ".venv",
    "venv",
}

LOCKFILES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
}

INSTALL_HOOKS = {"preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly"}
REMOTE_DEP_PREFIXES = ("git+", "github:", "git://", "git@", "http://", "https://", "file:", "link:")
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def read_text(path: Path, limit: int = 5_000_000) -> str:
    try:
        if path.stat().st_size > limit:
            return path.read_bytes()[:limit].decode("utf-8", "replace")
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def load_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def line_number(text: str, needle: str) -> int:
    idx = text.find(needle)
    if idx < 0:
        return 0
    return text[:idx].count("\n") + 1


def finding(
    findings: list[dict[str, Any]],
    *,
    severity: str,
    area: str,
    title: str,
    path: Path,
    root: Path,
    line: int = 0,
    evidence: str = "",
    recommendation: str = "",
    advisory: str | None = None,
) -> None:
    findings.append(
        {
            "severity": severity,
            "area": area,
            "title": title,
            "file": rel(path, root),
            "line": line,
            "evidence": evidence[:260],
            "recommendation": recommendation,
            "advisory": advisory or "",
        }
    )


def iter_files(root: Path, names: set[str] | None = None, suffixes: tuple[str, ...] = ()) -> list[Path]:
    results: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
        base = Path(dirpath)
        for name in filenames:
            if names and name in names:
                results.append(base / name)
            elif suffixes and name.endswith(suffixes):
                results.append(base / name)
    return results


def detect_ecosystems(root: Path) -> list[str]:
    ecosystems = []
    if iter_files(root, {"package.json"}):
        ecosystems.append("npm")
    if iter_files(root, {"requirements.txt", "pyproject.toml", "Pipfile"}):
        ecosystems.append("python")
    if iter_files(root, {"go.mod"}):
        ecosystems.append("go")
    if iter_files(root, {"Cargo.toml"}):
        ecosystems.append("rust")
    return ecosystems


def normalize_version(value: str) -> str:
    value = value.strip()
    value = re.sub(r"^[~^=<>v\s]+", "", value)
    value = value.split(" ")[0]
    return value


def package_json_dependencies(data: dict[str, Any]) -> dict[str, str]:
    deps: dict[str, str] = {}
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        value = data.get(key)
        if isinstance(value, dict):
            for dep, spec in value.items():
                deps[str(dep)] = str(spec)
    return deps


def scan_package_json(path: Path, root: Path, findings: list[dict[str, Any]]) -> None:
    data = load_json(path)
    if not isinstance(data, dict):
        finding(
            findings,
            severity="medium",
            area="manifest",
            title="package.json cannot be parsed",
            path=path,
            root=root,
            recommendation="Fix JSON syntax before trusting dependency scan results.",
        )
        return

    text = read_text(path)
    deps = package_json_dependencies(data)
    for pkg, spec in deps.items():
        normalized = normalize_version(spec)
        if pkg in TANSTACK_MALICIOUS and normalized in TANSTACK_MALICIOUS[pkg]:
            finding(
                findings,
                severity="critical",
                area="tanstack",
                title=f"Direct dependency requests known malicious {pkg}@{normalized}",
                path=path,
                root=root,
                line=line_number(text, pkg),
                evidence=f"{pkg}: {spec}",
                advisory=TANSTACK_ADVISORY,
                recommendation="Upgrade to the patched version and regenerate the lockfile from a clean environment.",
            )
        elif pkg.startswith("@tanstack/") and pkg in TANSTACK_MALICIOUS and spec[:1] in {"^", "~", "*", ">", "<"}:
            finding(
                findings,
                severity="medium",
                area="tanstack",
                title=f"Range dependency on affected TanStack package {pkg}",
                path=path,
                root=root,
                line=line_number(text, pkg),
                evidence=f"{pkg}: {spec}",
                advisory=TANSTACK_ADVISORY,
                recommendation="Check the lockfile for exact installed versions. Pin or upgrade to patched versions.",
            )

        if spec.startswith(REMOTE_DEP_PREFIXES):
            finding(
                findings,
                severity="high" if pkg.startswith("@tanstack/") else "medium",
                area="dependency-source",
                title=f"Dependency uses non-registry source: {pkg}",
                path=path,
                root=root,
                line=line_number(text, pkg),
                evidence=f"{pkg}: {spec}",
                recommendation="Prefer registry packages with lockfile integrity. If this is intentional, pin and audit the source commit.",
            )

    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for name, command in scripts.items():
            if name in INSTALL_HOOKS:
                severity = "high" if re.search(r"curl|wget|bash|sh\s+-c|base64|node\s+-e|python\s+-c", str(command)) else "medium"
                finding(
                    findings,
                    severity=severity,
                    area="install-script",
                    title=f"Install lifecycle script present: {name}",
                    path=path,
                    root=root,
                    line=line_number(text, f'"{name}"'),
                    evidence=f"{name}: {command}",
                    recommendation="Audit install scripts carefully. Disable install scripts by default in CI when possible.",
                )

    if "packageManager" not in data:
        finding(
            findings,
            severity="medium",
            area="hardening",
            title="packageManager field is missing",
            path=path,
            root=root,
            recommendation="Add packageManager to pin npm/pnpm/yarn/bun behavior across developer machines and CI.",
        )


def lockfile_hit_text(text: str, pkg: str, version: str) -> bool:
    pkg_re = re.escape(pkg)
    ver_re = re.escape(version)
    if re.search(pkg_re + r"[@/:\",\s-]+" + ver_re, text):
        return True
    for match in re.finditer(pkg_re, text):
        window = text[match.start() : match.start() + 700]
        if re.search(r"version[:=\s\"']+" + ver_re, window):
            return True
        if version in window and "integrity" in window:
            return True
    return False


def scan_lockfile(path: Path, root: Path, findings: list[dict[str, Any]]) -> None:
    data = load_json(path) if path.name in {"package-lock.json", "npm-shrinkwrap.json"} else None
    text = read_text(path)
    seen_malicious: set[tuple[str, str]] = set()
    if isinstance(data, dict):
        packages = data.get("packages")
        if isinstance(packages, dict):
            for package_path, meta in packages.items():
                if not isinstance(meta, dict):
                    continue
                name = meta.get("name")
                if not name and isinstance(package_path, str):
                    marker = "node_modules/"
                    if marker in package_path:
                        name = package_path.split(marker, 1)[1]
                version = str(meta.get("version") or "")
                if name in TANSTACK_MALICIOUS and version in TANSTACK_MALICIOUS[name]:
                    seen_malicious.add((str(name), version))
                    finding(
                        findings,
                        severity="critical",
                        area="tanstack",
                        title=f"Lockfile contains malicious {name}@{version}",
                        path=path,
                        root=root,
                        line=line_number(text, str(name)),
                        evidence=f"{name}@{version}",
                        advisory=TANSTACK_ADVISORY,
                        recommendation="Upgrade to patched version, remove node_modules, reinstall from a clean lockfile, and rotate reachable credentials if installed during the incident window.",
                    )
        dependencies = data.get("dependencies")
        if isinstance(dependencies, dict):
            for name, meta in dependencies.items():
                if isinstance(meta, dict):
                    version = str(meta.get("version") or "")
                    if name in TANSTACK_MALICIOUS and version in TANSTACK_MALICIOUS[name]:
                        seen_malicious.add((str(name), version))
                        finding(
                            findings,
                            severity="critical",
                            area="tanstack",
                            title=f"Lockfile contains malicious {name}@{version}",
                            path=path,
                            root=root,
                            line=line_number(text, str(name)),
                            evidence=f"{name}@{version}",
                            advisory=TANSTACK_ADVISORY,
                            recommendation="Upgrade to patched version, remove node_modules, reinstall from a clean lockfile, and rotate reachable credentials if installed during the incident window.",
                        )

    for pkg, versions in TANSTACK_MALICIOUS.items():
        for version in versions:
            if (pkg, version) in seen_malicious:
                continue
            if lockfile_hit_text(text, pkg, version):
                finding(
                    findings,
                    severity="critical",
                    area="tanstack",
                    title=f"Lockfile text matches malicious {pkg}@{version}",
                    path=path,
                    root=root,
                    line=line_number(text, pkg),
                    evidence=f"{pkg}@{version}",
                    advisory=TANSTACK_ADVISORY,
                    recommendation="Verify exact lockfile entry. If confirmed, upgrade and treat the install host as potentially compromised.",
                )

    for pattern in ("getsession.org", "filev2.getsession.org", "seed1.getsession.org", "seed2.getsession.org", "seed3.getsession.org", "router_init.js"):
        if pattern in text:
            finding(
                findings,
                severity="critical",
                area="ioc",
                title=f"TanStack payload indicator found: {pattern}",
                path=path,
                root=root,
                line=line_number(text, pattern),
                evidence=pattern,
                advisory=TANSTACK_ADVISORY,
                recommendation="Treat this as a possible malware indicator and investigate immediately.",
            )

    if re.search(r"git\+|github:|git://|git@", text):
        finding(
            findings,
            severity="medium",
            area="dependency-source",
            title="Lockfile contains git-based dependency source",
            path=path,
            root=root,
            line=0,
            evidence="git/github dependency source detected",
            recommendation="Audit git-based dependencies. Registry packages with integrity hashes are easier to verify.",
        )


def scan_package_manager_hardening(root: Path, findings: list[dict[str, Any]]) -> None:
    package_jsons = iter_files(root, {"package.json"})
    for package_json in package_jsons:
        project_dir = package_json.parent
        lockfiles = [project_dir / name for name in LOCKFILES if (project_dir / name).exists()]
        if not lockfiles:
            finding(
                findings,
                severity="medium",
                area="hardening",
                title="npm project has no lockfile",
                path=package_json,
                root=root,
                recommendation="Commit a lockfile and use frozen installs in CI. Without it, ranges may resolve to newly published poisoned versions.",
            )

        npmrc = project_dir / ".npmrc"
        pnpm_workspace = project_dir / "pnpm-workspace.yaml"
        yarnrc = project_dir / ".yarnrc.yml"
        if npmrc.exists():
            text = read_text(npmrc)
            if "ignore-scripts=true" not in text.replace(" ", ""):
                finding(
                    findings,
                    severity="low",
                    area="hardening",
                    title=".npmrc does not set ignore-scripts=true",
                    path=npmrc,
                    root=root,
                    recommendation="For sensitive CI, consider disabling install scripts and rebuilding only allowlisted native dependencies.",
                )
        elif not pnpm_workspace.exists() and not yarnrc.exists():
            finding(
                findings,
                severity="low",
                area="hardening",
                title="No package-manager install-script hardening file found",
                path=package_json,
                root=root,
                recommendation="Consider .npmrc ignore-scripts=true, pnpm allowBuilds/minimumReleaseAge, or yarn enableScripts=false for high-risk environments.",
            )


def scan_github_actions(root: Path, findings: list[dict[str, Any]]) -> None:
    workflow_dir = root / ".github" / "workflows"
    if not workflow_dir.is_dir():
        return
    for path in sorted(workflow_dir.glob("*.y*ml")):
        text = read_text(path)
        lower = text.lower()
        has_pr_target = "pull_request_target" in lower
        has_checkout_pr = bool(re.search(r"refs/pull|github\.event\.pull_request\.(head|number)|pull_request\.head", text))
        runs_code = bool(re.search(r"\b(npm|pnpm|yarn|bun)\s+(install|ci|test|build|run)|\bmake\b|\bpytest\b|\bgo test\b|\bcargo\s+(test|build)\b", text))
        uses_cache = "actions/cache" in lower or "setup-node" in lower and "cache:" in lower
        id_token_write = bool(re.search(r"id-token\s*:\s*write", lower))

        if has_pr_target and has_checkout_pr and runs_code:
            finding(
                findings,
                severity="critical",
                area="github-actions",
                title="pull_request_target appears to run fork-controlled code",
                path=path,
                root=root,
                line=line_number(lower, "pull_request_target"),
                evidence="pull_request_target + PR checkout + install/build/test command",
                recommendation="Use pull_request for untrusted code, or keep pull_request_target limited to metadata-only actions that never check out or run PR code.",
            )
        elif has_pr_target:
            finding(
                findings,
                severity="medium",
                area="github-actions",
                title="Workflow uses pull_request_target",
                path=path,
                root=root,
                line=line_number(lower, "pull_request_target"),
                evidence="pull_request_target",
                recommendation="Verify it never checks out or executes fork-controlled code and uses minimal permissions.",
            )

        if has_pr_target and uses_cache:
            finding(
                findings,
                severity="high",
                area="github-actions",
                title="pull_request_target workflow uses dependency cache",
                path=path,
                root=root,
                line=line_number(lower, "actions/cache") or line_number(lower, "cache:"),
                evidence="pull_request_target + cache",
                recommendation="Avoid writing caches from untrusted PR contexts. Cache poisoning was central to the TanStack incident.",
            )

        if id_token_write:
            severity = "high" if "npm publish" in lower or "trusted" in lower or "publish" in lower else "medium"
            finding(
                findings,
                severity=severity,
                area="github-actions",
                title="Workflow grants id-token: write",
                path=path,
                root=root,
                line=line_number(lower, "id-token"),
                evidence="id-token: write",
                recommendation="Scope OIDC permissions to the narrow publish job only, after all untrusted build steps and cache restores are complete.",
            )

        for match in re.finditer(r"uses:\s*([^\s#]+)", text):
            ref = match.group(1)
            if "@" not in ref:
                continue
            version_ref = ref.rsplit("@", 1)[1].strip().strip("'\"")
            if not re.fullmatch(r"[0-9a-fA-F]{40}", version_ref):
                severity = "medium" if any(x in lower for x in ("publish", "release", "id-token")) else "low"
                finding(
                    findings,
                    severity=severity,
                    area="github-actions",
                    title=f"Action is not pinned to a full commit SHA: {ref}",
                    path=path,
                    root=root,
                    line=text[: match.start()].count("\n") + 1,
                    evidence=ref,
                    recommendation="For sensitive workflows, pin third-party actions to full commit SHAs.",
                )


def scan(root: Path) -> dict[str, Any]:
    root = root.resolve()
    findings: list[dict[str, Any]] = []
    ecosystems = detect_ecosystems(root)

    for path in iter_files(root, {"package.json"}):
        scan_package_json(path, root, findings)

    for path in iter_files(root, LOCKFILES):
        scan_lockfile(path, root, findings)

    scan_package_manager_hardening(root, findings)
    scan_github_actions(root, findings)

    findings.sort(key=lambda item: (SEVERITY_ORDER.get(item["severity"], 9), item["file"], item["line"]))
    counts = {level: 0 for level in ("critical", "high", "medium", "low")}
    for item in findings:
        counts[item["severity"]] = counts.get(item["severity"], 0) + 1

    return {
        "scan_root": str(root),
        "scanner": "security-scan/supply_chain_scan.py",
        "ecosystems_detected": ecosystems,
        "advisories_embedded": [TANSTACK_ADVISORY, TANSTACK_CVE],
        "summary": {
            "total": len(findings),
            **counts,
        },
        "findings": findings,
        "exit_code": 1 if counts.get("critical", 0) or counts.get("high", 0) else 0,
    }


def render_text(result: dict[str, Any]) -> str:
    summary = result["summary"]
    if summary["critical"]:
        verdict = f"CRITICAL: {summary['critical']} critical, {summary['high']} high, {summary['medium']} medium, {summary['low']} low"
    elif summary["high"]:
        verdict = f"HIGH RISK: {summary['high']} high, {summary['medium']} medium, {summary['low']} low"
    elif summary["total"]:
        verdict = f"WARNINGS: {summary['medium']} medium, {summary['low']} low"
    else:
        verdict = "PASS: no local supply-chain findings detected"

    lines = [
        verdict,
        f"Root: {result['scan_root']}",
        f"Ecosystems: {', '.join(result['ecosystems_detected']) or 'none detected'}",
        "",
    ]
    for item in result["findings"]:
        location = item["file"]
        if item["line"]:
            location += f":{item['line']}"
        lines.append(f"[{item['severity'].upper()}] {item['title']}")
        lines.append(f"  area: {item['area']}")
        lines.append(f"  file: {location}")
        if item["evidence"]:
            lines.append(f"  evidence: {item['evidence']}")
        if item["recommendation"]:
            lines.append(f"  recommendation: {item['recommendation']}")
        if item["advisory"]:
            lines.append(f"  advisory: {item['advisory']}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only npm supply-chain and GitHub Actions scanner.")
    parser.add_argument("root", nargs="?", default=".", help="Project root to scan")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    args = parser.parse_args()

    root = Path(args.root).expanduser()
    if not root.exists():
        print(f"Path does not exist: {root}", file=sys.stderr)
        return 2
    result = scan(root)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(render_text(result), end="")
    return int(result["exit_code"])


if __name__ == "__main__":
    raise SystemExit(main())

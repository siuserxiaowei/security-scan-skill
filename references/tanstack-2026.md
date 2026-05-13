# TanStack 2026 npm Supply-Chain Incident

Use this reference when explaining the TanStack npm compromise or interpreting scan results.

## What Happened

On 2026-05-11 between 19:20 and 19:26 UTC, 84 malicious versions across 42 `@tanstack/*` npm packages were published.

The important point: this was not a simple "npm password got stolen" case.

The attack chain was:

1. A malicious fork PR triggered `pull_request_target`.
2. The workflow checked out or built fork-controlled code while running in the base repository trust context.
3. GitHub Actions cache was poisoned across the fork-to-base boundary.
4. A later release workflow restored the poisoned cache.
5. The release workflow had `id-token: write` for npm trusted publishing.
6. Malware extracted an OIDC token from the runner process memory and used it to publish malicious npm packages.

## Why It Matters

The payload ran during `npm install`, `pnpm install`, or `yarn install`. If a developer laptop or CI runner installed an affected version, treat that machine as potentially compromised.

The payload attempted to collect:

- AWS metadata and secrets.
- GCP metadata credentials.
- Kubernetes service-account tokens.
- Vault tokens.
- npm tokens in `~/.npmrc`.
- GitHub tokens from environment, `gh` CLI config, and `.git-credentials`.
- SSH private keys under `~/.ssh`.

It also used Session/Oxen network endpoints such as `filev2.getsession.org` and `seed1.getsession.org` / `seed2.getsession.org` / `seed3.getsession.org`.

## Packages

The local scanner embeds exact affected versions from `GHSA-g7cv-rxg3-hmpx`. Each affected package has two malicious versions.

Confirmed-clean TanStack families according to the official postmortem include `@tanstack/query*`, `@tanstack/table*`, `@tanstack/form*`, `@tanstack/virtual*`, `@tanstack/store`, and `@tanstack/start` meta-package, but not every similarly named package is automatically safe. Check the lockfile.

## What To Do If A Project Hits

If a lockfile contains an affected version:

1. Stop running installs/builds/deploys on the affected machine and CI runner.
2. Upgrade to patched versions listed by the advisory.
3. Delete `node_modules` and reinstall from a clean lockfile.
4. Review CI logs and npm publish logs during the incident window.
5. Rotate credentials reachable from that host: npm, GitHub, SSH, AWS, GCP, Kubernetes, Vault.
6. In CI, purge caches that may have been restored by release workflows.
7. Add package-manager hardening:
   - Prefer lockfile-enforced installs: `npm ci`, `pnpm install --frozen-lockfile`, `yarn install --immutable`.
   - Consider release-age/cooldown policies for newly published packages.
   - Consider disabling install scripts by default and allowlisting only trusted build scripts.

## GitHub Actions Hardening

Look for:

- `pull_request_target` that checks out PR code or `refs/pull/...`.
- `pull_request_target` that runs install, build, test, benchmark, or codegen on fork-controlled code.
- `actions/cache` in workflows that cross fork/base trust boundaries.
- `id-token: write` set at workflow scope instead of only on the publish job.
- Release workflows that restore caches before publish.
- Third-party actions referenced by tags such as `@v4`, `@main`, or `@master` instead of commit SHAs.

Safer patterns:

- Use `pull_request` for untrusted code.
- Use `pull_request_target` only for metadata actions that never check out or run PR code.
- Split test/build and publish credentials into separate workflows/jobs.
- Scope `permissions` at the narrowest job level.
- Pin third-party actions by full commit SHA for sensitive workflows.
- Use cache keys that cannot be written by untrusted PR code.

## Sources To Cite

- TanStack official postmortem: https://tanstack.com/blog/npm-supply-chain-compromise-postmortem
- GitHub Advisory: https://github.com/advisories/GHSA-g7cv-rxg3-hmpx
- Cloudsmith writeup on cooldown policies: https://cloudsmith.com/blog/tanstack-npm-packages-compromised-in-mini-shai-hulud-attack

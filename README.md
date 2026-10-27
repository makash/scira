# scira

**SCIRA** stands for **Supply Chain Incident Response Agent**.

`scira` is a single-binary host/folder incident-response agent for software supply chain incidents, starting with PyPI and npm.

Out of the box, SCIRA helps you respond to two major package supply chain incidents and one MCP configuration risk profile:
- **LiteLLM on PyPI** — detect compromised `litellm` versions, IOC domains, IOC files, and Python environment evidence
- **Axios on npm** — detect compromised `axios` versions, the malicious `plain-crypto-js` dependency, IOC domains, and Node/npm environment evidence
- **MCP STDIO configs** — inventory local MCP servers and flag shell execution, package-runner execution, unpinned runtime resolution, and credential exposure risk

For the first cut, it bundles ecosystem-specific incident-response expertise from [agent-infra-security](https://github.com/makash/agent-infra-security) and ships with built-in `litellm`, `axios`, and `mcp-stdio` incident flows.

![SCIRA demo](assets/demo.gif)

*A quick scan → explain flow for one of SCIRA's built-in incidents.*

## Why SCIRA?

Most incident-response tools people built after the LiteLLM compromise fell into one of four buckets:
- web checkers that cannot inspect your actual machine
- one-off bash or Python scripts tied to a single incident
- agent skills that require Claude Code or another host agent
- manual command lists with no report structure or audit trail

SCIRA takes a different approach:

- **Single binary** — scan a compromised ecosystem without having to trust that ecosystem's tooling first
- **Local-first** — inspect a repo, a home directory, or a server directly
- **Structured output** — human-readable summary, JSON report, and meaningful exit codes
- **Agentic workflow** — deterministic scan first, optional AI explanation second
- **Offline-capable scanning** — the core scan does not need network access
- **Useful today** — built-in response flows for the LiteLLM PyPI compromise and the Axios npm compromise
- **Built to grow** — the model is designed for more incident profiles over time

## Built-in incident response

### Host runtime advisories (October 2026 wave)
Use SCIRA to audit a whole host for the October 2026 security wave. These profiles
detect installed runtimes host-wide (PATH, dpkg, per-user installs like nvm/volta,
running Docker containers, and Docker image metadata), compare them against the
advisory fixed versions, and for eMudhra check TLS trust stores for the
distrusted root.

```bash
sudo scira scan node --all-dirs     # Node.js Oct 2026 security releases (Brotli RCE, TLS/DNS bypasses, eMudhra CA update)
sudo scira scan php --all-dirs      # PHP "PHP2Shell" CVE-2026-109618 / CVE-2026-109619 critical RCEs
sudo scira scan brotli --all-dirs   # Brotli decoder OOB write RCE, CVE-2026-111497 (1.0.3–1.2.0)
sudo scira scan emudhra --all-dirs  # eMudhra emSign intermediate CA compromise (distrusted emSign ECC Root CA - G3)
```

Each profile knows the fixed versions per release line (PHP 8.2.35/8.3.36/8.4.27/8.5.12,
Node 22.23.4/24.22.1/26.12.1, Brotli 1.0.10/1.1.1/1.2.1) and flags EOL lines as
vulnerable. Bundled response expertise and IOC tables live in
`bundled/host-runtime-response/`.

### LiteLLM on PyPI
Use SCIRA to check whether a host, repo, or user environment was affected by the LiteLLM compromise.

SCIRA looks for:
- compromised `litellm` versions
- loose and pinned references in Python manifests and lockfiles
- IOC domains like `models.litellm.cloud` and `checkmarx.zone`
- IOC files like `litellm_init.pth`
- installed-package evidence from Python environments and caches

### Axios on npm
Use SCIRA to check whether a host, repo, or CI workspace was affected by the Axios compromise.

SCIRA looks for:
- compromised `axios` versions
- the malicious `plain-crypto-js` dependency
- loose and pinned references in `package.json` and `package-lock.json`
- IOC domains like `sfrclak.com`
- installed-package evidence from npm environments and caches

### MCP STDIO configuration risk
Use SCIRA to inventory local MCP server configs and find command-execution or supply-chain risk before trusting an AI client, laptop, or developer workstation.

SCIRA looks for:
- MCP config files like `.mcp.json`, `.vscode/mcp.json`, `mcp.json`, `claude_desktop_config.json`, and `mcp_config.json`
- Docker and Compose surfaces like `Dockerfile`, `docker-compose.yml`, `compose.yml`, mounted MCP configs, container commands, env keys, ports, and local Docker runtime metadata when available
- STDIO servers that execute shells like `bash -c`, `sh -c`, `cmd /c`, or PowerShell command strings
- package-runner launchers like `npx -c`, plus unpinned `npx`, `uvx`, `pipx`, `bunx`, and `pnpx` servers
- project-scoped MCP configs that may be editable by local tools or agents
- credential-bearing paths or names such as `.ssh`, `.aws`, `.kube`, `.npmrc`, `docker.sock`, tokens, and API keys

## What it does

- scans a target folder or broad host-visible paths
- ignores self-generated paths like `.git/`, `target/`, and bundled skill assets when walking a target tree
- checks common Python and Node/npm manifests and lockfiles
- hunts for exact compromised versions, loose references, IOC files, IOC domains, and user-visible environment evidence
- reports permission gaps cleanly and suggests `sudo` only when it would help
- can optionally explain the findings with an LLM so the CLI feels like an agent, not just a scanner

## Quick start

```bash
scira scan litellm
scira scan axios --target /srv/app
scira scan mcp-stdio --target ~
scira scan litellm --all-dirs
scira scan axios --format json --output axios-report.json
```

If LLM access is configured and you are in an interactive terminal, `scira` offers to explain the report after the deterministic scan completes.

You can also explain a saved JSON report later:

```bash
scira scan litellm --format json --output report.json
scira explain report.json
```

## What you get back

Example terminal summary:

```text
Status: likely_affected

Why:
- A compromised version or strong IOC evidence was found during the scan.
- Found compromised version 1.82.8 in /srv/app/requirements.txt:1
- Found IOC domain models.litellm.cloud in logs/app.log:42

Immediate next steps:
1. Isolate the affected host or runner
2. Preserve evidence before cleanup
3. Rotate credentials in scope
```

If you need something scriptable or shareable, use JSON output:

```bash
scira scan litellm --target /srv/app --format json --output report.json
```

## Server usage

One of the intended workflows for SCIRA is: copy a single binary to a server, run it as a specific user, and inspect that user's environment.

```bash
scp scira-linux-amd64 server:/tmp/scira
ssh server
chmod +x /tmp/scira
sudo -u myuser -H /tmp/scira scan litellm --target /home/myuser
```

This is useful when:
- you want to inspect a particular operator or app user's home directory
- you do not want to install Python packages or helper scripts on the server
- you want deterministic output plus a report you can save or ship elsewhere

## Install

Download the right binary from the [SCIRA GitHub Releases page](https://github.com/makash/scira/releases), rename it to `scira`, and make it executable.

### macOS (Apple Silicon)

```bash
curl -L -o scira https://github.com/makash/scira/releases/download/v0.2.0/scira-darwin-arm64
chmod +x scira
xattr -d com.apple.quarantine ./scira 2>/dev/null || true
./scira scan litellm
```

### macOS (Intel)

```bash
curl -L -o scira https://github.com/makash/scira/releases/download/v0.2.0/scira-darwin-amd64
chmod +x scira
xattr -d com.apple.quarantine ./scira 2>/dev/null || true
./scira scan litellm
```

### macOS note: Gatekeeper / quarantine

If macOS says the binary cannot be opened because it is from an unidentified developer, remove the quarantine attribute after download:

```bash
xattr -d com.apple.quarantine ./scira
```

If needed, you can verify the attribute first:

```bash
xattr ./scira
```

#### Why devtools hit this

When you download a CLI binary from GitHub Releases, macOS often marks it with `com.apple.quarantine`. Gatekeeper then treats it like an unknown internet download until it is notarized, signed, or explicitly allowed.

That is normal for indie and open source developer tools. `scira` is a direct release binary, not an app distributed through Apple's pipeline, so you may need to clear quarantine before running it.

#### Why this is not just security theater

This should be a deliberate developer workflow, not a blind bypass:

- download from the official [`makash/scira` releases page](https://github.com/makash/scira/releases)
- verify the URL and repo owner
- verify `sha256sums.txt` if you want a stronger trust check
- then remove quarantine and run it

In other words, you are not saying:

> "run a random binary from the internet"

You are saying:

> "I trust this specific release artifact and want macOS to stop treating it as an unknown download."

If `scira` later adds code signing and notarization, this manual step should disappear.

### Linux (x86_64)

```bash
curl -L -o scira https://github.com/makash/scira/releases/download/v0.2.0/scira-linux-amd64
chmod +x scira
./scira scan litellm
```

## LLM setup

### Easiest path

Set a single env var:

```bash
export SCIRA_LLM_API_KEY=...
```

`scira` will try to:
- infer the provider from the key shape
- choose a sensible default model
- enable AI explanation automatically

### Optional overrides

```bash
export SCIRA_LLM_PROVIDER=anthropic|openai|gemini
export SCIRA_LLM_MODEL=...
export SCIRA_LLM_BASE_URL=...
```

It also supports provider-native env vars when present:
- `ANTHROPIC_API_KEY`
- `OPENAI_API_KEY`
- `GEMINI_API_KEY`
- `GOOGLE_API_KEY`

## Trust model

SCIRA is designed to keep evidence collection and reasoning separate.

- **Deterministic scan results are the source of truth**
- **AI explanation is optional and advisory**
- **Core scanning is local-first and offline-capable**
- **MCP Docker inspection is metadata-only** — no registry lookups, no network calls, no `docker exec`, and no container filesystem traversal
- **Nothing leaves the machine unless you explicitly enable an LLM-backed explanation**

That means you can use SCIRA as a plain local incident-response CLI, or as a more agentic tool when you want help interpreting findings.

## Exit codes

- `0` = scan completed, no likely-affected indicators
- `10` = scan completed, follow-up needed
- `20` = scan completed, likely affected
- `1` = operational/configuration error

## Build

```bash
cargo build --release
```

The binary name is:

```bash
./target/release/scira
```

## Bundled intelligence

This repo bundles local copies of:
- `bundled/pypi-supply-chain-response/SKILL.md`
- `bundled/pypi-supply-chain-response/references/ioc-patterns.md`
- `bundled/npm-supply-chain-response/SKILL.md`
- `bundled/npm-supply-chain-response/references/ioc-patterns.md`
- `bundled/mcp-supply-chain-response/SKILL.md`
- `bundled/mcp-supply-chain-response/references/ioc-patterns.md`

Those are used as explanation context so the runtime stays aligned with the marketplace skills while keeping deterministic scanning logic in Rust.

## Current scope

This first cut is intentionally narrow:
- two built-in package incidents: `litellm`, `axios`
- one built-in MCP local config profile: `mcp-stdio`
- ecosystem starting points: PyPI / Python, npm / Node.js, local MCP server configuration, and local Docker/Compose metadata
- host/folder CLI first

Later versions can add more bundled incidents, offline advisory data, and broader ecosystem coverage.

# scira

**SCIRA** stands for **Supply Chain Incident Response Agent**.

`scira` is a single-binary host/folder incident-response agent for software supply chain incidents, starting with PyPI and npm.

For the first cut, it bundles ecosystem-specific incident-response expertise from [agent-infra-security](https://github.com/makash/agent-infra-security) and ships with built-in `litellm` and `axios` incident flows.

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
- **Built to grow** — current built-in incidents are `litellm` and `axios`, and the model is designed for more incident profiles over time

## What it does

- scans a target folder or broad host-visible paths
- ignores self-generated paths like `.git/`, `target/`, and bundled skill assets when walking a target tree
- checks common Python manifests and lockfiles
- hunts for exact compromised versions, loose references, IOC files, IOC domains, and user-visible Python environment evidence
- reports permission gaps cleanly and suggests `sudo` only when it would help
- can optionally explain the findings with an LLM so the CLI feels like an agent, not just a scanner

## Quick start

```bash
scira scan litellm
scira scan axios --target /srv/app
scira scan litellm --all-dirs
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
curl -L -o scira https://github.com/makash/scira/releases/download/v0.1.1/scira-darwin-arm64
chmod +x scira
xattr -d com.apple.quarantine ./scira 2>/dev/null || true
./scira scan litellm
```

### macOS (Intel)

```bash
curl -L -o scira https://github.com/makash/scira/releases/download/v0.1.1/scira-darwin-amd64
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
curl -L -o scira https://github.com/makash/scira/releases/download/v0.1.1/scira-linux-amd64
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

Those are used as explanation context so the runtime stays aligned with the marketplace skills while keeping deterministic scanning logic in Rust.

## Current scope

This first cut is intentionally narrow:
- two built-in incidents: `litellm`, `axios`
- two ecosystem starting points: PyPI / Python and npm / Node.js
- host/folder CLI first

Later versions can add more bundled incidents and broader ecosystem coverage.

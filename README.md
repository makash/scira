# scira

**SCIRA** stands for **Supply Chain Incident Response Agent**.

`scira` is a single-binary host/folder incident-response agent for Python/PyPI supply chain incidents.

For the first cut, it bundles the `pypi-supply-chain-response` expertise from `agent-infra-security` and ships with a built-in `litellm` incident flow.

## What it does

- scans a target folder or broad host-visible paths
- ignores self-generated paths like `.git/`, `target/`, and bundled skill assets when walking a target tree
- checks common Python manifests and lockfiles
- hunts for exact compromised versions, loose references, IOC files, IOC domains, and user-visible Python environment evidence
- reports permission gaps cleanly and suggests `sudo` only when it would help
- can optionally explain the findings with an LLM so the CLI feels like an agent, not just a scanner

## First-cut UX

```bash
scira scan litellm
scira scan litellm --target /srv/app
scira scan litellm --all-dirs
```

If LLM access is configured and you are in an interactive terminal, `scira` offers to explain the report after the deterministic scan completes.

You can also explain a saved JSON report later:

```bash
scira scan litellm --format json --output report.json
scira explain report.json
```

## Install

Download the right binary from the [GitHub Releases](../../releases) page, rename it to `scira`, and make it executable.

### macOS (Apple Silicon)

```bash
curl -L -o scira https://github.com/makash/scira/releases/download/v0.1.0/scira-darwin-arm64
chmod +x scira
./scira scan litellm
```

### macOS (Intel)

```bash
curl -L -o scira https://github.com/makash/scira/releases/download/v0.1.0/scira-darwin-amd64
chmod +x scira
./scira scan litellm
```

### Linux (x86_64)

```bash
curl -L -o scira https://github.com/makash/scira/releases/download/v0.1.0/scira-linux-amd64
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

## Example

```bash
scira scan litellm --target .
```

Typical flow:
1. `scira` collects deterministic evidence
2. `scira` prints a human-readable summary
3. if an LLM API key is available, `scira` offers to explain the findings and remediation guidance

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

Those are used as explanation context so the runtime stays aligned with the marketplace skill while keeping deterministic scanning logic in Rust.

## Current scope

This first cut is intentionally narrow:
- one built-in incident: `litellm`
- one ecosystem focus: PyPI / Python
- host/folder CLI first

Later versions can add more bundled incidents and broader ecosystem coverage.

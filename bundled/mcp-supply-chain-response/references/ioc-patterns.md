# MCP STDIO Risk Patterns

These patterns are local configuration risk indicators, not proof of compromise by themselves.

## High Risk

- `command` is a shell such as `sh`, `bash`, `zsh`, `cmd`, `powershell`, or `pwsh` with command-evaluation args such as `-c` or `/c`.
- `command` is a package runner such as `npx` with command-evaluation args such as `-c` or `--call`.
- Docker or Compose service mounts `/var/run/docker.sock`.
- Docker or Compose service has writable broad host mounts such as `/`, `$HOME`, `/home/*`, or `/Users/*`.
- Docker or Compose service mounts MCP config files such as `.mcp.json`, `mcp.json`, or `claude_desktop_config.json` writable.

## Medium Risk

- STDIO server starts through an unpinned package runner such as `npx`, `uvx`, `pipx`, `bunx`, or `pnpx`.
- MCP config is project-scoped and writable by local developer tools or agents.
- MCP server config references credential-bearing paths or names such as `.ssh`, `.aws`, `.kube`, `.npmrc`, `docker.sock`, `TOKEN`, `SECRET`, or `API_KEY`.
- Docker or Compose service mounts credential paths such as `.ssh`, `.aws`, `.kube`, `.npmrc`, `.docker/config.json`, or `.env`.
- Docker or Compose service exposes MCP-like ports publicly.
- Docker or Compose service references secret-like environment variable names.

## Low Risk

- STDIO MCP server was found, but no higher-risk pattern was detected.
- MCP-like Docker service or container was found, but no higher-risk pattern was detected.

# appcrane-mcp

A tiny **stdio ↔ HTTP bridge** that connects any MCP client to a remote
[AppCrane](https://github.com/gitayg/appCrane) server's `appcrane_*` tools.

AppCrane's MCP is a remote HTTP endpoint (JSON-RPC 2.0 at `POST /api/mcp`), so
clients that speak remote HTTP can connect **directly** — no package needed:

```bash
claude mcp add --transport http appcrane https://crane.example.com/api/mcp \
  --header "X-API-Key: dhk_..." \
  --header "X-Github-Token: ghp_..."
```

Use this proxy only when you want an **npx / Docker** install path, a
**registry listing**, or your MCP client can only spawn a **local stdio**
process. It carries no logic of its own — every tool call runs on your
AppCrane server.

## Configuration

| Env var | Purpose | Required |
|---|---|---|
| `APPCRANE_URL` | Base URL (`https://crane.example.com`) or full `…/api/mcp` URL | yes |
| `APPCRANE_API_KEY` | Your `dhk_*` key → `X-API-Key` | yes |
| `APPCRANE_GITHUB_TOKEN` | `ghp_*` PAT → `X-Github-Token` (enables `github_*` tools) | no |

Positional args also work: `appcrane-mcp <url> <api-key> [github-token]`.

## Use with Claude Code (stdio)

```bash
claude mcp add appcrane \
  --env APPCRANE_URL=https://crane.example.com \
  --env APPCRANE_API_KEY=dhk_user_xxxxxxxx \
  --env APPCRANE_GITHUB_TOKEN=ghp_xxxxxxxx \
  -- npx -y appcrane-mcp
```

## Docker

```bash
docker run -i --rm \
  -e APPCRANE_URL=https://crane.example.com \
  -e APPCRANE_API_KEY=dhk_user_xxxxxxxx \
  ghcr.io/gitayg/appcrane-mcp
```

```jsonc
// claude mcp config (stdio via Docker)
{
  "command": "docker",
  "args": ["run", "-i", "--rm",
    "-e", "APPCRANE_URL", "-e", "APPCRANE_API_KEY", "-e", "APPCRANE_GITHUB_TOKEN",
    "ghcr.io/gitayg/appcrane-mcp"],
  "env": {
    "APPCRANE_URL": "https://crane.example.com",
    "APPCRANE_API_KEY": "dhk_user_xxxxxxxx"
  }
}
```

## Publishing (maintainers)

```bash
cd packages/mcp
npm publish                          # → appcrane-mcp on npm (unscoped, public by default)
docker build -t ghcr.io/gitayg/appcrane-mcp . && docker push ghcr.io/gitayg/appcrane-mcp
```

Then list it in an MCP registry (e.g. the community registries) pointing at
`npx appcrane-mcp` for discoverability.

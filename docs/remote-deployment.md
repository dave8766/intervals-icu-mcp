# Remote Deployment (HTTP / SSE)

How to run the server over HTTP/SSE for remote or hosted use, the available transport flags, and the security model you must apply before exposing it.

By default the server runs over **stdio** — the right transport for local clients like Claude Desktop, Claude Code, and Cursor. For remote deployment (hosted MCP, reverse proxy, Docker-on-a-server, ChatGPT connector), pass `--transport`:

```bash
# Streamable HTTP (recommended — used by ChatGPT and modern remote clients)
intervals-icu-mcp --transport http --host 127.0.0.1 --port 8000

# Legacy SSE (for clients that haven't moved to streamable HTTP yet)
intervals-icu-mcp --transport sse --host 127.0.0.1 --port 8000
```

| Flag | Default | Description |
|---|---|---|
| `--transport` | `stdio` | One of `stdio`, `http`, `sse`, `streamable-http` |
| `--host` | `127.0.0.1` | Interface to bind. Use `0.0.0.0` only inside a container where Docker controls the exposure. |
| `--port` | `8000` | TCP port |
| `--path` | (framework default) | URL path to mount the server under |

## Authentication

Over stdio the operating system is the access boundary — only the local MCP client can reach the process. Over HTTP the URL *is* the boundary, and MCP defines none of its own. An unauthenticated HTTP deployment hands every caller the full tool surface under your Intervals.icu API key: read every activity, rewrite your FTP, create and update calendar events. That is equivalent to publishing the key.

Set `INTERVALS_ICU_AUTH=github` to require OAuth. Authentication is **off by default**, so stdio installs and existing tunnel-fronted deployments are unchanged.

| Variable | Required | Description |
|---|---|---|
| `INTERVALS_ICU_AUTH` | — | `none` (default) or `github` |
| `INTERVALS_ICU_AUTH_GITHUB_CLIENT_ID` | when `github` | Client ID of your GitHub OAuth App |
| `INTERVALS_ICU_AUTH_GITHUB_CLIENT_SECRET` | when `github` | Client secret of that app |
| `INTERVALS_ICU_AUTH_ALLOWED_GITHUB_USERS` | when `github` | Comma-separated GitHub logins permitted to connect |
| `INTERVALS_ICU_AUTH_BASE_URL` | when `github` | Public `https://` URL of the deployment. On Railway, `RAILWAY_PUBLIC_DOMAIN` is used automatically if this is unset. |

### The allowlist is not optional

`INTERVALS_ICU_AUTH_ALLOWED_GITHUB_USERS` is the setting that actually restricts access, and the server **refuses to start without it**.

GitHub OAuth proves that a caller holds a valid GitHub token. It cannot prove the caller is *you* — every GitHub account in the world holds a valid GitHub token. A GitHub OAuth App with no allowlist is therefore a login screen that everybody passes: it reads as security while granting the same access as no authentication at all. The allowlist turns authentication into authorisation.

Logins are matched case-insensitively, as GitHub treats them.

### Setup

1. Create a GitHub OAuth App at <https://github.com/settings/developers> → **New OAuth App**.
2. Set **Authorization callback URL** to your deployment's URL plus `/auth/callback`, for example `https://your-app.up.railway.app/auth/callback`. GitHub compares this exactly, so it must match the running host.
3. Copy the client ID, generate a client secret.
4. Set the variables on your host:

```bash
INTERVALS_ICU_AUTH=github
INTERVALS_ICU_AUTH_GITHUB_CLIENT_ID=Iv1.xxxxxxxxxxxx
INTERVALS_ICU_AUTH_GITHUB_CLIENT_SECRET=xxxxxxxxxxxxxxxx
INTERVALS_ICU_AUTH_ALLOWED_GITHUB_USERS=your-github-login
```

5. Restart the server. The startup line on stderr reports the active mode: `auth=github`.

Clients discover the flow automatically — an unauthenticated request returns `401` with a `WWW-Authenticate` header naming the protected-resource document, which names the authorization server, which supports dynamic client registration. Adding the server as a connector triggers a GitHub sign-in and a consent screen; no client ID needs to be issued by hand.

A GitHub user outside the allowlist can still complete the sign-in, and is then refused on every MCP call. Blocking earlier would need the upstream identity before the token exists, which the proxy flow does not expose. No access is granted either way — only the error arrives later.

### If you have been running unauthenticated

Treat the Intervals.icu API key as exposed: regenerate it at <https://intervals.icu/settings> and update `INTERVALS_ICU_API_KEY` on the host. Adding authentication does not retroactively protect a key that was already reachable.

## Defence in depth

> ⚠️ **Security: do not expose an HTTP-mode server to untrusted networks.**
>
> With `INTERVALS_ICU_AUTH=none` (the default) the server has no authentication of its own. Anyone who can reach the URL can exercise every tool with your credentials — read every activity, delete activities, modify your FTP, create calendar events, etc. Binding to `0.0.0.0` on a direct-exposed host (VPS, LAN with open port) is equivalent to publishing your Intervals.icu API key.
>
> Besides `INTERVALS_ICU_AUTH=github` above, these gate access without touching the server:
> - **Tailscale / Cloudflare Tunnel / ZeroTier** — only your authenticated devices can reach the endpoint. Zero code changes, simplest option.
> - **Reverse proxy with auth** (nginx + basic auth, Cloudflare Access, etc.) — terminates TLS and gates access.
> - **SSH tunnel** — `ssh -L 8000:localhost:8000 host` if you just need occasional access from one machine.
>
> Credentials are always read from `INTERVALS_ICU_API_KEY` and `INTERVALS_ICU_ATHLETE_ID` — use env vars (not a committed `.env`) when deploying to a shared host.

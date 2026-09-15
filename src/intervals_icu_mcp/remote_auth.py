"""Access control for the HTTP-transport server.

This is deliberately separate from `auth.py`. That module holds the
*outbound* Intervals.icu API credentials — the key this server presents to
intervals.icu. This module answers the opposite question: who is allowed to
reach this server at all?

The distinction matters when the server is deployed somewhere public (Railway,
Fly, a VPS). Over stdio the operating system is the access control: only the
local MCP client can speak to the process. Over HTTP there is no such boundary
— the URL is the boundary, and MCP defines none of its own. An unauthenticated
HTTP deployment hands every caller the full tool surface under the deployer's
API key, which is equivalent to publishing that key.

Auth is **off by default** (`INTERVALS_ICU_AUTH=none`) so stdio installs and
existing HTTP-behind-a-tunnel deployments are unaffected. Set
`INTERVALS_ICU_AUTH=github` to require OAuth.

## Why an allowlist is mandatory

FastMCP's `GitHubProvider` verifies that a caller holds a valid GitHub token.
It does not, and cannot, know whether that caller is *you* — every GitHub
account in the world holds a valid GitHub token. Wiring the provider up on its
own therefore produces a login screen that everybody passes, which reads as
security but is not.

`INTERVALS_ICU_AUTH_ALLOWED_GITHUB_USERS` is the control that actually
restricts access, so `build_auth_provider` refuses to start without it rather
than defaulting to "anyone". Failing closed on a missing allowlist is the whole
point of this module.
"""

from __future__ import annotations

import os
from typing import Any, Literal, cast

from fastmcp.server.auth import AuthProvider
from fastmcp.server.auth.auth import AccessToken
from fastmcp.server.auth.providers.github import GitHubProvider
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

AuthMode = Literal["none", "github"]
VALID_AUTH_MODES: tuple[AuthMode, ...] = ("none", "github")


class RemoteAuthConfig(BaseSettings):
    """Remote-access settings, read from the environment.

    Kept out of `ICUConfig` on purpose: that object is injected into the
    FastMCP context state for every tool call, so anything on it is reachable
    from tool code. The OAuth client secret has no business being there.
    """

    model_config = SettingsConfigDict(
        env_prefix="INTERVALS_ICU_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    auth: AuthMode = "none"
    auth_github_client_id: str = ""
    auth_github_client_secret: str = ""
    auth_allowed_github_users: str = ""
    auth_base_url: str = ""

    @field_validator("auth", mode="before")
    @classmethod
    def _normalize_auth_mode(cls, v: object) -> str:
        if v is None or v == "":
            return "none"
        normalized = str(v).lower().strip()
        if normalized not in VALID_AUTH_MODES:
            raise ValueError(
                f"INTERVALS_ICU_AUTH must be one of: {', '.join(VALID_AUTH_MODES)}. Got: '{v}'"
            )
        return normalized

    @property
    def allowed_github_logins(self) -> frozenset[str]:
        """The allowlist, case-folded.

        GitHub logins are case-insensitive, so `Dave8766` and `dave8766` are
        the same account and must compare equal.
        """
        return frozenset(
            entry.strip().casefold()
            for entry in self.auth_allowed_github_users.split(",")
            if entry.strip()
        )

    def resolve_base_url(self) -> str:
        """The server's public URL, used to build the OAuth redirect URI.

        Falls back to Railway's injected `RAILWAY_PUBLIC_DOMAIN` so a Railway
        deployment does not have to restate a hostname the platform already
        knows. Any other host must set `INTERVALS_ICU_AUTH_BASE_URL` explicitly.
        """
        if self.auth_base_url:
            return self.auth_base_url.rstrip("/")
        railway_domain = os.environ.get("RAILWAY_PUBLIC_DOMAIN", "").strip()
        if railway_domain:
            return f"https://{railway_domain}"
        return ""


class AllowlistedGitHubProvider(GitHubProvider):
    """`GitHubProvider` that admits only named GitHub logins.

    GitHub authenticates the caller; this narrows that to authorisation. The
    check sits in `verify_token`, which runs on every MCP request, so a token
    issued before a login was removed from the allowlist stops working as soon
    as the server restarts with the new list.

    A rejected user still completes the GitHub round-trip and is then refused
    on every call. Blocking earlier, at the consent screen, would need the
    upstream identity before the token exists — which the proxy flow does not
    expose. No access is granted either way; only the error is later.
    """

    def __init__(self, *, allowed_logins: frozenset[str], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._allowed_logins = allowed_logins

    async def verify_token(self, token: str) -> AccessToken | None:
        access_token = await super().verify_token(token)
        if access_token is None:
            return None

        claims: dict[str, Any] = access_token.claims or {}
        login = claims.get("login")
        if not login:
            # OAuthProxy nests the originating provider's claims here when the
            # token was minted through its JWT token-factory path.
            upstream: object = claims.get("upstream_claims")
            if isinstance(upstream, dict):
                login = cast("dict[str, Any]", upstream).get("login")

        if not isinstance(login, str) or login.casefold() not in self._allowed_logins:
            # Deliberately not echoed to the caller: the 401 says "denied", not
            # which logins would have worked.
            return None

        return access_token


def build_auth_provider(config: RemoteAuthConfig | None = None) -> AuthProvider | None:
    """Construct the auth provider for the configured mode.

    Returns None when auth is disabled, which is what `FastMCP(auth=...)`
    expects for an unauthenticated server.

    Raises:
        ValueError: if a mode is selected but its configuration is incomplete.
            Startup fails loudly rather than silently serving without the
            protection that was asked for.
    """
    config = config or RemoteAuthConfig()

    if config.auth == "none":
        return None

    missing = [
        name
        for name, value in (
            ("INTERVALS_ICU_AUTH_GITHUB_CLIENT_ID", config.auth_github_client_id),
            ("INTERVALS_ICU_AUTH_GITHUB_CLIENT_SECRET", config.auth_github_client_secret),
        )
        if not value
    ]
    if missing:
        raise ValueError(
            f"INTERVALS_ICU_AUTH=github requires {' and '.join(missing)}. "
            "Create a GitHub OAuth App at https://github.com/settings/developers "
            "and set its client ID and secret."
        )

    allowed_logins = config.allowed_github_logins
    if not allowed_logins:
        raise ValueError(
            "INTERVALS_ICU_AUTH=github requires INTERVALS_ICU_AUTH_ALLOWED_GITHUB_USERS "
            "(comma-separated GitHub logins). Without it, every GitHub account in the "
            "world would pass authentication and gain full access to your "
            "Intervals.icu data — GitHub proves who a caller is, not that they are you."
        )

    base_url = config.resolve_base_url()
    if not base_url:
        raise ValueError(
            "INTERVALS_ICU_AUTH=github requires INTERVALS_ICU_AUTH_BASE_URL — the public "
            "https:// URL of this deployment, used to build the OAuth redirect URI. "
            "(On Railway, RAILWAY_PUBLIC_DOMAIN is used automatically if set.)"
        )

    return AllowlistedGitHubProvider(
        allowed_logins=allowed_logins,
        client_id=config.auth_github_client_id,
        client_secret=config.auth_github_client_secret,
        base_url=base_url,
    )

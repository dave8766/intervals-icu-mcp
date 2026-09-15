"""Tests for HTTP-transport access control.

The security-relevant assertions here are the *refusals*: a misconfigured
`INTERVALS_ICU_AUTH=github` must fail to start rather than serve unprotected,
and an authenticated-but-unlisted GitHub user must be refused. A bug in either
direction is silent — the server looks like it is protected while it is not —
so both are pinned.
"""

import pytest
from fastmcp.server.auth.auth import AccessToken

from intervals_icu_mcp.remote_auth import (
    AllowlistedGitHubProvider,
    RemoteAuthConfig,
    build_auth_provider,
)

GITHUB_ENV = {
    "auth": "github",
    "auth_github_client_id": "Iv1.testclientid",
    "auth_github_client_secret": "test_client_secret",
    "auth_allowed_github_users": "dave8766",
    "auth_base_url": "https://mcp.example.com",
}


def _config(**overrides: str) -> RemoteAuthConfig:
    # model_validate rather than kwargs: `auth` is typed as the narrow
    # AuthMode literal, but the point of its `mode="before"` validator is to
    # normalise looser input, which the tests below need to exercise.
    return RemoteAuthConfig.model_validate({**GITHUB_ENV, **overrides})


@pytest.fixture(autouse=True)
def _no_railway_domain(monkeypatch: pytest.MonkeyPatch):
    """Keep the Railway fallback out of tests that assert on base_url."""
    monkeypatch.delenv("RAILWAY_PUBLIC_DOMAIN", raising=False)


class TestAuthMode:
    def test_defaults_to_none(self):
        """Auth off by default — stdio installs must be unaffected."""
        assert RemoteAuthConfig().auth == "none"

    def test_none_mode_builds_no_provider(self):
        assert build_auth_provider(RemoteAuthConfig()) is None

    def test_empty_string_is_treated_as_none(self):
        assert RemoteAuthConfig.model_validate({"auth": ""}).auth == "none"

    def test_mode_is_case_insensitive(self):
        assert RemoteAuthConfig.model_validate({"auth": "GitHub"}).auth == "github"

    def test_rejects_unknown_mode(self):
        with pytest.raises(ValueError, match="INTERVALS_ICU_AUTH must be one of"):
            RemoteAuthConfig.model_validate({"auth": "basic"})


class TestGitHubModeFailsClosed:
    """A half-configured auth mode must not degrade into an open server."""

    def test_requires_client_id(self):
        with pytest.raises(ValueError, match="CLIENT_ID"):
            build_auth_provider(_config(auth_github_client_id=""))

    def test_requires_client_secret(self):
        with pytest.raises(ValueError, match="CLIENT_SECRET"):
            build_auth_provider(_config(auth_github_client_secret=""))

    def test_requires_allowlist(self):
        """Without an allowlist every GitHub account on earth authenticates."""
        with pytest.raises(ValueError, match="ALLOWED_GITHUB_USERS"):
            build_auth_provider(_config(auth_allowed_github_users=""))

    def test_allowlist_of_only_separators_is_not_an_allowlist(self):
        with pytest.raises(ValueError, match="ALLOWED_GITHUB_USERS"):
            build_auth_provider(_config(auth_allowed_github_users=" , , "))

    def test_requires_base_url(self):
        with pytest.raises(ValueError, match="AUTH_BASE_URL"):
            build_auth_provider(_config(auth_base_url=""))

    def test_fully_configured_builds_allowlisted_provider(self):
        provider = build_auth_provider(_config())
        assert isinstance(provider, AllowlistedGitHubProvider)


class TestBaseUrlResolution:
    def test_explicit_value_wins(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("RAILWAY_PUBLIC_DOMAIN", "ignored.up.railway.app")
        assert _config().resolve_base_url() == "https://mcp.example.com"

    def test_trailing_slash_is_stripped(self):
        """The redirect URI is built by appending a path; a double slash breaks
        the exact-match comparison GitHub does against the registered callback."""
        assert _config(auth_base_url="https://mcp.example.com/").resolve_base_url() == (
            "https://mcp.example.com"
        )

    def test_falls_back_to_railway_public_domain(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("RAILWAY_PUBLIC_DOMAIN", "app-production.up.railway.app")
        assert _config(auth_base_url="").resolve_base_url() == (
            "https://app-production.up.railway.app"
        )

    def test_no_base_url_and_no_railway_is_empty(self):
        assert _config(auth_base_url="").resolve_base_url() == ""


class TestAllowlistParsing:
    def test_splits_on_commas_and_trims(self):
        config = _config(auth_allowed_github_users=" dave8766 , someone-else ")
        assert config.allowed_github_logins == frozenset({"dave8766", "someone-else"})

    def test_is_case_folded(self):
        """GitHub logins are case-insensitive; Dave8766 and dave8766 are one account."""
        assert _config(auth_allowed_github_users="Dave8766").allowed_github_logins == (
            frozenset({"dave8766"})
        )

    def test_empty_entries_are_dropped(self):
        config = _config(auth_allowed_github_users="dave8766,,")
        assert config.allowed_github_logins == frozenset({"dave8766"})


def _access_token(**claims: object) -> AccessToken:
    return AccessToken(token="tok", client_id="12345", scopes=["user"], claims=claims)


class TestAllowlistEnforcement:
    """`verify_token` runs on every MCP request — this is the live gate."""

    @pytest.fixture
    def provider(self) -> AllowlistedGitHubProvider:
        built = build_auth_provider(_config())
        assert isinstance(built, AllowlistedGitHubProvider)
        return built

    async def test_allows_listed_login(
        self, provider: AllowlistedGitHubProvider, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setattr(
            AllowlistedGitHubProvider.__mro__[1],
            "verify_token",
            _stub(_access_token(login="dave8766")),
        )
        assert await provider.verify_token("tok") is not None

    async def test_allows_listed_login_in_other_case(
        self, provider: AllowlistedGitHubProvider, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setattr(
            AllowlistedGitHubProvider.__mro__[1],
            "verify_token",
            _stub(_access_token(login="DAVE8766")),
        )
        assert await provider.verify_token("tok") is not None

    async def test_rejects_unlisted_login(
        self, provider: AllowlistedGitHubProvider, monkeypatch: pytest.MonkeyPatch
    ):
        """The whole point: a valid GitHub token is not an authorisation."""
        monkeypatch.setattr(
            AllowlistedGitHubProvider.__mro__[1],
            "verify_token",
            _stub(_access_token(login="a-stranger")),
        )
        assert await provider.verify_token("tok") is None

    async def test_rejects_token_with_no_login_claim(
        self, provider: AllowlistedGitHubProvider, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setattr(
            AllowlistedGitHubProvider.__mro__[1],
            "verify_token",
            _stub(_access_token(sub="12345")),
        )
        assert await provider.verify_token("tok") is None

    async def test_reads_login_from_nested_upstream_claims(
        self, provider: AllowlistedGitHubProvider, monkeypatch: pytest.MonkeyPatch
    ):
        """OAuthProxy nests provider claims here on its JWT token-factory path."""
        monkeypatch.setattr(
            AllowlistedGitHubProvider.__mro__[1],
            "verify_token",
            _stub(_access_token(upstream_claims={"login": "dave8766"})),
        )
        assert await provider.verify_token("tok") is not None

    async def test_propagates_upstream_rejection(
        self, provider: AllowlistedGitHubProvider, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setattr(AllowlistedGitHubProvider.__mro__[1], "verify_token", _stub(None))
        assert await provider.verify_token("tok") is None


def _stub(result: AccessToken | None):
    async def _verify(self: object, token: str) -> AccessToken | None:
        return result

    return _verify


class TestDiscoveryEndpoints:
    """The OAuth handshake Claude performs is a discovery chain: an
    unauthenticated call must 401 with a `WWW-Authenticate` header pointing at
    the protected-resource document, which in turn names the authorization
    server. If any link breaks, the client cannot begin the flow and the
    connector simply fails to add — so each link is pinned here.
    """

    @pytest.fixture
    def app(self):
        from fastmcp import FastMCP

        return FastMCP("test", auth=build_auth_provider(_config())).http_app()

    @pytest.fixture
    async def client(self, app):
        import httpx
        from asgi_lifespan import LifespanManager

        async with LifespanManager(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="https://mcp.example.com",
                follow_redirects=True,
            ) as client:
                yield client

    async def test_unauthenticated_call_is_rejected(self, client):
        response = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Accept": "application/json, text/event-stream"},
        )
        assert response.status_code == 401

    async def test_rejection_points_the_client_at_discovery(self, client):
        response = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Accept": "application/json, text/event-stream"},
        )
        assert "resource_metadata=" in response.headers["www-authenticate"]

    async def test_protected_resource_metadata_names_the_auth_server(self, client):
        response = await client.get("/.well-known/oauth-protected-resource/mcp")
        assert response.status_code == 200
        assert response.json()["authorization_servers"] == ["https://mcp.example.com/"]

    async def test_authorization_server_metadata_is_served(self, client):
        response = await client.get("/.well-known/oauth-authorization-server")
        assert response.status_code == 200
        metadata = response.json()
        # Dynamic client registration is what lets Claude add the connector
        # without a client ID being issued by hand.
        assert metadata["registration_endpoint"] == "https://mcp.example.com/register"

    async def test_callback_path_is_the_one_registered_with_github(self, app):
        """The GitHub OAuth App's callback URL must match this exactly, so a
        change here is a breaking change for every existing deployment."""
        assert "/auth/callback" in {getattr(route, "path", None) for route in app.routes}


class TestServerDefaultsToUnauthenticated:
    def test_module_level_server_has_no_auth(self):
        """Importing the server with no auth env vars must not enable auth —
        stdio users and existing deployments keep working untouched."""
        from intervals_icu_mcp.server import mcp

        assert mcp.auth is None

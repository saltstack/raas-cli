"""
HTTP client for VMware Aria Automation Config (Enterprise Salt) API.

Implements the SaltStack Enterprise (RaaS) auth flow:

  1. GET  /account/login   -> obtain `_xsrf` cookie
  2. POST /account/login   -> body {username, password, config_name, token_type: "jwt"}
                              -> returns JWT in the response body and a session cookie
  3. All RPC calls          -> POST /raas/rpc with:
                                 - Authorization: JWT <jwt>
                                 - X-Xsrftoken: <xsrf>
                                 - _xsrf cookie (set by httpx automatically)
  4. On 401                 -> re-authenticate once, then retry

JWTs and cookies are persisted to ~/.scc/cache so subsequent commands reuse the
session without re-prompting for the password. When the cached token expires
(typical SSC default is 30m), the client transparently re-authenticates using
the credentials supplied via the settings object - which, by design, come from
the OS keychain / env / prompt rather than the command line.

This client is intentionally strict:

  * Never claims `_authenticated = True` without a verified server round trip.
  * Treats a non-JSON response on /raas/rpc as an authentication failure
    (SSC returns the HTML login page when the JWT is missing/expired).
  * On 401 it raises `AuthenticationError` with the original server message.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Union

import httpx

from salt_config_cli.api.exceptions import (
    APIError,
    AuthenticationError,
    ConnectionError,
    NotFoundError,
    ServerError,
    TimeoutError,
    ValidationError,
)
from salt_config_cli.api.token_cache import get_token_cache, TokenCache
from salt_config_cli.core.config import SaltConfigSettings

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Response container
# ---------------------------------------------------------------------------

class RPCResponse:
    """Container for RPC response data: RPCResponse(riq, ret, error, warnings)."""

    def __init__(
        self,
        riq: int,
        ret: Any = None,
        error: Optional[Dict[str, Any]] = None,
        warnings: Optional[List[str]] = None,
    ):
        self.riq = riq
        self.ret = ret
        self.error = error
        self.warnings = warnings or []

    @property
    def success(self) -> bool:
        return self.error is None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RPCResponse":
        return cls(
            riq=data.get("riq", 0),
            ret=data.get("ret"),
            error=data.get("error"),
            warnings=data.get("warnings", []),
        )

    def __repr__(self) -> str:  # pragma: no cover
        return f"RPCResponse(riq={self.riq}, ret={self.ret!r}, error={self.error}, warnings={self.warnings})"


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class AriaConfigClient:
    """Client for VMware Aria Automation Config (Enterprise Salt) API."""

    DEFAULT_RPC_PATH = "/rpc"
    LOGIN_PATH = "/account/login"
    # Fallback candidates if DEFAULT_RPC_PATH returns 404/405. Order matters:
    # newer SSC/RaaS deployments expose just /rpc, older ones use /raas/rpc.
    RPC_PATH_CANDIDATES = ("/rpc", "/raas/rpc")
    # The login endpoint sits behind the same /raas prefix split as the RPC
    # endpoint on older deployments.
    LOGIN_PATH_CANDIDATES = ("/account/login", "/raas/account/login")
    # Tenant path segment for the API-token exchange (POST
    # {auth_server_url}/acs/t/{API_TOKEN_TENANT}/token). Fixed for this
    # deployment rather than user-configurable.
    API_TOKEN_TENANT = "CUSTOMER"
    # RaaS requires this header on RPC calls authenticated with an
    # api-token-derived Bearer token, or it rejects the request with an
    # empty-body 401 (observed against a real server; JWT/csp-token sessions
    # don't appear to need it).
    RAAS_RPC_VERSION = "13"

    def __init__(
        self,
        server: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        config_name: str = "internal",
        csp_url: str = "https://console.cloud.vmware.com",
        csp_api_token: Optional[str] = None,
        csp_org_id: Optional[str] = None,
        auth_server_url: Optional[str] = None,
        api_token: Optional[str] = None,
        timeout: int = 60,
        ssl_verify: bool = True,
        ssl_cert: Optional[str] = None,
        ssl_key: Optional[str] = None,
        rpc_path: Optional[str] = None,
        use_cache: bool = True,
    ):
        self.server = server.rstrip("/")
        self.username = username
        self.password = password
        self.config_name = config_name
        self.csp_url = csp_url.rstrip("/")
        self.csp_api_token = csp_api_token
        self.csp_org_id = csp_org_id
        if auth_server_url and not auth_server_url.startswith(("http://", "https://")):
            auth_server_url = f"https://{auth_server_url}"
        self.auth_server_url = auth_server_url.rstrip("/") if auth_server_url else None
        self.api_token = api_token
        self.timeout = timeout
        self.ssl_verify = ssl_verify
        self.ssl_cert = ssl_cert
        self.ssl_key = ssl_key
        self.rpc_path = rpc_path or self.DEFAULT_RPC_PATH
        self.login_path = self.LOGIN_PATH
        self.use_cache = use_cache

        # Authentication state
        self._xsrf_token: Optional[str] = None
        self._jwt: Optional[str] = None
        self._csp_access_token: Optional[str] = None
        self._api_token_access_token: Optional[str] = None
        self._authenticated = False
        self._riq_counter = 0

        self._token_cache: Optional[TokenCache] = get_token_cache() if use_cache else None

        self._api_version: Optional[str] = None

        # HTTP client - NO BasicAuth (RaaS uses JWT). Cookies are auto-managed.
        self._client = self._create_http_client()

    # ------------------------------------------------------------------ setup

    def _create_http_client(self) -> httpx.Client:
        cert = None
        if self.ssl_cert and self.ssl_key:
            cert = (self.ssl_cert, self.ssl_key)
        elif self.ssl_cert:
            cert = self.ssl_cert
        return httpx.Client(
            timeout=self.timeout,
            verify=self.ssl_verify,
            cert=cert,
            follow_redirects=True,
        )

    @classmethod
    def connect(
        cls,
        server: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        config_name: str = "internal",
        ssl_verify: bool = True,
        **kwargs,
    ) -> "AriaConfigClient":
        client = cls(
            server=server,
            username=username,
            password=password,
            config_name=config_name,
            ssl_verify=ssl_verify,
            **kwargs,
        )
        client.authenticate()
        return client

    @classmethod
    def from_settings(cls, settings: SaltConfigSettings) -> "AriaConfigClient":
        auth_config = settings.get_auth_config()
        return cls.connect(**auth_config)

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:
            pass

    def __enter__(self) -> "AriaConfigClient":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    # --------------------------------------------------------- low-level utils

    def _next_riq(self) -> int:
        self._riq_counter += 1
        return self._riq_counter

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        # api-token auth is a stateless Bearer flow - never mix in an XSRF
        # header/cookie, even if one happens to be set from a prior session.
        if self._xsrf_token and not self._api_token_access_token:
            headers["X-Xsrftoken"] = self._xsrf_token
        if self._jwt:
            headers["Authorization"] = f"JWT {self._jwt}"
        if self._csp_access_token:
            headers["csp-auth-token"] = self._csp_access_token
        if self._api_token_access_token:
            headers["Authorization"] = f"Bearer {self._api_token_access_token}"
            headers["x-raas-rpc-version"] = self.RAAS_RPC_VERSION
        return headers

    def _extract_xsrf_token(self, response: httpx.Response) -> None:
        # httpx exposes Set-Cookie via response.cookies; persisted cookies live
        # on the client cookie jar (self._client.cookies).
        for name, value in response.cookies.items():
            if name == "_xsrf":
                self._xsrf_token = value
                log.debug("Extracted XSRF token from cookies")
                break
        if self._xsrf_token is None:
            # Fall back to the client jar, which retains older cookies.
            jar_value = self._client.cookies.get("_xsrf")
            if jar_value:
                self._xsrf_token = jar_value

    def _looks_like_html(self, text: str) -> bool:
        if not text:
            return False
        head = text.lstrip()[:200].lower()
        return head.startswith("<!doctype") or head.startswith("<html") or "<title" in head

    def _describe_error_response(self, response: httpx.Response, limit: int = 200) -> Optional[str]:
        """Best-effort detail string for an error response.

        Some servers return an error status with an empty body; in that case
        fall back to response headers (WWW-Authenticate in particular is the
        standard way a server hints at the auth scheme/realm it expects) so
        we're not left debugging blind.
        """
        if response.text:
            return response.text[:limit]
        www_auth = response.headers.get("WWW-Authenticate")
        if www_auth:
            return f"WWW-Authenticate: {www_auth}"
        skip = {"date", "content-length", "connection", "content-type"}
        header_dump = "; ".join(f"{k}: {v}" for k, v in response.headers.items() if k.lower() not in skip)
        if header_dump:
            return f"(empty body) headers: {header_dump[:limit]}"
        return None

    def _next_rpc_path_candidate(self) -> Optional[str]:
        """Return the next RPC path to try, or None if we've exhausted them."""
        try:
            idx = self.RPC_PATH_CANDIDATES.index(self.rpc_path)
        except ValueError:
            return self.RPC_PATH_CANDIDATES[0] if self.RPC_PATH_CANDIDATES else None
        for cand in self.RPC_PATH_CANDIDATES[idx + 1 :]:
            if cand != self.rpc_path:
                return cand
        return None

    def _next_login_path_candidate(self) -> Optional[str]:
        """Return the next login path to try, or None if we've exhausted them."""
        try:
            idx = self.LOGIN_PATH_CANDIDATES.index(self.login_path)
        except ValueError:
            return self.LOGIN_PATH_CANDIDATES[0] if self.LOGIN_PATH_CANDIDATES else None
        for cand in self.LOGIN_PATH_CANDIDATES[idx + 1 :]:
            if cand != self.login_path:
                return cand
        return None

    # --------------------------------------------------------- authentication

    def authenticate(self) -> None:
        """Establish an authenticated session.

        Order of operations:
          1. Try cached JWT/cookies; verify with a cheap RPC.
          2. If invalid/missing, do XSRF GET + login POST.
          3. Verify with another cheap RPC and cache the result.
        """
        # 1. Cached token?
        if self._try_cached_auth():
            return

        # 2. Fresh login. API-token auth is a stateless Bearer flow with no
        # XSRF cookie/header involved (confirmed against a real server), so
        # skip the XSRF handshake entirely rather than mixing it with a
        # Bearer token and risking RaaS picking the wrong auth code path.
        use_api_token = bool(self.api_token and self.auth_server_url)
        if not use_api_token:
            self._init_xsrf()

        if use_api_token:
            self._authenticate_api_token()
        elif self.csp_api_token:
            self._authenticate_csp()
        elif self.username and self.password:
            # Exchange user/pass for a JWT.
            self._jwt = self._password_login()
            if not self._jwt:
                raise AuthenticationError(
                    "Login failed: server did not issue a session token. "
                    "Check username/password and (if using LDAP) `config_name`.",
                    code=401,
                )
        else:
            raise AuthenticationError(
                "No credentials available. Provide username/password, a CSP API token, "
                "or an API token with an auth server URL.",
                code=401,
            )

        # 3. Verify the session by making one real RPC call.
        self._verify_session()
        self._authenticated = True
        self._cache_auth_token()

    def _init_xsrf(self) -> None:
        """GET the login page to obtain the _xsrf cookie."""
        try:
            response = self._client.get(f"{self.server}{self.login_path}")
            if response.status_code in (404, 405):
                alt = self._next_login_path_candidate()
                if alt:
                    log.debug(
                        "Login path %s returned %s; retrying with %s",
                        self.login_path, response.status_code, alt,
                    )
                    self.login_path = alt
                    response = self._client.get(f"{self.server}{self.login_path}")
            # An old-style deployment that needed the /raas/ prefix on the
            # login path needs it on the RPC path too - applies regardless
            # of auth mode (password, csp-token, or api-token), since only
            # _password_login() used to run this check.
            if self.login_path.startswith("/raas/") and self.rpc_path == self.DEFAULT_RPC_PATH:
                self.rpc_path = "/raas/rpc"
            self._extract_xsrf_token(response)
        except httpx.RequestError as e:
            raise ConnectionError(f"Cannot reach RaaS server at {self.server}: {e}") from e

    def _password_login(self) -> Optional[str]:
        """POST /account/login with credentials, returning the JWT."""
        body = {
            "username": self.username,
            "password": self.password,
            "config_name": self.config_name,
            "token_type": "jwt",
        }
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._xsrf_token:
            headers["X-Xsrftoken"] = self._xsrf_token
        try:
            response = self._client.post(
                f"{self.server}{self.login_path}",
                headers=headers,
                json=body,
                timeout=self.timeout,
            )
            if response.status_code in (404, 405):
                alt = self._next_login_path_candidate()
                if alt:
                    log.debug(
                        "Login path %s returned %s; retrying with %s",
                        self.login_path, response.status_code, alt,
                    )
                    self.login_path = alt
                    if self.login_path.startswith("/raas/") and self.rpc_path == self.DEFAULT_RPC_PATH:
                        self.rpc_path = "/raas/rpc"
                    response = self._client.post(
                        f"{self.server}{self.login_path}",
                        headers=headers,
                        json=body,
                        timeout=self.timeout,
                    )
        except httpx.RequestError as e:
            raise ConnectionError(f"Login request failed: {e}") from e

        self._extract_xsrf_token(response)

        if response.status_code in (404, 405):
            raise NotFoundError(
                f"Login endpoint not found at {self.server}{self.login_path} "
                f"(also tried the fallback path). This server may not expose a "
                f"SSC/RaaS-style /account/login endpoint at this URL.",
                code=response.status_code,
                detail=self._describe_error_response(response),
            )
        if response.status_code in (401, 403):
            raise AuthenticationError(
                "Invalid username or password.",
                code=response.status_code,
                detail=self._describe_error_response(response),
            )
        if response.status_code >= 500:
            raise ServerError(
                f"RaaS server returned {response.status_code} during login.",
                code=response.status_code,
                detail=self._describe_error_response(response, limit=500),
            )

        text = response.text or ""
        if self._looks_like_html(text):
            raise AuthenticationError(
                "Server returned an HTML page instead of a JWT. "
                "Verify the server URL points to a RaaS host (not a UI host) and try again.",
                code=response.status_code,
            )

        try:
            data = response.json()
        except json.JSONDecodeError as e:
            raise AuthenticationError(
                f"Login response was not valid JSON: {e}",
                code=response.status_code,
                detail=text[:200],
            ) from e

        # SSE returns {"jwt": "...", "attributes": {"username": "..."}}
        if isinstance(data, dict):
            jwt_token = data.get("jwt")
            if jwt_token:
                return jwt_token
            # Some deployments wrap it in {"data": {...}} - tolerate that.
            nested = data.get("data") if isinstance(data.get("data"), dict) else None
            if nested and nested.get("jwt"):
                return nested["jwt"]

        return None

    def _verify_session(self) -> None:
        """Make a minimal RPC call to confirm the session works."""
        try:
            response = self.call("test", "echo", message="scc_auth_probe", _verify=True)
        except AuthenticationError:
            raise
        except Exception as e:
            raise AuthenticationError(
                f"Session verification failed: {e}. The server accepted the "
                "login but rejected the first RPC. This usually means the "
                "XSRF cookie was not honored or the account has no API access.",
                code=401,
            ) from e
        if not response.success or response.ret != "scc_auth_probe":
            # Try a fallback to api.get_versions which most accounts can call.
            try:
                versions = self.call("api", "get_versions", _verify=True)
                if versions.success:
                    self._api_version = versions.ret
                    return
            except Exception:
                pass
            raise AuthenticationError(
                "Authenticated request did not return expected payload.",
                code=401,
                detail=str(response.error) if response.error else None,
            )

    # ----------------------------------------------------------- token cache

    def _try_cached_auth(self) -> bool:
        if not self._token_cache or not self.username:
            return False
        cached = self._token_cache.get(self.server, self.username)
        if not cached:
            return False
        self._jwt = cached.get("jwt")
        self._xsrf_token = cached.get("xsrf_token")
        self._csp_access_token = cached.get("csp_access_token")
        self._api_token_access_token = cached.get("api_token_access_token")
        for name, value in (cached.get("cookies") or {}).items():
            self._client.cookies.set(name, value)
        if not self._jwt and not self._csp_access_token and not self._api_token_access_token:
            return False
        try:
            response = self.call("test", "echo", message="scc_cache_probe", _verify=True)
            if response.success and response.ret == "scc_cache_probe":
                self._authenticated = True
                log.debug("Reusing cached session for %s", self.server)
                return True
        except Exception as e:
            log.debug("Cached session invalid: %s", e)
        # Wipe stale state
        self._jwt = None
        self._xsrf_token = None
        self._csp_access_token = None
        self._api_token_access_token = None
        self._client.cookies.clear()
        self._token_cache.delete(self.server, self.username)
        return False

    def _cache_auth_token(self) -> None:
        if not self._token_cache:
            return
        cookies = {name: value for name, value in self._client.cookies.items()}
        self._token_cache.set(
            server=self.server,
            username=self.username,
            xsrf_token=self._xsrf_token,
            cookies=cookies,
            csp_access_token=self._csp_access_token,
            api_token_access_token=self._api_token_access_token,
            jwt=self._jwt,
        )

    def clear_cached_token(self) -> None:
        if self._token_cache and self.username:
            self._token_cache.delete(self.server, self.username)
            log.debug("Cleared cached token for %s", self.server)

    # -------------------------------------------------------------- CSP auth

    def _authenticate_csp(self) -> None:
        try:
            response = self._client.post(
                f"{self.csp_url}/csp/gateway/am/api/auth/api-tokens/authorize",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={"api_token": self.csp_api_token},
            )
            if response.status_code == 200:
                self._csp_access_token = response.json().get("access_token")
            else:
                raise AuthenticationError(
                    "CSP authentication failed",
                    code=response.status_code,
                    detail=self._describe_error_response(response),
                )
        except httpx.RequestError as e:
            raise ConnectionError(f"Failed to connect to CSP: {e}") from e

    # --------------------------------------------------------- API token auth

    def _authenticate_api_token(self) -> None:
        """Exchange an API token for a Bearer access token via the VCF auth
        server (POST {auth_server_url}/acs/t/{API_TOKEN_TENANT}/token)."""
        try:
            response = self._client.post(
                f"{self.auth_server_url}/acs/t/{self.API_TOKEN_TENANT}/token",
                headers={
                    "Accept": "application/json;charset=UTF-8",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                data={
                    "api_token": self.api_token,
                    "grant_type": "urn:custom:vcf:params:oauth:grant-type:api-token",
                },
            )
            if response.status_code == 200:
                self._api_token_access_token = response.json().get("access_token")
                if not self._api_token_access_token:
                    raise AuthenticationError(
                        "API token exchange succeeded but no access_token was returned.",
                        code=response.status_code,
                        detail=self._describe_error_response(response),
                    )
            else:
                raise AuthenticationError(
                    "API token exchange failed",
                    code=response.status_code,
                    detail=self._describe_error_response(response),
                )
        except httpx.RequestError as e:
            raise ConnectionError(f"Failed to connect to auth server {self.auth_server_url}: {e}") from e

    # ------------------------------------------------------------------ RPC

    def call(
        self,
        resource: str,
        method: str,
        *args,
        **kwargs,
    ) -> RPCResponse:
        """Make an RPC call. Auto-reauthenticates on 401 (once).

        Internal sentinel `_verify=True` indicates a verification probe; those
        calls do NOT trigger auto-reauth (to avoid infinite recursion).
        """
        riq = kwargs.pop("_riq", None) or self._next_riq()
        timeout = kwargs.pop("_timeout", None)
        is_verify = kwargs.pop("_verify", False)
        retried = kwargs.pop("_retried", False)

        payload: Dict[str, Any] = {"resource": resource, "method": method}
        if args:
            payload["arg"] = list(args)
        if kwargs:
            payload["kwarg"] = kwargs
        payload["riq"] = riq

        log.debug("RPC call: %s.%s(%s)", resource, method, kwargs)

        try:
            response = self._client.post(
                f"{self.server}{self.rpc_path}",
                headers=self._get_headers(),
                json=payload,
                timeout=timeout or self.timeout,
            )
        except httpx.TimeoutException as e:
            raise TimeoutError(f"Request timed out calling {resource}.{method}") from e
        except httpx.RequestError as e:
            raise ConnectionError(f"Request failed calling {resource}.{method}: {e}") from e

        self._extract_xsrf_token(response)

        # ---- Hard HTTP errors ----
        if response.status_code == 401:
            if is_verify and not retried:
                # Some deployments answer a wrong RPC path with 401 rather
                # than 404/405, so the initial verification probe never gets
                # a chance to try the other known layout. Try it once here.
                alt = self._next_rpc_path_candidate()
                if alt:
                    log.debug(
                        "RPC path %s returned 401 during verification; retrying with %s",
                        self.rpc_path, alt,
                    )
                    self.rpc_path = alt
                    kwargs["_retried"] = True
                    return self.call(resource, method, *args, **kwargs)
            if is_verify or retried:
                raise AuthenticationError(
                    "Authentication failed - check username/password",
                    code=401,
                    detail=self._describe_error_response(response),
                )
            # Re-auth once, then retry.
            log.debug("Session expired; re-authenticating...")
            self._jwt = None
            self._authenticated = False
            if self._token_cache and self.username:
                self._token_cache.delete(self.server, self.username)
            if not (self.username and self.password) and not self.csp_api_token:
                raise AuthenticationError(
                    "Session expired and no credentials are available to re-authenticate. "
                    "Store your password securely with `scc login` or pass --password-prompt.",
                    code=401,
                )
            self.authenticate()
            kwargs["_retried"] = True
            return self.call(resource, method, *args, **kwargs)

        if response.status_code == 403:
            raise AuthenticationError(
                "Access forbidden - insufficient permissions",
                code=403,
                detail=self._describe_error_response(response),
            )
        if response.status_code in (404, 405) and not retried:
            # Wrong RPC path for this server - try the other known layout once.
            alt = self._next_rpc_path_candidate()
            if alt:
                log.debug(
                    "RPC path %s returned %s; retrying with %s",
                    self.rpc_path, response.status_code, alt,
                )
                self.rpc_path = alt
                kwargs["_retried"] = True
                return self.call(resource, method, *args, **kwargs)
        if response.status_code == 404:
            raise NotFoundError(
                f"RPC endpoint not found: {self.rpc_path}",
                code=404,
                detail=self._describe_error_response(response),
            )
        if response.status_code == 405:
            raise APIError(
                f"RPC endpoint rejected POST: {self.rpc_path} (405 Method Not Allowed). "
                "The server may be using a different RPC path.",
                code=405,
                detail=self._describe_error_response(response),
            )
        if response.status_code == 422:
            raise ValidationError(
                "Validation failed",
                code=422,
                detail=self._describe_error_response(response, limit=500),
            )
        if response.status_code >= 500:
            raise ServerError(
                f"Server error {response.status_code}",
                code=response.status_code,
                detail=self._describe_error_response(response, limit=500),
            )

        # ---- Body parsing ----
        text = response.text or ""
        if self._looks_like_html(text):
            # 200 OK but HTML body = session expired or wrong endpoint.
            if not retried and not is_verify and (self.username and self.password):
                log.debug("Server returned HTML (likely session expired); re-authenticating...")
                self._jwt = None
                self._authenticated = False
                if self._token_cache and self.username:
                    self._token_cache.delete(self.server, self.username)
                self.authenticate()
                kwargs["_retried"] = True
                return self.call(resource, method, *args, **kwargs)
            raise AuthenticationError(
                "Server returned an HTML page instead of JSON. "
                "The session is unauthenticated, or the RPC path is wrong. "
                "Try `scc clear-cache` then re-run.",
                code=response.status_code,
                detail=text[:200],
            )

        try:
            data = response.json()
        except json.JSONDecodeError as e:
            raise APIError(
                f"Invalid JSON response from {resource}.{method}: {e}",
                code=response.status_code,
                detail=text[:200],
            ) from e

        rpc_response = RPCResponse.from_dict(data) if isinstance(data, dict) else RPCResponse(
            riq=riq, ret=data
        )

        if rpc_response.error:
            error_msg = rpc_response.error.get("message", "Unknown error")
            if "not found" not in error_msg.lower():
                log.warning("RPC error in %s.%s: %s", resource, method, error_msg)
        for warning in rpc_response.warnings:
            log.warning("RPC warning: %s", warning)

        return rpc_response

    def call_many(
        self,
        calls: List[Dict[str, Any]],
        timeout: Optional[int] = None,
    ) -> List[RPCResponse]:
        payloads = []
        for c in calls:
            p = {"resource": c["resource"], "method": c["method"]}
            if c.get("arg"):
                p["arg"] = c["arg"]
            if c.get("kwarg"):
                p["kwarg"] = c["kwarg"]
            payloads.append(p)

        try:
            response = self._client.post(
                f"{self.server}{self.rpc_path}",
                headers=self._get_headers(),
                json=payloads,
                timeout=timeout or self.timeout,
            )
        except httpx.TimeoutException as e:
            raise TimeoutError("Batch request timed out") from e
        except httpx.RequestError as e:
            raise ConnectionError(f"Batch request failed: {e}") from e

        self._extract_xsrf_token(response)

        if response.status_code == 401:
            raise AuthenticationError("Authentication failed (batch)", code=401)
        if response.status_code >= 400:
            raise APIError(
                f"Batch request failed with HTTP {response.status_code}",
                code=response.status_code,
                detail=(response.text or "")[:200],
            )

        try:
            data = response.json()
        except json.JSONDecodeError as e:
            raise APIError(
                f"Invalid JSON in batch response: {e}",
                code=response.status_code,
                detail=(response.text or "")[:200],
            ) from e

        if isinstance(data, list):
            return [RPCResponse.from_dict(r) if isinstance(r, dict) else RPCResponse(0, r) for r in data]
        return [RPCResponse.from_dict(data)] if isinstance(data, dict) else [RPCResponse(0, data)]

    # ----------------------------------------------------------- properties

    @property
    def is_authenticated(self) -> bool:
        return self._authenticated

    @property
    def api_version(self) -> Optional[str]:
        return self._api_version

    # =========================================================================
    # Convenience methods - unchanged behavior, just thin wrappers around call()
    # =========================================================================

    # --- test ---
    def ping(self) -> bool:
        try:
            response = self.call("test", "echo", message="ping")
            return response.success and response.ret == "ping"
        except Exception:
            return False

    # --- tgt (Target Groups) ---
    def get_target_groups(self) -> List[Dict[str, Any]]:
        response = self.call("tgt", "get_target_group")
        if response.success:
            ret = response.ret
            if isinstance(ret, list):
                return ret
            if isinstance(ret, dict) and "results" in ret:
                return ret["results"]
            return [ret] if ret else []
        return []

    def get_target_group(self, name: Optional[str] = None, uuid: Optional[str] = None) -> Optional[Dict[str, Any]]:
        kwargs = {}
        if name:
            kwargs["name"] = name
        if uuid:
            kwargs["uuid"] = uuid
        response = self.call("tgt", "get_target_group", **kwargs)
        if response.success and response.ret:
            ret = response.ret
            return ret[0] if isinstance(ret, list) and ret else ret
        return None

    def save_target_group(self, name: str, tgt: Union[str, List[Dict[str, str]]], tgt_type: str = "glob", desc: str = "", **kwargs) -> Dict[str, Any]:
        response = self.call("tgt", "save_target_group", name=name, tgt=tgt, tgt_type=tgt_type, desc=desc, **kwargs)
        if response.error:
            raise APIError(response.error.get("message", "Failed to save target group"), code=response.error.get("code"))
        return response.ret or {}

    def delete_target_group(self, name: Optional[str] = None, uuid: Optional[str] = None) -> None:
        kwargs = {}
        if name:
            kwargs["name"] = name
        if uuid:
            kwargs["uuid"] = uuid
        response = self.call("tgt", "delete_target_group", **kwargs)
        if response.error:
            raise APIError(response.error.get("message", "Failed to delete target group"), code=response.error.get("code"))

    # --- job ---
    def get_jobs(self) -> List[Dict[str, Any]]:
        response = self.call("job", "get_jobs")
        if response.success:
            ret = response.ret
            if isinstance(ret, list):
                return ret
            if isinstance(ret, dict) and "results" in ret:
                return ret["results"]
            return [ret] if ret else []
        return []

    def get_job(self, name: Optional[str] = None, uuid: Optional[str] = None) -> Optional[Dict[str, Any]]:
        kwargs = {}
        if name:
            kwargs["name"] = name
        if uuid:
            kwargs["uuid"] = uuid
        response = self.call("job", "get_job", **kwargs)
        if response.success and response.ret:
            ret = response.ret
            return ret[0] if isinstance(ret, list) and ret else ret
        return None

    def save_job(self, name: str, fun: str, cmd: str = "local", tgt_uuid: Optional[str] = None, arg: Optional[Dict[str, Any]] = None, desc: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        params = {"name": name, "cmd": cmd, "fun": fun}
        if desc:
            params["desc"] = desc
        if arg:
            params["arg"] = arg
        if tgt_uuid:
            params["tgt_uuid"] = tgt_uuid
        params.update(kwargs)
        response = self.call("job", "save_job", **params)
        if response.error:
            raise APIError(response.error.get("message", "Failed to save job"), code=response.error.get("code"))
        ret = response.ret
        return {"uuid": ret, "name": name} if isinstance(ret, str) else (ret or {})

    def delete_job(self, job_uuid: Optional[str] = None, name: Optional[str] = None) -> None:
        kwargs = {}
        if job_uuid:
            kwargs["job_uuid"] = job_uuid
        elif name:
            kwargs["job_uuid"] = name
        response = self.call("job", "delete_job", **kwargs)
        if response.error:
            raise APIError(response.error.get("message", "Failed to delete job"), code=response.error.get("code"))

    # --- cmd ---
    def run_command(self, tgt: str, fun: str, arg: Optional[List[str]] = None, kwarg: Optional[Dict[str, Any]] = None, tgt_type: str = "glob", **kwargs) -> Dict[str, Any]:
        params = {"tgt": tgt, "fun": fun, "tgt_type": tgt_type}
        if arg:
            params["arg"] = arg
        if kwarg:
            params["kwarg"] = kwarg
        params.update(kwargs)
        response = self.call("cmd", "run", **params)
        if response.error:
            raise APIError(response.error.get("message", "Failed to run command"), code=response.error.get("code"))
        return response.ret or {}

    # --- pillar ---
    def get_pillars(self) -> List[Dict[str, Any]]:
        response = self.call("pillar", "get_pillar")
        if response.success:
            ret = response.ret
            if isinstance(ret, list):
                return ret
            if isinstance(ret, dict) and "results" in ret:
                return ret["results"]
            return [ret] if ret else []
        return []

    def get_pillar(self, name: Optional[str] = None, uuid: Optional[str] = None) -> Optional[Dict[str, Any]]:
        kwargs = {}
        if name:
            kwargs["name"] = name
        if uuid:
            kwargs["uuid"] = uuid
        response = self.call("pillar", "get_pillar", **kwargs)
        if response.success and response.ret:
            ret = response.ret
            return ret[0] if isinstance(ret, list) and ret else ret
        return None

    def save_pillar(self, name: str, pillar: Dict[str, Any], pillar_type: str = "static", pillar_uuid: Optional[str] = None, desc: str = "", **kwargs) -> Dict[str, Any]:
        params = {"name": name, "pillar": pillar, "pillar_type": pillar_type, "desc": desc}
        if pillar_uuid:
            params["pillar_uuid"] = pillar_uuid
        params.update(kwargs)
        response = self.call("pillar", "save_pillar", **params)
        if response.error:
            raise APIError(response.error.get("message", "Failed to save pillar"), code=response.error.get("code"))
        return response.ret or {}

    def delete_pillar(self, name: Optional[str] = None, uuid: Optional[str] = None) -> None:
        kwargs = {}
        if name:
            kwargs["name"] = name
        if uuid:
            kwargs["uuid"] = uuid
        response = self.call("pillar", "delete_pillar", **kwargs)
        if response.error:
            raise APIError(response.error.get("message", "Failed to delete pillar"), code=response.error.get("code"))

    # --- fs ---
    def get_file(self, path: str, saltenv: str = "base") -> Optional[Dict[str, Any]]:
        response = self.call("fs", "get_file", path=path, saltenv=saltenv)
        return response.ret if response.success else None

    def save_file(self, path: str, contents: str, saltenv: str = "base", **kwargs) -> Dict[str, Any]:
        response = self.call("fs", "save_file", path=path, contents=contents, saltenv=saltenv, **kwargs)
        if response.error:
            raise APIError(response.error.get("message", "Failed to save file"), code=response.error.get("code"))
        return response.ret or {}

    def delete_file(self, path: str, saltenv: str = "base") -> None:
        response = self.call("fs", "delete_file", path=path, saltenv=saltenv)
        if response.error:
            raise APIError(response.error.get("message", "Failed to delete file"), code=response.error.get("code"))

    # --- minions ---
    def get_minions(self) -> List[Dict[str, Any]]:
        response = self.call("minions", "get_minion_details")
        if response.success:
            ret = response.ret
            if isinstance(ret, list):
                return ret
            if isinstance(ret, dict) and "results" in ret:
                return ret["results"]
            return [ret] if ret else []
        return []

    def get_minion(self, minion_id: str) -> Optional[Dict[str, Any]]:
        response = self.call("minions", "get_minion_details", minion_id=minion_id)
        if response.success and response.ret:
            ret = response.ret
            return ret[0] if isinstance(ret, list) and ret else ret
        return None

    # --- schedule ---
    def get_schedules(self) -> List[Dict[str, Any]]:
        response = self.call("schedule", "get_schedule")
        if response.success:
            ret = response.ret
            if isinstance(ret, list):
                return ret
            if isinstance(ret, dict) and "results" in ret:
                return ret["results"]
            return [ret] if ret else []
        return []

    def save_schedule(self, name: str, job_uuid: str, schedule: Dict[str, Any], enabled: bool = True, **kwargs) -> Dict[str, Any]:
        response = self.call("schedule", "save", name=name, job_uuid=job_uuid, schedule=schedule, enabled=enabled, **kwargs)
        if response.error:
            raise APIError(response.error.get("message", "Failed to save schedule"), code=response.error.get("code"))
        return response.ret or {}

    def delete_schedule(self, uuid: str) -> None:
        response = self.call("schedule", "delete", uuid=uuid)
        if response.error:
            raise APIError(response.error.get("message", "Failed to delete schedule"), code=response.error.get("code"))

    # --- master ---
    def get_masters(self) -> List[Dict[str, Any]]:
        response = self.call("master", "get_master")
        if response.success:
            ret = response.ret
            if isinstance(ret, list):
                return ret
            if isinstance(ret, dict) and "results" in ret:
                return ret["results"]
            return [ret] if ret else []
        return []

    # --- sec ---
    def download_content(self, auto_ingest: bool = True) -> Dict[str, Any]:
        response = self.call("sec", "download_content", auto_ingest=auto_ingest)
        if response.error:
            raise APIError(response.error.get("message", "Failed to download content"), code=response.error.get("code"))
        return response.ret or {}

    # --- license ---
    def get_license(self) -> Optional[Dict[str, Any]]:
        response = self.call("license", "get_license")
        return response.ret if response.success else None

    # --- api ---
    def get_versions(self) -> Optional[str]:
        response = self.call("api", "get_versions")
        return response.ret if response.success else None

    def discover_api(self) -> Dict[str, Any]:
        response = self.call("api", "discover")
        return (response.ret or {}) if response.success else {}

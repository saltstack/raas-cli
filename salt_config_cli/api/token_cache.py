"""
Token caching for VMware Aria Automation Config API.

Caches authentication tokens locally to avoid re-authenticating on every command.
"""

import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)

# Default token expiry time (30 minutes)
DEFAULT_TOKEN_TTL_SECONDS = 30 * 60

# Cache directory
CACHE_DIR = Path.home() / ".scc" / "cache"


class TokenCache:
    """
    Cache authentication tokens locally.
    
    Stores tokens in ~/.scc/cache/ directory with server-specific filenames.
    Tokens are cached with a TTL and automatically invalidated when expired.
    """
    
    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS
    ):
        """
        Initialize the token cache.
        
        Args:
            cache_dir: Directory to store cache files (default: ~/.scc/cache)
            ttl_seconds: Token time-to-live in seconds (default: 30 minutes)
        """
        self.cache_dir = cache_dir or CACHE_DIR
        self.ttl_seconds = ttl_seconds
    
    def _get_cache_key(self, server: str, username: Optional[str] = None) -> str:
        """Generate a unique cache key for the server/user combination."""
        key_data = f"{server}:{username or 'anonymous'}"
        return hashlib.sha256(key_data.encode()).hexdigest()[:16]
    
    def _get_cache_path(self, cache_key: str) -> Path:
        """Get the cache file path for a given key."""
        return self.cache_dir / f"token_{cache_key}.json"
    
    def _ensure_cache_dir(self) -> None:
        """Ensure the cache directory exists with appropriate permissions."""
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        # Set restrictive permissions (owner read/write only)
        try:
            os.chmod(self.cache_dir, 0o700)
        except OSError:
            pass
    
    def get(
        self,
        server: str,
        username: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Get cached token data if valid.
        
        Args:
            server: RaaS server URL
            username: Username for authentication
        
        Returns:
            Cached token data dict or None if not found/expired
        """
        cache_key = self._get_cache_key(server, username)
        cache_path = self._get_cache_path(cache_key)
        
        if not cache_path.exists():
            log.debug(f"No cached token found for {server}")
            return None
        
        try:
            with open(cache_path, "r") as f:
                data = json.load(f)
            
            # Check expiry
            expires_at = data.get("expires_at", 0)
            if time.time() > expires_at:
                log.debug(f"Cached token expired for {server}")
                self.delete(server, username)
                return None
            
            log.debug(f"Using cached token for {server}")
            return data
            
        except (json.JSONDecodeError, OSError) as e:
            log.warning(f"Failed to read token cache: {e}")
            return None
    
    def set(
        self,
        server: str,
        username: Optional[str] = None,
        xsrf_token: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        csp_access_token: Optional[str] = None,
        api_token_access_token: Optional[str] = None,
        jwt: Optional[str] = None,
        ttl_seconds: Optional[int] = None
    ) -> None:
        """
        Cache token data.

        Args:
            server: RaaS server URL
            username: Username for authentication
            xsrf_token: XSRF token from server
            cookies: HTTP cookies to cache
            csp_access_token: CSP access token (for cloud deployments)
            api_token_access_token: Access token from the API-token exchange
            jwt: JWT session token from /account/login
            ttl_seconds: Custom TTL (overrides default)
        """
        self._ensure_cache_dir()

        cache_key = self._get_cache_key(server, username)
        cache_path = self._get_cache_path(cache_key)

        ttl = ttl_seconds or self.ttl_seconds
        data = {
            "server": server,
            "username": username,
            "xsrf_token": xsrf_token,
            "cookies": cookies or {},
            "csp_access_token": csp_access_token,
            "api_token_access_token": api_token_access_token,
            "jwt": jwt,
            "created_at": time.time(),
            "expires_at": time.time() + ttl
        }
        
        try:
            with open(cache_path, "w") as f:
                json.dump(data, f)
            # Set restrictive permissions on cache file
            os.chmod(cache_path, 0o600)
            log.debug(f"Cached token for {server} (expires in {ttl}s)")
        except OSError as e:
            log.warning(f"Failed to write token cache: {e}")
    
    def delete(
        self,
        server: str,
        username: Optional[str] = None
    ) -> None:
        """
        Delete cached token.
        
        Args:
            server: RaaS server URL
            username: Username for authentication
        """
        cache_key = self._get_cache_key(server, username)
        cache_path = self._get_cache_path(cache_key)
        
        try:
            if cache_path.exists():
                cache_path.unlink()
                log.debug(f"Deleted cached token for {server}")
        except OSError as e:
            log.warning(f"Failed to delete token cache: {e}")
    
    def clear_all(self) -> int:
        """
        Clear all cached tokens.
        
        Returns:
            Number of tokens cleared
        """
        count = 0
        if self.cache_dir.exists():
            for cache_file in self.cache_dir.glob("token_*.json"):
                try:
                    cache_file.unlink()
                    count += 1
                except OSError:
                    pass
        log.debug(f"Cleared {count} cached tokens")
        return count


# Global cache instance
_token_cache: Optional[TokenCache] = None


def get_token_cache() -> TokenCache:
    """Get the global token cache instance."""
    global _token_cache
    if _token_cache is None:
        _token_cache = TokenCache()
    return _token_cache

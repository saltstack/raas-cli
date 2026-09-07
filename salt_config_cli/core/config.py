"""Configuration and named connection-profile management for Salt Config CLI.

The CLI supports both the original flat ``config.yaml`` format and the newer
profile-based format.  Secrets are never persisted in profile YAML; passwords
and tokens are resolved from the OS keyring, environment variables, stdin, or
an interactive prompt.
"""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path
from typing import Any, Dict, Literal, Optional
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, SecretStr, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

CONFIG_SCHEMA_VERSION = 2
DEFAULT_PROFILE = "default"
DEFAULT_THEME = "ocean"
SUPPORTED_THEMES = {"ocean", "enterprise", "graphite", "forest", "amber", "high-contrast", "plain"}
THEME_ALIASES = {"default": "ocean", "classic": "ocean", "none": "plain", "off": "plain", "disabled": "plain", "no-theme": "plain"}


def user_config_path() -> Path:
    """Return the user-level SCC configuration path."""
    return Path.home() / ".scc" / "config.yaml"


def workspace_config_path() -> Path:
    """Return the current workspace SCC configuration path."""
    return Path.cwd() / ".scc" / "config.yaml"


def discover_config_path(config_path: Optional[str | Path] = None) -> Path:
    """Resolve an explicit, environment, workspace, or user config path."""
    if config_path:
        return Path(config_path).expanduser()
    if os.getenv("SCC_CONFIG"):
        return Path(os.environ["SCC_CONFIG"]).expanduser()
    for candidate in (
        workspace_config_path(),
        Path.cwd() / ".scc" / "config.yml",
        user_config_path(),
        Path.home() / ".scc" / "config.yml",
    ):
        if candidate.exists():
            return candidate
    return user_config_path()


class ConnectionProfile(BaseModel):
    """One named RaaS connection profile.

    The model intentionally contains no password/token fields.  Credentials are
    stored separately in the OS keyring or supplied at runtime.
    """

    model_config = ConfigDict(extra="forbid")

    server_url: str
    username: Optional[str] = None
    auth: Literal["password", "csp-token", "api-token"] = "password"
    config_name: str = "internal"
    ssl_verify: bool = True
    ca_bundle: Optional[str] = None
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None
    timeout: int = Field(default=60, ge=1, le=3600)
    token_ttl: int = Field(default=1800, ge=60, le=86400)
    rpc_paths: list[str] = Field(default_factory=lambda: ["/rpc", "/raas/rpc"])
    default_environment: str = "base"
    default_target: str = "*"
    default_target_type: str = "glob"
    csp_url: str = "https://console.cloud.vmware.com"
    csp_org_id: Optional[str] = None
    auth_server_url: Optional[str] = None
    ops_server_url: Optional[str] = None
    ops_username: Optional[str] = None
    ops_ssl_verify: bool = False
    output_format: str = "text"
    color: bool = True
    theme: Optional[str] = None
    log_level: str = "INFO"

    @field_validator("theme")
    @classmethod
    def validate_theme(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = THEME_ALIASES.get(value.strip().lower().replace("_", "-"), value.strip().lower().replace("_", "-"))
        if normalized not in SUPPORTED_THEMES:
            raise ValueError(f"theme must be one of: {', '.join(sorted(SUPPORTED_THEMES))}")
        return normalized

    @field_validator("server_url")
    @classmethod
    def validate_server_url(cls, value: str) -> str:
        value = value.strip().rstrip("/")
        if not value:
            raise ValueError("server_url is required")
        if not value.startswith(("http://", "https://")):
            value = f"https://{value}"
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("server_url must be an absolute HTTP(S) URL")
        return value

    @field_validator("ops_server_url")
    @classmethod
    def validate_ops_server_url(cls, value: Optional[str]) -> Optional[str]:
        if value is None or not value.strip():
            return None
        normalized = value.strip().rstrip("/")
        if not normalized.startswith(("http://", "https://")):
            normalized = f"https://{normalized}"
        parsed = urlparse(normalized)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("ops_server_url must be an absolute HTTP(S) URL")
        return normalized

    @field_validator("auth_server_url")
    @classmethod
    def validate_auth_server_url(cls, value: Optional[str]) -> Optional[str]:
        if value is None or not value.strip():
            return None
        normalized = value.strip().rstrip("/")
        if not normalized.startswith(("http://", "https://")):
            normalized = f"https://{normalized}"
        parsed = urlparse(normalized)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("auth_server_url must be an absolute HTTP(S) URL")
        return normalized

    @field_validator("rpc_paths")
    @classmethod
    def validate_rpc_paths(cls, paths: list[str]) -> list[str]:
        cleaned: list[str] = []
        for path in paths:
            normalized = path.strip()
            if not normalized:
                continue
            if not normalized.startswith("/"):
                normalized = f"/{normalized}"
            if normalized not in cleaned:
                cleaned.append(normalized)
        if not cleaned:
            raise ValueError("at least one RPC path is required")
        return cleaned


class ProfileConfigFile(BaseModel):
    """Persistent profile document."""

    model_config = ConfigDict(extra="forbid")

    version: int = CONFIG_SCHEMA_VERSION
    default_profile: str = DEFAULT_PROFILE
    theme: str = DEFAULT_THEME
    profiles: dict[str, ConnectionProfile] = Field(default_factory=dict)

    # Git integration - pull a resource folder (<name>/<name>.sls,
    # map.jinja, defaults.yaml) from a GitHub repo by name (`scc pull
    # <name>`). Workspace-level, not per-connection, so this lives on the
    # document root rather than inside each ConnectionProfile.
    git_repo_url: Optional[str] = None
    git_branch: str = "main"
    git_resources_path: str = "vcf-infra"

    # Data-repo integration - pull per-deployment override values (private,
    # never shared) from a SEPARATE git repo by resource + file name (`scc
    # pull-data <name> <file>`). Kept deliberately separate from
    # git_repo_url/git_branch/git_resources_path above: the module repo
    # (states/map.jinja/defaults) and the values repo (override data) are two
    # different repos with two different lifecycles/ownership.
    git_data_repo_url: Optional[str] = None
    git_data_branch: str = "main"
    git_data_resources_path: str = "."

    @field_validator("theme")
    @classmethod
    def validate_theme(cls, value: str) -> str:
        normalized = THEME_ALIASES.get(value.strip().lower().replace("_", "-"), value.strip().lower().replace("_", "-"))
        if normalized not in SUPPORTED_THEMES:
            raise ValueError(f"theme must be one of: {', '.join(sorted(SUPPORTED_THEMES))}")
        return normalized


class SaltConfigSettings(BaseSettings):
    """Resolved runtime settings for Salt Config CLI.

    Resolution order is CLI override -> environment -> selected profile ->
    legacy flat config -> built-in default.
    """

    # Server connection and authentication
    server_url: str = Field(default="https://localhost")
    username: Optional[str] = None
    password: Optional[SecretStr] = None
    auth: Literal["password", "csp-token", "api-token"] = "password"
    config_name: str = "internal"

    # CSP
    csp_url: str = "https://console.cloud.vmware.com"
    csp_org_id: Optional[str] = None
    csp_api_token: Optional[SecretStr] = None

    # API token exchange (POST {auth_server_url}/acs/t/<fixed tenant>/token)
    auth_server_url: Optional[str] = None
    api_token: Optional[SecretStr] = None

    # VCF Operations connection
    ops_server_url: Optional[str] = None
    ops_username: Optional[str] = None
    ops_password: Optional[SecretStr] = None
    ops_ssl_verify: bool = False

    # TLS/client settings
    ssl_verify: bool = False
    ca_bundle: Optional[str] = None
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None

    # Request and session settings
    timeout: int = 60
    token_ttl: int = 1800
    rpc_paths: list[str] = Field(default_factory=lambda: ["/rpc", "/raas/rpc"])

    # Operational defaults
    default_environment: str = "base"
    default_target: str = "*"
    default_target_type: str = "glob"

    # Desired-state workspace settings
    state_file: str = ".scc/salt.state"
    state_backend: str = "local"
    working_dir: str = "."

    # Git integration - pull a resource folder (<name>/<name>.sls,
    # map.jinja, defaults.yaml) from a GitHub repo by name (`scc pull
    # <name>`). Not part of ConnectionProfile: this is a workspace-level
    # source, not a per-RaaS-server connection setting.
    git_repo_url: Optional[str] = None
    git_branch: str = "main"
    git_resources_path: str = "vcf-infra"
    git_token: Optional[SecretStr] = None

    # Data-repo integration - see ProfileConfigFile for the rationale.
    # git_data_token is intentionally separate from git_token: the module
    # repo and the data repo are commonly on different hosts (e.g. a
    # public github.com repo vs. a private GitHub Enterprise repo), so a
    # single shared token would get sent to both - which can actively break
    # the public one (some hosts 404 rather than 401 on a foreign token).
    git_data_repo_url: Optional[str] = None
    git_data_branch: str = "main"
    git_data_resources_path: str = "."
    git_data_token: Optional[SecretStr] = None

    # Logging/output
    log_level: str = "INFO"
    log_file: Optional[str] = None
    output_format: str = "text"
    color: bool = True
    theme: str = DEFAULT_THEME

    _profile_name: str = PrivateAttr(default=DEFAULT_PROFILE)
    _config_path: Optional[Path] = PrivateAttr(default=None)
    _config_format: str = PrivateAttr(default="default")

    model_config = SettingsConfigDict(
        env_prefix="SCC_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @property
    def profile_name(self) -> str:
        return self._profile_name

    @property
    def config_path(self) -> Optional[Path]:
        return self._config_path

    @property
    def config_format(self) -> str:
        return self._config_format

    @classmethod
    def load_from_file(
        cls,
        config_path: Optional[str] = None,
        profile_name: Optional[str] = None,
    ) -> "SaltConfigSettings":
        """Load a selected named profile or a backward-compatible flat config."""
        path = discover_config_path(config_path)
        data: dict[str, Any] = {}
        selected = profile_name or os.getenv("SCC_PROFILE") or DEFAULT_PROFILE
        source_format = "default"

        if path.exists():
            try:
                raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except (OSError, yaml.YAMLError) as exc:
                raise ValueError(f"Unable to read configuration file {path}: {exc}") from exc
            if not isinstance(raw, dict):
                raise ValueError(f"Configuration file {path} must contain a YAML mapping")

            # Never load plaintext secrets from YAML.
            raw.pop("password", None)
            raw.pop("csp_api_token", None)
            raw.pop("api_token", None)

            if "profiles" in raw:
                # Normalize hybrid v0.6 documents before selecting a profile.
                # This keeps every command usable even before an explicit
                # profile-management operation persists the migration.
                source_format = "profiles"
                document = ProfileConfigStore(path).load(persist_migration=False)
                selected = profile_name or os.getenv("SCC_PROFILE") or document.default_profile or DEFAULT_PROFILE
                if selected not in document.profiles:
                    available = ", ".join(sorted(document.profiles)) or "none"
                    raise ValueError(
                        f"Connection profile '{selected}' does not exist in {path}. "
                        f"Available profiles: {available}"
                    )
                profile = document.profiles[selected]
                data = profile.model_dump(exclude_none=True)
                data["theme"] = profile.theme or document.theme or DEFAULT_THEME
                data["git_repo_url"] = document.git_repo_url
                data["git_branch"] = document.git_branch
                data["git_resources_path"] = document.git_resources_path
                data["git_data_repo_url"] = document.git_data_repo_url
                data["git_data_branch"] = document.git_data_branch
                data["git_data_resources_path"] = document.git_data_resources_path
            else:
                source_format = "legacy-flat"
                selected = profile_name or os.getenv("SCC_PROFILE") or DEFAULT_PROFILE
                if selected != DEFAULT_PROFILE:
                    raise ValueError(
                        f"Configuration file {path} uses the legacy flat format and only exposes "
                        f"the '{DEFAULT_PROFILE}' profile. Run `scc configure --name {selected}` to migrate."
                    )
                data = dict(raw)

        settings = cls(**data)
        cls._apply_environment_overrides(settings)
        settings._profile_name = selected
        settings._config_path = path
        settings._config_format = source_format
        return settings

    @staticmethod
    def _apply_environment_overrides(settings: "SaltConfigSettings") -> None:
        """Apply supported environment variables after profile loading."""
        boolean = lambda value: value.strip().lower() in {"1", "true", "yes", "on"}
        mapping: dict[str, tuple[str, Any]] = {
            "SCC_SERVER_URL": ("server_url", str),
            "SCC_USERNAME": ("username", str),
            "SCC_CONFIG_NAME": ("config_name", str),
            "SCC_AUTH_SERVER_URL": ("auth_server_url", str),
            "SCC_SSL_VERIFY": ("ssl_verify", boolean),
            "SCC_CA_BUNDLE": ("ca_bundle", str),
            "SCC_SSL_CERT": ("ssl_cert", str),
            "SCC_SSL_KEY": ("ssl_key", str),
            "SCC_TIMEOUT": ("timeout", int),
            "SCC_DEFAULT_ENVIRONMENT": ("default_environment", str),
            "SCC_DEFAULT_TARGET": ("default_target", str),
            "SCC_DEFAULT_TARGET_TYPE": ("default_target_type", str),
            "SCC_OUTPUT_FORMAT": ("output_format", str),
            "SCC_GIT_REPO_URL": ("git_repo_url", str),
            "SCC_GIT_BRANCH": ("git_branch", str),
            "SCC_GIT_RESOURCES_PATH": ("git_resources_path", str),
            "SCC_GIT_DATA_REPO_URL": ("git_data_repo_url", str),
            "SCC_GIT_DATA_BRANCH": ("git_data_branch", str),
            "SCC_GIT_DATA_RESOURCES_PATH": ("git_data_resources_path", str),
            "SCC_THEME": ("theme", lambda value: THEME_ALIASES.get(value.strip().lower().replace("_", "-"), value.strip().lower().replace("_", "-"))),
            "SCC_LOG_LEVEL": ("log_level", str),
        }
        for env_name, (field_name, converter) in mapping.items():
            if env_name in os.environ:
                setattr(settings, field_name, converter(os.environ[env_name]))

    def to_profile(self) -> ConnectionProfile:
        """Convert resolved non-secret connection settings into a profile."""
        return ConnectionProfile(
            server_url=self.server_url,
            username=self.username,
            auth=self.auth,
            config_name=self.config_name,
            ssl_verify=self.ssl_verify,
            ca_bundle=self.ca_bundle,
            ssl_cert=self.ssl_cert,
            ssl_key=self.ssl_key,
            timeout=self.timeout,
            token_ttl=self.token_ttl,
            rpc_paths=self.rpc_paths,
            default_environment=self.default_environment,
            default_target=self.default_target,
            default_target_type=self.default_target_type,
            csp_url=self.csp_url,
            csp_org_id=self.csp_org_id,
            auth_server_url=self.auth_server_url,
            ops_server_url=self.ops_server_url,
            ops_username=self.ops_username,
            ops_ssl_verify=self.ops_ssl_verify,
            output_format=self.output_format,
            color=self.color,
            theme=self.theme,
            log_level=self.log_level,
        )

    def to_dict(self, exclude_secrets: bool = True) -> Dict[str, Any]:
        data = self.model_dump()
        if exclude_secrets:
            if data.get("password"):
                data["password"] = "***"
            if data.get("csp_api_token"):
                data["csp_api_token"] = "***"
            if data.get("api_token"):
                data["api_token"] = "***"
            if data.get("ops_password"):
                data["ops_password"] = "***"
        data["profile_name"] = self.profile_name
        data["config_path"] = str(self.config_path) if self.config_path else None
        return data

    def get_auth_config(self) -> Dict[str, Any]:
        verify: bool | str = self.ca_bundle or self.ssl_verify
        config: Dict[str, Any] = {
            "server": self.server_url,
            "timeout": self.timeout,
            "ssl_verify": verify,
            "config_name": self.config_name,
        }
        if self.ssl_cert:
            config["ssl_cert"] = self.ssl_cert
        if self.ssl_key:
            config["ssl_key"] = self.ssl_key
        if self.rpc_paths:
            config["rpc_path"] = self.rpc_paths[0]
        if self.username:
            config["username"] = self.username
        if self.password:
            config["password"] = self.password.get_secret_value()
        if self.csp_api_token:
            config["csp_url"] = self.csp_url
            config["csp_api_token"] = self.csp_api_token.get_secret_value()
            if self.csp_org_id:
                config["csp_org_id"] = self.csp_org_id
        if self.api_token and self.auth_server_url:
            config["auth_server_url"] = self.auth_server_url
            config["api_token"] = self.api_token.get_secret_value()
        return config

    def get_ops_auth_config(self) -> Optional[Dict[str, Any]]:
        if not self.ops_server_url:
            return None
        config: Dict[str, Any] = {
            "server": self.ops_server_url,
            "timeout": self.timeout,
            "ssl_verify": self.ops_ssl_verify,
        }
        if self.ops_username and self.ops_password:
            config["username"] = self.ops_username
            config["password"] = self.ops_password.get_secret_value()
        return config


class ProfileConfigStore:
    """Read/write named profiles with atomic, permission-safe persistence."""

    _LEGACY_SECRET_FIELDS = {"password", "csp_api_token", "ops_password"}
    _LEGACY_RUNTIME_FIELDS = {
        "state_file", "state_backend", "working_dir", "log_file",
    }
    # Root fields renamed across CLI versions ("pillar" -> "data" terminology).
    # Old key wins only if the new key isn't already present.
    _LEGACY_ROOT_FIELD_RENAMES = {
        "git_pillar_repo_url": "git_data_repo_url",
        "git_pillar_branch": "git_data_branch",
        "git_pillar_resources_path": "git_data_resources_path",
    }

    def __init__(self, path: Optional[str | Path] = None) -> None:
        self.path = discover_config_path(path)
        self.last_migration: Optional[str] = None
        self.backup_path: Optional[Path] = None

    @staticmethod
    def _copy_mapping(value: Any) -> dict[str, Any]:
        return dict(value) if isinstance(value, dict) else {}

    def _normalise_document(self, source: dict[str, Any]) -> tuple[ProfileConfigFile, Optional[str]]:
        """Validate current profile documents and repair legacy/hybrid formats.

        v0.6 could create a hybrid file containing both ``profiles`` and the
        original top-level ``server_url``/``username`` fields.  Pydantic quite
        correctly rejected that document because those fields are not part of
        the v2 root schema.  This normaliser moves known legacy connection
        fields into the selected profile before strict validation, while still
        rejecting genuinely unknown configuration keys.
        """
        raw = dict(source)
        for field in self._LEGACY_SECRET_FIELDS:
            raw.pop(field, None)

        renamed_fields: list[str] = []
        for old_key, new_key in self._LEGACY_ROOT_FIELD_RENAMES.items():
            if old_key in raw:
                if new_key not in raw:
                    raw[new_key] = raw.pop(old_key)
                else:
                    raw.pop(old_key, None)
                renamed_fields.append(f"{old_key} -> {new_key}")

        profile_fields = set(ConnectionProfile.model_fields)
        root_fields = set(ProfileConfigFile.model_fields)
        legacy_connection_fields = profile_fields - {"theme"}
        legacy_profile_data = {
            key: raw.get(key)
            for key in legacy_connection_fields
            if key in raw
        }
        legacy_runtime = {
            key: raw.get(key)
            for key in self._LEGACY_RUNTIME_FIELDS
            if key in raw
        }

        has_profiles_key = "profiles" in raw
        migration_reasons: list[str] = []

        if not has_profiles_key:
            # Original flat file. Theme is promoted to the global setting and
            # connection values become the default profile.
            profile_data = {key: value for key, value in legacy_profile_data.items() if value is not None}
            global_theme = raw.get("theme") or DEFAULT_THEME
            profiles: dict[str, ConnectionProfile] = {}
            if profile_data.get("server_url") not in {None, "", "https://localhost"}:
                profiles[DEFAULT_PROFILE] = ConnectionProfile.model_validate(profile_data)
            document = ProfileConfigFile(
                version=CONFIG_SCHEMA_VERSION,
                default_profile=DEFAULT_PROFILE,
                theme=global_theme,
                profiles=profiles,
                git_repo_url=raw.get("git_repo_url"),
                git_branch=raw.get("git_branch") or "main",
                git_resources_path=raw.get("git_resources_path") or "vcf-infra",
                git_data_repo_url=raw.get("git_data_repo_url"),
                git_data_branch=raw.get("git_data_branch") or "main",
                git_data_resources_path=raw.get("git_data_resources_path") or ".",
            )
            migration_reasons.append("legacy flat configuration")
            if legacy_runtime:
                migration_reasons.append("obsolete runtime-only settings")
            if renamed_fields:
                migration_reasons.append(f"renamed: {', '.join(renamed_fields)}")
            return document, ", ".join(migration_reasons)

        profiles_raw = raw.get("profiles")
        if profiles_raw is None:
            profiles_raw = {}
        if not isinstance(profiles_raw, dict):
            raise ValueError("profiles must contain a YAML mapping of profile names")

        cleaned_profiles: dict[str, Any] = {}
        for name, value in profiles_raw.items():
            if not isinstance(value, dict):
                raise ValueError(f"Profile '{name}' must contain a YAML mapping")
            profile_value = dict(value)
            for field in self._LEGACY_SECRET_FIELDS:
                if field in profile_value:
                    profile_value.pop(field, None)
                    migration_reasons.append(f"plaintext secret removed from profile '{name}'")
            # Drop only fields that belonged to the old runtime settings model.
            # Unknown profile keys still fail strict Pydantic validation.
            for field in self._LEGACY_RUNTIME_FIELDS:
                if field in profile_value:
                    profile_value.pop(field, None)
                    migration_reasons.append(f"obsolete field '{field}' removed from profile '{name}'")
            cleaned_profiles[str(name)] = profile_value

        default_profile = str(raw.get("default_profile") or DEFAULT_PROFILE)
        if legacy_profile_data:
            current = self._copy_mapping(cleaned_profiles.get(default_profile))
            merged = {
                **{key: value for key, value in legacy_profile_data.items() if value is not None},
                **current,
            }
            if merged.get("server_url") not in {None, "", "https://localhost"}:
                cleaned_profiles[default_profile] = merged
                migration_reasons.append("top-level connection fields moved into the default profile")

        # Remove only the recognised legacy fields. Any other unexpected root
        # key remains present so strict schema validation can report the typo.
        cleaned_root = {key: value for key, value in raw.items() if key in root_fields}
        cleaned_root["version"] = CONFIG_SCHEMA_VERSION
        cleaned_root["default_profile"] = default_profile
        cleaned_root["theme"] = raw.get("theme") or DEFAULT_THEME
        cleaned_root["profiles"] = cleaned_profiles

        recognised_legacy = legacy_connection_fields | self._LEGACY_RUNTIME_FIELDS | self._LEGACY_SECRET_FIELDS
        unknown_root = set(raw) - root_fields - recognised_legacy
        if unknown_root:
            # Preserve strict, actionable validation for actual spelling/schema
            # mistakes instead of silently discarding user configuration.
            for key in unknown_root:
                cleaned_root[key] = raw[key]

        if cleaned_profiles and default_profile not in cleaned_profiles:
            cleaned_root["default_profile"] = next(iter(cleaned_profiles))
            migration_reasons.append("invalid default_profile repaired")

        if legacy_runtime:
            migration_reasons.append("obsolete runtime-only settings removed")

        if renamed_fields:
            migration_reasons.append(f"renamed: {', '.join(renamed_fields)}")

        document = ProfileConfigFile.model_validate(cleaned_root)
        reason = ", ".join(dict.fromkeys(migration_reasons)) or None
        return document, reason

    def _backup_before_migration(self) -> Optional[Path]:
        if not self.path.exists():
            return None
        candidate = self.path.with_suffix(self.path.suffix + ".pre-v2.bak")
        if candidate.exists():
            return candidate
        try:
            candidate.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.path, candidate)
            return candidate
        except OSError:
            return None

    def load(self, *, persist_migration: bool = True) -> ProfileConfigFile:
        self.last_migration = None
        self.backup_path = None
        if not self.path.exists():
            return ProfileConfigFile()
        try:
            raw = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise ValueError(f"Unable to read configuration file {self.path}: {exc}") from exc
        if not isinstance(raw, dict):
            raise ValueError(f"Configuration file {self.path} must contain a YAML mapping")

        try:
            document, migration = self._normalise_document(raw)
        except ValidationError as exc:
            issues: list[str] = []
            for issue in exc.errors(include_url=False):
                location = ".".join(str(part) for part in issue.get("loc", ())) or "configuration"
                message = str(issue.get("msg", "invalid value"))
                if message == "Extra inputs are not permitted":
                    message = "unsupported field"
                issues.append(f"{location}: {message}")
            detail = "; ".join(issues) or str(exc)
            raise ValueError(f"Invalid profile configuration in {self.path}: {detail}") from exc
        if migration:
            self.last_migration = migration
            if persist_migration:
                self.backup_path = self._backup_before_migration()
                try:
                    self.save(document)
                except OSError:
                    # The in-memory profile remains usable even on read-only
                    # filesystems; a later explicit write will surface the error.
                    pass
        return document

    def save(self, config: ProfileConfigFile) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = config.model_dump(mode="json", exclude_none=True)
        temp = self.path.with_suffix(self.path.suffix + ".tmp")
        temp.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
        try:
            os.chmod(temp, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        temp.replace(self.path)

    def get_profile(self, name: Optional[str] = None) -> tuple[str, ConnectionProfile]:
        config = self.load()
        selected = name or os.getenv("SCC_PROFILE") or config.default_profile
        profile = config.profiles.get(selected)
        if profile is None:
            available = ", ".join(sorted(config.profiles)) or "none"
            raise ValueError(f"Profile '{selected}' does not exist. Available profiles: {available}")
        return selected, profile

    def upsert_profile(self, name: str, profile: ConnectionProfile, *, make_default: bool = False) -> None:
        if not name or any(char.isspace() for char in name):
            raise ValueError("Profile name must be non-empty and cannot contain whitespace")
        config = self.load()
        config.profiles[name] = profile
        if make_default or len(config.profiles) == 1 or config.default_profile not in config.profiles:
            config.default_profile = name
        self.save(config)

    def set_default(self, name: str) -> None:
        config = self.load()
        if name not in config.profiles:
            raise ValueError(f"Profile '{name}' does not exist")
        config.default_profile = name
        self.save(config)

    def delete_profile(self, name: str) -> ConnectionProfile:
        config = self.load()
        if name not in config.profiles:
            raise ValueError(f"Profile '{name}' does not exist")
        removed = config.profiles.pop(name)
        if config.default_profile == name:
            config.default_profile = next(iter(config.profiles), DEFAULT_PROFILE)
        self.save(config)
        return removed

    def clone_profile(self, source: str, destination: str, *, make_default: bool = False) -> None:
        _, profile = self.get_profile(source)
        config = self.load()
        if destination in config.profiles:
            raise ValueError(f"Profile '{destination}' already exists")
        config.profiles[destination] = profile.model_copy(deep=True)
        if make_default:
            config.default_profile = destination
        self.save(config)


class WorkspaceConfig(BaseModel):
    """Configuration for a Salt Config CLI workspace."""

    name: str = Field(description="Workspace name")
    environment: str = Field(default="base", description="Salt environment")
    backend: str = Field(default="local", description="State backend")
    config_dir: str = Field(default=".", description="Directory containing configuration files")
    state_dir: str = Field(default=".scc", description="Directory for state files")
    variables: Dict[str, Any] = Field(default_factory=dict)
    var_files: list[str] = Field(default_factory=list)

    @classmethod
    def load(cls, path: str = ".") -> "WorkspaceConfig":
        config_path = Path(path) / ".scc" / "workspace.yaml"
        if config_path.exists():
            data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
            return cls(**data)
        return cls(name=Path(path).name)

    def save(self, path: str = ".") -> None:
        config_dir = Path(path) / ".scc"
        config_dir.mkdir(parents=True, exist_ok=True)
        config_path = config_dir / "workspace.yaml"
        config_path.write_text(
            yaml.safe_dump(self.model_dump(), sort_keys=False),
            encoding="utf-8",
        )

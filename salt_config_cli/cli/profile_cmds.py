"""Themed connection-profile and configuration commands."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Optional

import click
import yaml
from pydantic import SecretStr
from rich.text import Text

from salt_config_cli import __version__
from salt_config_cli.api.client import AriaConfigClient
from salt_config_cli.core.config import (
    ConnectionProfile,
    ProfileConfigFile,
    ProfileConfigStore,
    SaltConfigSettings,
    discover_config_path,
    user_config_path,
    workspace_config_path,
)
from salt_config_cli.ui import (
    ICONS,
    RichGroup,
    badge,
    command_header,
    data_table,
    error as ui_error,
    hint as ui_hint,
    keychain_available,
    keychain_delete,
    keychain_get,
    keychain_set,
    kv_table,
    mask,
    mask_url,
    next_steps,
    prompt_password,
    result_summary,
    spinner,
    success as ui_success,
    warn as ui_warn,
)
from salt_config_cli.ui.theme import console


PROFILE_FIELDS = {
    "server_url",
    "username",
    "auth",
    "config_name",
    "ssl_verify",
    "ca_bundle",
    "ssl_cert",
    "ssl_key",
    "timeout",
    "token_ttl",
    "rpc_paths",
    "default_environment",
    "default_target",
    "default_target_type",
    "csp_url",
    "csp_org_id",
    "auth_server_url",
    "ops_server_url",
    "ops_username",
    "ops_ssl_verify",
    "output_format",
    "color",
    "theme",
    "log_level",
}
OPTIONAL_FIELDS = {"username", "ca_bundle", "ssl_cert", "ssl_key", "csp_org_id", "auth_server_url"}
BOOL_FIELDS = {"ssl_verify", "ops_ssl_verify", "color"}
INT_FIELDS = {"timeout", "token_ttl"}
LIST_FIELDS = {"rpc_paths"}


def _root_value(ctx: click.Context, key: str, default: Any = None) -> Any:
    root = ctx.find_root()
    return (root.obj or {}).get(key, default)


def _config_path(ctx: click.Context, explicit: Optional[str] = None) -> Path:
    return discover_config_path(explicit or _root_value(ctx, "config_path"))


def _profile_name(ctx: click.Context, explicit: Optional[str] = None) -> Optional[str]:
    return explicit or _root_value(ctx, "profile") or os.getenv("SCC_PROFILE")


def _store(ctx: click.Context, explicit: Optional[str] = None) -> ProfileConfigStore:
    return ProfileConfigStore(_config_path(ctx, explicit))


def _fail(ctx: click.Context, message: str, hint: Optional[str] = None, code: int = 2) -> None:
    ui_error(message, hint=hint)
    ctx.exit(code)


def _credential_identity(profile: ConnectionProfile) -> str:
    if profile.username:
        return profile.username
    return "__api_token__" if profile.auth == "api-token" else "__csp__"


def _credential_status(name: str, profile: ConnectionProfile) -> tuple[str, str]:
    if profile.auth == "csp-token":
        env_name = "SCC_CSP_API_TOKEN"
    elif profile.auth == "api-token":
        env_name = "SCC_API_TOKEN"
    else:
        env_name = "SCC_PASSWORD"
    if os.getenv(env_name):
        return f"environment:{env_name}", "success"
    if keychain_get(profile.server_url, _credential_identity(profile)):
        return "OS keychain", "success"
    return "not stored", "warning"


def _load_runtime_settings(ctx: click.Context, name: Optional[str] = None) -> SaltConfigSettings:
    selected = _profile_name(ctx, name)
    settings = SaltConfigSettings.load_from_file(str(_config_path(ctx)), selected)
    if settings.auth == "csp-token":
        token = os.getenv("SCC_CSP_API_TOKEN") or keychain_get(settings.server_url, settings.username or "__csp__")
        if token:
            settings.csp_api_token = SecretStr(token)
            object.__setattr__(settings, "_password_source", "environment" if os.getenv("SCC_CSP_API_TOKEN") else "keychain")
    elif settings.auth == "api-token":
        token = os.getenv("SCC_API_TOKEN") or keychain_get(settings.server_url, settings.username or "__api_token__")
        if token:
            settings.api_token = SecretStr(token)
            object.__setattr__(settings, "_password_source", "environment" if os.getenv("SCC_API_TOKEN") else "keychain")
    else:
        password = os.getenv("SCC_PASSWORD") or keychain_get(settings.server_url, settings.username)
        if password:
            settings.password = SecretStr(password)
            object.__setattr__(settings, "_password_source", "environment" if os.getenv("SCC_PASSWORD") else "keychain")
    return settings


def _test_profile(ctx: click.Context, name: str, *, prompt: bool = True) -> tuple[str, str]:
    settings = _load_runtime_settings(ctx, name)
    if settings.auth == "csp-token" and not settings.csp_api_token:
        if prompt and sys.stdin.isatty():
            token = prompt_password(f"CSP API token for profile '{name}'")
            if token:
                settings.csp_api_token = SecretStr(token)
        if not settings.csp_api_token:
            raise ValueError("No CSP API token is available; run `scc profile login` or set SCC_CSP_API_TOKEN")
    if settings.auth == "api-token":
        if not settings.api_token and prompt and sys.stdin.isatty():
            token = prompt_password(f"API token for profile '{name}'")
            if token:
                settings.api_token = SecretStr(token)
        if not settings.api_token:
            raise ValueError("No API token is available; run `scc profile login` or set SCC_API_TOKEN")
        if not settings.auth_server_url:
            raise ValueError("Profile is configured for api-token auth but has no auth_server_url; run `scc configure --auth api-token --auth-server-url <url>`")
    if settings.auth == "password" and not settings.password:
        if prompt and sys.stdin.isatty():
            password = prompt_password(f"Password for {settings.username or name}@{settings.server_url}")
            if password:
                settings.password = SecretStr(password)
        if not settings.password:
            raise ValueError("No password is available; run `scc profile login` or set SCC_PASSWORD")
    with spinner(f"Testing profile '{name}' against {mask_url(settings.server_url)}…"):
        client = AriaConfigClient.from_settings(settings)
    api_version = client._api_version or "unknown"
    rpc_path = client.rpc_path
    client.close()
    return api_version, rpc_path


def _parse_value(field: str, value: str) -> Any:
    if field in BOOL_FIELDS:
        normalized = value.strip().lower()
        if normalized not in {"1", "0", "true", "false", "yes", "no", "on", "off"}:
            raise ValueError(f"{field} expects true or false")
        return normalized in {"1", "true", "yes", "on"}
    if field in INT_FIELDS:
        return int(value)
    if field in LIST_FIELDS:
        return [part.strip() for part in value.split(",") if part.strip()]
    return value


@click.command("configure")
@click.option("--name", "name", default=None, help="Profile name to create or update.")
@click.option("--server", "server_url", default=None, help="RaaS server URL.")
@click.option("--username", default=None, help="RaaS username.")
@click.option("--auth", type=click.Choice(["password", "csp-token", "api-token"]), default=None)
@click.option("--auth-server-url", default=None, help="Auth server URL for API-token login (auth=api-token), e.g. https://host:9002.")
@click.option("--config-name", default=None, help="RaaS authentication configuration name.")
@click.option("--verify/--no-verify", default=None, help="Verify the RaaS TLS certificate.")
@click.option("--ca-bundle", type=click.Path(path_type=Path), default=None)
@click.option("--environment", default=None, help="Default Salt environment.")
@click.option("--target", default=None, help="Default Salt target.")
@click.option("--target-type", default=None, help="Default target type, such as glob or list.")
@click.option("--timeout", type=click.IntRange(1, 3600), default=None)
@click.option("--make-default/--no-make-default", default=True)
@click.option("--workspace", is_flag=True, help="Write to ./.scc/config.yaml.")
@click.option("--non-interactive", is_flag=True, help="Do not prompt for missing values.")
@click.option("--test/--no-test", "test_connection", default=False, help="Test after saving.")
@click.pass_context
def configure_command(
    ctx: click.Context,
    name: Optional[str],
    server_url: Optional[str],
    username: Optional[str],
    auth: Optional[str],
    auth_server_url: Optional[str],
    config_name: Optional[str],
    verify: Optional[bool],
    ca_bundle: Optional[Path],
    environment: Optional[str],
    target: Optional[str],
    target_type: Optional[str],
    timeout: Optional[int],
    make_default: bool,
    workspace: bool,
    non_interactive: bool,
    test_connection: bool,
) -> None:
    """Create or update a named RaaS connection profile."""
    path = workspace_config_path() if workspace else _config_path(ctx)
    store = ProfileConfigStore(path)
    config = store.load()
    selected = name or _profile_name(ctx) or config.default_profile or "default"
    existing = config.profiles.get(selected)

    command_header(
        "configure",
        "Create or update a connection profile",
        description="Connection properties are saved in YAML; passwords and tokens are never written there.",
        icon="config",
        meta=[("Profile", selected), ("Config file", path), ("Existing profiles", len(config.profiles))],
    )
    if store.last_migration:
        ui_success(
            "Legacy configuration upgraded to the profile schema",
            hint=f"Backup: {store.backup_path}" if store.backup_path else store.last_migration,
        )

    interactive = not non_interactive and sys.stdin.isatty()
    if interactive:
        selected = click.prompt("Profile name", default=selected).strip()
        existing = config.profiles.get(selected)
        server_url = server_url or click.prompt(
            "RaaS server URL",
            default=existing.server_url if existing else "https://raas.example.com",
        )
        auth = auth or click.prompt(
            "Authentication",
            type=click.Choice(["password", "csp-token", "api-token"]),
            default=existing.auth if existing else "password",
        )
        if auth == "password":
            username = username or click.prompt(
                "Username",
                default=(existing.username if existing and existing.username else "root"),
            )
        if auth == "api-token":
            auth_server_url = auth_server_url or click.prompt(
                "Auth server URL",
                default=existing.auth_server_url if existing and existing.auth_server_url else "https://auth.example.com:9002",
            )
        config_name = config_name or click.prompt(
            "Authentication config name",
            default=existing.config_name if existing else "internal",
        )
        if verify is None:
            verify = click.confirm(
                "Verify TLS certificates?",
                default=existing.ssl_verify if existing else True,
            )
        environment = environment or click.prompt(
            "Default Salt environment",
            default=existing.default_environment if existing else "base",
        )
        target = target or click.prompt(
            "Default target",
            default=existing.default_target if existing else "*",
        )

    base = existing.model_dump() if existing else {}
    updates = {
        "server_url": server_url,
        "username": username,
        "auth": auth,
        "auth_server_url": auth_server_url,
        "config_name": config_name,
        "ssl_verify": verify,
        "ca_bundle": str(ca_bundle) if ca_bundle else None,
        "default_environment": environment,
        "default_target": target,
        "default_target_type": target_type,
        "timeout": timeout,
    }
    for key, value in updates.items():
        if value is not None:
            base[key] = value
    if not base.get("server_url"):
        _fail(ctx, "RaaS server URL is required.", "Pass --server or run interactively.")
    resolved_auth = base.get("auth", "password")
    if resolved_auth == "password" and not base.get("username"):
        _fail(ctx, "Username is required for password authentication.")
    if resolved_auth == "api-token" and not base.get("auth_server_url"):
        _fail(ctx, "An auth server URL is required for api-token authentication.", "Pass --auth-server-url or run interactively.")

    try:
        profile = ConnectionProfile.model_validate(base)
        store.upsert_profile(selected, profile, make_default=make_default)
    except Exception as exc:
        _fail(ctx, f"Could not save profile: {exc}")
        return

    credential, credential_style = _credential_status(selected, profile)
    result_summary(
        f"Profile '{selected}' saved",
        details=[
            ("Server", mask_url(profile.server_url)),
            ("Authentication", profile.auth),
            ("Username", profile.username or "token-based authentication"),
            ("TLS verification", profile.ssl_verify),
            ("Default environment", profile.default_environment),
            ("Default target", profile.default_target),
            ("Credential", credential),
            ("Config file", path),
        ],
    )
    if credential_style == "warning":
        ui_warn("No credential is stored for this profile.", hint=f"Run `scc profile login {selected}`.")

    if test_connection:
        try:
            api_version, rpc_path = _test_profile(ctx, selected)
            ui_success("Connection test passed", hint=f"API {api_version} via {rpc_path}")
        except Exception as exc:
            ui_warn(f"Profile was saved, but the connection test failed: {exc}")

    next_steps([
        f"Store credentials: `scc profile login {selected}`",
        f"Test it: `scc profile test {selected}`",
        f"Use once: `scc --profile {selected} status`",
        f"Make active: `scc profile use {selected}`",
    ])



@click.command("configure-git")
@click.option("--repo-url", "git_repo_url", default=None, help="Reusable Salt-state repository URL.")
@click.option("--branch", "git_branch", default=None, help="Approved state-repository branch, tag, or commit.")
@click.option("--resources-path", "git_resources_path", default=None, help="Path containing state resource folders.")
@click.option("--data-repo-url", "git_data_repo_url", default=None, help="Customer-specific values repository URL.")
@click.option("--data-branch", "git_data_branch", default=None, help="Approved values-repository branch, tag, or commit.")
@click.option("--data-resources-path", "git_data_resources_path", default=None, help="Path containing customer values.")
@click.option("--data-layout", default=None, help="Values path template, e.g. {environment}/{version}/{resource}/values.yaml.")
@click.option("--workspace", is_flag=True, help="Write ./.scc/repositories.yaml instead of the user-level source file.")
@click.option("--non-interactive", is_flag=True, help="Do not prompt for missing values.")
@click.pass_context
def configure_git_command(
    ctx: click.Context,
    git_repo_url: Optional[str],
    git_branch: Optional[str],
    git_resources_path: Optional[str],
    git_data_repo_url: Optional[str],
    git_data_branch: Optional[str],
    git_data_resources_path: Optional[str],
    data_layout: Optional[str],
    workspace: bool,
    non_interactive: bool,
) -> None:
    """Backward-compatible guided alias for the new `scc repo` source catalog.

    Repository metadata is stored in a separate ``repositories.yaml`` file,
    not in the RaaS connection-profile file.  Private credentials are handled
    by Git/SSH, the OS keychain (`scc repo login`), or environment variables.

    Examples:
      $ scc configure-git --repo-url https://github.com/org/vcf-salt --resources-path vcf-infra
      $ scc configure-git --data-repo-url git@github.example.com:org/customer-config.git \
            --data-layout '{environment}/{version}/{resource}/values.yaml'
      $ scc repo setup
    """
    from salt_config_cli.core.repositories import RepositorySource, RepositoryStore
    from salt_config_cli.services.git_repository import GitRepositoryError, GitRepositoryService

    store = RepositoryStore(
        connection_config=_config_path(ctx),
        workspace=workspace,
    )
    document = store.load()
    existing_states = document.sources.get(document.default_states_source or "")
    existing_data = document.sources.get(document.default_data_source or "")

    command_header(
        "configure-git",
        "Configure Git content sources",
        description=(
            "Compatibility command: new metadata is saved in repositories.yaml; "
            "tokens are never written to YAML. Prefer `scc repo setup` for new users."
        ),
        icon="config",
        meta=[("Repository source file", store.path), ("RaaS profile file", _config_path(ctx))],
    )

    interactive = not non_interactive and sys.stdin.isatty()
    if interactive:
        if click.confirm("Configure the reusable Salt-state repository?", default=True):
            git_repo_url = git_repo_url or click.prompt(
                "State repository URL",
                default=existing_states.url if existing_states else "",
                show_default=bool(existing_states),
            ).strip() or None
            git_branch = git_branch or click.prompt(
                "Approved branch, tag, or commit",
                default=existing_states.ref if existing_states else "main",
            )
            git_resources_path = git_resources_path or click.prompt(
                "Path containing resource folders",
                default=existing_states.root if existing_states else "vcf-infra",
            )
        if click.confirm("Configure a separate customer-specific values repository?", default=True):
            git_data_repo_url = git_data_repo_url or click.prompt(
                "Values repository URL",
                default=existing_data.url if existing_data else "",
                show_default=bool(existing_data),
            ).strip() or None
            git_data_branch = git_data_branch or click.prompt(
                "Approved branch, tag, or commit",
                default=existing_data.ref if existing_data else "main",
            )
            git_data_resources_path = git_data_resources_path or click.prompt(
                "Path containing environment/version values",
                default=existing_data.root if existing_data else ".",
            )
            data_layout = data_layout or click.prompt(
                "Values layout",
                default=existing_data.layout if existing_data and existing_data.layout else "{environment}/{version}/{resource}/values.yaml",
            )

    if not git_repo_url and not git_data_repo_url:
        ui_warn("Nothing to update.", hint="Run `scc repo setup` or pass --repo-url/--data-repo-url.")
        return

    service = GitRepositoryService()
    rows = []
    if git_repo_url:
        source = RepositorySource(
            kind="states",
            url=git_repo_url,
            ref=git_branch or (existing_states.ref if existing_states else "main"),
            root=git_resources_path or (existing_states.root if existing_states else "vcf-infra"),
            layout="{resource}",
            auth=existing_states.auth if existing_states else "auto",
            description="Reusable Salt states",
        )
        store.add("vcf-salt", source, make_default=True)
        try:
            with spinner(f"Testing vcf-salt@{source.ref}…"):
                synced = service.test("vcf-salt", source)
            rows.append(("State source", f"vcf-salt @ {synced.commit[:12]}"))
        except GitRepositoryError as exc:
            rows.append(("State source", f"saved; access test failed: {exc}"))
            ui_warn(str(exc))

    if git_data_repo_url:
        source = RepositorySource(
            kind="data",
            url=git_data_repo_url,
            ref=git_data_branch or (existing_data.ref if existing_data else "main"),
            root=git_data_resources_path or (existing_data.root if existing_data else "."),
            layout=data_layout or (existing_data.layout if existing_data else "{environment}/{version}/{resource}/values.yaml"),
            auth=existing_data.auth if existing_data else "auto",
            description="Approved customer/environment-specific values",
        )
        store.add("customer-values", source, make_default=True)
        try:
            with spinner(f"Testing customer-values@{source.ref}…"):
                synced = service.test("customer-values", source)
            rows.append(("Values source", f"customer-values @ {synced.commit[:12]}"))
        except GitRepositoryError as exc:
            rows.append(("Values source", f"saved; access test failed: {exc}"))
            ui_warn(str(exc))

    rows.append(("Source file", str(store.path)))
    rows.append(("Secrets written", "No"))
    result_summary("Git source configuration saved", details=rows)
    ui_hint("For private HTTPS repos use `scc repo login <source>`; SSH and Git credential helpers work unchanged.")
    next_steps(
        [
            "Review sources: `scc repo list`",
            "Test all sources: `scc repo test --all`",
            "Create a no-change plan: `scc deploy <resource> --environment <env> --version <version>`",
        ]
    )


@click.group("profile", cls=RichGroup, invoke_without_command=True)
@click.pass_context
def profile_group(ctx: click.Context) -> None:
    """Manage named RaaS connection profiles."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help(), nl=False)


@profile_group.command("list")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
@click.pass_context
def profile_list(ctx: click.Context, as_json: bool) -> None:
    """List saved profiles and the active default."""
    store = _store(ctx)
    try:
        config = store.load()
    except Exception as exc:
        _fail(ctx, f"Could not load profiles: {exc}")
        return
    rows_data = []
    for name, profile in sorted(config.profiles.items()):
        credential, _ = _credential_status(name, profile)
        rows_data.append({
            "name": name,
            "default": name == config.default_profile,
            "server": profile.server_url,
            "username": profile.username,
            "auth": profile.auth,
            "tls_verify": profile.ssl_verify,
            "environment": profile.default_environment,
            "target": profile.default_target,
            "target_type": profile.default_target_type,
            "credential": credential,
        })
    if as_json:
        click.echo(json.dumps({"default_profile": config.default_profile, "profiles": rows_data}, indent=2))
        return
    command_header(
        "profile list",
        "Saved RaaS connection profiles",
        description="Switch profiles without repeatedly entering server and authentication options.",
        icon="profile",
        meta=[("Config file", store.path), ("Default", config.default_profile), ("Profiles", len(rows_data))],
    )
    if store.last_migration:
        ui_success(
            "Legacy configuration upgraded to the profile schema",
            hint=f"Backup: {store.backup_path}" if store.backup_path else store.last_migration,
        )
    if not rows_data:
        ui_warn("No connection profiles are configured.")
        next_steps(["Create one interactively: `scc configure`", "Create while connecting: `scc connect --name lab`"])
        return
    rows = []
    for item in rows_data:
        status = badge("ACTIVE", "success") if item["default"] else badge("SAVED", "info")
        cred_style = "scc.success" if item["credential"] != "not stored" else "scc.warning"
        endpoint = Text()
        endpoint.append(mask_url(item["server"]), style="scc.value")
        endpoint.append("\nTLS verification: ", style="scc.hint")
        endpoint.append(
            "enabled" if item["tls_verify"] else "disabled",
            style="scc.success" if item["tls_verify"] else "scc.warning",
        )
        identity = Text()
        identity.append(item["username"] or "token-based authentication", style="scc.value")
        identity.append(f"\n{item['auth']}", style="scc.hint")
        defaults = Text()
        defaults.append(f"environment: {item['environment']}", style="scc.value")
        defaults.append(f"\ntarget: {item['target']} ({item['target_type']})", style="scc.hint")
        rows.append([
            item["name"], status, endpoint, identity, defaults, f"[{cred_style}]{item['credential']}[/]",
        ])
    data_table(
        "Connection profiles",
        [("Name", "scc.strong"), ("Status", "scc.value"), ("Endpoint", "scc.value"),
         ("Identity", "scc.value"), ("Defaults", "scc.value"), ("Credential", "scc.value")],
        rows,
        icon="profile",
    )
    next_steps(["Switch: `scc profile use <name>`", "Inspect: `scc profile show <name>`", "Create: `scc configure --name <name>`"])


@profile_group.command("show")
@click.argument("name", required=False)
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def profile_show(ctx: click.Context, name: Optional[str], as_json: bool) -> None:
    """Show one profile without exposing its credential."""
    store = _store(ctx)
    try:
        selected, profile = store.get_profile(_profile_name(ctx, name))
        config = store.load()
    except Exception as exc:
        _fail(ctx, str(exc), "Run `scc profile list` to see available profiles.")
        return
    credential, _ = _credential_status(selected, profile)
    data = profile.model_dump(exclude_none=True)
    data.update({"name": selected, "default": selected == config.default_profile, "credential": credential, "config_file": str(store.path)})
    if as_json:
        click.echo(json.dumps(data, indent=2))
        return
    command_header("profile show", f"Profile '{selected}'", icon="profile", meta=[("Default", selected == config.default_profile), ("Config file", store.path)])
    kv_table(
        f"{ICONS['profile']} Connection",
        [
            ("Name", selected),
            ("Server", mask_url(profile.server_url)),
            ("Username", profile.username or "token-based authentication"),
            ("Authentication", profile.auth),
            ("Authentication config", profile.config_name),
            ("TLS verification", profile.ssl_verify),
            ("CA bundle", profile.ca_bundle or "system trust store"),
            ("Timeout", f"{profile.timeout}s"),
            ("RPC paths", ", ".join(profile.rpc_paths)),
            ("Default environment", profile.default_environment),
            ("Default target", f"{profile.default_target} ({profile.default_target_type})"),
            ("Credential", credential),
        ],
    )
    next_steps([f"Test: `scc profile test {selected}`", f"Use now: `scc --profile {selected} status`", f"Edit: `scc configure --name {selected}`"])


@profile_group.command("use")
@click.argument("name")
@click.pass_context
def profile_use(ctx: click.Context, name: str) -> None:
    """Make a saved profile the default for future commands."""
    store = _store(ctx)
    try:
        store.set_default(name)
        _, profile = store.get_profile(name)
    except Exception as exc:
        _fail(ctx, str(exc))
        return
    result_summary(
        f"Profile '{name}' is now active",
        message="New SCC commands will use this profile unless --profile or SCC_PROFILE overrides it.",
        details=[("Server", mask_url(profile.server_url)), ("User", profile.username or "token-based authentication"), ("Config file", store.path)],
    )
    next_steps(["Verify: `scc status`", "Temporarily override: `scc --profile <other> status`"])


@profile_group.command("login")
@click.argument("name", required=False)
@click.option("--password-stdin", is_flag=True, help="Read the credential from stdin.")
@click.option("--password-file", type=click.Path(exists=True, dir_okay=False), default=None)
@click.pass_context
def profile_login(ctx: click.Context, name: Optional[str], password_stdin: bool, password_file: Optional[str]) -> None:
    """Store a profile password or token in the OS keychain."""
    if not keychain_available():
        _fail(ctx, "No OS keychain backend is available.", "Install/configure keyring, or use SCC_PASSWORD/SCC_CSP_API_TOKEN/SCC_API_TOKEN.")
    store = _store(ctx)
    try:
        selected, profile = store.get_profile(_profile_name(ctx, name))
    except Exception as exc:
        _fail(ctx, str(exc))
        return
    if password_file:
        secret = Path(password_file).read_text(encoding="utf-8").strip()
        source = password_file
    elif password_stdin:
        secret = sys.stdin.read().strip()
        source = "stdin"
    elif sys.stdin.isatty():
        label = "CSP API token" if profile.auth == "csp-token" else ("API token" if profile.auth == "api-token" else "Password")
        secret = prompt_password(f"{label} for profile '{selected}'")
        source = "interactive prompt"
    else:
        _fail(ctx, "No credential source is available.", "Use --password-stdin or --password-file.")
        return
    if not secret:
        _fail(ctx, "Credential is empty; nothing was stored.")
    if not keychain_set(profile.server_url, _credential_identity(profile), secret):
        _fail(ctx, "The OS keychain rejected the credential.")
    result_summary(
        f"Credential stored for '{selected}'",
        details=[("Storage", "OS keychain"), ("Source", source), ("Server", mask_url(profile.server_url)), ("Secret", mask(secret))],
    )


@profile_group.command("logout")
@click.argument("name", required=False)
@click.option("--yes", is_flag=True)
@click.pass_context
def profile_logout(ctx: click.Context, name: Optional[str], yes: bool) -> None:
    """Remove a profile credential and cached session."""
    store = _store(ctx)
    try:
        selected, profile = store.get_profile(_profile_name(ctx, name))
    except Exception as exc:
        _fail(ctx, str(exc))
        return
    if not yes and sys.stdin.isatty() and not click.confirm(f"Forget the credential for profile '{selected}'?", default=False):
        ui_warn("Cancelled; credential was not changed.")
        return
    removed = keychain_delete(profile.server_url, _credential_identity(profile))
    try:
        from salt_config_cli.api.token_cache import get_token_cache
        get_token_cache().delete(profile.server_url, profile.username)
    except Exception:
        pass
    if removed:
        ui_success(f"Removed the keychain credential for '{selected}'.")
    else:
        ui_warn(f"No keychain credential was found for '{selected}'.")


@profile_group.command("test")
@click.argument("name", required=False)
@click.option("--no-prompt", is_flag=True, help="Fail rather than prompting for a missing credential.")
@click.pass_context
def profile_test(ctx: click.Context, name: Optional[str], no_prompt: bool) -> None:
    """Authenticate and verify the RPC endpoint for a profile."""
    store = _store(ctx)
    try:
        selected, profile = store.get_profile(_profile_name(ctx, name))
    except Exception as exc:
        _fail(ctx, str(exc))
        return
    command_header("profile test", f"Testing profile '{selected}'", icon="plug", meta=[("Server", mask_url(profile.server_url)), ("Authentication", profile.auth)])
    try:
        api_version, rpc_path = _test_profile(ctx, selected, prompt=not no_prompt)
    except Exception as exc:
        result_summary("Connection test failed", status="danger", message=str(exc), details=[("Profile", selected), ("Server", mask_url(profile.server_url))])
        ctx.exit(1)
        return
    result_summary("Connection test passed", details=[("Profile", selected), ("Server", mask_url(profile.server_url)), ("API version", api_version), ("RPC path", rpc_path)])


@profile_group.command("edit")
@click.argument("name")
@click.option("--test/--no-test", "test_connection", default=False, help="Test after saving.")
@click.pass_context
def profile_edit(ctx: click.Context, name: str, test_connection: bool) -> None:
    """Interactively edit an existing profile."""
    ctx.invoke(
        configure_command,
        name=name,
        server_url=None,
        username=None,
        auth=None,
        auth_server_url=None,
        config_name=None,
        verify=None,
        ca_bundle=None,
        environment=None,
        target=None,
        target_type=None,
        timeout=None,
        make_default=False,
        workspace=False,
        non_interactive=False,
        test_connection=test_connection,
    )


@profile_group.command("clone")
@click.argument("source")
@click.argument("destination")
@click.option("--make-default", is_flag=True)
@click.pass_context
def profile_clone(ctx: click.Context, source: str, destination: str, make_default: bool) -> None:
    """Clone profile properties without copying credentials."""
    store = _store(ctx)
    try:
        store.clone_profile(source, destination, make_default=make_default)
    except Exception as exc:
        _fail(ctx, str(exc))
        return
    result_summary(f"Profile '{source}' cloned to '{destination}'", message="Credentials are intentionally not copied.", details=[("Config file", store.path)])
    next_steps([f"Store a credential: `scc profile login {destination}`", f"Edit values: `scc configure --name {destination}`"])


@profile_group.command("delete")
@click.argument("name")
@click.option("--yes", is_flag=True)
@click.option("--keep-credential", is_flag=True, help="Do not remove its keychain credential.")
@click.pass_context
def profile_delete(ctx: click.Context, name: str, yes: bool, keep_credential: bool) -> None:
    """Delete a profile and normally forget its keychain credential."""
    store = _store(ctx)
    try:
        _, profile = store.get_profile(name)
    except Exception as exc:
        _fail(ctx, str(exc))
        return
    if not yes and sys.stdin.isatty() and not click.confirm(f"Delete profile '{name}'?", default=False):
        ui_warn("Cancelled; profile was not deleted.")
        return
    try:
        store.delete_profile(name)
    except Exception as exc:
        _fail(ctx, str(exc))
        return
    if not keep_credential:
        keychain_delete(profile.server_url, _credential_identity(profile))
    result_summary(f"Profile '{name}' deleted", details=[("Credential removed", not keep_credential), ("Config file", store.path)])


@profile_group.command("export")
@click.argument("name", required=False)
@click.option("--output", "output_path", type=click.Path(path_type=Path), default=None)
@click.option("--all", "export_all", is_flag=True, help="Export every profile.")
@click.pass_context
def profile_export(ctx: click.Context, name: Optional[str], output_path: Optional[Path], export_all: bool) -> None:
    """Export non-secret profile configuration as YAML."""
    store = _store(ctx)
    try:
        config = store.load()
        if export_all:
            payload = config.model_dump(mode="json", exclude_none=True)
        else:
            selected, profile = store.get_profile(_profile_name(ctx, name))
            payload = {"version": config.version, "default_profile": selected, "profiles": {selected: profile.model_dump(mode="json", exclude_none=True)}}
    except Exception as exc:
        _fail(ctx, str(exc))
        return
    text = yaml.safe_dump(payload, sort_keys=False)
    if output_path:
        output_path.write_text(text, encoding="utf-8")
        ui_success("Profile configuration exported", hint=str(output_path))
    else:
        click.echo(text, nl=False)


@profile_group.command("import")
@click.argument("input_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--replace", is_flag=True, help="Replace profiles with matching names.")
@click.option("--make-default", default=None, metavar="NAME", help="Select the active profile after import.")
@click.pass_context
def profile_import(ctx: click.Context, input_path: Path, replace: bool, make_default: Optional[str]) -> None:
    """Import one or more non-secret profiles from YAML."""
    store = _store(ctx)
    try:
        imported = ProfileConfigFile.model_validate(yaml.safe_load(input_path.read_text(encoding="utf-8")) or {})
        current = store.load()
        conflicts = sorted(set(imported.profiles) & set(current.profiles))
        if conflicts and not replace:
            raise ValueError(f"Profiles already exist: {', '.join(conflicts)}; pass --replace to overwrite")
        current.profiles.update(imported.profiles)
        if make_default:
            if make_default not in current.profiles:
                raise ValueError(f"Imported/default profile '{make_default}' does not exist")
            current.default_profile = make_default
        elif not current.profiles or current.default_profile not in current.profiles:
            current.default_profile = imported.default_profile
        store.save(current)
    except Exception as exc:
        _fail(ctx, f"Could not import profiles: {exc}")
        return
    result_summary("Profiles imported", metrics=[(len(imported.profiles), "profiles", "success")], details=[("Source", input_path), ("Config file", store.path), ("Credentials", "not imported")])


@click.group("config", cls=RichGroup, invoke_without_command=True)
@click.pass_context
def config_group(ctx: click.Context) -> None:
    """Inspect and modify SCC configuration."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help(), nl=False)


@config_group.command("show")
@click.option("--profile", "name", default=None)
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def config_show(ctx: click.Context, name: Optional[str], as_json: bool) -> None:
    """Show the effective configuration after profile and environment overrides."""
    try:
        settings = SaltConfigSettings.load_from_file(str(_config_path(ctx)), _profile_name(ctx, name))
    except Exception as exc:
        _fail(ctx, str(exc))
        return
    data = settings.to_dict(exclude_secrets=True)
    overrides = [key for key in os.environ if key.startswith("SCC_") and key not in {"SCC_PASSWORD", "SCC_CSP_API_TOKEN", "SCC_API_TOKEN"}]
    data["environment_overrides"] = sorted(overrides)
    if as_json:
        click.echo(json.dumps(data, indent=2, default=str))
        return
    command_header("config show", "Effective SCC configuration", icon="config", meta=[("Profile", settings.profile_name), ("Format", settings.config_format), ("Config file", settings.config_path)])
    kv_table(
        f"{ICONS['config']} Effective values",
        [
            ("Profile", settings.profile_name),
            ("Server", mask_url(settings.server_url)),
            ("Username", settings.username or "token-based authentication"),
            ("Authentication", settings.auth),
            ("TLS verify", settings.ssl_verify),
            ("CA bundle", settings.ca_bundle or "system trust store"),
            ("Timeout", f"{settings.timeout}s"),
            ("Default environment", settings.default_environment),
            ("Default target", f"{settings.default_target} ({settings.default_target_type})"),
            ("Output", settings.output_format),
            ("Environment overrides", ", ".join(sorted(overrides)) or "none"),
        ],
    )


@config_group.command("path")
@click.pass_context
def config_path_command(ctx: click.Context) -> None:
    """Show config search order and the selected file."""
    selected = _config_path(ctx)
    command_header("config path", "Configuration file resolution", icon="folder", meta=[("Selected", selected)])
    rows = [
        ("Explicit/global --config-file", _root_value(ctx, "config_path") or "not set"),
        ("SCC_CONFIG", os.getenv("SCC_CONFIG") or "not set"),
        ("Workspace", workspace_config_path()),
        ("User", user_config_path()),
        ("Selected", selected),
        ("Exists", selected.exists()),
    ]
    kv_table(f"{ICONS['folder']} Search order", rows)


@config_group.command("validate")
@click.pass_context
def config_validate(ctx: click.Context) -> None:
    """Validate all profiles and report configuration health."""
    store = _store(ctx)
    command_header("config validate", "Validate SCC profile configuration", icon="shield", meta=[("Config file", store.path)])
    try:
        config = store.load()
    except Exception as exc:
        result_summary("Configuration is invalid", status="danger", message=str(exc), details=[("Config file", store.path)])
        ctx.exit(1)
        return
    warnings = []
    if not config.profiles:
        warnings.append("No profiles are configured")
    if config.profiles and config.default_profile not in config.profiles:
        warnings.append("default_profile does not reference an existing profile")
    missing_credentials = [name for name, profile in config.profiles.items() if _credential_status(name, profile)[0] == "not stored"]
    if missing_credentials:
        warnings.append(f"No keychain/environment credential for: {', '.join(missing_credentials)}")
    result_summary(
        "Configuration is valid" if not warnings else "Configuration is valid with warnings",
        status="success" if not warnings else "warning",
        metrics=[(len(config.profiles), "profiles", "primary"), (len(missing_credentials), "missing credentials", "warning")],
        details=[("Default profile", config.default_profile), ("Schema version", config.version), ("Config file", store.path)],
    )
    for warning in warnings:
        ui_warn(warning)


@config_group.command("env")
@click.pass_context
def config_env(ctx: click.Context) -> None:
    """Show supported environment overrides and whether each is active."""
    command_header("config env", "Environment-variable overrides", description="Environment values override the selected profile without changing YAML.", icon="environment")
    variables = [
        ("SCC_PROFILE", "Select a profile"), ("SCC_CONFIG", "Use another config file"),
        ("SCC_SERVER_URL", "Override server URL"), ("SCC_USERNAME", "Override username"),
        ("SCC_PASSWORD", "Password for this process"), ("SCC_CSP_API_TOKEN", "CSP token for this process"),
        ("SCC_API_TOKEN", "API token for this process (auth=api-token)"),
        ("SCC_AUTH_SERVER_URL", "Auth server URL for API-token login"),
        ("SCC_CONFIG_NAME", "Authentication config name"), ("SCC_SSL_VERIFY", "TLS verification"),
        ("SCC_CA_BUNDLE", "Custom CA bundle"), ("SCC_TIMEOUT", "Request timeout"),
        ("SCC_DEFAULT_ENVIRONMENT", "Default Salt environment"), ("SCC_DEFAULT_TARGET", "Default target"),
        ("SCC_DEFAULT_TARGET_TYPE", "Default target type"), ("SCC_OUTPUT_FORMAT", "Default output format"),
        ("SCC_THEME", "Override the terminal theme for this invocation"),
    ]
    rows = []
    for variable, purpose in variables:
        active = variable in os.environ
        value = os.getenv(variable, "")
        if variable in {"SCC_PASSWORD", "SCC_CSP_API_TOKEN", "SCC_API_TOKEN"} and value:
            value = mask(value)
        rows.append([variable, purpose, badge("ACTIVE", "success") if active else badge("NOT SET", "info"), value or "—"])
    data_table("Supported overrides", [("Variable", "scc.strong"), ("Purpose", "scc.value"), ("Status", "scc.value"), ("Value", "scc.hint")], rows, icon="environment")


@config_group.command("set")
@click.argument("field", type=click.Choice(sorted(PROFILE_FIELDS)))
@click.argument("value")
@click.option("--profile", "name", default=None)
@click.pass_context
def config_set(ctx: click.Context, field: str, value: str, name: Optional[str]) -> None:
    """Set one field on a profile."""
    store = _store(ctx)
    try:
        selected, profile = store.get_profile(_profile_name(ctx, name))
        data = profile.model_dump()
        data[field] = _parse_value(field, value)
        updated = ConnectionProfile.model_validate(data)
        store.upsert_profile(selected, updated, make_default=False)
    except Exception as exc:
        _fail(ctx, f"Could not update configuration: {exc}")
        return
    result_summary(f"Updated '{field}' on profile '{selected}'", details=[("Value", value), ("Config file", store.path)])


@config_group.command("unset")
@click.argument("field", type=click.Choice(sorted(OPTIONAL_FIELDS)))
@click.option("--profile", "name", default=None)
@click.pass_context
def config_unset(ctx: click.Context, field: str, name: Optional[str]) -> None:
    """Clear one optional field on a profile."""
    store = _store(ctx)
    try:
        selected, profile = store.get_profile(_profile_name(ctx, name))
        updated = profile.model_copy(update={field: None})
        store.upsert_profile(selected, updated, make_default=False)
    except Exception as exc:
        _fail(ctx, f"Could not update configuration: {exc}")
        return
    result_summary(f"Cleared '{field}' on profile '{selected}'", details=[("Config file", store.path)])

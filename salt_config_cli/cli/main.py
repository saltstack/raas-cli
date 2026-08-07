"""
Main CLI entry point for Salt Config CLI.

Provides drift detection and remediation commands for VMware Aria Automation Config.
"""

import contextlib
import json
import logging
import os
import sys
from pathlib import Path
from typing import Optional, Sequence

import click
from rich import box
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich.syntax import Syntax
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich import print as rprint

from salt_config_cli import __version__
from salt_config_cli.core.config import (
    ConnectionProfile,
    ProfileConfigStore,
    SaltConfigSettings,
    WorkspaceConfig,
    discover_config_path,
)
from salt_config_cli.core.state import StateManager
from salt_config_cli.core.plan import PlanExecutor, Plan
from salt_config_cli.core.models import ChangeAction
from salt_config_cli.ui import (
    ICONS,
    RichGroup,
    badge,
    banner,
    bullet_list,
    command_header,
    data_table,
    empty_state,
    error as ui_error,
    hint as ui_hint,
    info as ui_info,
    install_error_handler,
    keychain_available,
    keychain_delete,
    keychain_set,
    kv_table,
    mask,
    mask_url,
    next_steps,
    prompt_password,
    resolve_password,
    result_summary,
    spinner,
    success as ui_success,
    warn as ui_warn,
    warn_cli_password,
    set_runtime_context,
)
from salt_config_cli.ui.theme import (
    active_theme as current_rich_theme,
    active_theme_name,
    bootstrap_theme,
    configure_theme,
    console as themed_console,
    is_plain,
)
from salt_config_cli.cli.profile_cmds import configure_command, configure_git_command, profile_group, config_group
from salt_config_cli.cli.theme_cmds import theme_group


def _cli_password_provided_on_argv() -> bool:
    """Detect if the user passed --password / -p on the command line.

    We look at sys.argv BEFORE Click parses it, because Click doesn't
    differentiate between an env-var-supplied option and an argv-supplied one.
    """
    argv = sys.argv[1:]
    for i, tok in enumerate(argv):
        # Long form: --password=secret  or  --password secret
        if tok == "--password" or tok.startswith("--password="):
            return True
        # Short form: -p secret  or  -psecret  (not -psk because that's clearly not -p)
        if tok == "-p":
            return True
        # Stand-alone -p<value> e.g. -psecret — only treat as -p if no other short-opt context.
        # We can't be 100% sure here, so be conservative: only flag if it starts with -p and length > 2
        # and the next character isn't another known short flag.
        if len(tok) > 2 and tok.startswith("-p") and not tok.startswith("--"):
            # Avoid matching -pX where X is a known unrelated flag char; keep simple — flag it.
            return True
    return False

# Rich console for formatted output (shared themed console)
console = themed_console

_ACTIVE_PROFILE_OVERRIDE: Optional[str] = None
_GLOBAL_CONFIG_PATH: Optional[str] = None

# Shared options
def common_options(f):
    """Common options for all commands."""
    f = click.option(
        "--config", "-c",
        type=click.Path(exists=False),
        help="Path to configuration file"
    )(f)
    f = click.option(
        "--server", "-s",
        envvar="SCC_SERVER_URL",
        help="Aria Config server URL"
    )(f)
    f = click.option(
        "--username", "-u",
        envvar="SCC_USERNAME",
        help="Username for authentication"
    )(f)
    # NOTE: --password on the command line is INSECURE; prefer the alternatives below.
    # We keep it for backward compatibility but warn loudly when it is used.
    f = click.option(
        "--password", "-p",
        envvar="SCC_PASSWORD",
        help="[INSECURE on CLI] Password. Prefer --password-stdin/-file/-prompt or `scc login`.",
        hide_input=True,
    )(f)
    f = click.option(
        "--password-stdin",
        "password_stdin",
        is_flag=True,
        help="Read password from stdin (e.g. `echo $PW | scc ... --password-stdin`).",
    )(f)
    f = click.option(
        "--password-file",
        "password_file",
        type=click.Path(dir_okay=False),
        help="Read password from a 0600 file (recommended for scripts).",
    )(f)
    f = click.option(
        "--password-prompt/--no-password-prompt",
        "password_prompt",
        default=False,
        help="Force an interactive masked password prompt.",
    )(f)
    f = click.option(
        "--csp-token",
        envvar="SCC_CSP_API_TOKEN",
        help="CSP API token for authentication"
    )(f)
    f = click.option(
        "--log-level", "-l",
        type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
        default="INFO",
        help="Logging level"
    )(f)
    f = click.option(
        "--no-color",
        is_flag=True,
        help="Disable colored output"
    )(f)
    return f


def setup_logging(level: str, no_color: bool = False) -> None:
    """Configure logging with Rich handler."""
    # Suppress verbose HTTP client logging
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(
            console=console,
            rich_tracebacks=True,
            show_path=False,
            markup=not no_color
        )]
    )


def load_settings(
    config: Optional[str] = None,
    server: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    csp_token: Optional[str] = None,
    *,
    password_stdin: bool = False,
    password_file: Optional[str] = None,
    password_prompt: bool = False,
) -> SaltConfigSettings:
    """Load the selected profile and resolve its runtime credential securely.

    Precedence: CLI -> environment -> OS keychain -> profile configuration.
    Secrets are never read from or written to profile YAML.
    """
    from pydantic import SecretStr

    effective_config = config or _GLOBAL_CONFIG_PATH
    settings = SaltConfigSettings.load_from_file(effective_config, _ACTIVE_PROFILE_OVERRIDE)

    if server:
        settings.server_url = server
    if username:
        settings.username = username

    if settings.auth == "csp-token" or csp_token:
        settings.auth = "csp-token"
        resolved_token = csp_token or os.getenv("SCC_CSP_API_TOKEN")
        source = "cli" if csp_token else ("environment" if resolved_token else "none")
        if not resolved_token:
            from salt_config_cli.ui import keychain_get
            resolved_token = keychain_get(settings.server_url, settings.username or "__csp__")
            if resolved_token:
                source = "keychain"
        if password_file and not resolved_token:
            resolved_token = Path(password_file).expanduser().read_text(encoding="utf-8").strip()
            source = f"file:{password_file}"
        elif password_stdin and not resolved_token:
            resolved_token = sys.stdin.readline().rstrip("\r\n")
            source = "stdin"
        elif password_prompt and not resolved_token:
            resolved_token = prompt_password("CSP API token")
            source = "prompt"
        if resolved_token:
            settings.csp_api_token = SecretStr(resolved_token)
        object.__setattr__(settings, "_password_source", source)
        return settings

    if password and _cli_password_provided_on_argv():
        warn_cli_password("--password")

    existing_pw = settings.password.get_secret_value() if settings.password is not None else None
    resolved, source = resolve_password(
        cli_password=password,
        password_stdin=password_stdin,
        password_file=password_file,
        password_prompt=password_prompt,
        server=settings.server_url,
        username=settings.username,
        existing=existing_pw,
    )
    if resolved:
        settings.password = SecretStr(resolved)
    object.__setattr__(settings, "_password_source", source if resolved else "none")
    return settings


def _user_config_path() -> Path:
    """Return the path to the user-level config file (~/.scc/config.yaml)."""
    return Path.home() / ".scc" / "config.yaml"


def _workspace_config_path() -> Path:
    """Return the path to the workspace-level config file (./.scc/config.yaml)."""
    return Path.cwd() / ".scc" / "config.yaml"


def _write_connection_config(
    target_path: Path,
    *,
    server_url: str,
    username: str,
    ssl_verify: Optional[bool] = None,
) -> None:
    """Persist server/username (and optionally ssl_verify) to a YAML config file.

    The file is created atomically: existing values are preserved if not
    explicitly overridden, and the file is written with 0o600 perms.
    """
    target_path.parent.mkdir(parents=True, exist_ok=True)

    existing: dict = {}
    if target_path.exists():
        try:
            import yaml as _yaml
            with target_path.open("r", encoding="utf-8") as f:
                existing = _yaml.safe_load(f) or {}
        except Exception:
            existing = {}

    existing["server_url"] = server_url
    existing["username"] = username
    if ssl_verify is not None:
        existing["ssl_verify"] = bool(ssl_verify)

    # Make sure we never accidentally persist a password
    existing.pop("password", None)

    import yaml as _yaml
    tmp = target_path.with_suffix(target_path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        _yaml.safe_dump(existing, f, sort_keys=False, default_flow_style=False)
    try:
        os.chmod(tmp, 0o600)
    except Exception:
        pass
    tmp.replace(target_path)


def connect_client(settings, *, label: Optional[str] = None):
    """Connect to RaaS with friendly error reporting and interactive re-auth.

    Resolution order is deliberately silent-first:

      1. If we have a cached JWT for this (server, username), try it. No
         password is read or prompted in this case.
      2. Otherwise, if no password is available but stdin is a TTY, prompt
         the user once.
      3. On auth failure with a TTY, offer one re-prompt before giving up.
    """
    from salt_config_cli.api.client import AriaConfigClient
    from salt_config_cli.api.token_cache import get_token_cache
    from salt_config_cli.api.exceptions import (
        AuthenticationError as _AuthError,
        ConnectionError as _ConnError,
    )

    if not settings.server_url or settings.server_url == "https://localhost":
        ui_error(
            "No server configured.",
            hint="Run `scc init` or pass `--server https://<raas-host>`.",
        )
        sys.exit(2)

    if not settings.username:
        ui_error(
            "No username configured.",
            hint="Pass `--username` or set `username:` in `.scc/config.yaml`.",
        )
        sys.exit(2)

    pw_source = getattr(settings, "_password_source", "none")
    has_password = bool(settings.password)
    has_csp = bool(getattr(settings, "csp_api_token", None))

    # Check whether a usable cached token exists. If so, we can authenticate
    # silently without ever asking for a password.
    cached = get_token_cache().get(settings.server_url, settings.username)
    has_usable_cache = bool(cached and (cached.get("jwt") or cached.get("csp_access_token")))

    # Only prompt for a password if we genuinely have no other way to authenticate.
    needs_prompt = (
        not has_password
        and not has_csp
        and not has_usable_cache
        and sys.stdin.isatty()
    )
    if needs_prompt:
        from pydantic import SecretStr
        pw = prompt_password(f"Password for {settings.username}@{settings.server_url}")
        if not pw:
            ui_error("Password is required.")
            sys.exit(2)
        settings.password = SecretStr(pw)
        object.__setattr__(settings, "_password_source", "prompt")
        pw_source = "prompt"
        has_password = True

    try:
        client = AriaConfigClient.from_settings(settings)
        return client
    except _AuthError as e:
        # The cached token may be stale and we also had no password to refresh
        # it. In that case, prompt the user once and retry from scratch.
        if has_usable_cache and not has_password and sys.stdin.isatty():
            ui_warn(
                "Cached session is no longer valid - please re-enter your password.",
                hint=f"Account: {settings.username}@{settings.server_url}",
            )
            try:
                from pydantic import SecretStr
                pw = prompt_password(f"Password for {settings.username}@{settings.server_url}")
                if pw:
                    settings.password = SecretStr(pw)
                    object.__setattr__(settings, "_password_source", "prompt")
                    # Clear stale token so we do a fresh login.
                    get_token_cache().delete(settings.server_url, settings.username)
                    return AriaConfigClient.from_settings(settings)
            except _AuthError as retry_err:
                ui_error(f"Authentication still failing: {retry_err.message}")
            except _ConnError as retry_err:
                ui_error(f"Connection error during retry: {retry_err}")

        ui_error(
            f"Authentication failed: {e.message}",
            hint=f"Account: {settings.username}@{settings.server_url}",
        )
        # Offer one re-prompt for the password-supplied case as well.
        if sys.stdin.isatty() and pw_source != "prompt" and not has_usable_cache:
            try:
                from pydantic import SecretStr
                ui_info("Re-enter your password and we'll try again.")
                pw = prompt_password(f"Password for {settings.username}@{settings.server_url}")
                if pw:
                    settings.password = SecretStr(pw)
                    object.__setattr__(settings, "_password_source", "prompt")
                    return AriaConfigClient.from_settings(settings)
            except _AuthError as retry_err:
                ui_error(f"Authentication still failing: {retry_err.message}")
            except _ConnError as retry_err:
                ui_error(f"Connection error during retry: {retry_err}")

        next_steps(
            [
                "Verify the username/password are correct.",
                "Store credentials securely: `scc login`.",
                "Clear stale tokens: `scc clear-cache`.",
                "Run end-to-end diagnostics: `scc doctor`.",
            ]
        )
        sys.exit(1)
    except _ConnError as e:
        ui_error(f"Cannot reach server: {e}")
        err_text = str(e)
        steps = [f"Confirm `{settings.server_url}` is reachable from this host."]
        if "CERTIFICATE_VERIFY_FAILED" in err_text or "self-signed" in err_text.lower():
            steps.append(
                f"This looks like a self-signed certificate. Disable TLS verification for this "
                f"profile: `scc config set ssl_verify false --profile {settings.profile_name}`"
            )
        elif "Connection reset" in err_text or "Errno 54" in err_text:
            steps.append(
                "This looks like a transient network interruption (VPN dropped, a firewall/proxy "
                "closed the connection, or the RaaS server briefly restarted) rather than a "
                "configuration problem - simply retry the command."
            )
        elif not settings.ssl_verify:
            pass  # TLS is already disabled; the generic ssl_verify hint would not help here.
        else:
            steps.append("If using self-signed certs, disable verification: "
                         f"`scc config set ssl_verify false --profile {settings.profile_name}`")
        steps.append("Run `scc doctor` for connectivity diagnostics.")
        next_steps(steps)
        sys.exit(1)
    except Exception as e:
        ui_error(f"Connection failed: {e}")
        next_steps(
            [
                "Re-run with `--log-level DEBUG` for the full traceback.",
                "Try `scc doctor` to pinpoint the failure.",
            ]
        )
        sys.exit(1)


@click.group(cls=RichGroup, invoke_without_command=True)
@click.version_option(version=__version__, prog_name="scc", message="%(prog)s %(version)s")
@click.option("--profile", "profile_name", envvar="SCC_PROFILE", default=None, help="Named connection profile for this command.")
@click.option("--config-file", "global_config_path", envvar="SCC_CONFIG", type=click.Path(exists=False), default=None, help="Profile configuration file to use.")
@click.option("--theme", "theme_name", type=click.Choice(["ocean", "enterprise", "graphite", "forest", "amber", "high-contrast", "plain", "none", "off"], case_sensitive=False), default=None, help="Terminal theme for this invocation; use plain, none or off for normal terminal output.")
@click.pass_context
def cli(ctx, profile_name, global_config_path, theme_name):
    """Drift detection & remediation for VMware Aria Automation Config.

    Define expected Salt configurations in YAML, detect drift from actual server
    state, and remediate to bring systems back into compliance.
    """
    global _ACTIVE_PROFILE_OVERRIDE, _GLOBAL_CONFIG_PATH
    _ACTIVE_PROFILE_OVERRIDE = profile_name
    _GLOBAL_CONFIG_PATH = global_config_path
    selected_theme = bootstrap_theme(cli_theme=theme_name, config_path=global_config_path, profile_name=profile_name)
    ctx.ensure_object(dict)
    ctx.obj["profile"] = profile_name
    ctx.obj["profile_explicit"] = profile_name
    ctx.obj["config_path"] = global_config_path
    ctx.obj["theme"] = selected_theme
    ctx.obj["theme_explicit"] = theme_name
    try:
        selected_settings = SaltConfigSettings.load_from_file(global_config_path, profile_name)
        if not theme_name and not os.getenv("SCC_THEME"):
            selected_theme = configure_theme(selected_settings.theme)
            ctx.obj["theme"] = selected_theme
        ctx.obj["profile"] = selected_settings.profile_name
        set_runtime_context(profile=selected_settings.profile_name, config_path=str(selected_settings.config_path or ""))
    except Exception:
        # Profile-management commands must remain available even when the
        # selected profile is missing or the config is being created.
        set_runtime_context(profile=profile_name or os.getenv("SCC_PROFILE") or "default", config_path=str(discover_config_path(global_config_path)))
    if ctx.invoked_subcommand is None:
        _render_home_screen(ctx)
        ctx.exit(0)


def _render_home_screen(ctx: click.Context) -> None:
    """Customer-friendly landing page shown when `scc` is run with no args.

    Goal: a user with zero prior knowledge can find their next action in
    under 10 seconds.
    """
    from rich.box import ROUNDED
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from salt_config_cli.ui import splash

    # Splash with environment context (workspace + server + user when available).
    scc_dir = Path.cwd() / ".scc"
    workspace_ready = scc_dir.exists()
    try:
        _settings = SaltConfigSettings.load_from_file(_GLOBAL_CONFIG_PATH, _ACTIVE_PROFILE_OVERRIDE)
        srv = _settings.server_url if _settings.server_url and _settings.server_url != "https://localhost" else None
        user = _settings.username or None
        # Mask any inline creds in the URL.
        from salt_config_cli.ui import mask_url
        srv = mask_url(srv) if srv else None
    except Exception:
        srv, user = None, None
        _settings = None

    splash(
        version=__version__,
        server=srv,
        username=user,
        workspace_ready=workspace_ready,
        profile=getattr(_settings, "profile_name", _ACTIVE_PROFILE_OVERRIDE or "default"),
    )

    if is_plain():
        click.echo("\nQuick start:")
        click.echo("  scc profile list  - choose a RaaS connection")
        click.echo("  scc repo setup    - configure shared states and private values")
        click.echo("  scc deploy <name> - create a no-change Git-to-RaaS plan")
        click.echo("  scc status        - check connection and configuration")
        click.echo("  scc list          - browse minions, jobs and files")
        click.echo("\nTheme controls: scc theme list | scc theme enable | scc theme use <name>")
        return

    # Top 3 actions - the ones a customer will need first
    quick = Table(show_header=False, box=None, padding=(0, 2), expand=False)
    quick.add_column("kbd", style="scc.kbd", no_wrap=True)
    quick.add_column("what", style="scc.value", no_wrap=False)
    quick.add_column("when", style="scc.hint", overflow="fold")

    quick.add_row("scc profile list", "Choose a RaaS connection", "Switch between lab, staging, and production")
    quick.add_row("scc repo setup", "Configure Git sources", "Shared states plus private environment/version values")
    quick.add_row("scc deploy <resource>", "Create a safe deployment plan", "Sync, validate, and display exact Git commits and files")
    quick.add_row("scc status", "Check your connection", "Verify config and server reachability")
    quick.add_row("scc list", "See what's on the server", "Minions, jobs, state files, target groups")

    console.print(
        Panel(
            quick,
            title=f"[scc.title]{ICONS['rocket']} Quick start[/scc.title]",
            border_style="scc.accent",
            box=ROUNDED,
            padding=(0, 1),
        )
    )

    # Discovery hint card
    discovery = Table(show_header=False, box=None, padding=(0, 2), expand=False)
    discovery.add_column("kbd", style="scc.cmd", no_wrap=True)
    discovery.add_column("desc", style="scc.value", overflow="fold")
    discovery.add_row("scc commands", "List every command with a one-line summary")
    discovery.add_row("scc search <word>", "Find commands by keyword (e.g. `scc search pillar`)")
    discovery.add_row("scc examples", "Copy-pasteable recipes for common tasks")
    discovery.add_row("scc tutorial", "5-minute interactive walkthrough")
    discovery.add_row("scc tutorial dns", "Complete DNS journey: repositories, plan, dry-run, and apply")
    discovery.add_row("scc tutorial kb-search", "Find a KB mapping and execute the reviewed DNS state")
    discovery.add_row("scc help <cmd>", "Friendly help for a specific command")
    discovery.add_row("scc --help", "Full command reference, grouped by category")

    console.print(
        Panel(
            discovery,
            title=f"[scc.title]{ICONS['magnify']} Discover commands[/scc.title]",
            border_style="scc.primary",
            box=ROUNDED,
            padding=(0, 1),
        )
    )

    # First-time setup hint
    scc_dir = Path.cwd() / ".scc"
    if not scc_dir.exists():
        next_steps(
            [
                "Create a connection profile: `scc configure --name lab`",
                "Store its credential: `scc profile login lab`",
                "Verify it: `scc profile test lab`",
                "Configure Git content sources: `scc repo setup`",
                "Follow the DNS customer journey: `scc tutorial dns`",
            ],
            title="First time here?",
        )
    else:
        next_steps(
            [
                "Review active connection: `scc profile list`",
                "Verify it: `scc status`",
                "Review Git sources: `scc repo list`",
                "Plan a resource without changing RaaS: `scc deploy <resource>`",
                "Stuck? Try `scc doctor` for diagnostics.",
            ],
        )


@cli.command()
@click.option(
    "--backend", "-b",
    type=click.Choice(["local", "remote"]),
    default="local",
    help="State backend type"
)
@click.option(
    "--reconfigure",
    is_flag=True,
    help="Reconfigure backend, ignoring saved settings"
)
@common_options
@click.pass_context
def init(ctx, backend, reconfigure, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """
    Initialize a new Salt Config CLI workspace.
    
    Creates the .scc directory and initializes state storage.
    
    \b
    Examples:
      $ scc init
      $ scc init --backend local
      $ scc init --reconfigure
    """
    setup_logging(log_level, no_color)

    banner(version=__version__, subtitle=f"{ICONS['rocket']} Initializing workspace")

    workspace_dir = Path.cwd()
    scc_dir = workspace_dir / ".scc"

    if scc_dir.exists() and not reconfigure:
        ui_warn(
            "Workspace already initialized.",
            hint="Use --reconfigure to reinitialize.",
        )
        return

    scc_dir.mkdir(parents=True, exist_ok=True)

    workspace_config = WorkspaceConfig(name=workspace_dir.name, backend=backend)
    workspace_config.save(str(workspace_dir))

    state_manager = StateManager(
        state_path=str(scc_dir / "salt.state"),
        backend=backend,
    )
    state_manager.save()

    ui_success("Created .scc directory", hint=str(scc_dir))
    ui_success("Initialized workspace configuration", hint=f"backend={backend}")
    ui_success("Initialized state file", hint=str(scc_dir / "salt.state"))

    next_steps(
        [
            "Edit `.scc/config.yaml` with your RaaS server URL and credentials",
            "Verify connection: `scc status`",
            "Discover server resources: `scc list`",
            "Detect drift: `scc drift`",
            "Enable Tab completion: `scc completion install`",
        ]
    )


@cli.command()
@click.option(
    "--target", "-t",
    help="Target specific resource address"
)
@click.option(
    "--out", "-o",
    type=click.Path(),
    help="Save plan to file"
)
@click.option(
    "--destroy",
    is_flag=True,
    help="Plan to destroy all resources"
)
@click.option(
    "--refresh/--no-refresh",
    default=True,
    help="Refresh state before planning"
)
@common_options
@click.pass_context
def plan(ctx, target, out, destroy, refresh, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """
    Generate and show an execution plan.
    
    Shows what changes will be made without actually applying them.
    
    \b
    Examples:
      $ scc plan
      $ scc plan --target target_group.web-servers
      $ scc plan --destroy
      $ scc plan --out plan.json
    """
    setup_logging(log_level, no_color)
    
    settings = load_settings(config, server, username, password, csp_token, password_stdin=password_stdin, password_file=password_file, password_prompt=password_prompt)
    
    console.print("\n[bold blue]Generating execution plan...[/bold blue]\n")
    
    # Initialize state manager
    state_manager = StateManager(
        state_path=settings.state_file,
        backend=settings.state_backend
    )
    
    # Create plan executor
    executor = PlanExecutor(
        state_manager=state_manager,
        api_client=None,  # Will be initialized if refresh is needed
        config_dir=settings.working_dir
    )
    
    # Generate plan
    execution_plan = executor.plan(target=target, destroy=destroy)
    
    # Display plan
    _display_plan(execution_plan, destroy)
    
    # Save plan to file if requested
    if out:
        with open(out, "w") as f:
            json.dump(execution_plan.model_dump(mode="json"), f, indent=2, default=str)
        console.print(f"\n[green]✓[/green] Plan saved to {out}")


def _display_plan(plan: Plan, is_destroy: bool = False) -> None:
    """Render an execution plan in Terraform-style with rich attribute diffs."""
    from rich.panel import Panel
    from rich.box import ROUNDED
    from rich.text import Text
    from rich.console import Group
    from salt_config_cli.ui.theme import ICONS

    if not plan.has_changes:
        console.print()
        console.print(
            Text.assemble(
                Text(f"{ICONS['success']}  ", style="scc.success bold"),
                Text("No changes. ", style="scc.success bold"),
                Text("Infrastructure matches the expected configuration.", style="scc.value"),
            )
        )
        console.print()
        return

    # Plan summary header (badge row) ----------------------------------------
    from salt_config_cli.ui import summary_pills, section as ui_section
    ui_section("Execution plan", icon="rocket")

    pills = []
    if plan.to_create:
        pills.append((plan.to_create, "to create", "success"))
    if plan.to_update:
        pills.append((plan.to_update, "to update", "warning"))
    if plan.to_delete:
        pills.append((plan.to_delete, "to destroy", "danger"))
    if pills:
        summary_pills(pills)
    console.print()

    # Per-change panels ------------------------------------------------------
    action_style = {
        ChangeAction.CREATE: ("scc.success",  "+", "created"),
        ChangeAction.UPDATE: ("scc.warning",  "~", "updated"),
        ChangeAction.DELETE: ("scc.danger",   "-", "destroyed"),
        ChangeAction.NO_OP:  ("scc.muted",    " ", "unchanged"),
        ChangeAction.READ:   ("scc.info",     "?", "read"),
    }
    for change in plan.changes:
        if change.action == ChangeAction.NO_OP:
            continue
        style, sym, action_label = action_style.get(change.action, ("scc.value", "?", "?"))

        header = Text()
        header.append(f"{sym}  ", style=style + " bold")
        header.append(change.resource_address, style="scc.strong")
        header.append(f"   will be {action_label}", style="scc.muted")

        body_parts = [header]

        if change.action == ChangeAction.UPDATE and change.attribute_changes:
            body_parts.append(Text(""))
            for attr, (old_val, new_val) in change.attribute_changes.items():
                body_parts.append(_render_attr_diff(attr, old_val, new_val))
        elif change.action == ChangeAction.CREATE:
            attrs = getattr(change, "after", None) or getattr(change, "new_attributes", None) or {}
            if isinstance(attrs, dict) and attrs:
                body_parts.append(Text(""))
                for k, v in list(attrs.items())[:8]:
                    line = Text()
                    line.append(f"  + ", style="scc.success bold")
                    line.append(f"{k} = ", style="scc.label")
                    line.append(_short_repr(v), style="scc.value")
                    body_parts.append(line)
                if len(attrs) > 8:
                    body_parts.append(Text(f"  + … {len(attrs) - 8} more attributes", style="scc.muted"))
        elif change.action == ChangeAction.DELETE:
            line = Text()
            line.append("  ⚠  ", style="scc.danger")
            line.append("This resource will be destroyed.", style="scc.danger bold")
            body_parts.append(Text(""))
            body_parts.append(line)

        console.print(
            Panel(
                Group(*body_parts),
                border_style=style,
                box=ROUNDED,
                padding=(0, 2),
            )
        )

    # Footer summary ---------------------------------------------------------
    footer = Text()
    footer.append("Plan:  ", style="scc.label")
    if plan.to_create:
        footer.append(f"{plan.to_create} to create  ", style="scc.success")
    if plan.to_update:
        footer.append(f"{plan.to_update} to update  ", style="scc.warning")
    if plan.to_delete:
        footer.append(f"{plan.to_delete} to destroy  ", style="scc.danger")
    console.print()
    console.print(footer)


def _render_attr_diff(attr: str, old_val, new_val) -> "Text":
    """Render a single attribute change in a 'before → after' style.

    For multi-line strings (dicts/lists serialized), render a real line-based diff.
    Otherwise render an inline `old  →  new`.
    """
    from rich.text import Text

    line = Text()
    line.append("  ~ ", style="scc.warning bold")
    line.append(f"{attr}: ", style="scc.label")

    old_repr = _short_repr(old_val, max_len=80)
    new_repr = _short_repr(new_val, max_len=80)

    # If either side is multi-line, do a real line-based diff.
    needs_vertical = ("\n" in str(old_val)) or ("\n" in str(new_val)) or (len(str(old_val)) + len(str(new_val)) > 70)
    if needs_vertical:
        line.append("\n")
        for ln in (str(old_val).splitlines() or [""]):
            sub = Text("    - ", style="scc.danger bold")
            sub.append(ln, style="scc.danger_dim")
            line.append_text(sub)
            line.append("\n")
        for ln in (str(new_val).splitlines() or [""]):
            sub = Text("    + ", style="scc.success bold")
            sub.append(ln, style="scc.success_dim")
            line.append_text(sub)
            line.append("\n")
    else:
        line.append(_plain(old_repr), style="scc.danger_dim")
        line.append(f"  {ICONS['arrow']}  ", style="scc.muted")
        line.append(_plain(new_repr), style="scc.success")
    return line


def _plain(s: str) -> str:
    """Strip [scc.*]…[/scc.*] markup tags from a rich-formatted string."""
    import re
    return re.sub(r"\[/?scc\.[^\]]+\]", "", s)


@cli.command()
@click.option(
    "--target", "-t",
    help="Target specific resource address"
)
@click.option(
    "--auto-approve",
    is_flag=True,
    help="Skip interactive approval"
)
@click.option(
    "--plan-file",
    type=click.Path(exists=True),
    help="Apply a saved plan file"
)
@click.option(
    "--refresh/--no-refresh",
    default=True,
    help="Refresh state before applying"
)
@common_options
@click.pass_context
def apply(ctx, target, auto_approve, plan_file, refresh, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """
    Apply configuration changes.
    
    Creates, updates, or deletes resources to match the configuration.
    
    \b
    Examples:
      $ scc apply
      $ scc apply --auto-approve
      $ scc apply --target target_group.web-servers
      $ scc apply --plan-file plan.json
    """
    setup_logging(log_level, no_color)
    
    settings = load_settings(config, server, username, password, csp_token, password_stdin=password_stdin, password_file=password_file, password_prompt=password_prompt)
    
    console.print("\n[bold blue]Applying configuration...[/bold blue]\n")
    
    # Initialize state manager
    state_manager = StateManager(
        state_path=settings.state_file,
        backend=settings.state_backend
    )
    
    # Acquire lock
    if not state_manager.lock():
        console.print("[red]Error:[/red] Could not acquire state lock.")
        console.print("Another operation may be in progress.")
        sys.exit(1)
    
    from salt_config_cli.ui import RowTracker, confirm_destructive

    try:
        # ---- Load or generate plan ----
        if plan_file:
            with open(plan_file, "r") as f:
                plan_data = json.load(f)
            execution_plan = Plan(**plan_data)
        else:
            # Connect via the centralized helper (handles auth + nice errors).
            api_client = None
            if settings.server_url and settings.server_url != "https://localhost":
                try:
                    api_client = connect_client(settings, label="apply")
                except SystemExit:
                    # connect_client already printed the error and chose an exit code;
                    # respect it.
                    raise
                except Exception as e:
                    ui_warn(f"Could not connect to server: {e}",
                            hint="Running offline; apply will use cached state only.")
            executor = PlanExecutor(
                state_manager=state_manager,
                api_client=api_client,
                config_dir=settings.working_dir,
            )
            execution_plan = executor.plan(target=target)

        # ---- Render plan ----
        _display_plan(execution_plan)
        if not execution_plan.has_changes:
            return

        # ---- Confirmation ----
        destroys = getattr(execution_plan, "to_delete", 0) or 0
        if destroys > 0:
            # Destructive: require typed confirmation.
            if not confirm_destructive(
                action=f"apply (with {destroys} destroy)",
                targets_summary=(
                    f"{getattr(execution_plan, 'to_create', 0)} create, "
                    f"{getattr(execution_plan, 'to_update', 0)} update, "
                    f"{destroys} destroy"
                ),
                typed_phrase="apply",
                auto_approve=auto_approve,
            ):
                ui_warn("Apply cancelled.")
                return
        elif not auto_approve:
            if not click.confirm("Apply these changes?"):
                ui_warn("Apply cancelled.")
                return

        # ---- Apply with live row tracker ----
        console.print()
        addresses = [c.resource_address for c in execution_plan.changes if c.action != ChangeAction.NO_OP]
        use_live = sys.stdout.isatty() and not _truthy_env("SCC_NO_LIVE")

        results = {"success": [], "failed": []}
        if use_live:
            with RowTracker(
                columns=("Resource", "State", "Detail"),
                title="Applying changes",
                border_style="scc.accent",
            ) as tracker:
                for addr in addresses:
                    tracker.add(addr, status="pending", detail="queued")

                # We don't have a per-resource apply API at this level, so we
                # apply the whole plan and then update the tracker once it
                # completes. Until a streaming API exists, mark all as
                # active first, then resolve per-resource from the result.
                for addr in addresses:
                    tracker.set(addr, status="active", detail="applying…")

                executor = PlanExecutor(
                    state_manager=state_manager,
                    api_client=api_client if not plan_file else None,
                    config_dir=settings.working_dir,
                )
                results = executor.apply(execution_plan, auto_approve=True)

                success_set = set(results.get("success", []))
                failures = {f.get("address"): f.get("error", "") for f in results.get("failed", [])}
                for addr in addresses:
                    if addr in success_set:
                        tracker.set(addr, status="ok", detail="applied")
                    elif addr in failures:
                        tracker.set(addr, status="fail", detail=failures[addr] or "failed")
                    else:
                        tracker.set(addr, status="skipped", detail="not applied")
                tracker.footer(
                    f"{len(results.get('success', []))} succeeded · "
                    f"{len(results.get('failed', []))} failed"
                )
        else:
            executor = PlanExecutor(
                state_manager=state_manager,
                api_client=api_client if not plan_file else None,
                config_dir=settings.working_dir,
            )
            results = executor.apply(execution_plan, auto_approve=True)
            for addr in results.get("success", []):
                ui_success(addr)
            for failure in results.get("failed", []):
                ui_error(f"{failure['address']}: {failure['error']}")

        console.print()
        if results.get("failed"):
            ui_error(
                f"Apply finished with errors. "
                f"{len(results.get('success', []))} succeeded · "
                f"{len(results.get('failed', []))} failed"
            )
            next_steps(
                [
                    "Inspect failures above for the cause.",
                    "Re-run `scc apply` after fixing the underlying issue.",
                    "Run `scc drift` to see what's still out of sync.",
                ]
            )
            sys.exit(1)
        ui_success(
            f"Apply complete. {len(results.get('success', []))} resource(s) updated."
        )

    finally:
        state_manager.unlock()


@cli.command()
@click.option(
    "--target", "-t",
    help="Target specific resource address"
)
@click.option(
    "--auto-approve",
    is_flag=True,
    help="Skip interactive approval"
)
@common_options
@click.pass_context
def destroy(ctx, target, auto_approve, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """
    Destroy all managed resources.
    
    Removes all resources managed by Salt Config CLI.
    
    \b
    Examples:
      $ scc destroy
      $ scc destroy --auto-approve
      $ scc destroy --target target_group.web-servers
    """
    setup_logging(log_level, no_color)
    
    settings = load_settings(config, server, username, password, csp_token, password_stdin=password_stdin, password_file=password_file, password_prompt=password_prompt)
    
    console.print("\n[bold red]Planning destruction...[/bold red]\n")
    
    # Initialize state manager
    state_manager = StateManager(
        state_path=settings.state_file,
        backend=settings.state_backend
    )
    
    # Generate destroy plan
    executor = PlanExecutor(
        state_manager=state_manager,
        api_client=None,
        config_dir=settings.working_dir
    )
    execution_plan = executor.plan(target=target, destroy=True)
    
    # Display plan
    _display_plan(execution_plan, is_destroy=True)
    
    if not execution_plan.has_changes:
        return
    
    # Typed confirmation - destroy is always destructive.
    from salt_config_cli.ui import confirm_destructive, RowTracker
    destroys = getattr(execution_plan, "to_delete", 0) or 0
    if not confirm_destructive(
        action="destroy",
        targets_summary=f"{destroys} resource(s) will be removed permanently",
        typed_phrase="destroy",
        auto_approve=auto_approve,
    ):
        ui_warn("Destroy cancelled.")
        return

    if not state_manager.lock():
        ui_error("Could not acquire state lock.", hint="Another scc process may be running.")
        sys.exit(1)

    addresses = [c.resource_address for c in execution_plan.changes if c.action == ChangeAction.DELETE]
    use_live = sys.stdout.isatty() and not _truthy_env("SCC_NO_LIVE")

    try:
        if use_live:
            with RowTracker(
                columns=("Resource", "State", "Detail"),
                title="Destroying resources",
                border_style="scc.danger",
            ) as tracker:
                for addr in addresses:
                    tracker.add(addr, status="active", detail="destroying…")
                results = executor.apply(execution_plan, auto_approve=True)
                ok_set = set(results.get("success", []))
                failures = {f.get("address"): f.get("error", "") for f in results.get("failed", [])}
                for addr in addresses:
                    if addr in ok_set:
                        tracker.set(addr, status="ok", detail="destroyed")
                    elif addr in failures:
                        tracker.set(addr, status="fail", detail=failures[addr] or "failed")
                tracker.footer(
                    f"{len(results.get('success', []))} destroyed · "
                    f"{len(results.get('failed', []))} failed"
                )
        else:
            results = executor.apply(execution_plan, auto_approve=True)
            for addr in results.get("success", []):
                ui_success(f"{addr} destroyed")
            for f in results.get("failed", []):
                ui_error(f"{f.get('address')}: {f.get('error')}")

        console.print()
        if results.get("failed"):
            ui_error(
                f"Destroy completed with errors. "
                f"{len(results.get('success', []))} destroyed · "
                f"{len(results.get('failed', []))} failed"
            )
            sys.exit(1)
        ui_success(
            f"Destroy complete. {len(results.get('success', []))} resource(s) removed."
        )
    finally:
        state_manager.unlock()


@cli.command()
@common_options
@click.pass_context
def validate(ctx, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """
    Validate configuration files.
    
    Checks syntax and references in configuration files.
    
    \b
    Examples:
      $ scc validate
    """
    setup_logging(log_level, no_color)
    
    settings = load_settings(config, server, username, password, csp_token, password_stdin=password_stdin, password_file=password_file, password_prompt=password_prompt)
    
    console.print("\n[bold blue]Validating configuration...[/bold blue]\n")
    
    # Load configurations
    state_manager = StateManager(
        state_path=settings.state_file,
        backend=settings.state_backend
    )
    
    executor = PlanExecutor(
        state_manager=state_manager,
        api_client=None,
        config_dir=settings.working_dir
    )
    
    try:
        resources = executor.load_configuration()
        console.print(f"[green]✓[/green] Found {len(resources)} valid resource(s)\n")
        
        for resource in resources:
            console.print(f"  • {resource.resource_type_value}.{resource.metadata.name}")
        
        console.print("\n[green]Configuration is valid![/green]\n")
        
    except Exception as e:
        console.print(f"[red]✗[/red] Validation failed: {e}\n")
        sys.exit(1)


@cli.command()
@click.option(
    "--file", "-f",
    type=click.Path(exists=True),
    help="Path to specific YAML config file"
)
@click.option(
    "--check-unexpected/--no-check-unexpected",
    default=True,
    help="Also check for unexpected resources on server"
)
@click.option(
    "--json", "as_json",
    is_flag=True,
    help="Output in JSON format"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Save drift report to file"
)
@common_options
@click.pass_context
def drift(ctx, file, check_unexpected, as_json, output, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """
    Detect drift between expected configuration and actual server state.
    
    Compares the YAML configuration files (expected state) against
    the actual resources on the RaaS server to identify differences.
    
    \b
    Drift Status:
      ✓ IN_SYNC    - Resource matches expected state
      ~ DRIFTED    - Resource exists but differs from expected
      ✗ MISSING    - Expected resource not found on server
      ? UNEXPECTED - Resource on server not in configuration
    
    \b
    Examples:
      $ scc drift
      $ scc drift -f ntp-drift.yaml
      $ scc drift --json
      $ scc drift --output drift-report.json
    """
    setup_logging(log_level, no_color)
    
    from salt_config_cli.core.drift import DriftDetector, DriftStatus, DriftSeverity, ProgressCallback
    from salt_config_cli.core.plan import PlanExecutor
    from rich.live import Live
    from rich.spinner import Spinner
    from rich.text import Text
    
    settings = load_settings(config, server, username, password, csp_token, password_stdin=password_stdin, password_file=password_file, password_prompt=password_prompt)
    
    console.print("\n[bold blue]Detecting drift...[/bold blue]\n")
    
    # Load expected configuration
    if file:
        # Load from specific file
        expected_resources = _load_resources_from_file(file)
    else:
        # Load from working directory
        state_manager = StateManager(
            state_path=settings.state_file,
            backend=settings.state_backend
        )
        
        executor = PlanExecutor(
            state_manager=state_manager,
            api_client=None,
            config_dir=settings.working_dir
        )
        
        expected_resources = executor.load_configuration()
    
    if not expected_resources:
        console.print("[yellow]No configuration files found.[/yellow]")
        console.print("Create YAML files defining expected resources.\n")
        return
    
    console.print(f"Found {len(expected_resources)} expected resource(s) in configuration\n")
    
    # Create API client if configured
    api_client = None
    if settings.server_url and settings.server_url != "https://localhost":
        try:
            from salt_config_cli.api.client import AriaConfigClient
            api_client = AriaConfigClient.from_settings(settings)
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to connect: {e}\n")
            console.print("[yellow]Running in offline mode - cannot verify actual state[/yellow]\n")
    
    # Live progress: a persistent table that fills in per resource.
    # Falls back to a simple line-by-line callback when stdout isn't a TTY.
    from salt_config_cli.ui import RowTracker

    use_live_drift = sys.stdout.isatty() and not _truthy_env("SCC_NO_LIVE")

    if use_live_drift:
        tracker = RowTracker(
            columns=("Resource", "State", "Detail"),
            title="Drift detection",
            border_style="scc.secondary",
        )

        # Map detector statuses -> tracker statuses.
        _STATUS_MAP = {
            "in_sync":     ("ok",   "in sync"),
            "drifted":     ("warn", "drifted"),
            "missing":     ("fail", "missing on server"),
            "unexpected":  ("info", "unexpected (on server only)"),
            "error":       ("fail", "error"),
            "timeout":     ("fail", "timeout"),
            "unknown":     ("info", "unknown"),
        }

        class _LiveDriftCallback(ProgressCallback):
            def __init__(self, t: RowTracker):
                self._t = t
                self._jobs: dict[str, str] = {}  # resource -> job_id

            def on_resource_start(self, resource_name: str, resource_type: str) -> None:
                key = f"{resource_type}.{resource_name}"
                self._t.add(key, status="active", detail="checking…")

            def on_job_submitted(self, resource_name: str, job_id: str) -> None:
                self._jobs[resource_name] = job_id

            def on_job_polling(self, resource_name: str, job_id: str, elapsed_seconds: int) -> None:
                # We don't know the resource_type here; update by suffix match.
                for key in list(self._t._rows.keys()):
                    if key.endswith(f".{resource_name}"):
                        self._t.set(key, detail=f"job {job_id} · {elapsed_seconds}s")
                        return

            def on_job_complete(self, resource_name: str, job_id: str, elapsed_seconds: int) -> None:
                for key in list(self._t._rows.keys()):
                    if key.endswith(f".{resource_name}"):
                        self._t.set(key, detail=f"job complete in {elapsed_seconds}s")
                        return

            def on_resource_complete(self, resource_name: str, status: str) -> None:
                mapped = _STATUS_MAP.get(status, ("info", status))
                for key in list(self._t._rows.keys()):
                    if key.endswith(f".{resource_name}"):
                        self._t.set(key, status=mapped[0], detail=mapped[1])
                        return

        with tracker:
            detector = DriftDetector(api_client=api_client, progress_callback=_LiveDriftCallback(tracker))
            report = detector.detect(expected_resources, check_unexpected=check_unexpected)
    else:
        # Non-interactive path: keep the simple line-by-line callback so logs
        # remain greppable for CI.
        class RichProgressCallback(ProgressCallback):
            def __init__(self, console):
                self.console = console
            def on_resource_start(self, resource_name: str, resource_type: str) -> None:
                self.console.print(f"[cyan]Checking[/cyan] {resource_type}.{resource_name}…")
            def on_job_submitted(self, resource_name: str, job_id: str) -> None:
                self.console.print(f"  [dim]Job submitted:[/dim] {job_id}")
            def on_job_polling(self, resource_name: str, job_id: str, elapsed_seconds: int) -> None:
                self.console.print(f"  [dim]Waiting for job {job_id}… ({elapsed_seconds}s)[/dim]", end="\r")
            def on_job_complete(self, resource_name: str, job_id: str, elapsed_seconds: int) -> None:
                self.console.print(f"  [green]Job {job_id} completed[/green] in {elapsed_seconds}s" + " " * 20)
            def on_resource_complete(self, resource_name: str, status: str) -> None:
                glyph = {
                    "in_sync":    "[green]✓[/green]",
                    "drifted":    "[yellow]~[/yellow]",
                    "missing":    "[red]✗[/red]",
                    "unexpected": "[blue]?[/blue]",
                    "unknown":    "[dim]?[/dim]",
                    "error":      "[red]![/red]",
                    "timeout":    "[red]⏱[/red]",
                }.get(status, "[dim]?[/dim]")
                self.console.print(f"  {glyph} {resource_name}: {status}")
        detector = DriftDetector(api_client=api_client, progress_callback=RichProgressCallback(console))
        report = detector.detect(expected_resources, check_unexpected=check_unexpected)
    
    # Display results
    if as_json:
        console.print_json(data=report.model_dump(mode="json"))
    else:
        _display_drift_report(report)
    
    # Save to file if requested
    if output:
        with open(output, "w") as f:
            json.dump(report.model_dump(mode="json"), f, indent=2, default=str)
        console.print(f"[green]✓[/green] Drift report saved to {output}\n")
    
    # Exit with error code if drift detected
    if report.has_drift:
        sys.exit(1)


def _load_resources_from_file(file_path: str) -> list:
    """Load resource configurations from a specific YAML file."""
    import yaml
    from salt_config_cli.core.models import ResourceType, ResourceMetadata, resource_factory
    
    resources = []
    
    try:
        with open(file_path, "r") as f:
            docs = list(yaml.safe_load_all(f))
        
        for doc in docs:
            if doc and isinstance(doc, dict):
                resource_type_str = doc.get("resource_type")
                if not resource_type_str:
                    continue
                
                try:
                    resource_type = ResourceType(resource_type_str)
                except ValueError:
                    console.print(f"[yellow]Warning: Unknown resource type '{resource_type_str}'[/yellow]")
                    continue
                
                metadata_data = doc.get("metadata", {})
                if not metadata_data.get("name"):
                    continue
                
                metadata = ResourceMetadata(**metadata_data)
                spec = doc.get("spec", {})
                
                resource = resource_factory(
                    resource_type=resource_type,
                    metadata=metadata,
                    spec=spec
                )
                resources.append(resource)
    except Exception as e:
        console.print(f"[red]Error loading {file_path}: {e}[/red]")
    
    return resources


def _display_drift_report(report) -> None:
    """Display drift report with rich formatting."""
    from salt_config_cli.core.drift import DriftStatus, DriftSeverity
    
    status_icons = {
        DriftStatus.IN_SYNC: "[green]✓[/green]",
        DriftStatus.DRIFTED: "[yellow]~[/yellow]",
        DriftStatus.MISSING: "[red]✗[/red]",
        DriftStatus.UNEXPECTED: "[blue]?[/blue]",
        DriftStatus.UNKNOWN: "[dim]?[/dim]",
    }
    
    severity_colors = {
        DriftSeverity.INFO: "dim",
        DriftSeverity.WARNING: "yellow",
        DriftSeverity.CRITICAL: "red",
    }
    
    # Group by status
    in_sync = [r for r in report.resources if r.status == DriftStatus.IN_SYNC]
    drifted = [r for r in report.resources if r.status == DriftStatus.DRIFTED]
    missing = [r for r in report.resources if r.status == DriftStatus.MISSING]
    unexpected = [r for r in report.resources if r.status == DriftStatus.UNEXPECTED]
    unknown = [r for r in report.resources if r.status == DriftStatus.UNKNOWN]
    
    # Display drifted resources first (most important)
    if drifted:
        console.print("[bold yellow]Drifted Resources:[/bold yellow]")
        for r in drifted:
            job_info = f" [dim](job: {r.job_id})[/dim]" if r.job_id else ""
            console.print(f"  {status_icons[r.status]} {r.resource_address}{job_info}")
            for attr_drift in r.attribute_drifts:
                color = severity_colors.get(attr_drift.severity, "white")
                console.print(f"      [{color}]• {attr_drift.attribute}:[/{color}]")
                console.print(f"        expected: {attr_drift.expected_value}")
                console.print(f"        actual:   {attr_drift.actual_value}")
        console.print()
    
    # Missing resources
    if missing:
        console.print("[bold red]Missing Resources (expected but not on server):[/bold red]")
        for r in missing:
            console.print(f"  {status_icons[r.status]} {r.resource_address}")
        console.print()
    
    # Unexpected resources
    if unexpected:
        console.print("[bold blue]Unexpected Resources (on server but not in config):[/bold blue]")
        for r in unexpected:
            console.print(f"  {status_icons[r.status]} {r.resource_address}")
        console.print()
    
    # In sync (summary only, but show job IDs if present)
    if in_sync:
        console.print(f"[green]✓ {len(in_sync)} resource(s) in sync[/green]")
        for r in in_sync:
            if r.job_id:
                console.print(f"    [dim]{r.resource_address} (job: {r.job_id})[/dim]")
    
    # Unknown
    if unknown:
        console.print(f"[dim]? {len(unknown)} resource(s) could not be verified[/dim]")
    
    console.print()
    
    # Summary
    if report.has_drift:
        console.print(f"[bold yellow]Drift detected![/bold yellow] {report.get_summary()}")
        console.print("\nRun [bold]scc remediate[/bold] to fix drift.\n")
    else:
        console.print("[bold green]No drift detected.[/bold green] All resources are in sync.\n")


@cli.command()
@click.option(
    "--file", "-f",
    type=click.Path(exists=True),
    help="Path to specific YAML config file"
)
@click.option(
    "--auto-approve",
    is_flag=True,
    help="Skip interactive approval"
)
@click.option(
    "--target", "-t",
    help="Target specific resource address"
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show what would be done without making changes"
)
@common_options
@click.pass_context
def remediate(ctx, file, auto_approve, target, dry_run, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """
    Remediate detected drift by syncing resources to expected state.
    
    First detects drift, then applies changes to bring resources
    back into compliance with the expected configuration.
    
    \b
    Actions:
      SYNC   - Update drifted resource to match expected state
      CREATE - Create missing resource
      DELETE - Remove unexpected resource (requires explicit selection)
    
    \b
    Examples:
      $ scc remediate
      $ scc remediate -f ntp-drift.yaml --auto-approve
      $ scc remediate --target target_group.web-servers
      $ scc remediate --dry-run
    """
    setup_logging(log_level, no_color)
    
    from salt_config_cli.core.drift import DriftDetector, DriftStatus, RemediationAction
    from salt_config_cli.core.plan import PlanExecutor
    
    settings = load_settings(config, server, username, password, csp_token, password_stdin=password_stdin, password_file=password_file, password_prompt=password_prompt)
    
    console.print("\n[bold blue]Detecting drift for remediation...[/bold blue]\n")
    
    # Load expected configuration
    if file:
        # Load from specific file
        expected_resources = _load_resources_from_file(file)
    else:
        # Load from working directory
        state_manager = StateManager(
            state_path=settings.state_file,
            backend=settings.state_backend
        )
        
        executor = PlanExecutor(
            state_manager=state_manager,
            api_client=None,
            config_dir=settings.working_dir
        )
        
        expected_resources = executor.load_configuration()
    
    if not expected_resources:
        console.print("[yellow]No configuration files found.[/yellow]\n")
        return
    
    # Create API client
    api_client = None
    if settings.server_url and settings.server_url != "https://localhost":
        try:
            from salt_config_cli.api.client import AriaConfigClient
            api_client = AriaConfigClient.from_settings(settings)
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to connect: {e}")
            console.print("[red]Cannot remediate without server connection.[/red]\n")
            sys.exit(1)
    else:
        console.print("[red]No server configured. Set server_url in config.[/red]\n")
        sys.exit(1)
    
    # Detect drift
    detector = DriftDetector(api_client=api_client)
    report = detector.detect(expected_resources, check_unexpected=True)
    
    if not report.has_drift:
        console.print("[green]No drift detected.[/green] Nothing to remediate.\n")
        return
    
    # Create remediation plan
    plan = detector.create_remediation_plan(report)
    
    # Filter by target if specified
    if target:
        plan.items = [i for i in plan.items if i.resource_address == target]
        if not plan.items:
            console.print(f"[yellow]No drift found for target: {target}[/yellow]\n")
            return
    
    # Display plan
    console.print("[bold]Remediation Plan:[/bold]\n")
    
    action_icons = {
        RemediationAction.SYNC: "[yellow]~[/yellow]",
        RemediationAction.CREATE: "[green]+[/green]",
        RemediationAction.DELETE: "[red]-[/red]",
        RemediationAction.SKIP: "[dim] [/dim]",
    }
    
    for item in plan.items:
        icon = action_icons.get(item.action, "?")
        selected = "✓" if item.selected else " "
        console.print(f"  [{selected}] {icon} {item.description}")
    
    console.print(f"\n{plan.get_summary()}\n")
    
    if dry_run:
        console.print("[yellow]Dry run - no changes made.[/yellow]\n")
        return
    
    if not plan.has_actions:
        console.print("[yellow]No actions selected for remediation.[/yellow]\n")
        return
    
    # Count destructive actions
    delete_count = sum(1 for it in plan.items if it.selected and it.action == RemediationAction.DELETE)
    actionable = [it for it in plan.items if it.selected and it.action != RemediationAction.SKIP]

    # Confirmation
    from salt_config_cli.ui import confirm_destructive, RowTracker
    if delete_count > 0:
        if not confirm_destructive(
            action="remediate (with delete)",
            targets_summary=(
                f"{sum(1 for it in actionable if it.action == RemediationAction.SYNC)} sync, "
                f"{sum(1 for it in actionable if it.action == RemediationAction.CREATE)} create, "
                f"{delete_count} delete"
            ),
            typed_phrase="remediate",
            auto_approve=auto_approve,
        ):
            ui_warn("Remediation cancelled.")
            return
    elif not auto_approve:
        if not click.confirm("Apply this remediation plan?"):
            ui_warn("Remediation cancelled.")
            return

    # Apply remediation with live tracker
    use_live = sys.stdout.isatty() and not _truthy_env("SCC_NO_LIVE")
    success_count = 0
    fail_count = 0

    if use_live:
        with RowTracker(
            columns=("Resource", "State", "Detail"),
            title="Applying remediation",
            border_style="scc.warning",
        ) as tracker:
            for item in actionable:
                tracker.add(item.description, status="pending", detail="queued")
            for item in actionable:
                tracker.set(item.description, status="active", detail=str(item.action.value if hasattr(item.action, "value") else item.action).lower())
                try:
                    _apply_remediation_item(api_client, item, expected_resources)
                    tracker.set(item.description, status="ok", detail="applied")
                    success_count += 1
                except Exception as e:
                    tracker.set(item.description, status="fail", detail=str(e))
                    fail_count += 1
            tracker.footer(f"{success_count} succeeded · {fail_count} failed")
    else:
        for item in actionable:
            try:
                _apply_remediation_item(api_client, item, expected_resources)
                ui_success(item.description)
                success_count += 1
            except Exception as e:
                ui_error(f"{item.description}: {e}")
                fail_count += 1

    console.print()
    if fail_count > 0:
        ui_error(f"Remediation completed with errors. {success_count} succeeded · {fail_count} failed")
        sys.exit(1)
    ui_success(f"Remediation complete. {success_count} resource(s) updated.")


def _apply_remediation_item(api_client, item, expected_resources) -> None:
    """Apply a single remediation action."""
    from salt_config_cli.core.drift import RemediationAction
    
    drift = item.resource_drift
    resource_type = drift.resource_type_value
    name = drift.name
    
    if item.action == RemediationAction.SYNC or item.action == RemediationAction.CREATE:
        # Find expected resource
        expected = next(
            (r for r in expected_resources 
             if r.resource_type_value == resource_type and r.metadata.name == name),
            None
        )
        
        if not expected:
            raise ValueError(f"Expected resource not found: {drift.resource_address}")
        
        # Apply based on resource type
        if resource_type == "target_group":
            api_client.call(
                "tgt", "save_target_group",
                name=name,
                tgt=expected.spec.get("targets", []),
                desc=expected.metadata.description or ""
            )
        elif resource_type == "job":
            api_client.call(
                "job", "save_job",
                name=name,
                cmd=expected.spec.get("function", "state.apply"),
                arg=expected.spec.get("arguments", []),
                kwarg=expected.spec.get("kwargs", {}),
                desc=expected.metadata.description or ""
            )
        elif resource_type == "pillar":
            pillar_data = expected.spec.get("data", {})
            api_client.call(
                "pillar", "save_pillar",
                name=name,
                pillar=pillar_data,
                pillar_type="static",
                desc=expected.metadata.description or ""
            )
        elif resource_type == "state_file":
            path = expected.spec.get("path", f"{name}.sls")
            api_client.call(
                "fs", "save_file",
                path=path,
                contents=expected.spec.get("contents", ""),
                saltenv=expected.spec.get("environment", "base")
            )
        elif resource_type == "minion_state":
            # Apply the state to minions (without test mode)
            _apply_minion_state(api_client, expected)
        else:
            raise ValueError(f"Unsupported resource type: {resource_type}")
    
    elif item.action == RemediationAction.DELETE:
        if resource_type == "target_group":
            api_client.call("tgt", "delete_target_group", name=name)
        elif resource_type == "job":
            api_client.call("job", "delete_job", name=name)
        elif resource_type == "pillar":
            api_client.call("pillar", "delete_pillar", name=name)
        elif resource_type == "state_file":
            path = name if name.endswith(".sls") else f"{name}.sls"
            api_client.call("fs", "delete_file", path=path)
        elif resource_type == "minion_state":
            # Cannot "delete" a minion state - skip
            pass
        else:
            raise ValueError(f"Unsupported resource type: {resource_type}")


def _apply_minion_state(api_client, expected) -> dict:
    """
    Apply a minion state configuration (remediation).
    
    Runs state.apply WITHOUT test mode to actually apply the changes.
    """
    import time
    
    spec = expected.spec
    name = expected.metadata.name
    
    # Extract state configuration
    state_file = spec.get("state_file", "")
    state_files = spec.get("state_files", [state_file] if state_file else [])
    
    # Check for target_group first, then fall back to target
    target_group_name = spec.get("target_group")
    if target_group_name:
        # Resolve target group
        groups = _list_target_groups(api_client)
        found = None
        for g in groups:
            if isinstance(g, dict) and g.get("name", "").lower() == target_group_name.lower():
                found = g
                break
        if not found:
            raise ValueError(f"Target group not found: {target_group_name}")
        
        tgt_spec_from_group = found.get("tgt", {})
        target = "*"
        target_type = "glob"
        if isinstance(tgt_spec_from_group, dict):
            for master_key, master_tgt in tgt_spec_from_group.items():
                if isinstance(master_tgt, dict):
                    target = master_tgt.get("tgt", "*")
                    target_type = master_tgt.get("tgt_type", "glob")
                    break
    else:
        target = spec.get("target", "*")
        target_type = spec.get("target_type", "glob")
    
    saltenv = spec.get("environment", "base")
    pillar_data = spec.get("pillar", {})
    
    if not state_files:
        raise ValueError(f"No state_file specified for minion_state: {name}")
    
    # Normalize state references
    state_refs = []
    for sf in state_files:
        ref = sf.lstrip("/")
        if ref.endswith(".sls"):
            ref = ref[:-4]
        state_refs.append(ref)
    
    # Build target specification
    tgt_spec = {
        "*": {
            "tgt": target,
            "tgt_type": target_type
        }
    }
    
    # Build arg specification WITHOUT test mode
    cmd_kwargs = {"saltenv": saltenv}
    if pillar_data:
        cmd_kwargs["pillar"] = pillar_data
    
    arg_spec = {
        "arg": state_refs,
        "kwarg": cmd_kwargs
    }
    
    # Run state.apply
    resp = api_client.call(
        "cmd", "route_cmd",
        cmd="local",
        fun="state.apply",
        tgt=tgt_spec,
        arg=arg_spec
    )
    
    if resp.error:
        raise RuntimeError(f"Failed to apply state: {resp.error.get('message', 'Unknown error')}")
    
    # Get job ID and wait for completion
    jid = resp.ret if isinstance(resp.ret, str) else resp.ret.get("jid") if isinstance(resp.ret, dict) else str(resp.ret)
    
    # Wait for job to complete. Default ceiling is 30 minutes; state.apply
    # against many minions can legitimately take a while. Override via the
    # SCC_APPLY_TIMEOUT env var (0 == wait forever).
    try:
        env_timeout = int(os.environ.get("SCC_APPLY_TIMEOUT", "1800"))
    except ValueError:
        env_timeout = 1800
    max_wait = env_timeout
    poll_interval = 3
    waited = 0
    unlimited = max_wait <= 0
    
    while unlimited or waited < max_wait:
        time.sleep(poll_interval)
        waited += poll_interval
        
        status_resp = api_client.call("cmd", "get_cmd_status", jids=[jid])
        if status_resp.success and status_resp.ret:
            status = status_resp.ret[0] if isinstance(status_resp.ret, list) else status_resp.ret
            if isinstance(status, str) and status in ("complete", "completed"):
                break
            elif isinstance(status, dict) and status.get("state") in ("complete", "completed"):
                break
    
    # Get results
    returns_resp = api_client.call("ret", "get_returns", jid=jid)
    
    # Analyze results for errors
    results = returns_resp.ret if returns_resp.success else None
    errors = []
    successes = 0
    failures = 0
    
    if results:
        minion_results = results.get("results", []) if isinstance(results, dict) else results
        if isinstance(minion_results, list):
            for ret in minion_results:
                minion_id = ret.get("minion_id", ret.get("id", "unknown"))
                has_errors = ret.get("has_errors", False)
                
                return_data = ret.get("return")
                if return_data is None:
                    return_data = ret.get("full_ret", {}).get("return")
                if return_data is None:
                    return_data = ret.get("ret", {})
                
                if isinstance(return_data, dict):
                    # Parse individual state results
                    for state_id, state_result in return_data.items():
                        if not isinstance(state_result, dict):
                            continue
                        
                        result_val = state_result.get("result")
                        comment = state_result.get("comment", "")
                        state_name = state_result.get("name", state_id)
                        
                        # Parse state ID for display
                        parts = state_id.split("_|-")
                        if len(parts) >= 4:
                            display_name = f"{parts[0]}.{parts[3]}"
                        else:
                            display_name = state_id[:40]
                        
                        if result_val is False:
                            failures += 1
                            error_msg = comment[:100] if comment else "Unknown error"
                            errors.append(f"{minion_id}/{display_name}: {error_msg}")
                        elif result_val is True:
                            successes += 1
                elif has_errors:
                    # Fallback if return_data is not a dict but has_errors is True
                    error_msg = str(return_data)[:100] if return_data else "Unknown execution error"
                    errors.append(f"{minion_id}: {error_msg}")
                    failures += 1
    
    result = {
        "jid": jid,
        "results": results,
        "successes": successes,
        "failures": failures,
        "errors": errors
    }
    
    if failures > 0:
        error_summary = f"{failures} state(s) failed"
        if errors:
            error_details = "\n      ".join(errors[:5])  # Show first 5 errors
            if len(errors) > 5:
                error_details += f"\n      ... and {len(errors) - 5} more errors"
            raise RuntimeError(f"{error_summary}:\n      {error_details}")
    
    return result


@cli.command()
@common_options
@click.pass_context
def status(ctx, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """Show workspace and server connection status."""
    setup_logging(log_level, no_color)

    settings = load_settings(config, server, username, password, csp_token, password_stdin=password_stdin, password_file=password_file, password_prompt=password_prompt)

    scc_dir = Path.cwd() / ".scc"
    workspace_initialized = scc_dir.exists()

    command_header(
        "status",
        "Workspace and connection status",
        description="Inspect local workspace health, credential source and live RaaS reachability.",
        icon="magnify",
        meta=[
            ("Profile", settings.profile_name),
            ("Workspace", "ready" if workspace_initialized else "not initialized"),
            ("Server", mask_url(settings.server_url) if settings.server_url else "not configured"),
            ("User", settings.username or "not configured"),
        ],
    )

    ws_badge = badge("READY", "success") if workspace_initialized else badge("NOT INITIALIZED", "warning")
    kv_table(
        f"{ICONS['folder']} Workspace",
        [
            ("Working directory", str(Path.cwd())),
            ("State file", str(settings.state_file)),
            ("Status", ws_badge),
        ],
    )

    credential_source = getattr(settings, "_password_source", "none")
    if settings.auth == "csp-token":
        credential_value = mask(settings.csp_api_token.get_secret_value() if settings.csp_api_token else None)
        credential_label = "CSP API token"
        identity_value = settings.username or "token-based authentication"
    else:
        credential_value = mask(settings.password.get_secret_value() if settings.password else None)
        credential_label = "Password"
        identity_value = settings.username or ""
    source_styled = {
        "stdin": "[scc.success]stdin (secure)[/scc.success]",
        "keychain": "[scc.success]OS keychain (secure)[/scc.success]",
        "environment": "[scc.success]environment variable[/scc.success]",
        "env:SCC_PASSWORD": "[scc.success]env: SCC_PASSWORD[/scc.success]",
        "prompt": "[scc.success]interactive prompt[/scc.success]",
        "cli": "[scc.warning]command line[/scc.warning]",
        "cli (insecure)": "[scc.warning]command line (insecure)[/scc.warning]",
        "config": "[scc.info]legacy config file[/scc.info]",
        "none": "[scc.muted](not set)[/scc.muted]",
    }.get(credential_source, credential_source)
    if str(credential_source).startswith("file:"):
        source_styled = f"[scc.success]{credential_source} (secure)[/scc.success]"

    kv_table(
        f"{ICONS['plug']} Server",
        {
            "Profile": settings.profile_name,
            "Config file": str(settings.config_path or discover_config_path()),
            "URL": mask_url(settings.server_url) or "",
            "Authentication": settings.auth,
            "Username": identity_value,
            credential_label: credential_value,
            "Credential source": source_styled,
            "SSL verify": str(settings.ssl_verify),
            "Timeout": f"{settings.timeout}s",
        },
    )

    # Connection probe
    if settings.server_url and settings.server_url != "https://localhost":
        try:
            from salt_config_cli.api.client import AriaConfigClient

            with spinner(f"Probing {mask_url(settings.server_url)}…"):
                client = AriaConfigClient.from_settings(settings)
            api_version = client._api_version or "unknown"
            result_summary(
                "RaaS connection is healthy",
                status="success",
                message="Authentication and the RPC endpoint responded successfully.",
                details=[
                    ("Server", mask_url(settings.server_url)),
                    ("API version", api_version),
                    ("Workspace", "ready" if workspace_initialized else "not initialized"),
                ],
            )
            try:
                client.close()
            except Exception:
                pass
            next_steps(
                [
                    "Browse available resources: `scc list`",
                    "Inspect file-server content: `scc fs-list`",
                    "Run deeper diagnostics: `scc doctor`",
                ],
                title="Continue exploring",
            )
        except Exception as e:
            result_summary(
                "RaaS connection needs attention",
                status="danger",
                message=str(e),
                details=[
                    ("Server", mask_url(settings.server_url)),
                    ("Recommended check", "scc doctor"),
                ],
            )
            next_steps(
                [
                    "Run end-to-end diagnostics: `scc doctor`",
                    "Update the saved connection: `scc connect --force`",
                    "Verify VPN, DNS, TLS certificates and RaaS availability.",
                ]
            )
    else:
        empty_state(
            "No RaaS server configured",
            "SCC can render local information, but remote operations need a saved RaaS connection.",
            icon="plug",
            actions=["scc connect", "scc init", "scc help connect"],
        )

    if not workspace_initialized:
        next_steps(
            [
                "Initialize the workspace: `scc init`",
                "Then list server resources: `scc list`",
                "Detect drift: `scc drift`",
            ],
            title="Initialize desired-state workflows",
        )


@cli.command("clear-cache")
@click.option(
    "--all", "clear_all",
    is_flag=True,
    help="Clear all cached tokens (all servers)"
)
@common_options
@click.pass_context
def clear_cache(ctx, clear_all, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """
    Clear cached authentication tokens.
    
    By default, clears the token for the configured server.
    Use --all to clear tokens for all servers.
    
    \b
    Examples:
      $ scc clear-cache
      $ scc clear-cache --all
    """
    setup_logging(log_level, no_color)
    
    from salt_config_cli.api.token_cache import get_token_cache
    
    cache = get_token_cache()
    
    if clear_all:
        count = cache.clear_all()
        ui_success(f"Cleared {count} cached token(s)")
    else:
        settings = load_settings(config, server, username, password, csp_token, password_stdin=password_stdin, password_file=password_file, password_prompt=password_prompt)
        cache.delete(settings.server_url, settings.username)
        ui_success(f"Cleared cached token", hint=settings.server_url)


@cli.command()
@click.option("--name", "profile_name", default=None, help="Named profile to create or update.")
@click.option("--make-default/--no-make-default", default=True, help="Make the saved profile active.")
@click.option("--server", "-s", envvar="SCC_SERVER_URL", metavar="URL",
              help="RaaS server URL (e.g. https://10.0.0.1)")
@click.option("--username", "-u", envvar="SCC_USERNAME", metavar="USER",
              help="Username for authentication")
@click.option("--password-prompt", is_flag=True, default=False,
              help="Force a masked password prompt (default behavior when no other "
                   "password source is given).")
@click.option("--password-stdin", is_flag=True, default=False,
              help="Read password from piped stdin (for scripts/CI). "
                   "Falls back to a prompt if stdin is a TTY.")
@click.option("--password-file",
              type=click.Path(dir_okay=False, exists=True, readable=True),
              default=None, metavar="PATH",
              help="Read password from a 0600-mode file.")
@click.option("--csp-token", envvar="SCC_CSP_API_TOKEN", default=None,
              metavar="TOKEN",
              help="Use a CSP API token instead of username/password.")
@click.option("--insecure", is_flag=True, default=False,
              help="Skip TLS certificate verification (saves ssl_verify=false).")
@click.option("--workspace", is_flag=True, default=False,
              help="Save the config in ./.scc/config.yaml instead of ~/.scc/config.yaml.")
@click.option("--no-test", "skip_test", is_flag=True, default=False,
              help="Skip the live connection test before saving.")
@click.option("--no-save", "skip_save_config", is_flag=True, default=False,
              help="Don't write server/username to the config file (keychain only).")
@click.option("--force", "-f", is_flag=True, default=False,
              help="Overwrite an existing connection without prompting.")
@click.pass_context
def connect(ctx, profile_name, make_default, server, username, password_prompt, password_stdin, password_file,
            csp_token, insecure, workspace, skip_test, skip_save_config, force):
    """
    Connect to a RaaS server and remember the connection.

    Interactive one-shot setup: asks for server URL, username, and password
    (masked), tests the connection, then persists everything so subsequent
    commands work without any flags.

    \b
    What gets stored:
      • Named profile settings → config file (~/.scc/config.yaml by default)
      • Password               →  OS keychain (Keychain / Secret Service / Credential Manager)

    \b
    Examples:
      $ scc connect --name lab                                     # fully interactive named profile
      $ scc connect -s https://10.0.0.1 -u root                    # prompts for password
      $ scc connect -s https://10.0.0.1 -u root --password-prompt  # force a prompt
      $ scc connect -s https://10.0.0.1 -u root --password-file ~/.scc/password
      $ echo "$PW" | scc connect -s ... -u root --password-stdin   # piped (CI/scripts)
      $ scc connect --csp-token "$CSP"                             # CSP token instead
      $ scc connect -s ... -u root --insecure                      # skip TLS verify
      $ scc connect --workspace                                    # save in ./.scc/config.yaml
      $ scc connect --no-test                                      # skip the live probe

    \b
    After running this once, just use the CLI without any auth flags:
      $ scc status
      $ scc fs-list
      $ scc exec test.ping
    """
    command_header(
        "connect",
        "Connect to a RaaS server",
        description="Enter the RaaS server URL, username, and password. Nothing is sent anywhere until you confirm.",
        icon="plug",
    )

    # Start from the requested/existing profile so prompts use useful defaults.
    selected_profile = profile_name or _ACTIVE_PROFILE_OVERRIDE
    target_config_path = _workspace_config_path() if workspace else discover_config_path(_GLOBAL_CONFIG_PATH)
    try:
        existing_settings = SaltConfigSettings.load_from_file(str(target_config_path), selected_profile)
    except Exception:
        existing_settings = SaltConfigSettings()
        object.__setattr__(existing_settings, "_profile_name", selected_profile or "default")
    selected_profile = selected_profile or existing_settings.profile_name or "default"
    default_server = server or (existing_settings.server_url
                                if existing_settings.server_url and existing_settings.server_url != "https://localhost"
                                else "")
    default_user = username or existing_settings.username or ""

    # Whether the user can actually answer interactive prompts.
    tty_in = sys.stdin.isatty()

    # ---- Server URL ----
    if not server:
        if tty_in:
            if not default_server:
                ui_hint("e.g. https://raas.example.com or https://10.0.0.5:8443")
            try:
                server = click.prompt(
                    "RaaS server URL",
                    default=default_server or None,
                    show_default=bool(default_server),
                    type=str,
                ).strip()
            except click.exceptions.Abort:
                console.print("\n[yellow]Aborted by user.[/yellow]\n")
                sys.exit(1)
        else:
            ui_error("--server is required in non-interactive mode.",
                     hint="Pass --server https://<raas-host>")
            sys.exit(2)
    if not server:
        ui_error("Server URL is required.")
        sys.exit(2)
    # Light normalization: add scheme if missing.
    if not server.startswith(("http://", "https://")):
        server = "https://" + server
    server = server.rstrip("/")

    # ---- Username (skipped when using a CSP token) ----
    if not csp_token:
        if not username:
            if tty_in:
                try:
                    username = click.prompt(
                        "RaaS username",
                        default=default_user or None,
                        show_default=bool(default_user),
                        type=str,
                    ).strip()
                except click.exceptions.Abort:
                    console.print("\n[yellow]Aborted by user.[/yellow]\n")
                    sys.exit(1)
            else:
                ui_error("--username is required in non-interactive mode.",
                         hint="Pass --username <user> (or use --csp-token).")
                sys.exit(2)
        if not username:
            ui_error("Username is required.")
            sys.exit(2)

    # ---- Existing connection check ----
    already_configured = (
        existing_settings.server_url
        and existing_settings.server_url != "https://localhost"
        and existing_settings.username
        and (
            existing_settings.server_url != server
            or (username and existing_settings.username != username)
        )
    )
    if already_configured and not force and tty_in:
        console.print(
            f"\n[yellow]⚠[/yellow] A connection is already configured:\n"
            f"    [dim]server:[/dim]   [cyan]{existing_settings.server_url}[/cyan]\n"
            f"    [dim]username:[/dim] [cyan]{existing_settings.username}[/cyan]\n"
        )
        target = f"{username}@{server}" if username else f"CSP token @ {server}"
        if not click.confirm(f"Replace it with {target}?", default=True):
            console.print("[yellow]Aborted. Existing connection kept.[/yellow]\n")
            sys.exit(1)

    # ---- Password resolution ----
    # Resolution order:
    #   1. CSP token (skip password entirely)
    #   2. --password-file
    #   3. --password-stdin   (only if stdin is *actually* piped; falls back to prompt)
    #   4. --password-prompt  (or any other path that lands us in interactive mode)
    #   5. Existing keychain entry  (offer to reuse it)
    #   6. Default: prompt when running on a TTY
    pw: str = ""
    pw_source: str = ""

    if csp_token:
        pw_source = "csp-token"
        # Nothing to do; the probe will use the CSP token.

    elif password_file:
        try:
            with open(password_file, "r", encoding="utf-8") as f:
                pw = f.read().strip()
        except Exception as e:
            ui_error(f"Failed to read --password-file '{password_file}': {e}")
            sys.exit(1)
        if not pw:
            ui_error(f"--password-file '{password_file}' is empty; aborting.")
            sys.exit(1)
        pw_source = f"file:{password_file}"

    elif password_stdin:
        # Only treat stdin as a real piped source when it isn't a TTY.
        if tty_in:
            ui_warn(
                "--password-stdin was passed but stdin is a terminal (not piped).",
                hint="Falling back to an interactive prompt. "
                     "Use `--password-prompt` for this case to avoid the warning.",
            )
            pw = prompt_password(f"Password for {username}@{server}")
            pw_source = "prompt"
        else:
            try:
                pw = sys.stdin.read().strip()
            except Exception as e:
                ui_error(f"Failed to read password from stdin: {e}")
                sys.exit(1)
            if not pw:
                ui_error("Empty password on stdin; aborting.")
                sys.exit(1)
            pw_source = "stdin"

    else:
        # No explicit password source. If there's an existing keychain entry
        # for this exact (server, user), offer to reuse it so users can update
        # the server URL without re-typing their password.
        reused_from_keychain = False
        if (
            keychain_available()
            and existing_settings.server_url == server
            and existing_settings.username == username
            and tty_in
            and not password_prompt
        ):
            try:
                from salt_config_cli.ui import keychain_get
                cached_pw = keychain_get(server, username)
            except Exception:
                cached_pw = None
            if cached_pw:
                if click.confirm(
                    f"Use the password stored in your OS keychain for {username}@{server}?",
                    default=True,
                ):
                    pw = cached_pw
                    pw_source = "keychain"
                    reused_from_keychain = True

        if not reused_from_keychain:
            if not tty_in:
                ui_error(
                    "No password source available in non-interactive mode.",
                    hint="Pipe with --password-stdin, or use --password-file / --csp-token.",
                )
                sys.exit(2)
            pw = prompt_password(f"Password for {username}@{server}")
            pw_source = "prompt"

    if not csp_token and not pw:
        ui_error("Empty password; aborting.")
        sys.exit(1)

    # ---- Test the connection ----
    if not skip_test:
        from pydantic import SecretStr
        probe_settings = SaltConfigSettings()
        probe_settings.server_url = server
        if username:
            probe_settings.username = username
        if pw:
            probe_settings.password = SecretStr(pw)
        if csp_token:
            probe_settings.csp_api_token = SecretStr(csp_token)
        if insecure:
            probe_settings.ssl_verify = False
        object.__setattr__(probe_settings, "_password_source", pw_source)

        try:
            from salt_config_cli.api.client import AriaConfigClient
            with spinner(f"Testing connection to {mask_url(server)}…"):
                client = AriaConfigClient.from_settings(probe_settings)
            ui_success(
                f"Connected to {mask_url(server)}",
                hint=f"API version: {getattr(client, '_api_version', None) or 'unknown'}",
            )
            try:
                client.close()
            except Exception:
                pass
        except Exception as e:
            ui_error(f"Connection failed: {e}")
            next_steps([
                "Re-check the server URL and username.",
                "If the server uses a self-signed cert, retry with `--insecure`.",
                "Run `scc doctor` for end-to-end diagnostics.",
                "Skip the test and save anyway with `--no-test`.",
            ])
            sys.exit(1)

    # ---- Persist the credential to the OS keychain ----
    keychain_ok = False
    credential_identity = username or "__csp__"
    if csp_token and keychain_available():
        keychain_ok = keychain_set(server, credential_identity, csp_token)
        pw_source = "csp-token"
    elif pw_source == "keychain":
        # Already stored — nothing to do, but report it correctly.
        keychain_ok = True
    elif keychain_available():
        keychain_ok = keychain_set(server, username, pw)
        if not keychain_ok:
            ui_warn("Failed to write to keychain - the password was not saved.")
            ui_hint("Use `--password-file ~/.scc/password` (chmod 600) as a fallback.")
    else:
        ui_warn(
            "No OS keychain backend available - the password was not saved.",
            hint="Install `keyring` (and on Linux, `secretstorage` or `kwallet`).",
        )

    # ---- Persist the named profile (never the credential) ----
    cfg_path: Optional[Path] = None
    if not skip_save_config:
        cfg_path = target_config_path
        try:
            store = ProfileConfigStore(cfg_path)
            try:
                current = store.load().profiles.get(selected_profile)
            except Exception:
                current = None
            profile_data = current.model_dump() if current else {}
            profile_data.update({
                "server_url": server,
                "username": username or None,
                "auth": "csp-token" if csp_token else "password",
                "ssl_verify": not insecure,
            })
            profile = ConnectionProfile.model_validate(profile_data)
            store.upsert_profile(selected_profile, profile, make_default=make_default)
        except Exception as e:
            ui_error(f"Failed to save profile '{selected_profile}' to {cfg_path}: {e}")
            sys.exit(1)

    # ---- Summary ----
    if csp_token:
        password_cell = "OS keychain (secure)" if keychain_ok else "CSP token (runtime only)"
    elif keychain_ok:
        password_cell = "OS keychain (secure)"
    else:
        password_cell = "[yellow]not stored[/yellow]"

    kv_rows = {
        "Profile": selected_profile,
        "Server": server,
        "Username": username or "[dim](using CSP token)[/dim]",
        "Password": password_cell,
        "Source": {
            "csp-token": "CSP token",
            "prompt": "interactive prompt",
            "stdin": "stdin (piped)",
            "keychain": "OS keychain (reused)",
        }.get(pw_source, pw_source or "—"),
        "SSL verify": "[yellow]disabled[/yellow]" if insecure else "enabled",
    }
    if cfg_path:
        kv_rows["Config file"] = str(cfg_path)
    kv_table(f"{ICONS['shield']} Connection saved", kv_rows)

    next_steps([
        "Verify the connection: `scc status`",
        "Browse files:          `scc fs-list`",
        "Run something:         `scc exec test.ping`",
        f"Switch profile:        `scc profile use {selected_profile}`",
        "List profiles:         `scc profile list`",
        "Remove:                `scc profile delete <name>`",
    ])


@cli.command()
@click.option("--purge", is_flag=True, default=False,
              help="Also remove server_url and username from the config file.")
@click.option("--all", "clear_all", is_flag=True, default=False,
              help="Remove every cached session token across all servers/users.")
@click.option("--yes", "-y", "assume_yes", is_flag=True, default=False,
              help="Skip the confirmation prompt.")
@click.pass_context
def disconnect(ctx, purge, clear_all, assume_yes):
    """
    Disconnect from the current RaaS server.

    Removes the saved password from the OS keychain and clears any cached
    session token. Pass --purge to also strip server_url/username from
    your config file so the next CLI invocation starts clean.

    \b
    Examples:
      $ scc disconnect              # forget current credentials only
      $ scc disconnect --purge      # also wipe server/username from config
      $ scc disconnect --all        # plus clear every cached token
      $ scc disconnect --yes        # non-interactive (no confirmation)
    """
    banner(version=__version__, subtitle=f"{ICONS['lock']} Disconnect")

    settings = SaltConfigSettings.load_from_file(_GLOBAL_CONFIG_PATH, _ACTIVE_PROFILE_OVERRIDE)
    srv = settings.server_url
    user = settings.username
    credential_identity = user or "__csp__"

    if not srv or srv == "https://localhost" or (settings.auth == "password" and not user):
        ui_warn("No active connection to disconnect.",
                hint="Run `scc connect` to set one up.")
        return

    console.print(
        f"  [dim]Server:[/dim]   [cyan]{srv}[/cyan]\n"
        f"  [dim]Username:[/dim] [cyan]{user}[/cyan]\n"
    )

    if not assume_yes and sys.stdin.isatty():
        prompt_msg = "Disconnect and forget credentials?"
        if purge:
            prompt_msg += " (also purge config file)"
        if not click.confirm(prompt_msg, default=True):
            console.print("[yellow]Aborted.[/yellow]\n")
            sys.exit(1)

    # 1. Remove the keychain entry.
    if keychain_available():
        if keychain_delete(srv, credential_identity):
            ui_success("Removed keychain entry.")
        else:
            ui_warn("No keychain entry found.")
    else:
        ui_warn("No OS keychain backend available - nothing to remove from keychain.")

    # 2. Clear the session token cache.
    try:
        from salt_config_cli.api.token_cache import get_token_cache
        cache = get_token_cache()
        if clear_all:
            count = cache.clear_all()
            ui_success(f"Cleared {count} cached session token(s).")
        else:
            cache.delete(srv, user)
            ui_success("Cleared cached session token.")
    except Exception as e:
        ui_warn(f"Could not clear token cache: {e}")

    # 3. Optionally remove the selected profile from its config file.
    if purge:
        try:
            store = ProfileConfigStore(_GLOBAL_CONFIG_PATH)
            removed = store.delete_profile(settings.profile_name)
            ui_success(f"Deleted profile '{settings.profile_name}' from {store.path}")
        except Exception as e:
            ui_warn(f"Could not delete profile '{settings.profile_name}': {e}")

    next_steps([
        "Reconnect later: `scc connect`",
        "List remaining cached tokens: `scc doctor`",
    ])


@cli.command(hidden=True)
@click.option("--server", "-s", envvar="SCC_SERVER_URL", help="RaaS server URL")
@click.option("--username", "-u", envvar="SCC_USERNAME", help="Username")
@click.pass_context
def login(ctx, server, username):
    """Store the password for an already-configured server in your OS keychain.

    \b
    NOTE: For first-time setup, prefer `scc connect`, which also saves the
    server URL and username so you never need to pass --server again.
    Use `scc login` only to refresh the keychain password for the existing
    configured (server, username).

    \b
    Reads server/username from your config file if --server / --username
    are omitted. Prompts for the password (masked, never echoed).

    On macOS, this uses Keychain; on Linux, Secret Service / kwallet; on
    Windows, Credential Manager. Falls back with a clear message if no
    keychain backend is available.
    """
    banner(version=__version__, subtitle=f"{ICONS['shield']} Login (OS keychain)")

    if not keychain_available():
        ui_error("No OS keychain backend available.")
        next_steps(
            [
                "Install the `keyring` package: `pip install keyring`",
                "On Linux you may also need `secretstorage` or `kwallet`.",
                "Alternatively use `--password-file ~/.scc/password` (chmod 600).",
            ]
        )
        sys.exit(1)

    settings = SaltConfigSettings.load_from_file(_GLOBAL_CONFIG_PATH, _ACTIVE_PROFILE_OVERRIDE)
    srv = server or settings.server_url
    user = username or settings.username

    if not srv or srv == "https://localhost":
        ui_error("Server URL is required.", hint="Pass --server or set server_url in .scc/config.yaml")
        sys.exit(2)
    if not user:
        ui_error("Username is required.", hint="Pass --username or set username in .scc/config.yaml")
        sys.exit(2)

    pw = prompt_password(f"Password for {user}@{srv}")
    if not pw:
        ui_error("Empty password; aborting.")
        sys.exit(1)

    if keychain_set(srv, user, pw):
        ui_success("Stored password in OS keychain.", hint=f"{user}@{srv}")
        kv_table(
            f"{ICONS['shield']} Stored",
            {
                "Server": srv,
                "Username": user,
                "Password": mask(pw),
                "Source": "OS keychain (secure)",
            },
        )
        next_steps(
            [
                "Try it: `scc status` (no --password needed)",
                "Update later: `scc login` again",
                "Full reset (server + user + password): `scc connect`",
                "Remove: `scc disconnect` (or `scc logout`)",
            ]
        )
    else:
        ui_error("Failed to write to keychain.")
        sys.exit(1)


@cli.command(hidden=True)
@click.option("--server", "-s", envvar="SCC_SERVER_URL", help="RaaS server URL")
@click.option("--username", "-u", envvar="SCC_USERNAME", help="Username")
@click.option("--all", "clear_all", is_flag=True, help="Remove all stored credentials")
@click.pass_context
def logout(ctx, server, username, clear_all):
    """Remove credentials from the OS keychain.

    \b
    Examples:
      $ scc logout
      $ scc logout --all
    """
    if not keychain_available():
        ui_warn("No OS keychain backend available - nothing to remove.")
        return

    settings = SaltConfigSettings.load_from_file(_GLOBAL_CONFIG_PATH, _ACTIVE_PROFILE_OVERRIDE)
    srv = server or settings.server_url
    user = username or settings.username

    if clear_all:
        # We don't enumerate all keys (the keyring API doesn't expose listing portably);
        # at minimum, delete the active one.
        if srv and user:
            keychain_delete(srv, user)
        ui_success("Cleared keychain entry for the active server/username.")
        ui_hint("To remove other entries, run `scc logout --server <URL> --username <USER>`.")
        return

    if not srv or not user:
        ui_error("Server URL and username are required to log out.", hint="Pass --server and --username")
        sys.exit(2)

    if keychain_delete(srv, user):
        ui_success(f"Removed keychain entry for {user}@{srv}")
    else:
        ui_warn(f"No keychain entry found for {user}@{srv}")


@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Output diagnostics as JSON")
@common_options
@click.pass_context
def doctor(ctx, as_json, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """Run end-to-end environment diagnostics.

    Verifies Python version, required packages, workspace files, server URL
    reachability, authentication, and token cache health.
    """
    setup_logging(log_level, no_color)
    import importlib
    import platform
    import socket
    from urllib.parse import urlparse

    settings = load_settings(config, server, username, password, csp_token, password_stdin=password_stdin, password_file=password_file, password_prompt=password_prompt)

    banner(version=__version__, subtitle=f"{ICONS['shield']} Doctor - environment diagnostics")

    checks: list[dict] = []

    def record(name: str, ok: bool, detail: str = "", suggestion: str = "") -> None:
        checks.append({"name": name, "ok": ok, "detail": detail, "suggestion": suggestion})

    # Python version
    py_ver = platform.python_version()
    py_ok = sys.version_info >= (3, 9)
    record(
        "Python >= 3.9",
        py_ok,
        f"Found {py_ver}",
        "Install Python 3.9 or newer" if not py_ok else "",
    )

    # Required packages
    required_pkgs = ["click", "yaml", "rich", "pydantic", "httpx", "tabulate", "dotenv"]
    for pkg in required_pkgs:
        try:
            mod = importlib.import_module(pkg)
            ver = getattr(mod, "__version__", "?")
            record(f"package: {pkg}", True, f"v{ver}")
        except Exception as e:
            record(f"package: {pkg}", False, str(e), f"pip install {pkg}")

    # Workspace
    scc_dir = Path.cwd() / ".scc"
    record(
        "Workspace .scc/ present",
        scc_dir.exists(),
        str(scc_dir) if scc_dir.exists() else "missing",
        "Run `scc init` to create the workspace" if not scc_dir.exists() else "",
    )

    config_file = scc_dir / "config.yaml"
    record(
        "Config .scc/config.yaml",
        config_file.exists(),
        str(config_file) if config_file.exists() else "missing",
        "Create .scc/config.yaml with server_url, username, password" if not config_file.exists() else "",
    )

    # Server URL format
    parsed = urlparse(settings.server_url or "")
    url_ok = bool(parsed.scheme in {"http", "https"} and parsed.hostname)
    record(
        "Server URL configured",
        url_ok,
        settings.server_url or "(empty)",
        "Set `server_url: https://your-raas.example.com` in .scc/config.yaml" if not url_ok else "",
    )

    # Server DNS resolution
    if url_ok and parsed.hostname:
        try:
            with spinner(f"Resolving DNS for {parsed.hostname}…"):
                socket.gethostbyname(parsed.hostname)
            record("Server DNS resolves", True, parsed.hostname)
        except Exception as e:
            record("Server DNS resolves", False, str(e), "Check VPN / DNS / /etc/hosts")

    # Server TCP port reachability
    if url_ok and parsed.hostname:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            with spinner(f"Probing TCP {parsed.hostname}:{port}…"):
                with socket.create_connection((parsed.hostname, port), timeout=5):
                    pass
            record(f"Server TCP {port} open", True, f"{parsed.hostname}:{port}")
        except Exception as e:
            record(
                f"Server TCP {port} open",
                False,
                str(e),
                "Check VPN, firewall, and that the host is up",
            )

    # Auth credentials present
    has_user = bool(settings.username)
    has_pw = bool(settings.password)
    has_csp = bool(getattr(settings, "csp_api_token", None))
    has_keychain_entry = bool(
        has_user
        and settings.server_url
        and keychain_available()
        and __import__("salt_config_cli.ui.secrets", fromlist=["keychain_get"]).keychain_get(
            settings.server_url, settings.username
        )
    )
    # "OK" means: we have *some* way to authenticate without re-prompting.
    auth_ok = (has_user and has_pw) or has_csp or has_keychain_entry
    if has_user and has_pw:
        detail = f"username/password (source: {getattr(settings, '_password_source', 'config')})"
    elif has_csp:
        detail = "csp_api_token"
    elif has_keychain_entry:
        detail = f"keychain entry for {settings.username}@{settings.server_url}"
    elif has_user:
        detail = "username set, password will be prompted at runtime"
    else:
        detail = "no username/password/keychain entry/CSP token"
    suggestion = ""
    if not auth_ok:
        suggestion = (
            "Run `scc login` to store credentials in the OS keychain, "
            "or pass `--password-prompt` / `--password-file` at runtime."
        )
    # Username-set-but-no-password is informational, not a failure:
    # the CLI will prompt on demand. Only mark failure when we have *nothing*.
    record(
        "Credentials configured",
        auth_ok or has_user,
        detail,
        suggestion,
    )

    # OS keychain (informational - failing this is non-fatal)
    record(
        "OS keychain available",
        True,  # always pass: keychain is optional
        "ready for `scc login`" if keychain_available() else "not available (install `keyring`)",
    )

    # Token cache (not a hard requirement; informational only)
    try:
        from salt_config_cli.api.token_cache import get_token_cache
        cache_obj = get_token_cache()
        cached = cache_obj.get(settings.server_url, settings.username) if url_ok else None
        record(
            "Auth token cache",
            True,
            "valid token cached" if cached else "no cached token (will authenticate on next call)",
        )
    except Exception as e:
        record("Auth token cache", False, str(e))

    # API probe (only if everything else looks OK)
    if url_ok and auth_ok:
        try:
            from salt_config_cli.api.client import AriaConfigClient
            with spinner("Authenticating with RaaS…"):
                client = AriaConfigClient.from_settings(settings)
            record(
                "RaaS auth & API probe",
                True,
                f"API v{client._api_version or 'unknown'}",
            )
        except Exception as e:
            record("RaaS auth & API probe", False, str(e), "Run `scc clear-cache` and retry")

    # Output
    if as_json:
        console.print_json(data={"checks": checks})
        sys.exit(0 if all(c["ok"] for c in checks) else 1)

    from rich.box import ROUNDED
    from rich.panel import Panel
    from rich.table import Table

    table = Table(show_header=True, box=None, padding=(0, 2), expand=False, header_style="scc.label")
    table.add_column(" ", no_wrap=True)
    table.add_column("Check", style="scc.value", no_wrap=False)
    table.add_column("Detail", style="scc.muted", overflow="fold")

    failures: list[dict] = []
    for c in checks:
        icon = f"[scc.success]{ICONS['success']}[/scc.success]" if c["ok"] else f"[scc.danger]{ICONS['fail']}[/scc.danger]"
        table.add_row(icon, c["name"], c["detail"] or "")
        if not c["ok"]:
            failures.append(c)

    console.print(
        Panel(
            table,
            title=f"[scc.title]{ICONS['magnify']} Diagnostics[/scc.title]",
            border_style="scc.muted",
            box=ROUNDED,
            padding=(0, 1),
        )
    )

    if failures:
        ui_warn(f"{len(failures)} check(s) failed.")
        steps_list = []
        for f in failures:
            if f["suggestion"]:
                steps_list.append(f"{f['name']}: {f['suggestion']}")
        if steps_list:
            next_steps(steps_list, title="Suggested fixes")
        sys.exit(1)

    ui_success("All diagnostics passed.")


@cli.command()
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish", "auto"]), default="auto")
@click.option("--install", is_flag=True, help="Install completion into your shell rc file")
@click.option("--show", is_flag=True, help="Print the completion script to stdout")
@click.pass_context
def completion(ctx, shell, install, show):
    """Generate and install Tab-completion for your shell.

    \b
    Examples:
      $ scc completion                # auto-detect your shell and print instructions
      $ scc completion bash --show    # print the bash completion script
      $ scc completion --install      # auto-install for your current shell
      $ scc completion zsh --install  # install zsh completion
    """
    import os as _os

    detected: str
    if shell == "auto":
        sh_env = _os.environ.get("SHELL", "")
        if "zsh" in sh_env:
            detected = "zsh"
        elif "fish" in sh_env:
            detected = "fish"
        else:
            detected = "bash"
    else:
        detected = shell

    rc_files = {
        "bash": Path.home() / ".bashrc",
        "zsh": Path.home() / ".zshrc",
        "fish": Path.home() / ".config" / "fish" / "completions" / "scc.fish",
    }

    eval_lines = {
        "bash": 'eval "$(_SCC_COMPLETE=bash_source scc)"',
        "zsh": 'eval "$(_SCC_COMPLETE=zsh_source scc)"',
        "fish": "_SCC_COMPLETE=fish_source scc | source",
    }

    banner(version=__version__, subtitle=f"{ICONS['sparkle']} Shell completion ({detected})")

    if show:
        import subprocess
        env = dict(_os.environ, **{"_SCC_COMPLETE": f"{detected}_source"})
        result = subprocess.run(["scc"], env=env, capture_output=True, text=True)
        console.print(result.stdout)
        return

    snippet = eval_lines[detected]
    rc_path = rc_files[detected]

    kv_table(
        f"{ICONS['gear']} Completion details",
        {
            "Shell": detected,
            "RC file": str(rc_path),
            "Snippet": snippet,
        },
    )

    if install:
        try:
            rc_path.parent.mkdir(parents=True, exist_ok=True)
            existing = rc_path.read_text() if rc_path.exists() else ""
            marker = "# >>> scc completion >>>"
            end_marker = "# <<< scc completion <<<"
            block = f"\n{marker}\n{snippet}\n{end_marker}\n"
            if marker in existing:
                ui_info("Completion block already present in rc file - leaving as is.")
            else:
                with rc_path.open("a") as f:
                    f.write(block)
                ui_success(f"Installed completion in {rc_path}")
            next_steps(
                [
                    f"Reload your shell: `source {rc_path}` (or open a new terminal)",
                    "Try it: type `scc ` and press Tab",
                ]
            )
        except Exception as e:
            ui_error(f"Failed to install completion: {e}")
            sys.exit(1)
    else:
        next_steps(
            [
                f"Add this line to {rc_path}: `{snippet}`",
                "Or run: `scc completion --install` to auto-install",
                "Reload your shell, then press Tab after `scc `",
            ]
        )


@cli.command()
@click.option(
    "--json", "as_json",
    is_flag=True,
    help="Output in JSON format"
)
@common_options
@click.pass_context
def show(ctx, as_json, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """
    Show expected configuration.
    
    Displays all resources defined in YAML configuration files.
    
    \b
    Examples:
      $ scc show
      $ scc show --json
    """
    setup_logging(log_level, no_color)
    
    from salt_config_cli.core.plan import PlanExecutor
    
    settings = load_settings(config, server, username, password, csp_token, password_stdin=password_stdin, password_file=password_file, password_prompt=password_prompt)
    
    # Load expected configuration from YAML files
    state_manager = StateManager(
        state_path=settings.state_file,
        backend=settings.state_backend
    )
    
    executor = PlanExecutor(
        state_manager=state_manager,
        api_client=None,
        config_dir=settings.working_dir
    )
    
    resources = executor.load_configuration()
    
    if as_json:
        output = {
            "resources": [
                {
                    "resource_type": r.resource_type_value,
                    "name": r.metadata.name,
                    "description": r.metadata.description,
                    "labels": r.metadata.labels,
                    "spec": r.spec
                }
                for r in resources
            ]
        }
        console.print_json(data=output)
    else:
        console.print("\n[bold blue]Expected Configuration[/bold blue]\n")
        
        if not resources:
            console.print("  No resources defined in configuration files.\n")
            console.print("  Create YAML files with resource definitions.\n")
            return
        
        # Group by resource type
        by_type = {}
        for r in resources:
            rtype = r.resource_type_value
            if rtype not in by_type:
                by_type[rtype] = []
            by_type[rtype].append(r)
        
        for rtype, type_resources in sorted(by_type.items()):
            console.print(f"[bold]{rtype}[/bold] ({len(type_resources)})")
            for r in type_resources:
                desc = f" - {r.metadata.description}" if r.metadata.description else ""
                console.print(f"  • {r.metadata.name}{desc}")
            console.print()
        
        console.print(f"[dim]Total: {len(resources)} resource(s)[/dim]\n")


@cli.command()
@common_options
@click.pass_context
def refresh(ctx, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """
    Update local state from remote.
    
    Fetches the current state of resources from the server.
    
    \b
    Examples:
      $ scc refresh
    """
    setup_logging(log_level, no_color)
    
    settings = load_settings(config, server, username, password, csp_token, password_stdin=password_stdin, password_file=password_file, password_prompt=password_prompt)
    
    console.print("\n[bold blue]Refreshing state...[/bold blue]\n")
    
    # Initialize state manager
    state_manager = StateManager(
        state_path=settings.state_file,
        backend=settings.state_backend
    )
    
    # TODO: Connect to server and refresh
    console.print("[yellow]Note:[/yellow] Remote refresh requires server connection.\n")
    console.print("Configure server with --server or SCC_SERVER_URL environment variable.\n")


@cli.command("list")
@click.option(
    "--type", "-t", "resource_type",
    type=click.Choice(["all", "state-files", "target-groups", "jobs", "pillars", "minions", "schedules", "envs"]),
    default="all",
    help="Type of resources to list"
)
@click.option(
    "--env", "-e", "saltenv",
    help="Salt environment (for state files)"
)
@click.option(
    "--json", "as_json",
    is_flag=True,
    help="Output in JSON format"
)
@common_options
@click.pass_context
def list_resources(ctx, resource_type, saltenv, as_json, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """
    List resources from the RaaS server.
    
    Shows state files, target groups, jobs, pillars, minions, and schedules
    currently configured on the Aria Automation Config server.
    
    \b
    Resource Types:
      state-files    - State files (.sls) from the file server
      target-groups  - Target group definitions
      jobs           - Job configurations
      pillars        - Pillar data definitions
      minions        - Connected Salt minions
      schedules      - Scheduled jobs
      envs           - Salt environments
    
    \b
    Examples:
      $ scc list
      $ scc list --type state-files
      $ scc list --type state-files --env vcfsecops
      $ scc list --type target-groups --json
    """
    setup_logging(log_level, no_color)
    
    settings = load_settings(config, server, username, password, csp_token, password_stdin=password_stdin, password_file=password_file, password_prompt=password_prompt)

    if not as_json:
        command_header(
            "list",
            "Browse RaaS resources",
            description="Discover server-side objects before running or changing anything.",
            icon="magnify",
            meta=[
                ("Resource type", resource_type),
                ("Environment", saltenv or "all"),
                ("Server", mask_url(settings.server_url)),
            ],
        )

    api_client = connect_client(settings, label="resource discovery")
    if not as_json:
        ui_success(f"Connected to {mask_url(settings.server_url)}")

    results = {}
    
    # Collect requested resources
    if resource_type in ("all", "state-files"):
        results["state_files"] = _list_state_files(api_client, saltenv)
    
    if resource_type in ("all", "target-groups"):
        results["target_groups"] = _list_target_groups(api_client)
    
    if resource_type in ("all", "jobs"):
        results["jobs"] = _list_jobs(api_client)
    
    if resource_type in ("all", "pillars"):
        results["pillars"] = _list_pillars(api_client)
    
    if resource_type in ("all", "minions"):
        results["minions"] = _list_minions(api_client)
    
    if resource_type in ("all", "schedules"):
        results["schedules"] = _list_schedules(api_client)
    
    if resource_type in ("all", "envs"):
        verbose = log_level == "debug"
        results["environments"] = _list_environments(api_client, verbose=verbose)
    
    # Display results
    if as_json:
        console.print_json(data=results)
    else:
        _display_resource_list(results, resource_type)
        total = sum(len(value) for value in results.values() if isinstance(value, list))
        result_summary(
            "Resource discovery complete",
            status="success" if total else "warning",
            message=(
                f"Found {total} resource item(s) across {len(results)} requested category(ies)."
                if total else
                "The request completed successfully, but no matching resources were returned."
            ),
            metrics=[(len(results), "categories", "primary"), (total, "items", "success" if total else "warning")],
        )
        next_steps(
            [
                "Inspect Salt files: `scc fs-list`",
                "Inspect targeting: `scc target-group-list`",
                "Test one minion safely: `scc exec test.ping --target <minion-id> --output text`",
            ],
            title="Useful follow-up commands",
        )

    api_client.close()


def _get_content_type(filename: str) -> str:
    """
    Determine the content type based on file extension.
    
    Must match RaaS expected values from the API schema:
    - text/x-yaml (for SLS, YAML, YML, JINJA files)
    - text/x-python (for Python files)
    - application/json (for JSON files)
    - text/plain (for plain text)
    - application/x-rpm (for RPM, WHL files)
    - application/octet-stream (for binary/archive files)
    """
    extension_map = {
        # YAML/Salt state files
        'sls': 'text/x-yaml',
        'yaml': 'text/x-yaml',
        'yml': 'text/x-yaml',
        'jinja': 'text/x-yaml',
        # Python
        'py': 'text/x-python',
        # JSON
        'json': 'application/json',
        # Plain text
        'txt': 'text/plain',
        # RPM/packages
        'rpm': 'application/x-rpm',
        'whl': 'application/x-rpm',
        'deb': 'application/octet-stream',
        # Archives/binary
        'gz': 'application/octet-stream',
        'tar': 'application/octet-stream',
        'zip': 'application/octet-stream',
        'bin': 'application/octet-stream',
    }
    
    # Get extension (lowercase, without dot)
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    return extension_map.get(ext, 'application/octet-stream')


def _is_text_content_type(ct: str) -> bool:
    """Return True for content types that are safe to read as utf-8 text."""
    if not ct:
        return False
    return ct.startswith("text/") or ct in ("application/json", "application/xml", "application/yaml")


def _read_local_file(path: Path) -> tuple:
    """Read a local file, returning (contents_str, content_type, is_binary).

    Binary files are base64-encoded so they can be transported as a JSON string.
    """
    content_type = _get_content_type(path.name)
    if _is_text_content_type(content_type):
        try:
            return path.read_text(encoding="utf-8"), content_type, False
        except UnicodeDecodeError:
            # Fall through to binary handling
            pass
    # Binary fallback (base64) — RaaS supports this for non-text uploads.
    import base64 as _b64
    data = path.read_bytes()
    return _b64.b64encode(data).decode("ascii"), content_type, True


def _upload_single_file(
    api_client,
    *,
    local_path: Path,
    remote_path: str,
    saltenv: str,
    force: bool = False,
) -> dict:
    """Upload one local file to the RaaS file server.

    Returns a dict with keys: ok (bool), action (created|updated|skipped|failed),
    remote_path, uuid, error (optional message).
    """
    result = {
        "ok": False,
        "action": "failed",
        "remote_path": remote_path,
        "local_path": str(local_path),
        "uuid": "",
        "error": "",
    }

    try:
        exists_resp = api_client.call("fs", "file_exists", path=remote_path, saltenv=saltenv)
        file_exists = bool(exists_resp.success and exists_resp.ret)

        if file_exists and not force:
            result["ok"] = False
            result["action"] = "skipped"
            result["error"] = "exists (use --force to overwrite)"
            return result

        contents, content_type, _is_binary = _read_local_file(local_path)
        operation = "update_file" if file_exists else "save_file"

        resp = api_client.call(
            "fs", operation,
            path=remote_path,
            contents=contents,
            saltenv=saltenv,
            content_type=content_type,
        )

        if resp.error:
            msg = (
                resp.error.get("message", "unknown error")
                if isinstance(resp.error, dict)
                else str(resp.error)
            )
            result["error"] = msg
            return result

        result["ok"] = True
        result["action"] = "updated" if file_exists else "created"
        if resp.ret and isinstance(resp.ret, dict):
            result["uuid"] = resp.ret.get("uuid", "")
        return result

    except Exception as exc:
        result["error"] = str(exc)
        return result


def _collect_local_uploads(
    source: Path,
    *,
    remote_base: Optional[str],
    include: Sequence[str] = (),
    exclude: Sequence[str] = (),
) -> list:
    """Walk a file or folder and produce a plan of (local_path, remote_path) pairs.

    Args:
        source: a file or directory path.
        remote_base: target prefix on the file server. For a single file, this
            becomes the full remote path (default: /<filename>). For a folder,
            files are placed under this prefix, preserving relative paths
            (default: /<folder-name>/...).
        include: optional list of fnmatch patterns; if non-empty, only files
            matching at least one pattern are kept.
        exclude: optional list of fnmatch patterns; files matching any
            pattern are dropped (applied after include).
    """
    import fnmatch

    def _matches_any(name: str, patterns: Sequence[str]) -> bool:
        return any(fnmatch.fnmatchcase(name, p) for p in patterns)

    plan: list = []

    if source.is_file():
        if remote_base:
            remote = remote_base if remote_base.startswith("/") else "/" + remote_base
            # If remote_base ends with "/", treat as a folder: append filename.
            if remote.endswith("/"):
                remote = remote + source.name
        else:
            remote = "/" + source.name
        plan.append((source, remote))
        return plan

    # Directory: walk recursively
    base_prefix = (remote_base or "/" + source.name).rstrip("/")
    if not base_prefix.startswith("/"):
        base_prefix = "/" + base_prefix

    # Default exclusions that nobody wants on the file server
    default_excludes = (
        ".git/*", "*/.git/*", "__pycache__/*", "*/__pycache__/*",
        "*.pyc", ".DS_Store", "*/.DS_Store", "*.swp", "*~",
    )
    all_excludes = list(exclude) + list(default_excludes)

    for entry in sorted(source.rglob("*")):
        if not entry.is_file():
            continue
        rel = entry.relative_to(source).as_posix()
        if include and not _matches_any(rel, include) and not _matches_any(entry.name, include):
            continue
        if _matches_any(rel, all_excludes) or _matches_any(entry.name, all_excludes):
            continue
        remote = f"{base_prefix}/{rel}"
        plan.append((entry, remote))

    return plan


def _resolve_editor() -> list:
    """Return the editor command (as argv-style list) to launch.

    Honors $VISUAL, then $EDITOR, then falls back to a sensible default.
    """
    import shlex
    for var in ("VISUAL", "EDITOR"):
        val = os.environ.get(var)
        if val:
            return shlex.split(val)
    # Fallbacks per platform
    if sys.platform == "win32":
        return ["notepad"]
    for cmd in ("nano", "vim", "vi"):
        from shutil import which as _which
        if _which(cmd):
            return [cmd]
    return ["vi"]


def _open_in_editor(file_path: Path) -> int:
    """Open ``file_path`` in the user's editor; return the exit code."""
    import subprocess
    cmd = _resolve_editor() + [str(file_path)]
    return subprocess.call(cmd)


def _list_state_files(api_client, saltenv: Optional[str] = None) -> list:
    """List state files from file server."""
    files = []
    
    # Get all environments if not specified
    if saltenv:
        envs = [saltenv]
    else:
        resp = api_client.call("fs", "get_envs")
        envs = resp.ret if resp.success else []
    
    for env in envs:
        resp = api_client.call("fs", "get_env", saltenv=env)
        if resp.success and resp.ret:
            for f in resp.ret:
                files.append({
                    "path": f.get("path", ""),
                    "uuid": f.get("uuid", ""),
                    "saltenv": f.get("saltenv", env),
                    "content_type": f.get("content_type", ""),
                })
    
    return files


def _list_fs_files(api_client, saltenv: Optional[str] = None) -> list:
    """List files on the RaaS file server, optionally filtered by environment.

    Returns a list of dicts with keys: path, saltenv, uuid, content_type, size.
    When ``saltenv`` is None, all environments are queried.
    """
    files: list = []

    if saltenv:
        envs = [saltenv]
    else:
        resp = api_client.call("fs", "get_envs")
        if resp.success and resp.ret:
            ret = resp.ret
            envs = ret if isinstance(ret, list) else (ret.get("results", []) if isinstance(ret, dict) else [])
        else:
            envs = []

    for env in envs:
        resp = api_client.call("fs", "get_env", saltenv=env)
        if not (resp.success and resp.ret):
            continue
        items = resp.ret if isinstance(resp.ret, list) else resp.ret.get("results", [])
        for f in items or []:
            if not isinstance(f, dict):
                continue
            files.append({
                "path": f.get("path", ""),
                "saltenv": f.get("saltenv", env),
                "uuid": f.get("uuid", ""),
                "content_type": f.get("content_type", ""),
                "size": f.get("size", f.get("file_size", None)),
                "updated": f.get("ts_updated", f.get("updated", "")),
            })

    return files


def _build_fs_tree(files: list) -> dict:
    """Build a nested dict tree from a flat list of files.

    Each level is a dict of name -> (sub-dict for folders | file-info dict for files).
    Files are stored with key "__file__" set to True so they can be distinguished
    from directories at render time.

    Example structure::

        {
            "vcfsecops": {
                "states": {
                    "init.sls": {"__file__": True, "path": "/states/init.sls", ...},
                },
                "pillars": { ... },
            }
        }
    """
    root: dict = {}
    for f in files:
        env = f.get("saltenv") or "base"
        path = (f.get("path") or "").lstrip("/")
        if not path:
            continue
        parts = path.split("/")
        node = root.setdefault(env, {})
        for part in parts[:-1]:
            child = node.get(part)
            if not isinstance(child, dict) or child.get("__file__"):
                child = {}
                node[part] = child
            node = child
        leaf = parts[-1]
        node[leaf] = {
            "__file__": True,
            "path": f.get("path", ""),
            "saltenv": env,
            "uuid": f.get("uuid", ""),
            "content_type": f.get("content_type", ""),
            "size": f.get("size"),
        }
    return root


def _fs_file_icon(name: str, content_type: str = "") -> str:
    """Pick an icon for a file based on extension/content-type."""
    n = name.lower()
    if n.endswith((".sls", ".yaml", ".yml", ".jinja")):
        return ICONS.get("pillar", "•")
    if n.endswith(".py"):
        return ICONS.get("gear", "•")
    if n.endswith(".json"):
        return ICONS.get("doc", "•")
    if n.endswith((".tar", ".gz", ".zip", ".rpm", ".whl", ".deb")):
        return ICONS.get("package", "•")
    if n.endswith((".sh", ".bash")):
        return ICONS.get("tool", "•")
    if n.endswith((".txt", ".log", ".md")):
        return ICONS.get("log", "•")
    return ICONS.get("doc", "•")


def _human_size(size) -> str:
    """Format byte size as a short human-readable string."""
    try:
        n = float(size)
    except (TypeError, ValueError):
        return ""
    if n < 1024:
        return f"{int(n)} B"
    for unit in ("KB", "MB", "GB", "TB"):
        n /= 1024.0
        if n < 1024:
            return f"{n:.1f} {unit}"
    return f"{n:.1f} PB"


def _render_fs_tree(root_dict: dict, *, title: Optional[str] = None, highlight_path: Optional[str] = None) -> None:
    """Render a nested fs tree using rich.tree.Tree."""
    from rich.tree import Tree
    from rich.text import Text

    folder_icon = ICONS.get("folder", "/")
    env_icon = ICONS.get("environment", "*")
    title_text = title or "RaaS file server"
    tree = Tree(f"[bold scc.accent]{folder_icon}  {title_text}[/bold scc.accent]", guide_style="scc.tree.guide")

    def _add(node: Tree, mapping: dict):
        # Sort: directories first, then files, both alphabetically
        dirs = sorted(
            (k for k, v in mapping.items() if isinstance(v, dict) and not v.get("__file__")),
            key=str.lower,
        )
        files = sorted(
            (k for k, v in mapping.items() if isinstance(v, dict) and v.get("__file__")),
            key=str.lower,
        )
        for name in dirs:
            sub = mapping[name]
            branch = node.add(f"[scc.tree.label]{folder_icon}  {name}[/scc.tree.label]")
            _add(branch, sub)
        for name in files:
            info = mapping[name]
            icon = _fs_file_icon(name, info.get("content_type", ""))
            size_str = _human_size(info.get("size"))
            full = info.get("path", "")
            is_highlight = highlight_path and full == highlight_path
            label = Text()
            label.append(f"{icon}  ", style="scc.muted")
            label.append(name, style="scc.value.strong" if is_highlight else "scc.value")
            if size_str:
                label.append(f"  ({size_str})", style="scc.muted")
            if is_highlight:
                label.append("  ← just uploaded", style="scc.success")
            node.add(label)

    for env in sorted(root_dict.keys(), key=str.lower):
        env_branch = tree.add(f"[scc.title]{env_icon}  {env}[/scc.title]")
        _add(env_branch, root_dict[env])

    console.print(tree)


def _filter_fs_files(files: list, path_filter: Optional[str]) -> list:
    """Filter files by a path prefix or fnmatch glob (case-sensitive)."""
    if not path_filter:
        return files
    import fnmatch
    pat = path_filter if path_filter.startswith("/") else "/" + path_filter
    out = []
    for f in files:
        p = f.get("path", "") or ""
        if "*" in pat or "?" in pat or "[" in pat:
            if fnmatch.fnmatchcase(p, pat) or fnmatch.fnmatchcase(p, pat + "*"):
                out.append(f)
        else:
            if p == pat or p.startswith(pat.rstrip("/") + "/"):
                out.append(f)
    return out


def _list_target_groups(api_client) -> list:
    """List target groups."""
    resp = api_client.call("tgt", "get_target_group")
    if resp.success and resp.ret:
        ret = resp.ret
        if isinstance(ret, list):
            return ret
        elif isinstance(ret, dict) and "results" in ret:
            return ret["results"]
    return []


def _list_jobs(api_client) -> list:
    """List jobs."""
    resp = api_client.call("job", "get_jobs")
    if resp.success and resp.ret:
        ret = resp.ret
        if isinstance(ret, list):
            return ret
        elif isinstance(ret, dict) and "results" in ret:
            return ret["results"]
    return []


def _list_pillars(api_client) -> list:
    """List pillars."""
    # Try different API method names - varies by RaaS version
    for method in ["get_pillars", "get_pillar"]:
        resp = api_client.call("pillar", method)
        if resp.success and resp.ret:
            ret = resp.ret
            if isinstance(ret, list):
                return ret
            elif isinstance(ret, dict) and "results" in ret:
                return ret["results"]
        # If method not found, try next one
        if resp.error and "not found" in str(resp.error.get("message", "")).lower():
            continue
        break
    return []


def _list_minions(api_client) -> list:
    """List minions."""
    resp = api_client.call("minions", "get_minion_details")
    if resp.success and resp.ret:
        ret = resp.ret
        if isinstance(ret, list):
            return ret
        elif isinstance(ret, dict) and "results" in ret:
            return ret["results"]
    return []


def _list_schedules(api_client) -> list:
    """List schedules."""
    # Try different API method names - varies by RaaS version
    for method in ["get_schedules", "get_schedule"]:
        resp = api_client.call("schedule", method)
        if resp.success and resp.ret:
            ret = resp.ret
            if isinstance(ret, list):
                return ret
            elif isinstance(ret, dict) and "results" in ret:
                return ret["results"]
        # If method not found, try next one
        if resp.error and "not found" in str(resp.error.get("message", "")).lower():
            continue
        break
    return []


def _list_environments(api_client, verbose: bool = False) -> list:
    """List Salt environments."""
    resp = api_client.call("fs", "get_envs")
    
    if verbose:
        console.print(f"[dim]API Response: success={resp.success}, ret type={type(resp.ret).__name__}[/dim]")
        if resp.error:
            console.print(f"[dim]API Error: {resp.error}[/dim]")
    
    if resp.success and resp.ret:
        ret = resp.ret
        
        if verbose:
            console.print(f"[dim]Raw response: {ret}[/dim]")
        
        # Handle various response formats
        if isinstance(ret, list):
            return ret
        elif isinstance(ret, dict):
            # API may return {"results": [...]} or {"envs": [...]}
            if "results" in ret:
                return ret["results"]
            if "envs" in ret:
                return ret["envs"]
            # Some APIs return {master_id: [env1, env2, ...]}
            # Collect all unique environments from all masters
            all_envs = set()
            for key, value in ret.items():
                if isinstance(value, list):
                    all_envs.update(value)
                elif isinstance(value, str):
                    all_envs.add(value)
            if all_envs:
                return sorted(list(all_envs))
            # Or it might be a dict of env_name -> details
            if ret and not any(k in ret for k in ["error", "message"]):
                return list(ret.keys())
        elif isinstance(ret, str):
            return [ret]
    elif resp.error:
        if verbose:
            console.print(f"[red]Error fetching environments: {resp.error}[/red]")
    return []


@cli.command("exec")
@click.argument("function")
@click.argument("args", nargs=-1)
@click.option(
    "--target", "-t",
    default=None,
    help="Target minion pattern (e.g., '*', 'web-*', 'os:VMkernel')"
)
@click.option(
    "--target-group", "-g",
    default=None,
    help="Target group name from RaaS (e.g., 'ops', 'All Minions')"
)
@click.option(
    "--target-type", "-T",
    type=click.Choice(["glob", "grain", "compound", "list", "nodegroup", "pillar", "pcre"]),
    default="glob",
    help="Target type (default: glob)"
)
@click.option(
    "--kwarg", "-k",
    multiple=True,
    help="Keyword argument in key=value format (can be used multiple times)"
)
@click.option(
    "--pillar", "-P",
    default=None,
    help="Pillar data as JSON string (e.g., '{\"key\": \"value\"}')"
)
@click.option(
    "--pillar-file",
    type=click.Path(exists=True),
    default=None,
    help="Path to YAML/JSON file containing pillar data"
)
@click.option(
    "--async", "run_async",
    is_flag=True,
    help="Run asynchronously (don't wait for result)"
)
@click.option(
    "--wait",
    type=int,
    default=600,
    show_default=True,
    metavar="SECONDS",
    help="Max seconds to wait for the job to complete. Use 0 for no timeout "
         "(wait forever until the job finishes or you press Ctrl+C). "
         "Use --async to submit and exit immediately.",
)
@click.option(
    "--output", "-o",
    "output_fmt",
    type=click.Choice(["yaml", "json", "text"], case_sensitive=False),
    default="text",
    show_default=True,
    help="Output format for results.",
)
@common_options
@click.pass_context
def exec_module(ctx, function, args, target, target_group, target_type, kwarg, pillar, pillar_file, run_async, wait, output_fmt, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """
    Execute a Salt module function on minions.
    
    Runs Salt execution modules (like test.ping, grains.items, cmd.run)
    directly on targeted minions.
    
    \b
    Common Functions:
      test.ping           - Check minion connectivity
      test.version        - Show Salt version
      grains.items        - List all grains
      grains.get <key>    - Get specific grain
      cmd.run <command>   - Run shell command
      pkg.list_pkgs       - List installed packages
      service.status <name> - Check service status
      disk.usage          - Show disk usage
      network.interfaces  - Show network interfaces
    
    \b
    Examples:
      $ scc exec test.ping
      $ scc exec test.ping --target "web-*"
      $ scc exec test.ping --target-group ops
      $ scc exec grains.get os
      $ scc exec cmd.run "uptime"
      
      # Target by grain
      $ scc exec test.ping --target "os:VMkernel" --target-type grain
      $ scc exec vcf_version.get_version --target "vcfops_resource_kind:nsx" -T grain
      
      # Compound targeting
      $ scc exec test.ping --target "G@os:VMkernel and web-*" --target-type compound
    """
    setup_logging(log_level, no_color)
    output_fmt = (output_fmt or "yaml").lower()
    # In structured-output modes, route all chatter to stderr so stdout stays
    # clean for piping into `jq`, `yq`, etc.
    info_console = themed_console if output_fmt == "text" else _stderr_console()
    
    settings = load_settings(config, server, username, password, csp_token, password_stdin=password_stdin, password_file=password_file, password_prompt=password_prompt)
    if output_fmt == "text":
        read_only_prefixes = ("test.", "grains.", "disk.", "network.", "pillar.", "service.status", "pkg.list")
        command_header(
            "exec",
            "Salt execution module",
            description="Run a function against an explicit minion scope and watch the result per minion.",
            icon="gear",
            meta=[
                ("Function", function),
                ("Scope", target_group or target or "all minions"),
                ("Output", output_fmt),
            ],
            mode=("READ ONLY", "black on #35e66f") if function.startswith(read_only_prefixes) else ("CONFIRM", "black on #e6c75a"),
        )
    api_client = connect_client(settings, label="Salt exec")
    if output_fmt == "text":
        ui_success(f"Connected to {mask_url(settings.server_url)}")
    else:
        info_console.print(f"[scc.muted]Connected to {mask_url(settings.server_url)} (output: {output_fmt})[/scc.muted]")
    
    # Default to all minions if neither target nor target_group specified
    if not target and not target_group:
        target = "*"
    
    # Resolve target group if specified
    resolved_target = target
    resolved_target_type = target_type
    
    if target_group:
        info_console.print(f"[bold]Resolving target group:[/bold] {target_group}...")
        groups = _list_target_groups(api_client)
        found = None
        for g in groups:
            if isinstance(g, dict) and g.get("name", "").lower() == target_group.lower():
                found = g
                break
        
        if not found:
            info_console.print(f"[red]✗[/red] Target group not found: {target_group}\n")
            info_console.print("Available target groups:")
            for g in groups[:10]:
                if isinstance(g, dict):
                    info_console.print(f"  • {g.get('name', 'unknown')}")
            sys.exit(1)
        
        tgt_spec_from_group = found.get("tgt", {})
        if isinstance(tgt_spec_from_group, dict):
            for master_key, master_tgt in tgt_spec_from_group.items():
                if isinstance(master_tgt, dict):
                    resolved_target = master_tgt.get("tgt", "*")
                    resolved_target_type = master_tgt.get("tgt_type", "glob")
                    break
        
        info_console.print(f"[green]✓[/green] Resolved: target={resolved_target}, type={resolved_target_type}\n")
    
    if output_fmt == "text":
        kv_table(
            f"{ICONS['target']} Execution request",
            [
                ("Function", function),
                ("Target", resolved_target),
                ("Target type", resolved_target_type),
                ("Target group", target_group or "-"),
                ("Arguments", json.dumps(list(args), default=str) if args else "none"),
                ("Keyword arguments", ", ".join(kwarg) if kwarg else "none"),
                ("Wait", "async" if run_async else f"up to {wait}s" if wait else "until complete"),
            ],
        )
    else:
        info_console.print(f"[scc.muted]Function: {function} · target: {resolved_target} ({resolved_target_type})[/scc.muted]")
    
    # Parse kwargs from key=value format
    parsed_kwargs = {}
    for kv in kwarg:
        if "=" in kv:
            key, value = kv.split("=", 1)
            # Try to parse as JSON for complex values
            try:
                import json
                parsed_kwargs[key] = json.loads(value)
            except (json.JSONDecodeError, ValueError):
                parsed_kwargs[key] = value
    
    # Parse pillar data
    pillar_data = None
    if pillar_file:
        try:
            import yaml
            with open(pillar_file, 'r') as f:
                pillar_data = yaml.safe_load(f)
            console.print(f"[bold]Pillar file:[/bold] {pillar_file}")
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to load pillar file: {e}\n")
            sys.exit(1)
    elif pillar:
        try:
            import json
            pillar_data = json.loads(pillar)
            console.print(f"[bold]Pillar:[/bold] (inline JSON)")
        except json.JSONDecodeError as e:
            console.print(f"[red]✗[/red] Invalid pillar JSON: {e}\n")
            sys.exit(1)
    
    # Build target specification
    tgt_spec = {
        "*": {
            "tgt": resolved_target,
            "tgt_type": resolved_target_type
        }
    }
    
    # Build arg specification
    arg_spec = {}
    if args:
        arg_spec["arg"] = list(args)
    if parsed_kwargs:
        arg_spec["kwarg"] = parsed_kwargs
    
    info_console.print(f"[bold blue]Executing {function}...[/bold blue]\n")
    
    try:
        call_params = {
            "cmd": "local",
            "fun": function,
            "tgt": tgt_spec,
        }
        
        # Build arg structure - pillar goes inside arg.kwarg.pillar
        if arg_spec or pillar_data:
            if not arg_spec:
                arg_spec = {}
            if pillar_data:
                if "kwarg" not in arg_spec:
                    arg_spec["kwarg"] = {}
                arg_spec["kwarg"]["pillar"] = pillar_data
            call_params["arg"] = arg_spec
        
        resp = api_client.call("cmd", "route_cmd", **call_params)
        
        if resp.error:
            info_console.print(f"[red]✗[/red] Error: {resp.error.get('message', 'Unknown error')}\n")
            sys.exit(1)
        
        jid = resp.ret if isinstance(resp.ret, str) else resp.ret.get("jid", "unknown") if isinstance(resp.ret, dict) else str(resp.ret)
        
        if run_async:
            payload = {"jid": jid, "status": "submitted", "function": function, "target": resolved_target}
            if output_fmt == "json":
                _print_stdout(json.dumps(payload, indent=2, default=str))
            elif output_fmt == "yaml":
                import yaml as _yaml
                _print_stdout(_yaml.safe_dump(payload, sort_keys=False, default_flow_style=False).rstrip())
            else:
                info_console.print(f"[green]✓[/green] Job submitted: {jid}\n")
                info_console.print(f"Use 'scc job-status {jid}' to check the result.\n")
        else:
            info_console.print(f"[dim]Job ID: {jid}[/dim]\n")
            
            completed, timed_out, cancelled = _wait_for_job(
                api_client,
                jid,
                max_wait=wait,
                description="Waiting for minions to respond",
                expected_minions=_expected_minion_count(resolved_target, resolved_target_type),
            )
            
            if completed:
                returns_resp = api_client.call("ret", "get_returns", jid=jid)
                if returns_resp.success and returns_resp.ret:
                    _render_exec_results(returns_resp.ret, function, output_fmt, jid=jid)
                else:
                    info_console.print("[yellow]Job completed but no results were returned.[/yellow]\n")
                    if output_fmt in ("json", "yaml"):
                        empty = {"jid": jid, "function": function, "results": [], "count": 0}
                        if output_fmt == "json":
                            _print_stdout(json.dumps(empty, indent=2, default=str))
                        else:
                            import yaml as _yaml
                            _print_stdout(_yaml.safe_dump(empty, sort_keys=False).rstrip())
            elif cancelled:
                info_console.print(
                    f"[yellow]⚠ Cancelled while waiting. Job still running on server.[/yellow]\n"
                    f"  Check status later: [cyan]scc job-status {jid}[/cyan]\n"
                )
            elif timed_out:
                info_console.print(
                    f"[yellow]⚠ Timed out after {wait}s waiting for results. "
                    f"The job is still running on the server.[/yellow]\n"
                    f"  Check status:  [cyan]scc job-status {jid}[/cyan]\n"
                    f"  Tail results:  [cyan]scc job-status {jid} --wait[/cyan]\n"
                    f"  Or re-run with [cyan]--wait 0[/cyan] (no timeout) or a larger [cyan]--wait[/cyan] value.\n"
                )
        
    except Exception as e:
        info_console.print(f"[red]✗[/red] Failed to execute: {e}\n")
        sys.exit(1)
    
    api_client.close()


def _expected_minion_count(target, target_type) -> int | None:
    """Best-effort count of minions a resolved target spec addresses.

    Returns ``None`` when the count can't be known ahead of time (glob,
    compound, and grain matches depend on live minion membership the client
    has no visibility into) -- callers must fall back to relying solely on
    the server-side job status in that case.

    ``list``-type targets are the one case where the CLI already knows
    exactly how many minions were asked for (it either resolved a target
    group's explicit member list, or the user passed ``--target`` with
    ``--target-type list`` directly), so it's also the one case where "every
    expected minion has reported a result" is a trustworthy completion
    signal independent of RaaS's own job-status flag.
    """
    if target_type != "list":
        return None
    if isinstance(target, (list, tuple, set)):
        return len(target) or None
    if isinstance(target, str):
        parts = [p for p in target.split(",") if p.strip()]
        return len(parts) or None
    return None


def _wait_for_job(
    api_client,
    jid,
    *,
    max_wait: int = 600,
    description: str = "Waiting for job",
    live: bool = True,
    expected_minions: int | None = None,
):
    """Poll a Salt job until it completes, times out, or the user cancels.

    When ``live=True`` and the terminal supports it, render a continuously
    updating panel showing per-minion status as each one reports back. This
    gives customers real-time visibility instead of an opaque spinner.

    Args:
        api_client: connected AriaConfigClient.
        jid:        Salt job id returned by cmd.route_cmd.
        max_wait:   seconds to wait. 0 means wait forever.
        description: spinner description (no trailing "...").
        live:       enable the live per-minion tracker (auto-disabled when
                    stdout is not a TTY).
        expected_minions: if known (see ``_expected_minion_count``), the
                    number of minions targeted. Once ``ret.get_returns``
                    has a result for that many distinct minions, the job is
                    treated as complete even if RaaS's own
                    ``cmd.get_cmd_status`` never reports ``"complete"`` --
                    which is exactly what happens for jids dispatched via a
                    direct ``cmd.route_cmd`` ("local") call instead of one
                    of RaaS's tracked Job entities: that status flag simply
                    has no record of the jid and would otherwise leave this
                    loop spinning until ``max_wait`` on every single run.

    Returns:
        (completed: bool, timed_out: bool, cancelled: bool)
    """
    import time

    from salt_config_cli.api.exceptions import APIError

    use_live = bool(live) and sys.stdout.isatty() and not _truthy_env("SCC_NO_LIVE")
    poll_interval = 2
    waited = 0
    completed = False
    cancelled = False
    timed_out = False
    unlimited = max_wait <= 0

    if use_live:
        return _wait_for_job_live(
            api_client,
            jid,
            max_wait=max_wait,
            description=description,
            poll_interval=poll_interval,
            expected_minions=expected_minions,
        )

    # Plain spinner mode (CI/non-TTY/explicit opt-out)
    seen_returns: set[str] = set()
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(f"{description}...", total=None)
        try:
            while unlimited or waited < max_wait:
                time.sleep(poll_interval)
                waited += poll_interval
                try:
                    status_resp = api_client.call("cmd", "get_cmd_status", jids=[jid])
                except APIError as poll_err:
                    progress.update(task, description=f"[yellow]Poll error: {poll_err}[/yellow]")
                    continue
                if status_resp.success and status_resp.ret:
                    status = status_resp.ret[0] if isinstance(status_resp.ret, list) else status_resp.ret
                    if status == "complete":
                        completed = True
                        break
                    if status in ("failed", "error"):
                        progress.update(task, description="[red]Job failed[/red]")
                        break
                # Independent completion signal: if we know how many minions
                # were targeted, check the master's own return cache directly
                # rather than trusting the RaaS job-status flag alone (see
                # docstring -- that flag never fires for direct-dispatch jids).
                if expected_minions:
                    try:
                        returns_resp = api_client.call("ret", "get_returns", jid=jid)
                    except APIError:
                        returns_resp = None
                    if returns_resp and returns_resp.success and returns_resp.ret:
                        payload = returns_resp.ret
                        results = (
                            payload.get("results", [])
                            if isinstance(payload, dict)
                            else (payload if isinstance(payload, list) else [])
                        )
                        for ret in results:
                            if isinstance(ret, dict):
                                mid = ret.get("minion_id") or ret.get("id")
                                if mid:
                                    seen_returns.add(mid)
                        if len(seen_returns) >= expected_minions:
                            completed = True
                            break
                if unlimited:
                    progress.update(task, description=f"{description}... ({waited}s, Ctrl+C to detach)")
                else:
                    remaining = max(0, max_wait - waited)
                    progress.update(
                        task,
                        description=f"{description}... ({waited}s / {max_wait}s, {remaining}s left)",
                    )
        except KeyboardInterrupt:
            cancelled = True

    if not completed and not cancelled and not unlimited and waited >= max_wait:
        timed_out = True

    return completed, timed_out, cancelled


def _truthy_env(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _wait_for_job_live(
    api_client,
    jid,
    *,
    max_wait: int,
    description: str,
    poll_interval: int = 2,
    expected_minions: int | None = None,
):
    """Live, in-place job tracker showing per-minion status.

    Renders a Rich Live panel that updates as minions check in:

        ╭ Waiting for minions · jid 20260527…  (00:00:18 / 60s) ─────────────╮
        │  ✔  test-alpine-vm        True                       3s            │
        │  ⏳  k8s-worker-1          (waiting…)                              │
        │  ✖  broken-node           ConnectionRefused          5s            │
        │  ...                                                                │
        ╰─────────────────────────────────────────────────────────────────────╯

    ``expected_minions``, when known (see ``_expected_minion_count``), lets
    this loop finish as soon as every targeted minion has reported a result
    -- independent of RaaS's own ``cmd.get_cmd_status`` flag, which never
    reports ``"complete"`` for jids dispatched via a direct
    ``cmd.route_cmd``/state.apply call (as opposed to one of RaaS's tracked
    Job entities). Without this, a job that finished on every minion in
    seconds would otherwise sit here polling until ``max_wait``.

    Returns ``(completed, timed_out, cancelled)`` like ``_wait_for_job``.
    """
    import time
    from rich.live import Live
    from rich.panel import Panel
    from rich.box import ROUNDED
    from rich.table import Table
    from rich.text import Text
    from rich.console import Group
    from salt_config_cli.ui.theme import ICONS
    from salt_config_cli.api.exceptions import APIError

    unlimited = max_wait <= 0
    waited = 0
    completed = False
    cancelled = False
    timed_out = False

    # Per-minion state: minion_id -> {"status": pending|running|ok|fail,
    #                                  "return": <repr>, "elapsed": float}
    minions: dict[str, dict] = {}
    server_status = "queued"  # queued -> running -> complete/failed
    start = time.time()

    def _render() -> Panel:
        elapsed = time.time() - start
        elapsed_s = f"{int(elapsed // 60):02d}:{int(elapsed % 60):02d}"
        if unlimited:
            time_str = f"elapsed {elapsed_s}, Ctrl+C to detach"
        else:
            remaining = max(0, max_wait - int(elapsed))
            time_str = f"elapsed {elapsed_s} / {max_wait}s ({remaining}s left)"

        # Compose summary row
        total = len(minions)
        ok = sum(1 for m in minions.values() if m["status"] == "ok")
        fail = sum(1 for m in minions.values() if m["status"] == "fail")
        running = sum(1 for m in minions.values() if m["status"] in ("pending", "running"))

        head = Text()
        head.append(f"{ICONS['spinner']} ", style="scc.accent")
        head.append(f"{description}  ", style="scc.value")
        head.append(f"jid {jid}", style="scc.muted")
        head.append("\n")
        head.append(time_str, style="scc.subtitle")
        head.append("    ")
        head.append(f"{total} minion(s)", style="scc.muted")
        if ok:
            head.append(f"   {ok} ok", style="scc.success")
        if fail:
            head.append(f"   {fail} fail", style="scc.danger")
        if running:
            head.append(f"   {running} running", style="scc.warning")

        # Table of per-minion progress
        t = Table(
            show_header=True,
            box=None,
            expand=True,
            header_style="scc.table.header",
            padding=(0, 1),
        )
        t.add_column("", width=2)
        t.add_column("Minion", overflow="fold", ratio=2)
        t.add_column("State", width=10)
        t.add_column("Result", overflow="fold", ratio=3)
        t.add_column("Time", justify="right", width=8)

        if not minions:
            t.add_row(
                f"[scc.muted]{ICONS['spinner']}[/scc.muted]",
                "[scc.muted](waiting for first minion to report)[/scc.muted]",
                f"[scc.warning]{server_status}[/scc.warning]",
                "",
                "",
            )
        else:
            for mid in sorted(minions.keys()):
                m = minions[mid]
                st = m["status"]
                if st == "ok":
                    icon = f"[scc.success]{ICONS['success']}[/scc.success]"
                    state = "[scc.success]ok[/scc.success]"
                elif st == "fail":
                    icon = f"[scc.danger]{ICONS['fail']}[/scc.danger]"
                    state = "[scc.danger]fail[/scc.danger]"
                elif st == "running":
                    icon = f"[scc.warning]{ICONS['spinner']}[/scc.warning]"
                    state = "[scc.warning]running[/scc.warning]"
                else:
                    icon = f"[scc.muted]{ICONS['bullet']}[/scc.muted]"
                    state = "[scc.muted]pending[/scc.muted]"
                t.add_row(
                    icon,
                    f"[scc.strong]{mid}[/scc.strong]",
                    state,
                    _short_repr(m.get("return")),
                    _fmt_secs(m.get("elapsed", 0)),
                )

        return Panel(
            Group(head, Text(""), t),
            box=ROUNDED,
            border_style="scc.primary",
            padding=(1, 2),
        )

    # Track which returns we've already ingested by minion_id so we don't
    # spam updates each tick.
    seen_returns: set[str] = set()

    with Live(_render(), console=console, refresh_per_second=8, transient=True) as live:
        try:
            while unlimited or waited < max_wait:
                time.sleep(poll_interval)
                waited += poll_interval

                # 1. Cheap server-side status check
                try:
                    status_resp = api_client.call("cmd", "get_cmd_status", jids=[jid])
                    if status_resp.success and status_resp.ret:
                        s = (
                            status_resp.ret[0]
                            if isinstance(status_resp.ret, list)
                            else status_resp.ret
                        )
                        if isinstance(s, str):
                            server_status = s
                except APIError:
                    pass

                # 2. Pull any returns that have come in so far
                try:
                    returns_resp = api_client.call("ret", "get_returns", jid=jid)
                except APIError:
                    returns_resp = None

                if returns_resp and returns_resp.success and returns_resp.ret:
                    payload = returns_resp.ret
                    results = (
                        payload.get("results", [])
                        if isinstance(payload, dict)
                        else (payload if isinstance(payload, list) else [])
                    )
                    for ret in results:
                        if not isinstance(ret, dict):
                            continue
                        mid = ret.get("minion_id") or ret.get("id") or "unknown"
                        if mid in seen_returns:
                            continue
                        seen_returns.add(mid)
                        full_ret = ret.get("full_ret") if isinstance(ret.get("full_ret"), dict) else {}
                        return_data = full_ret.get("return", ret.get("return"))
                        ok = full_ret.get("success", not ret.get("has_errors", False))
                        elapsed_seconds = time.time() - start
                        minions[mid] = {
                            "status": "ok" if ok else "fail",
                            "return": return_data,
                            "elapsed": elapsed_seconds,
                        }

                live.update(_render())

                if server_status in ("complete", "completed"):
                    # Pull one more time to make sure we got the final returns
                    completed = True
                    break
                if server_status in ("failed", "error"):
                    break

                # Independent completion signal: every minion we expected to
                # hear from has reported a result, regardless of what RaaS's
                # own job-status flag says. This is what actually fires for
                # jids from a direct cmd.route_cmd dispatch (e.g. `scc run`/
                # `scc deploy`) -- those never get a tracked Job entity, so
                # `server_status` above sits on something like "not-found" or
                # "queued" forever even after every minion is done.
                if (
                    expected_minions
                    and len(minions) >= expected_minions
                    and all(m["status"] in ("ok", "fail") for m in minions.values())
                ):
                    completed = True
                    break
        except KeyboardInterrupt:
            cancelled = True

    if not completed and not cancelled and not unlimited and waited >= max_wait:
        timed_out = True

    return completed, timed_out, cancelled


def _short_repr(value, max_len: int = 80) -> str:
    """Return a single-line compact preview of a Salt return value."""
    if value is None:
        return "[scc.muted]—[/scc.muted]"
    if isinstance(value, bool):
        return "[scc.success]true[/scc.success]" if value else "[scc.danger]false[/scc.danger]"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        s = value.replace("\n", " ").strip()
        if len(s) > max_len:
            s = s[: max_len - 1] + "…"
        return s
    if isinstance(value, dict):
        # For state.apply-like nested returns, summarize succeeded/failed.
        items = list(value.items())
        succeeded = sum(
            1 for _, v in items if isinstance(v, dict) and v.get("result") is True
        )
        failed = sum(
            1 for _, v in items if isinstance(v, dict) and v.get("result") is False
        )
        if succeeded or failed:
            parts = []
            if succeeded:
                parts.append(f"[scc.success]{succeeded} ok[/scc.success]")
            if failed:
                parts.append(f"[scc.danger]{failed} fail[/scc.danger]")
            return " · ".join(parts) + f" of {len(items)} states"
        keys = ", ".join(list(value.keys())[:3])
        more = f" +{len(value) - 3}" if len(value) > 3 else ""
        return f"{{{keys}{more}}}"
    if isinstance(value, list):
        return f"list[{len(value)}]"
    return str(value)[:max_len]


def _fmt_secs(s: float) -> str:
    s = int(s)
    if s < 60:
        return f"{s}s"
    return f"{s // 60}m{s % 60:02d}s"


def _stderr_console():
    """Return a Rich console that writes to stderr (no theming side effects)."""
    from rich.console import Console as _RConsole
    # Reuse the same theme for color/style consistency.
    return _RConsole(stderr=True, theme=current_rich_theme(), highlight=False, no_color=is_plain())


def _print_stdout(text: str) -> None:
    """Print plain text directly to stdout (no Rich markup interpretation).

    Used for machine-readable formats (JSON/YAML) so that downstream tools
    receive byte-accurate output regardless of TTY/color settings.
    """
    sys.stdout.write(text)
    if not text.endswith("\n"):
        sys.stdout.write("\n")
    sys.stdout.flush()


def _normalize_exec_results(result: dict, function: str, *, jid: Optional[str] = None) -> dict:
    """Normalize raw RaaS return data into a stable, documented schema.

    The shape is intentionally simple and stable so that scripts can rely on
    it across CLI versions:

        {
          "jid": "20260527202411897579",
          "function": "test.ping",
          "count": 14,
          "succeeded": 13,
          "failed": 1,
          "results": [
            {"minion_id": "...", "success": true, "return": <any>},
            ...
          ]
        }
    """
    raw_results = result.get("results", []) if isinstance(result, dict) else []
    normalized = []
    for ret in raw_results:
        if not isinstance(ret, dict):
            continue
        minion_id = ret.get("minion_id") or ret.get("id") or "unknown"
        full_ret = ret.get("full_ret") if isinstance(ret.get("full_ret"), dict) else {}
        return_data = full_ret.get("return", ret.get("return"))
        has_errors = ret.get("has_errors", False)
        success = full_ret.get("success", not has_errors)
        normalized.append(
            {
                "minion_id": minion_id,
                "success": bool(success),
                "return": return_data,
            }
        )
    succeeded = sum(1 for r in normalized if r["success"])
    failed = len(normalized) - succeeded
    payload = {
        "function": function,
        "count": len(normalized),
        "succeeded": succeeded,
        "failed": failed,
        "results": normalized,
    }
    if jid is not None:
        payload = {"jid": jid, **payload}
    return payload


def _render_exec_results(
    result: dict,
    function: str,
    fmt: str = "yaml",
    *,
    jid: Optional[str] = None,
) -> None:
    """Render exec results in the requested output format.

    - yaml (default):  YAML dumped to stdout, status chatter to stderr
    - json:            pretty JSON to stdout, status chatter to stderr
    - text:            human-friendly Rich output to stdout
    """
    fmt = (fmt or "yaml").lower()
    if fmt == "text":
        _display_exec_results(result, function)
        return

    payload = _normalize_exec_results(result, function, jid=jid)

    if fmt == "json":
        _print_stdout(json.dumps(payload, indent=2, default=str, sort_keys=False))
        return

    # YAML (default)
    import yaml as _yaml
    _print_stdout(
        _yaml.safe_dump(
            payload,
            sort_keys=False,
            default_flow_style=False,
            allow_unicode=True,
            width=120,
        ).rstrip()
    )


def _display_exec_results(result: dict, function: str) -> None:
    """Pretty Rich rendering of exec results (text format)."""
    from salt_config_cli.ui import section as ui_section, summary_pills

    results = result.get("results", []) if isinstance(result, dict) else []
    count = result.get("count", len(results)) if isinstance(result, dict) else len(results)
    succeeded = sum(
        1
        for r in results
        if isinstance(r, dict)
        and (r.get("full_ret") or {}).get("success", not r.get("has_errors", False))
    )
    failed = count - succeeded

    ui_section(f"Results · {function}", icon="minion")

    summary_pills(
        [
            (count, "minions", "primary"),
            (succeeded, "succeeded", "success"),
            *( [(failed, "failed", "danger")] if failed else [] ),
        ]
    )
    console.print()

    # Group: render each minion as a small bordered "card" with icon + payload
    from rich.panel import Panel
    from rich.box import ROUNDED
    from rich.text import Text
    from salt_config_cli.ui.theme import ICONS

    for ret in results:
        if not isinstance(ret, dict):
            continue
        minion_id = ret.get("minion_id", ret.get("id", "unknown"))
        full_ret = ret.get("full_ret") if isinstance(ret.get("full_ret"), dict) else {}
        return_data = full_ret.get("return", ret.get("return"))
        ok = full_ret.get("success", not ret.get("has_errors", False))

        head = Text()
        head.append(f"{ICONS['success'] if ok else ICONS['fail']}  ", style="scc.success" if ok else "scc.danger")
        head.append(f"{ICONS['minion']}  ", style="scc.accent")
        head.append(minion_id, style="scc.strong")

        body = _format_return_data(return_data)

        console.print(
            Panel(
                Text.assemble(head, "\n", body),
                box=ROUNDED,
                border_style="scc.success_dim" if ok else "scc.danger_dim",
                padding=(0, 2),
            )
        )

    if failed == 0 and count > 0:
        console.print()
        console.print(
            Text.assemble(
                Text(f"{ICONS['success']}  ", style="scc.success bold"),
                Text(f"All {count} minion(s) succeeded.", style="scc.success bold"),
            )
        )
    elif failed > 0:
        console.print()
        console.print(
            Text.assemble(
                Text(f"{ICONS['warn']}  ", style="scc.warning bold"),
                Text(f"{succeeded} succeeded · ", style="scc.success"),
                Text(f"{failed} failed", style="scc.danger bold"),
            )
        )


def _parse_compliance_results(return_data: dict) -> dict:
    """Extract compliance check results from nested state orchestration output.
    
    Parses runner.state.orchestrate results to find vmware_compliance_control states
    and extracts desired vs. current values.
    """
    compliances = []
    
    if not isinstance(return_data, dict):
        return {"compliances": compliances, "is_compliance_job": False}
    
    # Look for data -> minion -> state results structure
    data = return_data.get("data", {})
    if not isinstance(data, dict):
        return {"compliances": compliances, "is_compliance_job": False}
    
    # Iterate through minions (keys in data)
    for minion_id, states in data.items():
        if not isinstance(states, dict):
            continue
        
        # Look for salt_|-...-|-...-|-state entries (orchestration state calls)
        for state_id, state_result in states.items():
            if not isinstance(state_result, dict):
                continue
            
            # Check if this is a state orchestration call
            if "_|-state" not in state_id:
                continue
            
            changes = state_result.get("changes", {})
            if not isinstance(changes, dict):
                continue
            
            # Look for nested minion results in the ret/data
            ret_data = changes.get("ret", {})
            if not isinstance(ret_data, dict):
                continue
            
            for nested_minion, nested_states in ret_data.items():
                if not isinstance(nested_states, dict):
                    continue
                
                # Look for vmware_compliance_control states
                for control_id, control_result in nested_states.items():
                    if "vmware_compliance_control" not in control_id:
                        continue
                    
                    if not isinstance(control_result, dict):
                        continue
                    
                    control_changes = control_result.get("changes", {})
                    compliance_config = control_changes.get("compliance_config", {})
                    
                    if not compliance_config:
                        continue
                    
                    # Extract policy info
                    for policy_type, policy_data in compliance_config.items():
                        if not isinstance(policy_data, dict):
                            continue
                        
                        for policy_name, policy_status in policy_data.items():
                            if not isinstance(policy_status, dict):
                                continue
                            
                            current = policy_status.get("current", {})
                            desired = policy_status.get("desired", {})
                            status = policy_status.get("status", "UNKNOWN")
                            
                            compliances.append({
                                "minion": nested_minion,
                                "policy_type": policy_type,
                                "policy_name": policy_name,
                                "status": status,
                                "current": current,
                                "desired": desired,
                                "control_name": control_result.get("name", control_id),
                                "comment": control_result.get("comment", ""),
                            })
    
    return {
        "compliances": compliances,
        "is_compliance_job": len(compliances) > 0
    }


def _display_compliance_results(result: dict, is_test: bool = False) -> None:
    """Display compliance check results in human-readable format."""
    from rich.table import Table
    from rich.panel import Panel
    from rich.box import ROUNDED
    from salt_config_cli.ui.theme import ICONS
    
    parsed = _parse_compliance_results(result)
    if not parsed["is_compliance_job"]:
        return False  # Let the default formatter handle it
    
    compliances = parsed["compliances"]
    if not compliances:
        console.print("[yellow]No compliance results found[/yellow]\n")
        return True
    
    # Group by minion
    by_minion = {}
    for comp in compliances:
        minion = comp["minion"]
        if minion not in by_minion:
            by_minion[minion] = []
        by_minion[minion].append(comp)
    
    console.print(f"\n[bold]Compliance Check Results[/bold]")
    console.print(f"[dim]Test Mode: {is_test}[/dim]\n")
    
    # Display per minion
    for minion_id, items in by_minion.items():
        # Count compliant vs non-compliant for this minion
        compliant_count = sum(1 for item in items if item["status"] == "COMPLIANT")
        non_compliant_count = len(items) - compliant_count
        
        # Minion header with status summary
        status_summary = []
        if compliant_count > 0:
            status_summary.append(f"[green]{compliant_count} compliant[/green]")
        if non_compliant_count > 0:
            status_summary.append(f"[yellow]{non_compliant_count} non-compliant[/yellow]")
        
        summary_text = " · ".join(status_summary) if status_summary else "no results"
        console.print(f"\n[bold underline]{ICONS['minion']}  {minion_id}[/bold underline]")
        console.print(f"[dim]{summary_text}[/dim]\n")
        
        for comp in items:
            status = comp["status"]
            status_icon = "[green]✓[/green]" if status == "COMPLIANT" else "[yellow]⚠[/yellow]"
            
            console.print(f"  {status_icon} {comp['policy_type']}.{comp['policy_name']}")
            console.print(f"     Status: [bold]{status}[/bold]")
            if comp["comment"]:
                console.print(f"     Comment: {comp['comment']}")
            
            # Only show comparison table for NON_COMPLIANT policies
            if status != "COMPLIANT":
                # Create comparison table
                table = Table(
                    show_header=True,
                    header_style="scc.table.header",
                    box=ROUNDED,
                    padding=(0, 1),
                )
                table.add_column("Property", style="scc.label")
                table.add_column("Current", style="scc.value")
                table.add_column("Desired", style="scc.value")
                
                current = comp["current"]
                desired = comp["desired"]
                
                # Get all keys from both current and desired
                all_keys = set()
                if isinstance(current, dict) and current:
                    all_keys.update(current.keys())
                if isinstance(desired, dict) and desired:
                    all_keys.update(desired.keys())
                
                # Display each property
                for key in sorted(all_keys):
                    curr_val = current.get(key, "-") if isinstance(current, dict) else "-"
                    desired_val = desired.get(key, "-") if isinstance(desired, dict) else "-"
                    
                    # Format nicely
                    if isinstance(curr_val, (list, dict)):
                        curr_str = str(curr_val)[:50] + ("..." if len(str(curr_val)) > 50 else "")
                    else:
                        curr_str = str(curr_val) if curr_val != "-" and curr_val is not None else "[dim]-[/dim]"
                    
                    if isinstance(desired_val, (list, dict)):
                        desired_str = str(desired_val)[:50] + ("..." if len(str(desired_val)) > 50 else "")
                    else:
                        desired_str = str(desired_val) if desired_val != "-" and desired_val is not None else "[dim]-[/dim]"
                    
                    table.add_row(key, curr_str, desired_str)
                
                console.print(Panel(table, padding=(0, 1), border_style="scc.muted"))
            
            console.print()
        
        console.print()
    
    return True


def _detect_result_type(return_data: dict) -> str:
    """Detect the type of result to determine appropriate formatting.
    
    Returns one of:
    - 'compliance_state_apply': vmware_compliance_control states (direct, not nested)
    - 'compliance_orchestration': vmware_compliance_control states (nested orchestration)
    - 'state_apply': Standard state.apply results
    - 'runner_orchestrate': runner.state.orchestrate (non-compliance)
    - 'simple': Simple key-value results
    - 'unknown': Unknown format
    """
    if not isinstance(return_data, dict):
        return 'unknown'
    
    # Check for direct compliance states (flat state.apply result)
    # This is when targeting multiple minions with state.apply
    has_compliance_states = False
    if return_data:
        for key, value in return_data.items():
            if isinstance(value, dict) and "vmware_compliance_control" in key:
                has_compliance_states = True
                break
    
    if has_compliance_states:
        return 'compliance_state_apply'
    
    # Check for compliance orchestration pattern (nested)
    data = return_data.get("data", {})
    if isinstance(data, dict):
        for minion_states in data.values():
            if isinstance(minion_states, dict):
                for state_id, state_data in minion_states.items():
                    if isinstance(state_data, dict):
                        changes = state_data.get("changes", {})
                        if isinstance(changes, dict) and "ret" in changes:
                            # Check for nested compliance controls
                            nested_ret = changes.get("ret", {})
                            if isinstance(nested_ret, dict):
                                for nested_states in nested_ret.values():
                                    if isinstance(nested_states, dict):
                                        for control_id in nested_states.keys():
                                            if "vmware_compliance_control" in control_id:
                                                return 'compliance_orchestration'
    
    # Check for state.apply results (minion -> states dict)
    if all(isinstance(v, dict) for v in return_data.values() if v is not None):
        # Check if it looks like state results
        for minion_result in return_data.values():
            if isinstance(minion_result, dict):
                for key in minion_result.keys():
                    if "_|-" in key:  # State ID format
                        return 'state_apply'
    
    # Check for simple key-value results
    is_simple = all(
        not isinstance(v, dict) or v == {} 
        for v in return_data.values()
    )
    if is_simple and return_data:
        return 'simple'
    
    # Check for nested structure
    if return_data:
        return 'runner_orchestrate'
    
    return 'unknown'


def _parse_compliance_state_results(return_data: dict) -> dict:
    """Parse compliance results from state.apply (flat structure with direct compliance states)."""
    compliances = []
    
    if not isinstance(return_data, dict):
        return {"compliances": compliances, "is_compliance_job": False}
    
    # Iterate through state results looking for vmware_compliance_control states
    for state_id, state_result in return_data.items():
        if not isinstance(state_result, dict):
            continue
        
        if "vmware_compliance_control" not in state_id:
            continue
        
        changes = state_result.get("changes", {})
        compliance_config = changes.get("compliance_config", {})
        
        if not compliance_config:
            continue
        
        # Extract policy info
        for policy_type, policy_data in compliance_config.items():
            if not isinstance(policy_data, dict):
                continue
            
            for policy_name, policy_status in policy_data.items():
                if not isinstance(policy_status, dict):
                    continue
                
                current = policy_status.get("current", {})
                desired = policy_status.get("desired", {})
                status = policy_status.get("status", "UNKNOWN")
                
                compliances.append({
                    "policy_type": policy_type,
                    "policy_name": policy_name,
                    "status": status,
                    "current": current,
                    "desired": desired,
                    "control_name": state_result.get("name", state_id),
                    "comment": state_result.get("comment", ""),
                })
    
    return {
        "compliances": compliances,
        "is_compliance_job": len(compliances) > 0
    }


def _display_compliance_state_results(result: dict, is_test: bool = False) -> None:
    """Display compliance state.apply results in human-readable format (multiple minions)."""
    from rich.table import Table
    from rich.panel import Panel
    from rich.box import ROUNDED
    from salt_config_cli.ui.theme import ICONS
    
    parsed = _parse_compliance_state_results(result)
    if not parsed["is_compliance_job"]:
        return False
    
    compliances = parsed["compliances"]
    if not compliances:
        console.print("[yellow]No compliance results found[/yellow]\n")
        return True
    
    console.print(f"\n[bold]Compliance Results[/bold]")
    console.print(f"[dim]Test Mode: {is_test}[/dim]\n")
    
    for comp in compliances:
        status = comp["status"]
        status_icon = "[green]✓[/green]" if status == "COMPLIANT" else "[yellow]⚠[/yellow]"
        
        console.print(f"  {status_icon} {comp['policy_type']}.{comp['policy_name']}")
        console.print(f"     Status: [bold]{status}[/bold]")
        if comp["comment"]:
            console.print(f"     Comment: {comp['comment']}")
        
        # Only show comparison table for NON_COMPLIANT policies
        if status != "COMPLIANT":
            # Create comparison table
            table = Table(
                show_header=True,
                header_style="scc.table.header",
                box=ROUNDED,
                padding=(0, 1),
            )
            table.add_column("Property", style="scc.label")
            table.add_column("Current", style="scc.value")
            table.add_column("Desired", style="scc.value")
            
            current = comp["current"]
            desired = comp["desired"]
            
            # Get all keys from both current and desired
            all_keys = set()
            if isinstance(current, dict) and current:
                all_keys.update(current.keys())
            if isinstance(desired, dict) and desired:
                all_keys.update(desired.keys())
            
            # Display each property
            for key in sorted(all_keys):
                curr_val = current.get(key, "-") if isinstance(current, dict) else "-"
                desired_val = desired.get(key, "-") if isinstance(desired, dict) else "-"
                
                # Format nicely
                if isinstance(curr_val, (list, dict)):
                    curr_str = str(curr_val)[:50] + ("..." if len(str(curr_val)) > 50 else "")
                else:
                    curr_str = str(curr_val) if curr_val != "-" and curr_val is not None else "[dim]-[/dim]"
                
                if isinstance(desired_val, (list, dict)):
                    desired_str = str(desired_val)[:50] + ("..." if len(str(desired_val)) > 50 else "")
                else:
                    desired_str = str(desired_val) if desired_val != "-" and desired_val is not None else "[dim]-[/dim]"
                
                table.add_row(key, curr_str, desired_str)
            
            console.print(Panel(table, padding=(0, 1), border_style="scc.muted"))
        
        console.print()


def _display_simple_results(result: dict) -> None:
    """Display simple key-value results (generic catch-all)."""
    from rich.table import Table
    
    console.print(f"\n[bold]Results[/bold]\n")
    
    # Create a simple table for key-value pairs
    table = Table(show_header=True, header_style="scc.table.header", box=ROUNDED, padding=(0, 1))
    table.add_column("Key", style="scc.label")
    table.add_column("Value", style="scc.value")
    
    for key, value in result.items():
        if isinstance(value, (dict, list)):
            value_str = str(value)[:80] + ("..." if len(str(value)) > 80 else "")
        else:
            value_str = str(value)
        table.add_row(key, value_str)
    
    console.print(Panel(table, padding=(0, 1), border_style="scc.muted"))
    console.print()


def _format_return_data(return_data) -> "Text":
    """Render Salt return data in a compact, type-aware way."""
    from rich.text import Text
    out = Text()
    if return_data is None:
        out.append("   no return data", style="scc.muted")
        return out

    if isinstance(return_data, bool):
        out.append("   ", style="")
        out.append("true" if return_data else "false", style="scc.success" if return_data else "scc.danger")
        return out

    if isinstance(return_data, (int, float)):
        out.append(f"   {return_data}", style="scc.value")
        return out

    if isinstance(return_data, str):
        lines = return_data.split("\n")
        for line in lines[:20]:
            out.append(f"   {line}\n", style="scc.value")
        if len(lines) > 20:
            out.append(f"   … {len(lines) - 20} more lines\n", style="scc.muted")
        return out

    if isinstance(return_data, dict):
        items = list(return_data.items())
        for key, value in items[:20]:
            out.append(f"   {key}", style="scc.label")
            out.append("  ", style="")
            if isinstance(value, (dict, list)):
                out.append(f"{type(value).__name__} ({len(value)})\n", style="scc.muted")
            else:
                out.append(f"{value}\n", style="scc.value")
        if len(items) > 20:
            out.append(f"   … {len(items) - 20} more keys\n", style="scc.muted")
        return out

    if isinstance(return_data, list):
        for item in return_data[:20]:
            out.append(f"   • {item}\n", style="scc.value")
        if len(return_data) > 20:
            out.append(f"   … {len(return_data) - 20} more items\n", style="scc.muted")
        return out

    out.append(f"   {return_data}", style="scc.value")
    return out


@cli.command("run")
@click.argument("state_file")
@click.option(
    "--target", "-t",
    default=None,
    help="Minion pattern (e.g., '*', 'web-*')"
)
@click.option(
    "--target-group", "-g",
    default=None,
    help="Target group name from RaaS (e.g., 'ops', 'All Minions')"
)
@click.option(
    "--target-type", "-T",
    default="glob",
    type=click.Choice(["glob", "grain", "compound", "list", "nodegroup", "pillar", "pcre"]),
    help="Target type when using --target (default: glob)"
)
@click.option(
    "--env", "-e", "saltenv",
    default="base",
    help="Salt environment"
)
@click.option(
    "--test/--no-test",
    default=True,
    show_default=True,
    help="Run in safe test mode by default. Use --no-test to apply changes."
)
@click.option(
    "--yes",
    is_flag=True,
    help="Confirm a non-test state application without an interactive prompt."
)
@click.option(
    "--async", "run_async",
    is_flag=True,
    help="Run asynchronously (don't wait for result)"
)
@click.option(
    "--wait",
    type=int,
    default=1800,
    show_default=True,
    metavar="SECONDS",
    help="Max seconds to wait for state apply to complete. "
         "Use 0 for no timeout (wait forever until completion or Ctrl+C). "
         "Use --async to submit and exit immediately.",
)
@click.option(
    "--json", "as_json",
    is_flag=True,
    help="Output full results in JSON format"
)
@click.option(
    "--pillar", "-P",
    default=None,
    help="Pillar data as JSON string (e.g., '{\"key\": \"value\"}')"
)
@click.option(
    "--pillar-file",
    type=click.Path(exists=True),
    default=None,
    help="Path to YAML/JSON file containing pillar data"
)
@common_options
@click.pass_context
def run_state(ctx, state_file, target, target_group, target_type, saltenv, test, yes, run_async, wait, as_json, pillar, pillar_file, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """
    Run a state file against a target group.
    
    Executes a Salt state file from the RaaS file server against
    the specified target group or minion pattern.
    
    \b
    Examples:
      $ scc run /ntp-config.sls --target "*"                 # safe dry-run
      $ scc run /ntp-config.sls --target-group ops --test
      $ scc run /ntp-config.sls --target "web-*" --no-test   # apply after confirmation
    """
    setup_logging(log_level, no_color)
    
    settings = load_settings(config, server, username, password, csp_token, password_stdin=password_stdin, password_file=password_file, password_prompt=password_prompt)

    if not as_json:
        command_header(
            "run",
            "Salt desired-state execution",
            description="Resolve the target, validate the state file, then show live per-minion progress and compliance details.",
            icon="shield",
            meta=[
                ("State", state_file),
                ("Scope", target_group or target or "not specified"),
                ("Environment", saltenv),
            ],
            mode=("DRY RUN", "black on #35e66f") if test else ("APPLY", "white on #b54453"),
        )

    api_client = connect_client(settings, label="state execution")
    if not as_json:
        ui_success(f"Connected to {mask_url(settings.server_url)}")
    
    # Validate target options
    if not target and not target_group:
        console.print("[red]Error: Either --target or --target-group is required[/red]\n")
        sys.exit(1)
    if target and target_group:
        console.print("[red]Error: Use either --target or --target-group, not both[/red]\n")
        sys.exit(1)
    
    # Normalize state file path
    if not state_file.startswith("/"):
        state_file = "/" + state_file
    if not state_file.endswith(".sls"):
        state_file = state_file + ".sls"
    
    # Resolve target group if specified
    resolved_target = target
    resolved_target_type = target_type
    
    if target_group:
        console.print(f"[bold]Resolving target group:[/bold] {target_group}...")
        
        # List all target groups and find by name (API is "get_target_group" without 's')
        groups = _list_target_groups(api_client)
        found = None
        for g in groups:
            if isinstance(g, dict) and g.get("name", "").lower() == target_group.lower():
                found = g
                break
        
        if not found:
            console.print(f"[red]✗[/red] Target group not found: {target_group}\n")
            console.print("Available target groups:")
            for g in groups[:10]:
                if isinstance(g, dict):
                    console.print(f"  • {g.get('name', 'unknown')}")
            sys.exit(1)
        
        # Extract target spec from the group
        # Structure: {"tgt": {"*": {"tgt": "...", "tgt_type": "..."}}}
        tgt_spec_from_group = found.get("tgt", {})
        if isinstance(tgt_spec_from_group, dict):
            for master_key, master_tgt in tgt_spec_from_group.items():
                if isinstance(master_tgt, dict):
                    resolved_target = master_tgt.get("tgt", "*")
                    resolved_target_type = master_tgt.get("tgt_type", "glob")
                    break
        
        if not resolved_target:
            console.print(f"[red]✗[/red] Could not extract target from group: {target_group}\n")
            sys.exit(1)
            
        console.print(f"[green]✓[/green] Resolved: target={resolved_target}, type={resolved_target_type}\n")
    
    if not as_json:
        kv_table(
            f"{ICONS['target']} State execution request",
            [
                ("State file", state_file),
                ("Target", resolved_target),
                ("Target type", resolved_target_type),
                ("Target group", target_group or "-"),
                ("Environment", saltenv),
                ("Mode", "DRY RUN — test=True" if test else "APPLY — test=False"),
                ("Wait", "async" if run_async else f"up to {wait}s" if wait else "until complete"),
            ],
        )

    if not test:
        from salt_config_cli.ui import confirm_destructive
        if not confirm_destructive(
            action=f"apply state {state_file}",
            targets_summary=f"Target: {resolved_target} ({resolved_target_type}), environment: {saltenv}",
            typed_phrase="apply",
            auto_approve=yes,
        ):
            ui_warn("State application cancelled. Run without --no-test for a safe dry-run.")
            api_client.close()
            return
    
    # Check if the state exists. Right after a folder upload the RaaS
    # fileserver index can lag briefly, so use a small bounded retry rather
    # than failing an otherwise valid deploy workflow immediately.
    import time as _state_file_time

    resp = None
    for attempt in range(1, 6):
        resp = api_client.call("fs", "file_exists", path=state_file, saltenv=saltenv)
        if resp.success and resp.ret:
            break
        if attempt < 5:
            if not as_json and attempt == 1:
                ui_hint("Waiting for the RaaS file-server index to include the newly published state…")
            _state_file_time.sleep(2)
    if resp is None or not resp.success or not resp.ret:
        console.print(f"[red]✗[/red] State file not found: {state_file} in {saltenv} environment\n")
        console.print("Available state files:")
        files = _list_state_files(api_client, saltenv)
        sls_files = [f for f in files if f.get("path", "").endswith(".sls")]
        for f in sls_files[:10]:
            console.print(f"  • {f.get('path')}")
        sys.exit(1)
    
    # Parse pillar data if provided
    pillar_data = None
    if pillar_file:
        try:
            import yaml
            with open(pillar_file, 'r') as f:
                pillar_data = yaml.safe_load(f)
            console.print(f"[bold]Pillar file:[/bold] {pillar_file}")
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to load pillar file: {e}\n")
            sys.exit(1)
    elif pillar:
        try:
            import json
            pillar_data = json.loads(pillar)
            console.print(f"[bold]Pillar:[/bold] (inline JSON)")
        except json.JSONDecodeError as e:
            console.print(f"[red]✗[/red] Invalid pillar JSON: {e}\n")
            sys.exit(1)
    
    # Prepare state.apply command
    # Convert state file path to Salt state reference
    # e.g., /ops_assess_u.sls -> ops_assess_u
    state_ref = state_file.lstrip("/").removesuffix(".sls").replace("/", ".")
    
    console.print(f"[bold blue]Executing state.apply {state_ref}...[/bold blue]\n")
    
    # Run the command using route_cmd
    # route_cmd requires specific format per API documentation:
    # - cmd: "local" for minion targeting
    # - tgt: {"<master_id>": {"tgt": "...", "tgt_type": "..."}, ...}
    # - arg: {"arg": [...], "kwarg": {...}}
    try:
        cmd_kwargs = {"saltenv": saltenv}
        if test:
            cmd_kwargs["test"] = True
        if pillar_data:
            cmd_kwargs["pillar"] = pillar_data
        
        # Build target specification - use "*" as master to target all masters
        tgt_spec = {
            "*": {
                "tgt": resolved_target,
                "tgt_type": resolved_target_type
            }
        }
        
        # Build arg specification
        arg_spec = {
            "arg": [state_ref],
            "kwarg": cmd_kwargs
        }
        
        resp = api_client.call(
            "cmd", "route_cmd",
            cmd="local",
            fun="state.apply",
            tgt=tgt_spec,
            arg=arg_spec
        )
        
        if resp.error:
            console.print(f"[red]✗[/red] Error: {resp.error.get('message', 'Unknown error')}\n")
            sys.exit(1)
        
        # Display results
        result = resp.ret
        jid = result if isinstance(result, str) else result.get("jid", "unknown") if isinstance(result, dict) else str(result)
        
        if run_async:
            console.print(f"[green]✓[/green] Job submitted: {jid}\n")
            console.print(f"Use 'scc job-status {jid}' to check the result.\n")
        else:
            console.print(f"[dim]Job ID: {jid}[/dim]\n")

            import time as _time

            max_attempts = 2
            returns_ret = None
            completed = timed_out = cancelled = False
            for attempt in range(1, max_attempts + 1):
                completed, timed_out, cancelled = _wait_for_job(
                    api_client,
                    jid,
                    max_wait=wait,
                    description="Applying state to minions",
                    expected_minions=_expected_minion_count(resolved_target, resolved_target_type),
                )

                if not completed:
                    break

                console.print("[green]✓[/green] Job completed\n")
                returns_resp = api_client.call("ret", "get_returns", jid=jid)
                returns_ret = returns_resp.ret if (returns_resp.success and returns_resp.ret) else None

                # RaaS's fileserver cache can briefly lag right after `scc upload`
                # writes new files - a state.apply issued in that window can come
                # back with this exact error even though the env/files are fine.
                # One automatic retry after a short delay smooths over that race.
                if (
                    attempt < max_attempts
                    and returns_ret
                    and "No matching salt environment" in str(returns_ret)
                ):
                    console.print(
                        f"[yellow]⚠[/yellow] RaaS fileserver cache hasn't caught up with the "
                        f"'{saltenv}' environment yet - retrying in 5s...\n"
                    )
                    _time.sleep(5)
                    resp = api_client.call(
                        "cmd", "route_cmd", cmd="local", fun="state.apply", tgt=tgt_spec, arg=arg_spec
                    )
                    if resp.error:
                        console.print(f"[red]✗[/red] Error: {resp.error.get('message', 'Unknown error')}\n")
                        sys.exit(1)
                    retry_result = resp.ret
                    jid = (
                        retry_result if isinstance(retry_result, str)
                        else retry_result.get("jid", "unknown") if isinstance(retry_result, dict)
                        else str(retry_result)
                    )
                    console.print(f"[dim]Retry job ID: {jid}[/dim]\n")
                    continue
                break

            if completed:
                if returns_ret:
                    if as_json:
                        import json as _json
                        console.print(_json.dumps(returns_ret, indent=2, default=str))
                    else:
                        _display_job_returns(returns_ret, test)
            elif cancelled:
                console.print(
                    f"[yellow]⚠ Cancelled while waiting. Job still running on server.[/yellow]\n"
                    f"  Check status later: [cyan]scc job-status {jid}[/cyan]\n"
                )
            elif timed_out:
                console.print(
                    f"[yellow]⚠ Timed out after {wait}s. The job is still running on the server.[/yellow]\n"
                    f"  Check status:  [cyan]scc job-status {jid}[/cyan]\n"
                    f"  Tail results:  [cyan]scc job-status {jid} --wait[/cyan]\n"
                    f"  Or re-run with [cyan]--wait 0[/cyan] (no timeout) or a larger [cyan]--wait[/cyan] value.\n"
                )
        
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to run state: {e}\n")
        sys.exit(1)
    
    api_client.close()


def _save_job_results_to_file(
    result,
    output_file: str,
    *,
    fmt: Optional[str] = None,
    jid: Optional[str] = None,
) -> str:
    """Serialize job results and write them to ``output_file``.

    The format is inferred in this order:
      1. Explicit ``fmt`` argument ("json", "yaml", or "text").
      2. File extension (``.json`` / ``.yaml`` / ``.yml`` / ``.txt``).
      3. Defaults to YAML (machine-friendly and human-readable).

    Returns the absolute path of the written file.
    """
    from pathlib import Path as _Path

    path = _Path(output_file).expanduser().resolve()

    if not fmt:
        ext = path.suffix.lower().lstrip(".")
        if ext == "json":
            fmt = "json"
        elif ext in ("yaml", "yml"):
            fmt = "yaml"
        elif ext in ("txt", "log", "text"):
            fmt = "text"
        else:
            fmt = "yaml"  # sensible default for unknown extensions

    if fmt == "json":
        import json as _json
        payload = {"jid": jid, "results": result} if jid else result
        content = _json.dumps(payload, indent=2, default=str)
    elif fmt == "yaml":
        import yaml as _yaml
        payload = {"jid": jid, "results": result} if jid else result
        content = _yaml.safe_dump(payload, sort_keys=False, default_flow_style=False)
    else:  # text — render the same view the user sees on screen, plain.
        from rich.console import Console as _Console
        import io as _io
        buf = _io.StringIO()
        plain_console = _Console(file=buf, force_terminal=False, no_color=True, width=120)
        # Temporarily swap the module-level console to capture rendered output.
        global console
        original = console
        try:
            console = plain_console
            if jid:
                plain_console.print(f"Job Results: {jid}\n")
            _display_job_returns(result)
        finally:
            console = original
        content = buf.getvalue()

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return str(path)


def _display_job_returns(result: dict, is_test: bool = False) -> None:
    """Display job return data from ret.get_returns API with smart formatting."""
    
    if not result:
        console.print("[yellow]No return data[/yellow]\n")
        return
    
    # Handle both list and dict with results key
    if isinstance(result, list):
        results = result
    elif isinstance(result, dict):
        results = result.get("results", [])
        if not results and "ret" in result:
            # Alternative format with ret key
            results = [result]
    else:
        console.print(f"[yellow]Unexpected result format: {type(result)}[/yellow]\n")
        return
    
    if not results:
        console.print("[yellow]No minion results returned[/yellow]\n")
        return
    
    # Check if this is compliance state.apply with multiple minions
    # In this case, we need to aggregate and display per-minion compliance results
    if len(results) > 1:
        all_compliance_results = []
        all_non_compliance = False
        
        for ret_item in results:
            if isinstance(ret_item, dict):
                return_data = ret_item.get("return")
                if not return_data:
                    return_data = ret_item.get("full_ret", {}).get("return")
                
                if isinstance(return_data, dict):
                    result_type = _detect_result_type(return_data)
                    if result_type == 'compliance_state_apply':
                        all_compliance_results.append((ret_item.get("minion_id", "unknown"), return_data))
                    else:
                        all_non_compliance = True
        
        # If all results are compliance state.apply, display them with minion headers
        if all_compliance_results and not all_non_compliance:
            console.print(f"\n[bold]Compliance Results[/bold]")
            console.print(f"[dim]Test Mode: {is_test}[/dim]\n")
            
            for minion_id, return_data in all_compliance_results:
                parsed = _parse_compliance_state_results(return_data)
                compliances = parsed["compliances"]
                
                if not compliances:
                    continue
                
                # Count compliant vs non-compliant
                compliant_count = sum(1 for c in compliances if c["status"] == "COMPLIANT")
                non_compliant_count = len(compliances) - compliant_count
                
                # Minion header
                from salt_config_cli.ui.theme import ICONS
                status_summary = []
                if compliant_count > 0:
                    status_summary.append(f"[green]{compliant_count} compliant[/green]")
                if non_compliant_count > 0:
                    status_summary.append(f"[yellow]{non_compliant_count} non-compliant[/yellow]")
                
                summary_text = " · ".join(status_summary) if status_summary else "no results"
                console.print(f"\n[bold underline]{ICONS['minion']}  {minion_id}[/bold underline]")
                console.print(f"[dim]{summary_text}[/dim]\n")
                
                # Display each compliance check
                from rich.table import Table
                from rich.panel import Panel
                from rich.box import ROUNDED
                
                for comp in compliances:
                    status = comp["status"]
                    status_icon = "[green]✓[/green]" if status == "COMPLIANT" else "[yellow]⚠[/yellow]"
                    
                    console.print(f"  {status_icon} {comp['policy_type']}.{comp['policy_name']}")
                    console.print(f"     Status: [bold]{status}[/bold]")
                    if comp["comment"]:
                        console.print(f"     Comment: {comp['comment']}")
                    
                    # Only show comparison table for NON_COMPLIANT policies
                    if status != "COMPLIANT":
                        # Create comparison table
                        table = Table(
                            show_header=True,
                            header_style="scc.table.header",
                            box=ROUNDED,
                            padding=(0, 1),
                        )
                        table.add_column("Property", style="scc.label")
                        table.add_column("Current", style="scc.value")
                        table.add_column("Desired", style="scc.value")
                        
                        current = comp["current"]
                        desired = comp["desired"]
                        
                        # Get all keys from both current and desired
                        all_keys = set()
                        if isinstance(current, dict) and current:
                            all_keys.update(current.keys())
                        if isinstance(desired, dict) and desired:
                            all_keys.update(desired.keys())
                        
                        # Display each property
                        for key in sorted(all_keys):
                            curr_val = current.get(key, "-") if isinstance(current, dict) else "-"
                            desired_val = desired.get(key, "-") if isinstance(desired, dict) else "-"
                            
                            # Format nicely
                            if isinstance(curr_val, (list, dict)):
                                curr_str = str(curr_val)[:50] + ("..." if len(str(curr_val)) > 50 else "")
                            else:
                                curr_str = str(curr_val) if curr_val != "-" and curr_val is not None else "[dim]-[/dim]"
                            
                            if isinstance(desired_val, (list, dict)):
                                desired_str = str(desired_val)[:50] + ("..." if len(str(desired_val)) > 50 else "")
                            else:
                                desired_str = str(desired_val) if desired_val != "-" and desired_val is not None else "[dim]-[/dim]"
                            
                            table.add_row(key, curr_str, desired_str)
                        
                        console.print(Panel(table, padding=(0, 1), border_style="scc.muted"))
                    
                    console.print()
            
            return
    
    # Single minion compliance check
    if results and isinstance(results[0], dict):
        ret_item = results[0]
        return_data = ret_item.get("return")
        if not return_data:
            return_data = ret_item.get("full_ret", {}).get("return")
        
        if isinstance(return_data, dict):
            result_type = _detect_result_type(return_data)
            
            # Use appropriate formatter based on result type
            if result_type == 'compliance_orchestration':
                if _display_compliance_results(return_data, is_test):
                    return
            elif result_type == 'compliance_state_apply':
                if _display_compliance_state_results(return_data, is_test):
                    return
            elif result_type == 'simple':
                _display_simple_results(return_data)
                return
    
    total_success = 0
    total_changed = 0
    total_failed = 0
    
    for ret in results:
        minion_id = ret.get("minion_id", ret.get("id", "unknown"))
        has_errors = ret.get("has_errors", False)
        fun = ret.get("fun", "state.apply")
        
        # Get the return data - try multiple possible locations
        return_data = ret.get("return")
        if return_data is None:
            return_data = ret.get("full_ret", {}).get("return")
        if return_data is None:
            return_data = ret.get("ret")
        
        # Check if return_data contains state results - don't just trust has_errors
        is_state_output = False
        actual_has_errors = False
        
        if isinstance(return_data, dict) and return_data:
            first_value = next(iter(return_data.values()), None)
            is_state_output = (
                isinstance(first_value, dict) and 
                any(k in first_value for k in ['result', 'changes', 'comment', '__run_num__'])
            )
            
            if is_state_output:
                # Check actual state results for errors
                for state_result in return_data.values():
                    if isinstance(state_result, dict) and state_result.get("result") is False:
                        actual_has_errors = True
                        break
            else:
                actual_has_errors = has_errors
        elif isinstance(return_data, str) and ("Error" in return_data or "error" in return_data):
            actual_has_errors = True
        else:
            actual_has_errors = has_errors
        
        # Status icon based on actual errors
        if actual_has_errors:
            icon = "[red]✗[/red]"
        else:
            icon = "[green]✓[/green]"
        
        console.print(f"{icon} [bold]{minion_id}[/bold]")
        
        if is_state_output:
            minion_success, minion_changed, minion_failed = _display_state_details(
                return_data, is_test
            )
            total_success += minion_success
            total_changed += minion_changed
            total_failed += minion_failed
        elif actual_has_errors:
            console.print(f"   [red]Status: Error[/red]")
            _display_error_details(return_data)
        else:
            if isinstance(return_data, dict) and return_data:
                console.print(f"   [green]Status: Success[/green]")
                console.print(f"   Return: {len(return_data)} items")
            elif isinstance(return_data, (str, bool, int, float)):
                console.print(f"   [green]Status: Success[/green]")
                console.print(f"   Return: {return_data}")
            elif isinstance(return_data, list):
                console.print(f"   [green]Status: Success[/green]")
                console.print(f"   Return: {len(return_data)} items")
            else:
                console.print(f"   [green]Status: Success[/green]")
        
        console.print()
    
    # Summary
    if total_success > 0 or total_changed > 0 or total_failed > 0:
        summary_parts = []
        if total_success > 0:
            summary_parts.append(f"[green]{total_success} passed[/green]")
        if total_changed > 0:
            color = "blue" if is_test else "yellow"
            label = "would change" if is_test else "changed"
            summary_parts.append(f"[{color}]{total_changed} {label}[/{color}]")
        if total_failed > 0:
            summary_parts.append(f"[red]{total_failed} failed[/red]")
        
        console.print(f"[bold]Total:[/bold] {', '.join(summary_parts)}\n")
        
        if is_test and total_changed > 0:
            console.print("[dim]Test mode - no changes were applied[/dim]\n")


def _display_error_details(return_data) -> None:
    """Display error details from return data."""
    if isinstance(return_data, list) and return_data:
        error_msg = return_data[0] if len(return_data) == 1 else str(return_data)
        if isinstance(error_msg, str):
            lines = error_msg.split('\n')
            if len(lines) > 5:
                for line in lines[:5]:
                    console.print(f"   [red]{line[:100]}[/red]")
                console.print(f"   [dim]... ({len(lines) - 5} more lines)[/dim]")
            else:
                for line in lines:
                    console.print(f"   [red]{line[:100]}[/red]")
        else:
            console.print(f"   [red]{str(error_msg)[:200]}[/red]")
    elif isinstance(return_data, str):
        console.print(f"   [red]{return_data[:200]}[/red]")
    elif isinstance(return_data, dict):
        # Error might be in a nested structure
        for key, value in list(return_data.items())[:5]:
            console.print(f"   [red]{key}: {str(value)[:100]}[/red]")


def _display_state_details(states: dict, is_test: bool = False) -> tuple:
    """Display individual state results and return counts."""
    success_count = 0
    changed_count = 0
    failed_count = 0
    
    # Sort states by run order if available
    sorted_states = sorted(
        states.items(),
        key=lambda x: x[1].get("__run_num__", 0) if isinstance(x[1], dict) else 0
    )
    
    for state_id, state_result in sorted_states:
        if not isinstance(state_result, dict):
            continue
        
        result_val = state_result.get("result")
        changes = state_result.get("changes", {})
        comment = state_result.get("comment", "")
        name = state_result.get("name", "")
        
        # Parse state ID to get readable name
        # Format is usually: module_|-id_|-name_|-function
        parts = state_id.split("_|-")
        if len(parts) >= 4:
            state_module = parts[0]
            state_name = parts[1]
            state_func = parts[3]
            display_id = f"{state_module}.{state_func}: {state_name}"
        else:
            display_id = state_id[:60]
        
        # Determine icon and status
        if result_val is True:
            success_count += 1
            if changes:
                changed_count += 1
                icon = "[yellow]~[/yellow]"
                status = "changed"
            else:
                icon = "[green]✓[/green]"
                status = "ok"
        elif result_val is False:
            failed_count += 1
            icon = "[red]✗[/red]"
            status = "failed"
        elif result_val is None:
            # Test mode - would change
            changed_count += 1
            icon = "[blue]?[/blue]"
            status = "would change"
        else:
            icon = "[dim]○[/dim]"
            status = "unknown"
        
        console.print(f"   {icon} {display_id}")
        
        # Show changes or diff for drifted states
        if changes and isinstance(changes, dict):
            # Check if this is cmd.run output (has stdout, retcode, pid)
            is_cmd_output = 'stdout' in changes or 'retcode' in changes
            
            if is_cmd_output:
                # Display cmd.run output cleanly
                retcode = changes.get('retcode', 0)
                stdout = changes.get('stdout', '')
                stderr = changes.get('stderr', '')
                
                if retcode != 0:
                    console.print(f"      [yellow]Exit code: {retcode}[/yellow]")
                
                if stdout:
                    console.print(f"      [dim]Output:[/dim]")
                    for line in stdout.split('\n'):
                        console.print(f"      {line}")
                
                if stderr:
                    console.print(f"      [red]Stderr:[/red]")
                    for line in stderr.split('\n')[:5]:
                        console.print(f"      [red]{line}[/red]")
                    if len(stderr.split('\n')) > 5:
                        console.print(f"      [dim]... ({len(stderr.split(chr(10))) - 5} more lines)[/dim]")
            else:
                # Standard state changes display
                for change_key, change_val in list(changes.items())[:3]:
                    if isinstance(change_val, dict):
                        old_val = change_val.get("old", "")
                        new_val = change_val.get("new", "")
                        if old_val or new_val:
                            old_str = str(old_val)[:30] if old_val else "(none)"
                            new_str = str(new_val)[:30] if new_val else "(none)"
                            console.print(f"      [dim]{change_key}: {old_str} → {new_str}[/dim]")
                    else:
                        console.print(f"      [dim]{change_key}: {str(change_val)[:50]}[/dim]")
                if len(changes) > 3:
                    console.print(f"      [dim]... and {len(changes) - 3} more changes[/dim]")
        
        # Show comment for failures or test mode
        if result_val is False and comment:
            console.print(f"      [red]{comment[:100]}[/red]")
        elif result_val is None and comment:
            console.print(f"      [dim]{comment[:80]}[/dim]")
    
    # Print summary for this minion
    summary_parts = []
    if success_count > 0:
        summary_parts.append(f"{success_count} ok")
    if changed_count > 0:
        summary_parts.append(f"{changed_count} {'would change' if is_test else 'changed'}")
    if failed_count > 0:
        summary_parts.append(f"{failed_count} failed")
    
    if summary_parts:
        console.print(f"   [dim]Summary: {', '.join(summary_parts)}[/dim]")
    
    return success_count, changed_count, failed_count


def _display_state_result(result: dict, is_test: bool = False) -> None:
    """Display state.apply result with formatting."""
    
    if not result:
        console.print("[yellow]No results returned[/yellow]\n")
        return
    
    # Handle job results format
    if isinstance(result, dict):
        jid = result.get("jid")
        if jid:
            console.print(f"[dim]Job ID: {jid}[/dim]\n")
        
        # Get minion results
        minion_results = result.get("ret", result)
        if isinstance(minion_results, dict):
            for minion_id, states in minion_results.items():
                console.print(f"[bold]{minion_id}[/bold]")
                
                if isinstance(states, dict):
                    success_count = 0
                    changed_count = 0
                    failed_count = 0
                    
                    for state_id, state_result in states.items():
                        if isinstance(state_result, dict):
                            result_val = state_result.get("result")
                            changes = state_result.get("changes", {})
                            comment = state_result.get("comment", "")
                            
                            if result_val is True:
                                success_count += 1
                                if changes:
                                    changed_count += 1
                                    icon = "[yellow]~[/yellow]"
                                else:
                                    icon = "[green]✓[/green]"
                            elif result_val is False:
                                failed_count += 1
                                icon = "[red]✗[/red]"
                            elif result_val is None:
                                # Test mode - would change
                                icon = "[blue]?[/blue]"
                                changed_count += 1
                            else:
                                icon = "[dim]?[/dim]"
                            
                            # Extract state name from ID
                            state_name = state_id.split("|")[-1] if "|" in state_id else state_id
                            console.print(f"  {icon} {state_name[:60]}")
                            
                            if changes and not is_test:
                                for key, val in list(changes.items())[:3]:
                                    console.print(f"      [dim]{key}: {str(val)[:50]}[/dim]")
                    
                    # Summary for minion
                    console.print(f"  [dim]Summary: {success_count} ok, {changed_count} changed, {failed_count} failed[/dim]")
                elif isinstance(states, str):
                    # Error message
                    console.print(f"  [red]{states}[/red]")
                
                console.print()
    else:
        console.print(f"Result: {result}\n")
    
    if is_test:
        console.print("[yellow]Test mode - no changes were made[/yellow]\n")


def _display_resource_list(results: dict, resource_type: str) -> None:
    """Render a list of RaaS resources with a consistent, modern look."""
    from salt_config_cli.ui import (
        section as ui_section,
        summary_pills,
        tree_panel,
        info as ui_info,
    )
    from salt_config_cli.ui.theme import ICONS

    # Top-level summary pills (only the ones that were requested + non-empty)
    pills = []
    if "state_files" in results:
        pills.append((len(results["state_files"]), "state files", "primary"))
    if "target_groups" in results:
        pills.append((len(results["target_groups"]), "target groups", "secondary"))
    if "jobs" in results:
        pills.append((len(results["jobs"]), "jobs", "accent"))
    if "pillars" in results:
        pills.append((len(results["pillars"]), "pillars", "info"))
    if "minions" in results:
        pills.append((len(results["minions"]), "minions", "primary"))
    if "schedules" in results:
        pills.append((len(results["schedules"]), "schedules", "info"))
    if "environments" in results:
        pills.append((len(results["environments"]), "environments", "secondary"))
    if pills:
        summary_pills(pills)
        console.print()

    def _empty(label: str):
        ui_info(f"No {label} found.")
        console.print()

    # State files (grouped by environment) ----------------------------------
    if "state_files" in results:
        files = results["state_files"]
        ui_section("State files", icon="doc")
        if not files:
            _empty("state files")
        else:
            by_env: dict[str, list] = {}
            for f in files:
                env = f.get("saltenv", "base")
                by_env.setdefault(env, []).append(f)
            for env, env_files in sorted(by_env.items()):
                children = [
                    (f.get("path", "?"), f.get("content_type", ""))
                    for f in sorted(env_files, key=lambda x: x.get("path", ""))
                ]
                tree_panel(f"{env}  ({len(env_files)} files)", children, icon="environment")
            console.print()

    # Target groups ---------------------------------------------------------
    if "target_groups" in results:
        groups = results["target_groups"]
        ui_section("Target groups", icon="target")
        if not groups:
            _empty("target groups")
        else:
            for g in groups:
                name = g.get("name", "unknown")
                desc = g.get("desc", "")
                tgt = g.get("tgt", "")
                meta_parts = []
                if isinstance(tgt, (str, int)):
                    meta_parts.append(f"target={tgt}")
                if desc:
                    meta_parts.append(desc)
                console.print(
                    f"  [scc.accent]{ICONS['target']}[/scc.accent]  "
                    f"[scc.strong]{name}[/scc.strong]"
                    + (f"  [scc.muted]{ICONS['arrow']} {'  '.join(meta_parts)}[/scc.muted]" if meta_parts else "")
                )
            console.print()

    # Jobs ------------------------------------------------------------------
    if "jobs" in results:
        jobs = results["jobs"]
        ui_section("Jobs", icon="rocket")
        if not jobs:
            _empty("jobs")
        else:
            for j in jobs:
                name = j.get("name", "unknown")
                cmd = j.get("cmd", "")
                fun = j.get("fun", "")
                meta = "  ".join(p for p in (cmd, fun) if p)
                console.print(
                    f"  [scc.accent]{ICONS['rocket']}[/scc.accent]  "
                    f"[scc.strong]{name}[/scc.strong]"
                    + (f"  [scc.muted]{ICONS['arrow']} {meta}[/scc.muted]" if meta else "")
                )
            console.print()

    # Pillars ---------------------------------------------------------------
    if "pillars" in results:
        pillars = results["pillars"]
        ui_section("Pillars", icon="pillar")
        if not pillars:
            _empty("pillars")
        else:
            for p in pillars:
                name = p.get("name", "unknown")
                saltenv = p.get("saltenv", "base")
                console.print(
                    f"  [scc.accent]{ICONS['pillar']}[/scc.accent]  "
                    f"[scc.strong]{name}[/scc.strong]  [scc.muted]({saltenv})[/scc.muted]"
                )
            console.print()

    # Minions ---------------------------------------------------------------
    if "minions" in results:
        minions = results["minions"]
        ui_section("Minions", icon="minion")
        if not minions:
            _empty("minions")
        else:
            for m in minions:
                minion_id = m.get("minion_id", m.get("id", "unknown"))
                grain_os = (m.get("grains") or {}).get("os", "") if isinstance(m.get("grains"), dict) else ""
                master = m.get("master_id", "")
                presence = m.get("presence", "")
                online = presence == "present"
                dot = "[scc.success]●[/scc.success]" if online else "[scc.danger]○[/scc.danger]"
                meta_parts = []
                if grain_os:
                    meta_parts.append(grain_os)
                if master:
                    meta_parts.append(f"master={master}")
                console.print(
                    f"  {dot}  [scc.strong]{minion_id}[/scc.strong]"
                    + (f"  [scc.muted]{ICONS['arrow']} {'  '.join(meta_parts)}[/scc.muted]" if meta_parts else "")
                )
            console.print()

    # Schedules -------------------------------------------------------------
    if "schedules" in results:
        schedules = results["schedules"]
        ui_section("Schedules", icon="schedule")
        if not schedules:
            _empty("schedules")
        else:
            for s in schedules:
                name = s.get("name", "unknown")
                enabled = s.get("enabled", False)
                pill = "[scc.badge.success] ON [/scc.badge.success]" if enabled else "[scc.badge.muted] OFF [/scc.badge.muted]"
                console.print(f"  {pill}  [scc.strong]{name}[/scc.strong]")
            console.print()

    # Environments ----------------------------------------------------------
    if "environments" in results:
        envs = results["environments"]
        ui_section("Salt environments", icon="environment")
        if not envs:
            _empty("environments")
        else:
            for env in envs:
                console.print(
                    f"  [scc.accent]{ICONS['environment']}[/scc.accent]  "
                    f"[scc.strong]{env}[/scc.strong]"
                )
            console.print()


@cli.command("target-group-create")
@click.argument("name")
@click.option(
    "--target", "-t",
    default="*",
    help="Target pattern for minions (default: *)"
)
@click.option(
    "--target-type", "-T",
    type=click.Choice(["glob", "grain", "compound", "list", "pcre"]),
    default="glob",
    help="Target type (default: glob)"
)
@click.option(
    "--description", "-d",
    default="",
    help="Target group description"
)
@common_options
@click.pass_context
def target_group_create(ctx, name, target, target_type, description, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """
    Create a new target group.
    
    Target groups define collections of minions that can be used for
    targeting jobs, states, and associating pillars.
    
    \b
    Examples:
      $ scc target-group-create my-group --target "*"
      $ scc target-group-create nsx-minions --target "vcfops_resource_kind:nsx" -T grain
      $ scc target-group-create web-servers --target "web-*" -d "Web server minions"
    """
    setup_logging(log_level, no_color)
    
    settings = load_settings(config, server, username, password, csp_token, password_stdin=password_stdin, password_file=password_file, password_prompt=password_prompt)
    
    if not settings.server_url or settings.server_url == "https://localhost":
        console.print("[red]No server configured. Set server_url in config.[/red]\n")
        sys.exit(1)
    
    api_client = connect_client(settings)
    ui_success(f"Connected to {mask_url(settings.server_url)}")
    
    console.print(f"[bold]Creating target group:[/bold] {name}")
    console.print(f"  Target: {target}")
    console.print(f"  Target type: {target_type}")
    if description:
        console.print(f"  Description: {description}")
    console.print()
    
    tgt_spec = {
        "*": {
            "tgt_type": target_type,
            "tgt": target
        }
    }
    
    try:
        call_params = {
            "name": name,
            "tgt": tgt_spec,
        }
        if description:
            call_params["desc"] = description
        
        logging.debug(f"Creating target group with params: {call_params}")
        resp = api_client.call("tgt", "save_target_group", **call_params)
        
        if resp.error:
            error_msg = resp.error.get('message', 'Unknown error')
            error_detail = resp.error.get('detail', '')
            console.print(f"[red]✗[/red] Failed to create target group: {error_msg}")
            if error_detail:
                console.print(f"  Detail: {error_detail}")
            console.print()
            sys.exit(1)
        
        tgt_uuid = resp.ret if isinstance(resp.ret, str) else resp.ret.get("uuid") if isinstance(resp.ret, dict) else None
        console.print(f"[green]✓[/green] Target group created!")
        if tgt_uuid:
            console.print(f"  UUID: {tgt_uuid}")
        console.print()
        console.print(f"[bold]Usage:[/bold]")
        console.print(f"  scc upload-pillar <file> --target-group {name}")
        console.print(f"  scc run <state> --target-group {name}")
        console.print(f"  scc exec test.ping --target-group {name}")
        console.print()
        
    except Exception as e:
        console.print(f"[red]✗[/red] Failed: {e}\n")
        sys.exit(1)
    
    api_client.close()


@cli.command("pillar-list")
@click.option(
    "--name", "-n",
    default=None,
    help="Filter by pillar name"
)
@click.option(
    "--show-data", "-d",
    is_flag=True,
    help="Show pillar data contents"
)
@click.option(
    "--json", "output_json",
    is_flag=True,
    help="Output as JSON"
)
@common_options
@click.pass_context
def pillar_list(ctx, name, show_data, output_json, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """
    List pillars configured in RaaS.

    Shows pillar metadata, target-group assignments and optional pillar data.

    \b
    Examples:
      $ scc pillar-list
      $ scc pillar-list --name vcf_credentials
      $ scc pillar-list --show-data
      $ scc pillar-list --json
    """
    setup_logging(log_level, no_color)
    settings = load_settings(
        config, server, username, password, csp_token,
        password_stdin=password_stdin,
        password_file=password_file,
        password_prompt=password_prompt,
    )

    if not output_json:
        command_header(
            "pillar-list",
            "Pillar catalog",
            description="Review pillar definitions and verify which target groups receive them.",
            icon="pillar",
            meta=[
                ("Filter", name or "all pillars"),
                ("Show data", "yes" if show_data else "no"),
                ("Server", mask_url(settings.server_url)),
            ],
        )

    api_client = connect_client(settings, label="pillars")
    try:
        call_kwargs = {"name": name} if name else {}
        with spinner("Loading pillar definitions…") if not output_json else contextlib.nullcontext():
            resp = api_client.call("pillar", "get_pillars", **call_kwargs)
        if resp.error:
            message = resp.error.get("message", "Unknown error") if isinstance(resp.error, dict) else str(resp.error)
            raise RuntimeError(message)

        pillars = resp.ret.get("results", []) if isinstance(resp.ret, dict) else []
        if output_json:
            _print_stdout(json.dumps(pillars, indent=2, default=str))
            return

        if not pillars:
            empty_state(
                "No pillars found",
                "RaaS returned no pillar definitions matching this request.",
                icon="pillar",
                actions=["scc upload-pillar <file.yaml>", "scc pillar-list", "scc help upload-pillar"],
            )
            return

        tgt_resp = api_client.call("tgt", "get_target_group", include_pillar_data=True)
        tgt_groups = tgt_resp.ret.get("results", []) if isinstance(tgt_resp.ret, dict) and not tgt_resp.error else []
        pillar_to_groups: dict[str, list[str]] = {}
        for target_group in tgt_groups:
            target_name = target_group.get("name", "Unknown")
            for pillar_ref in target_group.get("pillars", []):
                pillar_uuid = pillar_ref if isinstance(pillar_ref, str) else pillar_ref.get("uuid")
                if pillar_uuid:
                    pillar_to_groups.setdefault(pillar_uuid, []).append(target_name)

        rows = []
        unassigned = 0
        for pillar in pillars:
            pillar_uuid = pillar.get("uuid", "")
            groups = pillar_to_groups.get(pillar_uuid, [])
            if not groups:
                unassigned += 1
            assignment = ", ".join(groups) if groups else "Not assigned"
            status_text = Text(
                f"{ICONS['success']} Assigned" if groups else f"{ICONS['warning']} Unassigned",
                style="scc.success" if groups else "scc.warning",
            )
            rows.append([
                pillar.get("name", "Unknown"),
                pillar.get("pillar_type", "static"),
                assignment,
                status_text,
                (pillar_uuid or "-")[:12],
            ])

        data_table(
            f"Pillars ({len(pillars)})",
            [
                ("Name", "scc.strong"),
                ("Type", "scc.info"),
                ("Assigned target groups", "scc.value"),
                ("Status", "scc.value"),
                ("UUID", "scc.muted"),
            ],
            rows,
            icon="pillar",
            caption="Use --show-data to inspect sanitized pillar content.",
        )

        if show_data:
            import yaml as _yaml
            for pillar in pillars:
                payload = pillar.get("pillar", {})
                rendered = _yaml.safe_dump(payload, sort_keys=False, default_flow_style=False).rstrip() if payload else "# no data returned"
                console.print(
                    Panel(
                        Syntax(rendered, "yaml", theme="ansi_dark", word_wrap=True),
                        title=f"[scc.title]{ICONS['pillar']} {pillar.get('name', 'Unknown')}[/scc.title]",
                        border_style="scc.secondary",
                        box=box.ROUNDED,
                    )
                )

        result_summary(
            "Pillar inventory loaded",
            status="warning" if unassigned else "success",
            message=(
                f"{unassigned} pillar(s) are not assigned to a target group and will not be delivered to minions."
                if unassigned else
                "All returned pillars are assigned to at least one target group."
            ),
            metrics=[
                (len(pillars), "pillars", "primary"),
                (len(pillars) - unassigned, "assigned", "success"),
                (unassigned, "unassigned", "warning" if unassigned else "success"),
            ],
        )
        next_steps(
            [
                "Assign a pillar: `scc pillar-assign <pillar> --target-group <group>`",
                "Refresh minion data: `scc pillar-refresh --target-group <group>`",
                "Verify on a minion: `scc exec pillar.items --target <minion> --output text`",
            ]
        )
    except Exception as exc:
        raise click.ClickException(f"Failed to list pillars: {exc}") from exc
    finally:
        api_client.close()

@cli.command("target-group-list")
@click.option(
    "--name", "-n",
    default=None,
    help="Filter by target group name"
)
@click.option(
    "--show-pillars",
    is_flag=True,
    help="Show associated pillars"
)
@click.option(
    "--json", "output_json",
    is_flag=True,
    help="Output as JSON"
)
@common_options
@click.pass_context
def target_group_list(ctx, name, show_pillars, output_json, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """
    List target groups configured in RaaS.

    \b
    Examples:
      $ scc target-group-list
      $ scc target-group-list --name vcf-all-group
      $ scc target-group-list --show-pillars
      $ scc target-group-list --json
    """
    setup_logging(log_level, no_color)
    settings = load_settings(
        config, server, username, password, csp_token,
        password_stdin=password_stdin,
        password_file=password_file,
        password_prompt=password_prompt,
    )

    if not output_json:
        command_header(
            "target-group-list",
            "Targeting inventory",
            description="See exactly which minions, patterns and pillars each saved target group represents.",
            icon="target",
            meta=[
                ("Filter", name or "all groups"),
                ("Pillar details", "shown" if show_pillars else "summary"),
                ("Server", mask_url(settings.server_url)),
            ],
        )

    api_client = connect_client(settings, label="target groups")
    try:
        call_kwargs = {"include_pillar_data": True}
        if name:
            call_kwargs["name"] = name
        with spinner("Loading target groups…") if not output_json else contextlib.nullcontext():
            resp = api_client.call("tgt", "get_target_group", **call_kwargs)
        if resp.error:
            message = resp.error.get("message", "Unknown error") if isinstance(resp.error, dict) else str(resp.error)
            raise RuntimeError(message)

        groups = resp.ret.get("results", []) if isinstance(resp.ret, dict) else []
        if output_json:
            _print_stdout(json.dumps(groups, indent=2, default=str))
            return
        if not groups:
            empty_state(
                "No target groups found",
                "RaaS returned no target groups matching this request.",
                icon="target",
                actions=["scc target-group-create <name> --target '<pattern>'", "scc target-group-list", "scc help target-group-create"],
            )
            return

        rows = []
        total_minions = 0
        groups_without_pillars = 0
        for group_data in groups:
            targets = []
            target_types = []
            for master_id, target_spec in (group_data.get("tgt", {}) or {}).items():
                if not isinstance(target_spec, dict):
                    continue
                target_pattern = target_spec.get("tgt", "*")
                target_type = target_spec.get("tgt_type", "glob")
                targets.append(f"{target_pattern} @ {master_id}")
                target_types.append(target_type)
            pillars = group_data.get("pillars", []) or []
            pillar_names = [
                p.get("name", p.get("uuid", "Unknown")) if isinstance(p, dict) else str(p)
                for p in pillars
            ]
            minion_count = int(group_data.get("minion_count", 0) or 0)
            total_minions += minion_count
            if not pillars:
                groups_without_pillars += 1
            rows.append([
                group_data.get("name", "Unknown"),
                minion_count,
                ", ".join(sorted(set(target_types))) or "-",
                "\n".join(targets) or "-",
                ", ".join(pillar_names) if pillar_names else "None",
                (group_data.get("uuid", "") or "-")[:12],
            ])

        data_table(
            f"Target groups ({len(groups)})",
            [
                ("Name", "scc.strong"),
                ("Count", "scc.info"),
                ("Type", "scc.secondary"),
                ("Target", "scc.value"),
                ("Pillars", "scc.accent" if show_pillars else "scc.muted"),
                ("UUID", "scc.muted"),
            ],
            rows,
            icon="target",
            caption="Counts are reported by RaaS and may reflect the most recent inventory refresh.",
        )

        result_summary(
            "Target-group inventory loaded",
            status="success",
            message="Use a saved target group to avoid broad or ambiguous minion targeting.",
            metrics=[
                (len(groups), "groups", "primary"),
                (total_minions, "reported minions", "success"),
                (groups_without_pillars, "without pillars", "warning" if groups_without_pillars else "success"),
            ],
        )
        next_steps(
            [
                "Test a group: `scc exec test.ping --target-group <group> --output text`",
                "Assign pillar data: `scc pillar-assign <pillar> --target-group <group>`",
                "Create another group: `scc target-group-create <name> --target '<pattern>'`",
            ]
        )
    except Exception as exc:
        raise click.ClickException(f"Failed to list target groups: {exc}") from exc
    finally:
        api_client.close()

@cli.command("pillar-assign")
@click.argument("pillar_name")
@click.option(
    "--target-group", "-g",
    required=True,
    help="Target group name to assign the pillar to"
)
@common_options
@click.pass_context
def pillar_assign(ctx, pillar_name, target_group, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """
    Assign a pillar to a target group.
    
    This associates existing pillar data with a target group so that
    minions in that group receive the pillar data.
    
    \b
    Examples:
      $ scc pillar-assign vcf_credentials --target-group vcf-all-group
      $ scc pillar-assign my_pillar -g nsx-minions
    """
    setup_logging(log_level, no_color)
    
    settings = load_settings(config, server, username, password, csp_token, password_stdin=password_stdin, password_file=password_file, password_prompt=password_prompt)
    
    if not settings.server_url or settings.server_url == "https://localhost":
        console.print("[red]No server configured. Set server_url in config.[/red]\n")
        sys.exit(1)
    
    api_client = connect_client(settings)
    ui_success(f"Connected to {mask_url(settings.server_url)}")
    
    # Find the pillar by name
    console.print(f"Looking up pillar: [cyan]{pillar_name}[/cyan]")
    try:
        pillar_resp = api_client.call("pillar", "get_pillars", name=pillar_name)
        if pillar_resp.error:
            console.print(f"[red]✗[/red] Failed to find pillar: {pillar_resp.error.get('message', 'Unknown error')}\n")
            sys.exit(1)
        
        pillars = pillar_resp.ret.get("results", []) if isinstance(pillar_resp.ret, dict) else []
        if not pillars:
            console.print(f"[red]✗[/red] Pillar '{pillar_name}' not found\n")
            sys.exit(1)
        
        # Find exact match
        pillar = next((p for p in pillars if p.get("name") == pillar_name), pillars[0])
        pillar_uuid = pillar.get("uuid")
        console.print(f"  Found pillar UUID: {pillar_uuid}")
    except Exception as e:
        console.print(f"[red]✗[/red] Error finding pillar: {e}\n")
        sys.exit(1)
    
    # Find the target group by name
    console.print(f"Looking up target group: [cyan]{target_group}[/cyan]")
    try:
        tgt_resp = api_client.call("tgt", "get_target_group", name=target_group)
        if tgt_resp.error:
            console.print(f"[red]✗[/red] Failed to find target group: {tgt_resp.error.get('message', 'Unknown error')}\n")
            sys.exit(1)
        
        tgt_groups = tgt_resp.ret.get("results", []) if isinstance(tgt_resp.ret, dict) else []
        if not tgt_groups:
            console.print(f"[red]✗[/red] Target group '{target_group}' not found\n")
            console.print("Create one with: scc target-group-create <name> --target <pattern>\n")
            sys.exit(1)
        
        # Find exact match
        tgt = next((t for t in tgt_groups if t.get("name") == target_group), tgt_groups[0])
        tgt_uuid = tgt.get("uuid")
        tgt_name = tgt.get("name")
        existing_pillars = tgt.get("pillars", [])
        existing_pillar_uuids = [p if isinstance(p, str) else p.get("uuid") for p in existing_pillars]
        tgt_spec = tgt.get("tgt", {})
        console.print(f"  Found target group UUID: {tgt_uuid}")
        
        # Check if pillar is already assigned
        if pillar_uuid in existing_pillar_uuids:
            console.print(f"\n[yellow]![/yellow] Pillar is already assigned to this target group\n")
            api_client.close()
            return
    except Exception as e:
        console.print(f"[red]✗[/red] Error finding target group: {e}\n")
        sys.exit(1)
    
    # Update target group with the pillar
    console.print(f"\nAssigning pillar to target group...")
    try:
        new_pillar_uuids = existing_pillar_uuids + [pillar_uuid]
        
        update_resp = api_client.call(
            "tgt", "save_target_group",
            tgt_uuid=tgt_uuid,
            name=tgt_name,
            tgt=tgt_spec,
            pillar_uuids=new_pillar_uuids,
        )
        
        if update_resp.error:
            error_msg = update_resp.error.get('message', 'Unknown error')
            console.print(f"[red]✗[/red] Failed to assign pillar: {error_msg}\n")
            sys.exit(1)
        
        console.print(f"[green]✓[/green] Pillar assigned to target group!\n")
        console.print(f"[bold]Next step:[/bold] Refresh pillar on minions:")
        console.print(f"  scc pillar-refresh --target '*'")
        console.print(f"  scc pillar-refresh --target-group {target_group}")
        console.print()
        
    except Exception as e:
        console.print(f"[red]✗[/red] Failed: {e}\n")
        sys.exit(1)
    
    api_client.close()


@cli.command("pillar-refresh")
@click.option(
    "--target", "-t",
    default="*",
    help="Target minion pattern (default: *)"
)
@click.option(
    "--target-type", "-T",
    type=click.Choice(["glob", "grain", "compound", "list", "nodegroup", "pillar", "pcre"]),
    default="glob",
    help="Target type (default: glob)"
)
@click.option(
    "--target-group", "-g",
    default=None,
    help="Target group name (alternative to --target)"
)
@common_options
@click.pass_context
def pillar_refresh(ctx, target, target_type, target_group, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """
    Refresh pillar data on minions.
    
    This runs saltutil.refresh_pillar on targeted minions to reload
    their pillar data from the Salt master.
    
    \b
    Examples:
      $ scc pillar-refresh
      $ scc pillar-refresh --target "web-*"
      $ scc pillar-refresh --target "vcfops_resource_kind:nsx" -T grain
      $ scc pillar-refresh --target-group vcf-all-group
    """
    setup_logging(log_level, no_color)
    
    settings = load_settings(config, server, username, password, csp_token, password_stdin=password_stdin, password_file=password_file, password_prompt=password_prompt)
    
    if not settings.server_url or settings.server_url == "https://localhost":
        console.print("[red]No server configured. Set server_url in config.[/red]\n")
        sys.exit(1)
    
    api_client = connect_client(settings)
    ui_success(f"Connected to {mask_url(settings.server_url)}")
    
    # Build the command
    cmd_kwargs = {
        "cmd": "local",
        "fun": "saltutil.refresh_pillar",
    }
    
    if target_group:
        # Resolve target group to UUID
        console.print(f"Resolving target group: [cyan]{target_group}[/cyan]")
        try:
            tgt_resp = api_client.call("tgt", "get_target_group", name=target_group)
            if tgt_resp.error:
                console.print(f"[red]✗[/red] Failed to find target group: {tgt_resp.error.get('message', 'Unknown error')}\n")
                sys.exit(1)
            
            tgt_groups = tgt_resp.ret.get("results", []) if isinstance(tgt_resp.ret, dict) else []
            if not tgt_groups:
                console.print(f"[red]✗[/red] Target group '{target_group}' not found\n")
                sys.exit(1)
            
            tgt = next((t for t in tgt_groups if t.get("name") == target_group), tgt_groups[0])
            tgt_uuid = tgt.get("uuid")
            console.print(f"  Found UUID: {tgt_uuid}")
            cmd_kwargs["tgt_uuid"] = tgt_uuid
        except Exception as e:
            console.print(f"[red]✗[/red] Error resolving target group: {e}\n")
            sys.exit(1)
    else:
        cmd_kwargs["tgt"] = {
            "*": {
                "tgt_type": target_type,
                "tgt": target
            }
        }
        console.print(f"Target: [cyan]{target}[/cyan] (type: {target_type})")
    
    console.print(f"\nRefreshing pillar on minions...")
    
    try:
        resp = api_client.call("cmd", "route_cmd", **cmd_kwargs)
        
        if resp.error:
            console.print(f"[red]✗[/red] Failed: {resp.error.get('message', 'Unknown error')}\n")
            sys.exit(1)
        
        jid = resp.ret
        console.print(f"[green]✓[/green] Pillar refresh initiated")
        console.print(f"  Job ID: {jid}")
        console.print()
        console.print(f"[bold]Verify with:[/bold]")
        console.print(f"  scc exec pillar.items --target <minion>")
        console.print()
        
    except Exception as e:
        console.print(f"[red]✗[/red] Failed: {e}\n")
        sys.exit(1)
    
    api_client.close()


@cli.command("job-create")
@click.argument("name")
@click.option(
    "--function", "-f", "cmd",
    required=True,
    help="Salt function to run (e.g., state.apply, test.ping)"
)
@click.option(
    "--target", "-t",
    default=None,
    help="Target minion pattern (e.g., '*', 'web-*')"
)
@click.option(
    "--target-group", "-g",
    default=None,
    help="Target group name from RaaS (e.g., 'ops', 'All Minions')"
)
@click.option(
    "--arg", "-a", "args",
    multiple=True,
    help="Positional arguments (can be used multiple times)"
)
@click.option(
    "--kwarg", "-k", "kwargs",
    multiple=True,
    help="Keyword arguments in key=value format (can be used multiple times)"
)
@click.option(
    "--pillar", "pillars",
    multiple=True,
    help="Pillar data in key=value format (can be used multiple times)"
)
@click.option(
    "--env", "-e", "saltenv",
    default=None,
    help="Salt environment"
)
@click.option(
    "--description", "-d", "desc",
    default="",
    help="Job description"
)
@click.option(
    "--state", "state",
    default=None,
    help="State module to apply (e.g., ntp-config, web-server)"
)
@click.option(
    "--cmd-type",
    type=click.Choice(["local", "ssh", "runner", "wheel"]),
    default="local",
    help="Command type (local=targeting minions, runner=master-level, etc.)"
)
@click.option(
    "--masters", "masters",
    multiple=True,
    help="Master names that should receive this command (can be used multiple times)"
)
@click.option(
    "--input", "inputs",
    multiple=True,
    metavar="KEY:TYPE:DEFAULT:REQUIRED",
    help="Define job inputs (e.g., --input 'mods:string:deploy_vm.sls:true')"
)
@common_options
@click.pass_context
def job_create(ctx, name, cmd, target, target_group, args, kwargs, pillars, saltenv, desc, state, cmd_type, masters, inputs, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """
    Create a job in RaaS.
    
    Creates a saved job definition that can be run manually or scheduled.
    Supports positional arguments, keyword arguments, pillar data, and detailed
    input definitions for UI presentation and validation.
    
    \b
    Examples:
      $ scc job-create my-ping-job -f test.ping --target-group ops
      $ scc job-create deploy-app -f state.apply --state app-deploy --target-group prod
      $ scc job-create ntp-check -f state.apply --arg ntp-config --target-group ops --env vcfsecops
      $ scc job-create check-disk -f disk.usage --target "*" --pillar server_type=prod
      $ scc job-create vm-deploy -f state.apply --state deploy_vm --kwarg size=xlarge --input 'size:string:xlarge:true'
    """
    setup_logging(log_level, no_color)
    
    settings = load_settings(config, server, username, password, csp_token, password_stdin=password_stdin, password_file=password_file, password_prompt=password_prompt)

    command_header(
        "job-create",
        "Create or update a saved RaaS job",
        description="Build a reusable, named operation with explicit function, target and input metadata.",
        icon="job",
        meta=[
            ("Job", name),
            ("Function", cmd),
            ("Scope", target_group or target or "not specified"),
        ],
        mode=("MUTATING", "white on #b54453") if str(cmd).startswith(("state.", "cmd.", "pkg.", "service.")) else ("REVIEW", "black on #e6c75a"),
    )

    api_client = connect_client(settings, label="saved job editor")
    ui_success(f"Connected to {mask_url(settings.server_url)}")
    
    # Resolve target group if specified
    tgt_uuid = None
    
    if target_group:
        with spinner(f"Resolving target group '{target_group}'…"):
            groups = _list_target_groups(api_client)
            found = None
            for g in groups:
                if isinstance(g, dict) and g.get("name", "").lower() == target_group.lower():
                    found = g
                    break
        
        if not found:
            ui_error(f"Target group not found: {target_group}",
                    hint=f"Run 'scc list target-groups' to see available groups.")
            sys.exit(1)
        
        tgt_uuid = found.get("uuid")
        ui_success(f"Resolved target group: {target_group}")
    
    # Parse keyword arguments
    kwarg_dict = {}
    for kv in kwargs:
        if "=" in kv:
            key, value = kv.split("=", 1)
            kwarg_dict[key] = value
    
    # Parse pillar arguments
    pillar_dict = {}
    for pv in pillars:
        if "=" in pv:
            key, value = pv.split("=", 1)
            pillar_dict[key] = value
    
    # If state is specified, add it as a hard-coded argument to mods
    if state:
        kwarg_dict["mods"] = {
            "display_name": "State",
            "input_type": "string",
            "default": state,
            "help": f"State to apply: {state}",
            "required": True,
            "hidden": True
        }
        # For state.apply, mods is typically the positional arg
        if not args:
            args = (state,)
    
    # Add saltenv if specified
    if saltenv:
        kwarg_dict["saltenv"] = {
            "display_name": "Environment",
            "input_type": "string",
            "default": saltenv,
            "help": f"Salt environment: {saltenv}",
            "required": True,
            "hidden": True
        }
    
    # Parse input definitions (format: key:type:default:required)
    # Example: --input 'size:string:xlarge:true'
    for input_def in inputs:
        parts = input_def.split(":")
        if len(parts) < 2:
            ui_error(f"Invalid input format: {input_def}",
                    hint="Use format: --input 'key:string:default_value:true'")
            sys.exit(1)
        
        key = parts[0]
        input_type = parts[1] if len(parts) > 1 else "string"
        default_val = parts[2] if len(parts) > 2 else None
        required = parts[3].lower() == "true" if len(parts) > 3 else False
        
        kwarg_dict[key] = {
            "display_name": key.replace("_", " ").title(),
            "input_type": input_type,
            "default": default_val,
            "help": f"Input: {key}",
            "required": required,
            "hidden": False
        }
    
    # Build arg dict for the API
    # API expects: arg = {"arg": [...], "kwarg": {...}, "pillar": {...}}
    arg_dict = {}
    if args:
        arg_dict["arg"] = list(args)
    if kwarg_dict:
        arg_dict["kwarg"] = kwarg_dict
    if pillar_dict:
        arg_dict["kwarg"] = arg_dict.get("kwarg", {})
        arg_dict["kwarg"]["pillar"] = pillar_dict
    
    # Build job parameters for display
    job_details = [
        ("Name", name),
        ("Function", cmd),
        ("Command type", cmd_type),
        ("State", state or "-"),
        ("Arguments", json.dumps(list(args), default=str) if args else "-"),
        ("Keyword inputs", f"{len(kwarg_dict)} defined" if kwarg_dict else "none"),
        ("Pillar keys", ", ".join(pillar_dict.keys()) if pillar_dict else "none"),
        ("Target group", target_group or "-"),
        ("Target", target or "-"),
        ("Masters", ", ".join(masters) if masters else "all/unspecified"),
        ("Description", desc or "-"),
    ]
    kv_table(f"{ICONS['job']} Job configuration preview", job_details)
    
    try:
        # First, check if job already exists by name
        existing_job = None
        with spinner(f"Checking if job '{name}' already exists…"):
            jobs_resp = api_client.call("job", "get_jobs")
            if jobs_resp.success and jobs_resp.ret:
                jobs = jobs_resp.ret.get("results", []) if isinstance(jobs_resp.ret, dict) else jobs_resp.ret
                for job in jobs:
                    if isinstance(job, dict) and job.get("name") == name:
                        existing_job = job
                        break
        
        is_update = existing_job is not None
        action = "Updating" if is_update else "Creating"
        
        # Create the job using API parameters
        save_params = {
            "name": name,
            "fun": cmd,
            "cmd": cmd_type,
            "arg": arg_dict if arg_dict else None,
            "desc": desc if desc else None,
        }
        
        if is_update:
            # If updating, pass the UUID to update the existing job
            save_params["job_uuid"] = existing_job.get("uuid")
        
        if tgt_uuid:
            save_params["tgt_uuid"] = tgt_uuid
        
        if masters:
            save_params["masters"] = list(masters)
        
        with spinner(f"{action} job '{name}'…"):
            result = api_client.save_job(**save_params)
        
        job_uuid = result.get("uuid", "unknown")
        
        action_label = "updated" if is_update else "created"
        result_summary(
            f"Saved job {action_label}",
            status="success",
            message="The RaaS job definition is ready for review and execution.",
            details=[
                ("Name", name),
                ("UUID", job_uuid),
                ("Function", cmd),
                ("Target", target_group or target or "configured by RaaS"),
            ],
        )
        next_steps(
            [
                f"Run it: `scc job-run '{name}'`",
                "Review all jobs: `scc job-list`",
                "After submission, fetch results: `scc job-results <jid>`",
            ],
            title="Use this job",
        )
        
    except Exception as e:
        ui_error(f"Failed to create job: {e}")
        sys.exit(1)


@cli.command("job-delete")
@click.argument("name")
@click.option(
    "--uuid",
    default=None,
    help="Job UUID (alternative to name)"
)
@click.option(
    "--force", "-f",
    is_flag=True,
    help="Skip confirmation"
)
@common_options
@click.pass_context
def job_delete(ctx, name, uuid, force, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """
    Delete a job from RaaS.
    
    \b
    Examples:
      $ scc job-delete my-ping-job
      $ scc job-delete my-ping-job --force
    """
    setup_logging(log_level, no_color)
    
    settings = load_settings(config, server, username, password, csp_token, password_stdin=password_stdin, password_file=password_file, password_prompt=password_prompt)
    
    api_client = connect_client(settings)
    ui_success(f"Connected to {mask_url(settings.server_url)}")
    
    # Look up job UUID by name if not provided
    job_uuid = uuid
    if not job_uuid:
        console.print(f"Looking up job: {name}...")
        response = api_client.call("job", "get_jobs")
        if response.success and response.ret:
            jobs = response.ret.get("results", []) if isinstance(response.ret, dict) else response.ret
            for job in jobs:
                if isinstance(job, dict) and job.get("name") == name:
                    job_uuid = job.get("uuid")
                    break
        
        if not job_uuid:
            console.print(f"[red]✗[/red] Job not found: {name}\n")
            sys.exit(1)
        console.print(f"[green]✓[/green] Found job UUID: {job_uuid}\n")
    
    # Confirm deletion
    if not force:
        if not click.confirm(f"Are you sure you want to delete job '{name}'?"):
            console.print("Cancelled.\n")
            return
    
    try:
        api_client.delete_job(job_uuid=job_uuid)
        console.print(f"[green]✓[/green] Job '{name}' deleted successfully!\n")
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to delete job: {e}\n")
        sys.exit(1)


@cli.command("job-list")
@click.option(
    "--json", "as_json",
    is_flag=True,
    help="Output in JSON format"
)
@common_options
@click.pass_context
def job_list(ctx, as_json, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """
    List all saved jobs in RaaS.

    \b
    Examples:
      $ scc job-list
      $ scc job-list --json
    """
    setup_logging(log_level, no_color)
    settings = load_settings(
        config, server, username, password, csp_token,
        password_stdin=password_stdin,
        password_file=password_file,
        password_prompt=password_prompt,
    )

    if not as_json:
        command_header(
            "job-list",
            "Saved job catalog",
            description="Review reusable RaaS operations before executing them.",
            icon="job",
            meta=[("Server", mask_url(settings.server_url)), ("Output", "interactive table")],
        )

    api_client = connect_client(settings, label="saved jobs")
    try:
        with spinner("Loading saved jobs…") if not as_json else contextlib.nullcontext():
            response = api_client.call("job", "get_jobs")
        if not response.success:
            error_value = response.error or "Unknown error"
            message = error_value.get("message", str(error_value)) if isinstance(error_value, dict) else str(error_value)
            raise RuntimeError(message)

        ret = response.ret or {}
        jobs = ret.get("results", []) if isinstance(ret, dict) else (ret if isinstance(ret, list) else [])
        if as_json:
            _print_stdout(json.dumps(jobs, indent=2, default=str))
            return
        if not jobs:
            empty_state(
                "No saved jobs found",
                "Create a reusable job definition for common Salt or state workflows.",
                icon="job",
                actions=["scc job-create <name> --function test.ping --target <minion>", "scc help job-create"],
            )
            return

        rows = []
        state_jobs = 0
        for job in jobs:
            if not isinstance(job, dict):
                continue
            function = job.get("fun", "")
            if str(function).startswith("state."):
                state_jobs += 1
            target = job.get("tgt_name") or job.get("target_group_name") or job.get("tgt_uuid") or "-"
            rows.append([
                job.get("name", "unknown"),
                function or "-",
                job.get("cmd", "local"),
                target,
                job.get("desc", "") or "-",
                (job.get("uuid", "") or "-")[:12],
            ])

        data_table(
            f"Saved jobs ({len(rows)})",
            [
                ("Name", "scc.strong"),
                ("Function", "scc.accent"),
                ("Type", "scc.secondary"),
                ("Target", "scc.value"),
                ("Description", "scc.value"),
                ("UUID", "scc.muted"),
            ],
            rows,
            icon="job",
            caption="Run a job with `scc job-run <name>`; inspect prior execution using `scc job-results <jid>`.",
        )
        result_summary(
            "Saved-job inventory loaded",
            status="success",
            message="Review the function and target before executing a saved job.",
            metrics=[
                (len(rows), "jobs", "primary"),
                (state_jobs, "state jobs", "warning" if state_jobs else "info"),
                (len(rows) - state_jobs, "module/runner jobs", "success"),
            ],
        )
        next_steps(
            [
                "Run a job: `scc job-run <name>`",
                "Create a safe ping job: `scc job-create ping --function test.ping --target <minion>`",
                "Fetch results later: `scc job-results <jid>`",
            ]
        )
    except Exception as exc:
        raise click.ClickException(f"Failed to list jobs: {exc}") from exc
    finally:
        api_client.close()


@cli.command("job-run")
@click.argument("name", nargs=-1, required=True)
@click.option(
    "--wait",
    type=int,
    default=1800,
    show_default=True,
    metavar="SECONDS",
    help="Wait for job to complete (seconds). Use 0 for no timeout, or -1 to not wait."
)
@click.option(
    "--no-wait",
    "no_wait",
    is_flag=True,
    default=False,
    help="Submit the job and return immediately (don't wait for completion)."
)
@click.option(
    "--yes",
    is_flag=True,
    help="Confirm execution of a potentially mutating saved job."
)
@click.option(
    "--json", "as_json",
    is_flag=True,
    help="Output in JSON format"
)
@click.option(
    "--output-file", "-O", "output_file",
    type=click.Path(dir_okay=False, writable=True, resolve_path=False),
    default=None,
    metavar="PATH",
    help="Write job results to this file. Format is inferred from extension "
         "(.json, .yaml, .yml, .txt) unless --json/--yaml is also passed.",
)
@click.option(
    "--pillar-file",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    metavar="PATH",
    help="Inject a local YAML file as ad-hoc pillar data for this run only "
         "(e.g. from `scc pull-data`). Not uploaded or persisted to RaaS - "
         "the saved job definition is never modified."
)
@common_options
@click.pass_context
def job_run(ctx, name, wait, no_wait, yes, as_json, output_file, pillar_file, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """
    Run a saved job from RaaS.

    Executes a previously created job by name and shows live progress
    until it completes (or the timeout is reached).

    \b
    Examples:
      $ scc job-run "my-ping-job"
      $ scc job-run "Cluster Configuration" --wait 600
      $ scc job-run "Cluster Configuration" --wait 0              # no timeout
      $ scc job-run "my-ping-job" --no-wait                       # fire-and-forget
      $ scc job-run "my-ping-job" --json
      $ scc job-run "Cluster Configuration" -O results.yaml       # save to file
      $ scc job-run "Cluster Configuration" --output-file out.json
      $ scc job-run "dvs-pg-vccluster-job" --pillar-file data/dvs-pg-vccluster/prod.yaml
    """
    setup_logging(log_level, no_color)

    pillar_data = None
    if pillar_file:
        import yaml as _yaml
        try:
            with open(pillar_file) as f:
                pillar_data = _yaml.safe_load(f)
        except Exception as e:
            ui_error(f"Failed to load pillar file: {e}")
            sys.exit(1)

    # Handle name tuple from nargs=-1
    job_name = " ".join(name) if isinstance(name, tuple) else name

    settings = load_settings(config, server, username, password, csp_token, password_stdin=password_stdin, password_file=password_file, password_prompt=password_prompt)

    api_client = connect_client(settings)
    ui_success(f"Connected to {mask_url(settings.server_url)}")

    # Look up job UUID by name with a spinner so it's clear we're working.
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(f"Looking up job '{job_name}'...", total=None)
        response = api_client.call("job", "get_jobs")

    job_uuid = None
    job_definition = None
    if response.success and response.ret:
        jobs = response.ret.get("results", []) if isinstance(response.ret, dict) else response.ret
        for job in jobs:
            if isinstance(job, dict) and job.get("name") == job_name:
                job_uuid = job.get("uuid")
                job_definition = job
                break

    if not job_uuid:
        console.print(f"[red]✗[/red] Job not found: [bold]{job_name}[/bold]\n")
        console.print("[dim]Run 'scc job-list' to see available jobs.[/dim]\n")
        sys.exit(1)

    console.print(f"[green]✓[/green] Found job: [bold]{job_name}[/bold] [dim]({job_uuid})[/dim]\n")

    function_name = str((job_definition or {}).get("fun") or "").strip()
    read_only_functions = {
        "test.ping", "grains.items", "grains.get", "pillar.items", "pillar.get",
        "disk.usage", "status.all_status", "status.uptime", "service.status",
    }
    is_read_only = function_name in read_only_functions
    if not is_read_only:
        from salt_config_cli.ui import confirm_destructive
        target_summary = str((job_definition or {}).get("tgt") or (job_definition or {}).get("tgt_uuid") or "saved target")
        if not confirm_destructive(
            action=f"run saved job {job_name}",
            targets_summary=f"Function: {function_name or 'unknown'}; target: {target_summary}",
            typed_phrase="run",
            auto_approve=yes,
        ):
            ui_warn("Saved job execution cancelled.")
            api_client.close()
            return

    # Run the job. With no --pillar-file, use the job_uuid shortcut
    # (unchanged). With --pillar-file, submit an explicit cmd/fun/tgt/arg
    # payload instead - RaaS's job_uuid-based route_cmd ignores any `arg`
    # passed alongside it and always runs the saved definition as-is
    # (verified against a live RaaS instance), so injecting ad-hoc pillar
    # data for a single run has to bypass the job_uuid shortcut entirely.
    expected_minions = None
    try:
        if pillar_data is not None:
            stored_arg = (job_definition or {}).get("arg") or {}
            base_args = list(stored_arg.get("arg") or [])
            base_kwargs_raw = dict(stored_arg.get("kwarg") or {})
            resolved_kwargs = {
                key: (value.get("default") if isinstance(value, dict) and "default" in value else value)
                for key, value in base_kwargs_raw.items()
            }
            # `job-create --state` stores the state name both positionally (arg[0])
            # and as a `mods` kwarg (UI display metadata only) - forwarding both
            # collides: state.apply() got multiple values for argument 'mods'.
            if base_args and "mods" in resolved_kwargs:
                del resolved_kwargs["mods"]
            resolved_kwargs["pillar"] = pillar_data

            tgt_name = (job_definition or {}).get("tgt_name")
            if not tgt_name:
                console.print(
                    "[red]✗[/red] Can't inject pillar data for this job: it has no "
                    "associated target group name to resolve.\n"
                )
                sys.exit(1)

            with spinner(f"Resolving target group '{tgt_name}'..."):
                groups = _list_target_groups(api_client)
            found = next(
                (g for g in groups if isinstance(g, dict) and g.get("name", "").lower() == tgt_name.lower()),
                None,
            )
            if not found:
                console.print(f"[red]✗[/red] Target group not found: {tgt_name}\n")
                sys.exit(1)

            resolved_target, resolved_target_type = "*", "glob"
            tgt_spec_from_group = found.get("tgt", {})
            if isinstance(tgt_spec_from_group, dict):
                for master_tgt in tgt_spec_from_group.values():
                    if isinstance(master_tgt, dict):
                        resolved_target = master_tgt.get("tgt", "*")
                        resolved_target_type = master_tgt.get("tgt_type", "glob")
                        break

            # This path dispatches via the same direct cmd.route_cmd
            # ("local") mechanism as `scc run`/`scc deploy` -- not the
            # job_uuid shortcut below -- so it hits the identical
            # untracked-jid problem: cmd.get_cmd_status never reports
            # "complete" for it. Compute the completion fallback the same
            # way.
            expected_minions = _expected_minion_count(resolved_target, resolved_target_type)

            console.print(f"[dim]Injecting pillar data from:[/dim] {pillar_file}\n")

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                progress.add_task(f"Submitting job '{job_name}' with pillar override...", total=None)
                run_response = api_client.call(
                    "cmd", "route_cmd",
                    cmd=(job_definition or {}).get("cmd", "local"),
                    fun=function_name,
                    tgt={"*": {"tgt": resolved_target, "tgt_type": resolved_target_type}},
                    arg={"arg": base_args, "kwarg": resolved_kwargs},
                )
        else:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                progress.add_task(f"Submitting job '{job_name}'...", total=None)
                run_response = api_client.call("cmd", "route_cmd", job_uuid=job_uuid)

        if run_response.error:
            console.print(f"[red]✗[/red] Failed to run job: {run_response.error.get('message')}\n")
            sys.exit(1)

        jid = run_response.ret
        if isinstance(jid, dict):
            jid = jid.get("jid") or jid.get("uuid") or str(jid)

        console.print(f"[green]✓[/green] Job submitted successfully")
        console.print(f"  [dim]Job ID (JID):[/dim] [cyan]{jid}[/cyan]\n")

        # Fire-and-forget mode
        if no_wait or wait == -1:
            if as_json:
                console.print_json(data={"jid": jid, "job_uuid": job_uuid, "name": job_name, "status": "submitted"})
            else:
                console.print(f"[dim]Check status later with:[/dim] [cyan]scc job-status {jid}[/cyan]")
                console.print(f"[dim]Fetch results with:[/dim]   [cyan]scc job-results {jid}[/cyan]\n")
            return

        # Wait for the job with the live per-minion tracker.
        completed, timed_out, cancelled = _wait_for_job(
            api_client,
            jid,
            max_wait=wait,
            description=f"Running '{job_name}'",
            expected_minions=expected_minions,
        )

        if completed:
            console.print(f"[green]✓[/green] Job completed\n")
            returns_resp = api_client.call("ret", "get_returns", jid=jid)
            if returns_resp.success and returns_resp.ret:
                if as_json and not output_file:
                    console.print_json(data=returns_resp.ret)
                else:
                    _display_job_returns(returns_resp.ret)

                if output_file:
                    try:
                        fmt_hint = "json" if as_json else None
                        saved_path = _save_job_results_to_file(
                            returns_resp.ret, output_file, fmt=fmt_hint, jid=jid
                        )
                        result_summary(
                    "Results exported",
                    status="success",
                    details=[("JID", jid), ("Output file", saved_path)],
                )
                    except Exception as save_err:
                        console.print(
                            f"[red]✗[/red] Failed to write results to '{output_file}': {save_err}\n"
                        )
                else:
                    console.print(f"[dim]Re-fetch results anytime with:[/dim] [cyan]scc job-results {jid}[/cyan]\n")
            elif as_json:
                console.print_json(data={"error": returns_resp.error})
            else:
                console.print("[yellow]Job completed but no results were returned.[/yellow]")
                console.print(f"[dim]Try:[/dim] [cyan]scc job-results {jid}[/cyan]\n")
        elif cancelled:
            console.print(
                f"[yellow]⚠ Cancelled while waiting. Job still running on server.[/yellow]\n"
                f"  Check status later: [cyan]scc job-status {jid}[/cyan]\n"
                f"  Fetch results:      [cyan]scc job-results {jid}[/cyan]\n"
            )
        elif timed_out:
            console.print(
                f"[yellow]⚠ Timed out after {wait}s. The job is still running on the server.[/yellow]\n"
                f"  Check status:  [cyan]scc job-status {jid}[/cyan]\n"
                f"  Tail results:  [cyan]scc job-status {jid} --wait[/cyan]\n"
                f"  Fetch results: [cyan]scc job-results {jid}[/cyan]\n"
                f"  Or re-run with a larger [cyan]--wait[/cyan] value (or [cyan]--wait 0[/cyan] for no timeout).\n"
            )

    except Exception as e:
        console.print(f"[red]✗[/red] Failed to run job: {e}\n")
        sys.exit(1)


@cli.command("job-status")
@click.argument("jid")
@click.option(
    "--wait/--no-wait",
    default=False,
    help="Wait for job to complete (use --timeout to control max wait time)."
)
@click.option(
    "--timeout",
    type=int,
    default=1800,
    show_default=True,
    metavar="SECONDS",
    help="When --wait is set, max seconds to wait. Use 0 for no timeout.",
)
@click.option(
    "--json", "as_json",
    is_flag=True,
    help="Output in JSON format"
)
@common_options
@click.pass_context
def job_status(ctx, jid, wait, timeout, as_json, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """
    Check the status of a job.
    
    Shows the current status and results of a job by its JID (Job ID).
    
    \b
    Examples:
      $ scc job-status 20260204170338799754
      $ scc job-status 20260204170338799754 --wait
      $ scc job-status 20260204170338799754 --wait --timeout 0   # no timeout
      $ scc job-status 20260204170338799754 --json
    """
    setup_logging(log_level, no_color)
    
    settings = load_settings(config, server, username, password, csp_token, password_stdin=password_stdin, password_file=password_file, password_prompt=password_prompt)
    
    api_client = connect_client(settings, label="job status")
    
    console.print(f"\n[bold]Job Status: {jid}[/bold]\n")
    
    import time
    if wait:
        max_wait = timeout  # 0 means no timeout
    else:
        max_wait = 0  # poll once and exit (sentinel handled below)
    poll_interval = 2
    waited = 0
    
    while True:
        # Get job status - API uses 'jids' as list
        status_resp = api_client.call("cmd", "get_cmd_status", jids=[jid])
        
        if as_json:
            console.print_json(data=status_resp.ret if status_resp.success else {"error": status_resp.error})
            break
        
        if status_resp.success and status_resp.ret:
            status_data = status_resp.ret
            
            # Handle list response (e.g., ['complete'])
            if isinstance(status_data, list):
                state = status_data[0] if status_data else "unknown"
            elif isinstance(status_data, dict):
                state = status_data.get("state", "unknown")
            else:
                state = str(status_data)
            
            console.print(f"  State: {state}")
            
            if state in ("completed", "complete"):
                console.print("[green]  ✓ Job completed[/green]\n")

                # Get full return data using ret.get_returns
                returns_resp = api_client.call("ret", "get_returns", jid=jid)
                if returns_resp.success and returns_resp.ret:
                    _display_job_returns(returns_resp.ret)
                else:
                    # Fallback to cmd.get_cmd_details
                    details_resp = api_client.call("cmd", "get_cmd_details", jid=jid)
                    if details_resp.success:
                        _display_state_result(details_resp.ret, False)
                break
            elif state in ("failed", "error"):
                error_msg = status_data.get('error', '') if isinstance(status_data, dict) else ''
                console.print(f"[red]  ✗ Job failed[/red]: {error_msg}\n")
                break

            # RaaS's job-status registry doesn't recognize this jid (most
            # commonly "not-found") or reports an in-progress state we don't
            # special-case above. That registry only tracks jids dispatched
            # through one of RaaS's own Job entities (job-create/job-run's
            # job_uuid shortcut); a jid from `scc run`/`scc deploy`/a direct
            # `scc exec` (all of which use a raw cmd.route_cmd "local" call)
            # was never registered there and will report a state like
            # "not-found" forever, even after every minion has finished. The
            # salt master's own return cache (ret.get_returns) is the ground
            # truth for those -- check it directly rather than trusting the
            # status flag alone.
            returns_resp = api_client.call("ret", "get_returns", jid=jid)
            if returns_resp.success and returns_resp.ret:
                payload = returns_resp.ret
                results = (
                    payload.get("results", [])
                    if isinstance(payload, dict)
                    else (payload if isinstance(payload, list) else [])
                )
                if results:
                    console.print(
                        f"[green]  ✓ Results found via the minion return cache[/green] "
                        f"(RaaS's job-status registry reports \"{state}\" for this jid -- "
                        f"it wasn't created as a tracked Job, so that flag never updates; "
                        f"the return cache is authoritative here)\n"
                    )
                    _display_job_returns(payload)
                    break

            if not wait:
                console.print(f"  [dim]No results yet. Use --wait to keep polling.[/dim]\n")
                break
        else:
            console.print(f"[red]✗[/red] Failed to get status: {status_resp.error}\n")
            break
        
        # Wait and poll again
        # max_wait == 0 + wait==True means "no timeout, wait forever".
        unlimited = wait and max_wait <= 0
        if wait and (unlimited or waited < max_wait):
            try:
                time.sleep(poll_interval)
            except KeyboardInterrupt:
                console.print("\n[yellow]  Cancelled by user. Job still running on server.[/yellow]\n")
                break
            waited += poll_interval
            if unlimited:
                console.print(f"  Waiting... ({waited}s, Ctrl+C to detach)")
            else:
                console.print(f"  Waiting... ({waited}s / {max_wait}s)")
        else:
            if wait:
                console.print(
                    f"[yellow]  Timeout after {max_wait}s. Job may still be running.[/yellow]\n"
                    f"  Re-check:   [cyan]scc job-status {jid}[/cyan]\n"
                    f"  No timeout: [cyan]scc job-status {jid} --wait --timeout 0[/cyan]\n"
                )
            break
    
    api_client.close()


@cli.command("job-results")
@click.argument("jid")
@click.option(
    "--json", "as_json",
    is_flag=True,
    help="Output raw results in JSON format"
)
@click.option(
    "--yaml", "as_yaml",
    is_flag=True,
    help="Output raw results in YAML format"
)
@click.option(
    "--raw",
    is_flag=True,
    default=False,
    help="Show raw return data without formatted rendering"
)
@click.option(
    "--output-file", "-O", "output_file",
    type=click.Path(dir_okay=False, writable=True, resolve_path=False),
    default=None,
    metavar="PATH",
    help="Write results to this file. Format is inferred from extension "
         "(.json, .yaml, .yml, .txt) unless --json/--yaml is also passed.",
)
@common_options
@click.pass_context
def job_results(ctx, jid, as_json, as_yaml, raw, output_file, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """
    Fetch and display the results of a completed job by its JID.

    This is useful when you submitted a job with --no-wait, or when you
    want to re-examine the output of a previously run job without polling
    its status again.

    \b
    Examples:
      $ scc job-results 20260528041400506330
      $ scc job-results 20260528041400506330 --json
      $ scc job-results 20260528041400506330 --yaml
      $ scc job-results 20260528041400506330 --raw
      $ scc job-results 20260528041400506330 -O results.yaml
      $ scc job-results 20260528041400506330 --output-file out.json
    """
    setup_logging(log_level, no_color)

    if as_json and as_yaml:
        console.print("[red]✗[/red] Choose either --json or --yaml, not both.\n")
        sys.exit(2)

    settings = load_settings(
        config, server, username, password, csp_token,
        password_stdin=password_stdin,
        password_file=password_file,
        password_prompt=password_prompt,
    )

    machine_stdout = (as_json or as_yaml) and not output_file
    if not machine_stdout:
        command_header(
            "job-results",
            "Saved-job execution results",
            description="Check the current state, fetch minion returns and render compliance-aware output.",
            icon="job",
            meta=[
                ("JID", jid),
                ("View", "raw" if raw else "formatted"),
                ("Export", output_file or "screen only"),
            ],
        )

    api_client = connect_client(settings, label="job results")

    try:
        # First, give the user a quick health check on the job's current state.
        if not machine_stdout:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                progress.add_task("Checking job status...", total=None)
                status_resp = api_client.call("cmd", "get_cmd_status", jids=[jid])

            if status_resp.success and status_resp.ret:
                status_data = status_resp.ret
                if isinstance(status_data, list):
                    state = status_data[0] if status_data else "unknown"
                elif isinstance(status_data, dict):
                    state = status_data.get("state", "unknown")
                else:
                    state = str(status_data)

                state_str = str(state).lower()
                if state_str in ("completed", "complete"):
                    result_summary(
                        "Job completed",
                        status="success",
                        message="RaaS reports the job as complete; fetching final minion returns.",
                        details=[("JID", jid), ("State", state)],
                    )
                elif state_str in ("failed", "error"):
                    result_summary(
                        "Job failed",
                        status="danger",
                        message="RaaS reports a failed execution. Returned error details are shown below when available.",
                        details=[("JID", jid), ("State", state)],
                    )
                elif state_str in ("running", "queued", "new"):
                    result_summary(
                        "Job is still running",
                        status="warning",
                        message="Partial results may be available; use job-status to wait for completion.",
                        details=[("JID", jid), ("State", state), ("Wait command", f"scc job-status {jid} --wait")],
                    )
                else:
                    result_summary(
                        "Job status returned",
                        status="info",
                        details=[("JID", jid), ("State", state)],
                    )

        # Fetch the actual returns.
        if not machine_stdout:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                progress.add_task("Fetching results...", total=None)
                returns_resp = api_client.call("ret", "get_returns", jid=jid)
        else:
            returns_resp = api_client.call("ret", "get_returns", jid=jid)

        if not returns_resp.success:
            err = returns_resp.error or {}
            msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
            console.print(f"[red]✗[/red] Failed to fetch results: {msg}\n")
            sys.exit(1)

        ret_data = returns_resp.ret

        if not ret_data:
            if not machine_stdout:
                empty_state(
                    "No minion returns yet",
                    "The job may still be running, or no targeted minion has reported a return for this JID.",
                    icon="clock",
                    actions=[f"scc job-status {jid} --wait", f"scc job-results {jid}", "scc doctor"],
                )
            sys.exit(0)

        # Render to stdout first (unless we are pure-file mode and user wants quiet output)
        if as_json and not output_file:
            import json as _json
            console.print(_json.dumps(ret_data, indent=2, default=str))
        elif as_yaml and not output_file:
            import yaml as _yaml
            console.print(_yaml.safe_dump(ret_data, sort_keys=False, default_flow_style=False).rstrip())
        elif raw and not output_file:
            console.print(ret_data)
        elif not output_file:
            _display_job_returns(ret_data)
        else:
            # Output file requested: still show a friendly summary on screen.
            _display_job_returns(ret_data)

        # Persist to file if requested.
        if output_file:
            fmt_hint = "json" if as_json else ("yaml" if as_yaml else None)
            try:
                saved_path = _save_job_results_to_file(
                    ret_data, output_file, fmt=fmt_hint, jid=jid
                )
                console.print(f"[green]✓[/green] Results saved to: [cyan]{saved_path}[/cyan]\n")
            except Exception as save_err:
                console.print(
                    f"[red]✗[/red] Failed to write results to '{output_file}': {save_err}\n"
                )
                sys.exit(1)

    except Exception as e:
        console.print(f"[red]✗[/red] Failed to fetch job results: {e}\n")
        sys.exit(1)
    finally:
        api_client.close()


@cli.command("fs-list")
@click.option(
    "--env", "-e", "saltenv",
    default=None,
    help="Salt environment to list (default: all environments)."
)
@click.option(
    "--path", "path_filter",
    default=None,
    metavar="PATTERN",
    help="Filter by remote path prefix or fnmatch glob (e.g. '/states/*', '/pillars/db/').",
)
@click.option(
    "--flat",
    is_flag=True,
    default=False,
    help="Show a flat table instead of the hierarchical tree.",
)
@click.option(
    "--json", "as_json",
    is_flag=True,
    help="Output in JSON format.",
)
@click.option(
    "--yaml", "as_yaml",
    is_flag=True,
    help="Output in YAML format.",
)
@click.option(
    "--output-file", "-O", "output_file",
    type=click.Path(dir_okay=False, writable=True, resolve_path=False),
    default=None,
    metavar="PATH",
    help="Write the listing to this file. Format inferred from extension "
         "(.json, .yaml, .yml, .txt) unless --json/--yaml is also passed.",
)
@common_options
@click.pass_context
def fs_list(ctx, saltenv, path_filter, flat, as_json, as_yaml, output_file,
            config, server, username, password, password_stdin, password_file,
            password_prompt, csp_token, log_level, no_color):
    """
    List files available on the RaaS file server.

    Shows the contents of the RaaS file server, optionally filtered by
    environment and/or path. By default all environments are listed in
    a hierarchical tree so you can quickly see the directory structure
    of uploaded states, pillars, and other files.

    \b
    Examples:
      $ scc fs-list                                # all envs, tree view
      $ scc fs-list --env vcfsecops                # one env only
      $ scc fs-list --env base --path /states/     # filter by path
      $ scc fs-list --path '/*.sls'                # glob across envs
      $ scc fs-list --flat                         # flat table view
      $ scc fs-list --json                         # JSON output
      $ scc fs-list --env vcfsecops -O fs.yaml     # save to file
    """
    setup_logging(log_level, no_color)

    if as_json and as_yaml:
        console.print("[red]✗[/red] Choose either --json or --yaml, not both.\n")
        sys.exit(2)

    settings = load_settings(
        config, server, username, password, csp_token,
        password_stdin=password_stdin,
        password_file=password_file,
        password_prompt=password_prompt,
    )

    machine_stdout = (as_json or as_yaml) and not output_file
    if not machine_stdout:
        command_header(
            "fs-list",
            "RaaS file-server browser",
            description="Explore Salt environments and remote paths using a hierarchical tree or flat inventory.",
            icon="folder",
            meta=[
                ("Environment", saltenv or "all"),
                ("Path filter", path_filter or "none"),
                ("View", "flat" if flat else "tree"),
            ],
        )

    api_client = connect_client(settings, label="file server")

    try:
        if not machine_stdout:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:
                progress.add_task("Loading file-server inventory…", total=None)
                files = _list_fs_files(api_client, saltenv)
        else:
            files = _list_fs_files(api_client, saltenv)

        files = _filter_fs_files(files, path_filter)

        # Group counts by env for summary
        envs_summary: dict = {}
        for f in files:
            envs_summary[f.get("saltenv", "?")] = envs_summary.get(f.get("saltenv", "?"), 0) + 1

        # Machine-readable stdout (no decoration)
        if as_json and not output_file:
            import json as _json
            console.print(_json.dumps({"count": len(files), "files": files}, indent=2, default=str))
            return
        if as_yaml and not output_file:
            import yaml as _yaml
            console.print(_yaml.safe_dump(
                {"count": len(files), "files": files},
                sort_keys=False, default_flow_style=False,
            ).rstrip())
            return

        if not files:
            empty_state(
                "No files matched",
                "The file-server request completed, but no files matched the selected environment or path filter.",
                icon="folder",
                actions=[
                    "scc list --type envs",
                    "scc fs-list",
                    "scc upload <local-path> --env <environment>",
                ],
            )
            if output_file:
                # Still write an empty payload for consistency
                try:
                    fmt_hint = "json" if as_json else ("yaml" if as_yaml else None)
                    saved_path = _save_job_results_to_file(
                        {"count": 0, "files": []}, output_file, fmt=fmt_hint
                    )
                    console.print(f"[green]✓[/green] Empty listing saved to: [cyan]{saved_path}[/cyan]\n")
                except Exception as save_err:
                    console.print(f"[red]✗[/red] Failed to write '{output_file}': {save_err}\n")
                    sys.exit(1)
            return

        # Summary pills
        from salt_config_cli.ui import summary_pills
        pills = [(len(files), "files", "primary"), (len(envs_summary), "environments", "secondary")]
        for env, count in sorted(envs_summary.items())[:5]:
            pills.append((count, env, "success"))
        summary_pills(pills)
        console.print()

        if flat:
            tbl = Table(show_header=True, header_style="scc.table.header", box=None, padding=(0, 1))
            tbl.add_column("Env", style="scc.accent")
            tbl.add_column("Path", style="scc.value", overflow="fold")
            tbl.add_column("Type", style="scc.muted")
            tbl.add_column("Size", style="scc.muted", justify="right")
            tbl.add_column("UUID", style="scc.muted")
            for f in sorted(files, key=lambda x: (x.get("saltenv", ""), x.get("path", ""))):
                uuid_short = (f.get("uuid") or "")[:8]
                tbl.add_row(
                    f.get("saltenv", ""),
                    f.get("path", ""),
                    f.get("content_type", "") or "-",
                    _human_size(f.get("size")) or "-",
                    uuid_short or "-",
                )
            console.print(tbl)
            console.print()
        else:
            root = _build_fs_tree(files)
            _render_fs_tree(root, title=f"RaaS file server  ({len(files)} files)")
            console.print()

        result_summary(
            "File-server inventory loaded",
            status="success",
            message=f"Found {len(files)} file(s) across {len(envs_summary)} environment(s).",
            metrics=[
                (len(files), "files", "success"),
                (len(envs_summary), "environments", "primary"),
            ],
        )
        next_steps(
            [
                "Download for review: `scc download <remote-path> --env <env> --output <dir>`",
                "Upload a folder (always previews + confirms first): `scc upload <local-path> --env <env>`",
                "Edit one file safely: `scc edit <remote-path> --env <env>`",
            ],
            title="Work with these files",
        )

        # Persist to file if requested.
        if output_file:
            fmt_hint = "json" if as_json else ("yaml" if as_yaml else None)
            try:
                # Save as a list of file metadata for easy programmatic consumption.
                saved_path = _save_job_results_to_file(
                    {"count": len(files), "files": files},
                    output_file,
                    fmt=fmt_hint,
                )
                console.print(f"[green]✓[/green] Listing saved to: [cyan]{saved_path}[/cyan]\n")
            except Exception as save_err:
                console.print(f"[red]✗[/red] Failed to write '{output_file}': {save_err}\n")
                sys.exit(1)

    except Exception as e:
        console.print(f"[red]✗[/red] Failed to list files: {e}\n")
        sys.exit(1)
    finally:
        api_client.close()


@cli.command("upload")
@click.argument("source", type=click.Path(exists=True))
@click.option(
    "--path", "-r", "path",
    help="Remote path on file server. For a single file: full destination "
         "(default: /<filename>). For a folder: target prefix (default: /<folder-name>)."
)
@click.option(
    "--env", "-e", "saltenv",
    default="vcfsecops",
    help="Salt environment (default: vcfsecops)"
)
@click.option(
    "--force", "-f",
    is_flag=True,
    help="Overwrite if files already exist"
)
@click.option(
    "--include",
    multiple=True,
    metavar="PATTERN",
    help="(Folder upload) Only include files matching this fnmatch pattern. "
         "Pass multiple times for an OR filter, e.g. --include '*.sls' --include '*.yaml'.",
)
@click.option(
    "--exclude",
    multiple=True,
    metavar="PATTERN",
    help="(Folder upload) Exclude files matching this fnmatch pattern. "
         "Pass multiple times. Common ones (.git, __pycache__, *.pyc) are excluded automatically.",
)
@click.option(
    "--yes", "-y", "assume_yes",
    is_flag=True,
    default=False,
    help="Skip the confirmation prompt before a folder upload.",
)
@click.option(
    "--show-tree/--no-show-tree",
    default=True,
    help="After a successful upload, show the file-server tree for the target environment "
         "(default: enabled).",
)
@common_options
@click.pass_context
def upload_file(ctx, source, path, saltenv, force, include, exclude, assume_yes,
                show_tree, config, server, username, password, password_stdin, password_file,
                password_prompt, csp_token, log_level, no_color):
    """
    Upload a file or an entire folder to the RaaS file server.

    Pass either a local file path or a directory. When uploading a folder,
    every regular file inside is uploaded recursively, preserving the
    relative directory structure under the remote prefix. Folder uploads
    always show a preview table and ask for confirmation before touching
    RaaS (skip the prompt with --yes). Dry-run previews belong to state
    application (`scc run --test` / `scc job-run`), not file transfer.

    \b
    Examples (single file):
      $ scc upload my-state.sls
      $ scc upload my-state.sls --path /custom/path/state.sls
      $ scc upload my-state.sls --env base --force

    \b
    Examples (folder):
      $ scc upload ./states/                                # uploads tree under /states
      $ scc upload ./states/ --path /vcfsecops/states       # custom remote prefix
      $ scc upload ./states/ --include '*.sls'              # only .sls files
      $ scc upload ./states/ --exclude '*.bak' --exclude 'tmp/*'
      $ scc upload ./states/ --force --yes                  # overwrite, no prompt
    """
    setup_logging(log_level, no_color)

    source_path = Path(source)
    is_folder = source_path.is_dir()

    # Build the upload plan first — this is a pure local operation and does
    # not require any server interaction.
    try:
        plan = _collect_local_uploads(
            source_path,
            remote_base=path,
            include=include,
            exclude=exclude,
        )
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to scan '{source}': {e}\n")
        sys.exit(1)

    if not plan:
        console.print(f"[yellow]⚠[/yellow] Nothing to upload from '{source}'.\n")
        if include or exclude:
            console.print("[dim]Check your --include / --exclude filters.[/dim]\n")
        sys.exit(0)

    # Header
    console.print(f"[bold]Source:[/bold]       {source} {'(folder)' if is_folder else '(file)'}")
    console.print(f"[bold]Environment:[/bold]  {saltenv}")
    console.print(f"[bold]Files:[/bold]        {len(plan)}")
    if include:
        console.print(f"[bold]Include:[/bold]      {', '.join(include)}")
    if exclude:
        console.print(f"[bold]Exclude:[/bold]      {', '.join(exclude)}")
    console.print()

    # Preview table (always for folders; for single file we keep it compact).
    if is_folder:
        preview = Table(
            title=None, show_header=True, header_style="scc.table.header",
            box=None, padding=(0, 1),
        )
        preview.add_column("#", style="scc.muted", justify="right", no_wrap=True)
        preview.add_column("Local", style="scc.value", overflow="fold")
        preview.add_column("→", style="scc.muted", no_wrap=True)
        preview.add_column("Remote", style="scc.accent", overflow="fold")
        preview.add_column("Size", style="scc.muted", justify="right", no_wrap=True)

        for idx, (lp, rp) in enumerate(plan, start=1):
            try:
                size = _human_size(lp.stat().st_size)
            except Exception:
                size = "-"
            preview.add_row(str(idx), str(lp), "→", rp, size)

        console.print(preview)
        console.print()

    # Confirmation for folder uploads (single-file keeps old terse behavior).
    if is_folder and not assume_yes:
        if not click.confirm(
            f"Upload {len(plan)} file(s) to env '{saltenv}'?",
            default=True,
        ):
            console.print("[yellow]Aborted by user.[/yellow]\n")
            sys.exit(1)

    # Connect only after the user has confirmed.
    settings = load_settings(
        config, server, username, password, csp_token,
        password_stdin=password_stdin,
        password_file=password_file,
        password_prompt=password_prompt,
    )
    api_client = connect_client(settings)
    ui_success(f"Connected to {mask_url(settings.server_url)}")

    # Perform the uploads with a progress bar.
    results: list = []
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task("Uploading...", total=len(plan))
            for lp, rp in plan:
                progress.update(task, description=f"Uploading [cyan]{rp}[/cyan]")
                res = _upload_single_file(
                    api_client,
                    local_path=lp,
                    remote_path=rp,
                    saltenv=saltenv,
                    force=force,
                )
                results.append(res)
                progress.advance(task)
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled by user. Partial upload may have occurred.[/yellow]\n")

    # Summarize
    created = sum(1 for r in results if r["action"] == "created")
    updated = sum(1 for r in results if r["action"] == "updated")
    skipped = sum(1 for r in results if r["action"] == "skipped")
    failed = sum(1 for r in results if r["action"] == "failed")

    try:
        from salt_config_cli.ui import summary_pills
        summary_pills([
            (f"created: {created}", "scc.success"),
            (f"updated: {updated}", "scc.accent"),
            (f"skipped: {skipped}", "scc.muted"),
            (f"failed: {failed}", "scc.error" if failed else "scc.muted"),
        ])
    except Exception:
        console.print(
            f"[scc.muted]created={created}  updated={updated}  "
            f"skipped={skipped}  failed={failed}[/scc.muted]\n"
        )

    # Report skipped / failed in detail
    for r in results:
        if r["action"] == "skipped":
            console.print(f"  [yellow]⏭ skipped[/yellow]  {r['remote_path']}   [dim]{r['error']}[/dim]")
        elif r["action"] == "failed":
            console.print(f"  [red]✗ failed[/red]   {r['remote_path']}   [dim]{r['error']}[/dim]")

    if failed:
        console.print(
            f"\n[red]✗[/red] {failed} file(s) failed to upload. "
            f"Re-run with [cyan]--force[/cyan] to overwrite existing files, "
            f"or fix the errors above.\n"
        )

    if created + updated == 0:
        sys.exit(1 if failed else 0)

    console.print(f"\n[green]✓[/green] Upload complete: "
                  f"{created} created, {updated} updated"
                  f"{f', {skipped} skipped' if skipped else ''}"
                  f"{f', {failed} failed' if failed else ''}.\n")

    # Show the file-server tree for the target env, highlighting any newly
    # created file when it's a single-file upload.
    if show_tree:
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                progress.add_task(f"Refreshing file tree for env '{saltenv}'...", total=None)
                env_files = _list_fs_files(api_client, saltenv)

            if env_files:
                root = _build_fs_tree(env_files)
                highlight = plan[0][1] if (len(plan) == 1) else None
                _render_fs_tree(
                    root,
                    title=f"RaaS file server  ({len(env_files)} files in '{saltenv}')",
                    highlight_path=highlight,
                )
                console.print()
        except Exception as tree_err:
            console.print(f"[dim](Could not render file tree: {tree_err})[/dim]\n")

    # Next-step hint
    if len(plan) == 1:
        only_remote = plan[0][1]
        if only_remote.endswith(".sls"):
            console.print(f"[bold]To run this state:[/bold]")
            console.print(f'  scc run {only_remote} --target "*"\n')
    else:
        sls_remotes = [rp for _, rp in plan if rp.endswith(".sls")]
        if sls_remotes:
            console.print(f"[bold]To run the uploaded state(s):[/bold]")
            for sls_remote in sls_remotes:
                console.print(
                    f"  scc run {sls_remote} --target-group <group> --env {saltenv} --test"
                    f"      [dim]# dry-run: preview changes, nothing applied[/dim]"
                )
                console.print(
                    f"  scc run {sls_remote} --target-group <group> --env {saltenv} --no-test"
                    f"   [dim]# applies for real (asks you to type 'apply' to confirm)[/dim]"
                )
            console.print()
    console.print(f"[dim]Browse files:[/dim] [cyan]scc fs-list --env {saltenv}[/cyan]\n")

    api_client.close()


@cli.command("download")
@click.argument("remote_path")
@click.option(
    "--output", "-o",
    type=click.Path(),
    metavar="PATH",
    help="Local destination. For a single file: file path (default: ./<basename>). "
         "For multiple files (folder/glob): directory to write into (default: ./).",
)
@click.option(
    "--env", "-e", "saltenv",
    default="vcfsecops",
    help="Salt environment (default: vcfsecops)",
)
@click.option(
    "--recursive", "-r",
    is_flag=True,
    default=False,
    help="Force folder-style download: treat REMOTE_PATH as a prefix and pull every "
         "file underneath it.",
)
@click.option(
    "--include",
    multiple=True,
    metavar="PATTERN",
    help="(Folder/glob download) Only include files matching this fnmatch pattern "
         "(matched against the remote path). Pass multiple times for OR.",
)
@click.option(
    "--exclude",
    multiple=True,
    metavar="PATTERN",
    help="(Folder/glob download) Exclude files matching this fnmatch pattern. "
         "Pass multiple times.",
)
@click.option(
    "--force", "-f",
    is_flag=True,
    default=False,
    help="Overwrite existing local files without prompting.",
)
@click.option(
    "--yes", "-y", "assume_yes",
    is_flag=True,
    default=False,
    help="Skip the confirmation prompt before a multi-file download.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Show what would be downloaded without actually fetching any files.",
)
@click.option(
    "--flatten",
    is_flag=True,
    default=False,
    help="(Folder/glob download) Strip the remote directory structure and write all "
         "files directly into the output directory (collisions are reported).",
)
@common_options
@click.pass_context
def download_file(ctx, remote_path, output, saltenv, recursive, include, exclude,
                  force, assume_yes, dry_run, flatten,
                  config, server, username, password, password_stdin, password_file,
                  password_prompt, csp_token, log_level, no_color):
    """
    Download one file, a folder, or a glob of files from the RaaS file server.

    REMOTE_PATH can be:

    \b
      • An exact file path:      /states/ntp.sls
      • A folder prefix:         /states/        (downloads everything below it)
      • A folder name:           /cluster_templates  (auto-detected as prefix)
      • An fnmatch glob:         '/states/*.sls'
      • '/' (the whole env):     scc download / -o ./mirror

    \b
    Examples:
      $ scc download /ops_assess_u.sls                          # single file
      $ scc download /ops_assess_u.sls -o my-local-copy.sls
      $ scc download /states/ -o ./states                       # whole folder
      $ scc download /cluster_templates -o ./tmpl --env vcf     # folder prefix
      $ scc download '/states/*.sls' -o ./out                   # glob
      $ scc download / --env vcf -o ./mirror --recursive        # mirror env
      $ scc download /states --include '*.sls' --exclude 'tmp/*'
      $ scc download /states --dry-run                          # preview
      $ scc download /states --flatten -o ./flat                # no dirs
    """
    setup_logging(log_level, no_color)

    settings = load_settings(
        config, server, username, password, csp_token,
        password_stdin=password_stdin,
        password_file=password_file,
        password_prompt=password_prompt,
    )

    api_client = connect_client(settings)
    ui_success(f"Connected to {mask_url(settings.server_url)}")

    # Normalize path.
    if not remote_path.startswith("/"):
        remote_path = "/" + remote_path
    remote_path_stripped = remote_path.rstrip("/") or "/"

    has_glob = any(ch in remote_path for ch in "*?[")

    console.print(f"[bold]Remote path:[/bold] [cyan]{remote_path}[/cyan]")
    console.print(f"[bold]Environment:[/bold] {saltenv}")

    # ------------------------------------------------------------------
    # Step 1: decide whether we're in single-file mode or multi-file mode.
    # ------------------------------------------------------------------
    # If the user explicitly passed --recursive, --include, --exclude, or a
    # glob in the path, we go straight to multi-file mode.
    explicit_multi = bool(recursive or include or exclude or has_glob or remote_path_stripped == "")

    single_file_contents: Optional[str] = None
    single_file_path: Optional[str] = None

    if not explicit_multi:
        # Try a direct fetch first — this is the fast path for the common case.
        try:
            resp = api_client.call("fs", "get_file", path=remote_path, saltenv=saltenv)
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to query file server: {e}\n")
            sys.exit(1)

        if resp.success and resp.ret:
            data = resp.ret
            single_file_contents = data.get("contents", "") if isinstance(data, dict) else str(data)
            single_file_path = remote_path

    # If single-file lookup failed (or was skipped), fall back to listing the
    # environment and treating the input as a prefix or glob.
    if single_file_contents is None:
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            ) as progress:
                progress.add_task(f"Listing files in env '{saltenv}'...", total=None)
                env_files = _list_fs_files(api_client, saltenv)
        except Exception as e:
            console.print(f"[red]✗[/red] Failed to list files in env '{saltenv}': {e}\n")
            sys.exit(1)

        if not env_files:
            console.print(
                f"[red]✗[/red] No files in env '{saltenv}', or env doesn't exist.\n"
            )
            sys.exit(1)

        # Build the candidate list.
        if remote_path_stripped == "" or remote_path == "/":
            # "/" -> everything in the env
            candidates = list(env_files)
        else:
            candidates = _filter_fs_files(env_files, remote_path)

        # Apply --include / --exclude (matched against the remote path).
        if include:
            import fnmatch as _fnm
            candidates = [
                f for f in candidates
                if any(_fnm.fnmatchcase(f.get("path", ""), p) for p in include)
            ]
        if exclude:
            import fnmatch as _fnm
            candidates = [
                f for f in candidates
                if not any(_fnm.fnmatchcase(f.get("path", ""), p) for p in exclude)
            ]

        if not candidates:
            console.print(
                f"[red]✗[/red] No files matched '[cyan]{remote_path}[/cyan]' in env '{saltenv}'.\n"
            )
            console.print(
                "[dim]Try:[/dim] [cyan]scc fs-list --env "
                f"{saltenv}[/cyan] to see what's available.\n"
            )
            sys.exit(1)

        # If exactly one candidate matched and the user didn't explicitly ask
        # for multi-file mode, still treat it as a single-file download for a
        # natural UX.
        if len(candidates) == 1 and not explicit_multi and not output_looks_like_dir(output):
            single_file_path = candidates[0].get("path")
            try:
                resp = api_client.call("fs", "get_file", path=single_file_path, saltenv=saltenv)
                if resp.success and resp.ret:
                    data = resp.ret
                    single_file_contents = (
                        data.get("contents", "") if isinstance(data, dict) else str(data)
                    )
            except Exception as e:
                console.print(f"[red]✗[/red] Failed to download '{single_file_path}': {e}\n")
                sys.exit(1)

    # ------------------------------------------------------------------
    # Step 2a: single-file path.
    # ------------------------------------------------------------------
    if single_file_contents is not None and single_file_path is not None:
        if not output:
            output = Path(single_file_path).name
        out_path = Path(output)

        # If user passed an existing directory, place the file inside it.
        if out_path.is_dir():
            out_path = out_path / Path(single_file_path).name

        if out_path.exists() and not force:
            console.print(
                f"[yellow]⚠[/yellow] Local file already exists: [cyan]{out_path}[/cyan]\n"
                "[dim]Use --force to overwrite.[/dim]\n"
            )
            sys.exit(1)

        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(single_file_contents, encoding="utf-8")
        console.print(
            f"\n[green]✓[/green] Downloaded [cyan]{single_file_path}[/cyan] "
            f"→ [cyan]{out_path}[/cyan]"
        )
        console.print(f"[dim]Size: {len(single_file_contents)} bytes[/dim]\n")
        api_client.close()
        return

    # ------------------------------------------------------------------
    # Step 2b: multi-file path.
    # ------------------------------------------------------------------
    # Decide the local output directory.
    if not output:
        # Default base name: the last path segment of the prefix.
        default_name = Path(remote_path_stripped or "/").name or saltenv
        out_root = Path(default_name)
    else:
        out_root = Path(output)

    # `out_root` is treated as a directory in multi-file mode.
    base_prefix = remote_path_stripped if remote_path_stripped != "/" else ""

    # Build the (remote_path, local_path) plan.
    plan: list = []
    for f in candidates:
        rp = f.get("path", "")
        if not rp:
            continue
        if flatten:
            local_name = Path(rp).name
            lp = out_root / local_name
        else:
            # Strip the prefix to preserve the relative subtree.
            if base_prefix and rp.startswith(base_prefix.rstrip("/") + "/"):
                rel = rp[len(base_prefix.rstrip("/")) + 1 :]
            elif base_prefix and rp == base_prefix:
                rel = Path(rp).name
            else:
                rel = rp.lstrip("/")
            lp = out_root / rel
        plan.append({
            "remote": rp,
            "local": lp,
            "size": f.get("size"),
        })

    # Preview table.
    preview = Table(
        show_header=True, header_style="scc.table.header",
        box=None, padding=(0, 1),
    )
    preview.add_column("#", style="scc.muted", justify="right", no_wrap=True)
    preview.add_column("Remote", style="scc.value", overflow="fold")
    preview.add_column("→", style="scc.muted", no_wrap=True)
    preview.add_column("Local", style="scc.accent", overflow="fold")
    preview.add_column("Size", style="scc.muted", justify="right", no_wrap=True)
    for idx, item in enumerate(plan, start=1):
        preview.add_row(
            str(idx),
            item["remote"],
            "→",
            str(item["local"]),
            _human_size(item["size"]) or "-",
        )
    console.print()
    console.print(preview)
    console.print()

    console.print(
        f"[bold]{len(plan)}[/bold] file(s) to download → [cyan]{out_root}[/cyan]\n"
    )

    if dry_run:
        console.print("[dim]Dry-run mode: nothing was downloaded.[/dim]\n")
        api_client.close()
        return

    # Detect local collisions (relevant especially in --flatten mode).
    collisions = {}
    for item in plan:
        collisions.setdefault(str(item["local"]), []).append(item["remote"])
    duplicates = {k: v for k, v in collisions.items() if len(v) > 1}
    if duplicates and flatten:
        console.print(
            "[yellow]⚠[/yellow] --flatten produced name collisions; only the "
            "last write will survive:\n"
        )
        for local, remotes in duplicates.items():
            console.print(f"  [cyan]{local}[/cyan]  ← " + ", ".join(remotes))
        console.print()

    # Confirmation.
    if not assume_yes and sys.stdin.isatty() and not explicit_multi:
        if not click.confirm(
            f"Download {len(plan)} file(s) to '{out_root}'?",
            default=True,
        ):
            console.print("[yellow]Aborted by user.[/yellow]\n")
            sys.exit(1)
    elif not assume_yes and sys.stdin.isatty() and len(plan) > 1:
        if not click.confirm(
            f"Download {len(plan)} file(s) to '{out_root}'?",
            default=True,
        ):
            console.print("[yellow]Aborted by user.[/yellow]\n")
            sys.exit(1)

    # Pull files.
    created = 0
    updated = 0
    skipped = 0
    failed: list = []
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task("Downloading...", total=len(plan))
            for item in plan:
                progress.update(task, description=f"Downloading [cyan]{item['remote']}[/cyan]")

                lp = item["local"]
                if lp.exists() and not force:
                    skipped += 1
                    progress.advance(task)
                    continue

                try:
                    resp = api_client.call(
                        "fs", "get_file",
                        path=item["remote"],
                        saltenv=saltenv,
                    )
                except Exception as e:
                    failed.append((item["remote"], str(e)))
                    progress.advance(task)
                    continue

                if not resp.success or not resp.ret:
                    err = (
                        resp.error.get("message", "unknown error")
                        if isinstance(resp.error, dict)
                        else "not found"
                    )
                    failed.append((item["remote"], err))
                    progress.advance(task)
                    continue

                data = resp.ret
                contents = data.get("contents", "") if isinstance(data, dict) else str(data)

                try:
                    lp.parent.mkdir(parents=True, exist_ok=True)
                    existed = lp.exists()
                    lp.write_text(contents, encoding="utf-8")
                    if existed:
                        updated += 1
                    else:
                        created += 1
                except Exception as e:
                    failed.append((item["remote"], f"local write failed: {e}"))

                progress.advance(task)
    except KeyboardInterrupt:
        console.print(
            "\n[yellow]Cancelled by user. Partial download may have occurred.[/yellow]\n"
        )

    # Summary.
    try:
        from salt_config_cli.ui import summary_pills
        summary_pills([
            (f"downloaded: {created}", "scc.success"),
            (f"overwrote: {updated}", "scc.accent"),
            (f"skipped: {skipped}", "scc.muted"),
            (f"failed: {len(failed)}", "scc.error" if failed else "scc.muted"),
        ])
    except Exception:
        console.print(
            f"[scc.muted]downloaded={created}  overwrote={updated}  "
            f"skipped={skipped}  failed={len(failed)}[/scc.muted]"
        )

    if skipped:
        console.print(
            f"[dim]({skipped} file(s) already existed locally — use [cyan]--force[/cyan] "
            f"to overwrite.)[/dim]"
        )
    for rp, err in failed:
        console.print(f"  [red]✗ failed[/red]   {rp}   [dim]{err}[/dim]")

    if failed:
        console.print(
            f"\n[red]✗[/red] {len(failed)} file(s) failed to download.\n"
        )
        api_client.close()
        sys.exit(1)

    if created + updated:
        console.print(
            f"\n[green]✓[/green] Downloaded to: [cyan]{out_root.resolve()}[/cyan]\n"
        )
    else:
        console.print(f"\n[yellow]Nothing new was downloaded.[/yellow]\n")

    api_client.close()


def output_looks_like_dir(output: Optional[str]) -> bool:
    """Return True if the user's --output value clearly refers to a directory."""
    if not output:
        return False
    if output.endswith("/") or output.endswith(os.sep):
        return True
    p = Path(output)
    return p.is_dir()


@cli.command("edit")
@click.argument("remote_path")
@click.option(
    "--env", "-e", "saltenv",
    default="vcfsecops",
    help="Salt environment (default: vcfsecops)",
)
@click.option(
    "--new",
    is_flag=True,
    default=False,
    help="Create a new file at REMOTE_PATH (don't fail if it doesn't exist).",
)
@click.option(
    "--editor",
    default=None,
    metavar="CMD",
    help="Editor command to use (overrides $VISUAL/$EDITOR for this invocation).",
)
@click.option(
    "--yes", "-y", "assume_yes",
    is_flag=True,
    default=False,
    help="Skip the confirmation prompt before uploading the edited file.",
)
@click.option(
    "--diff-only",
    is_flag=True,
    default=False,
    help="Show the diff of your edits but don't upload.",
)
@click.option(
    "--keep",
    type=click.Path(dir_okay=False, writable=True, resolve_path=False),
    default=None,
    metavar="PATH",
    help="Keep a local copy of the edited content at this path.",
)
@common_options
@click.pass_context
def edit_file(ctx, remote_path, saltenv, new, editor, assume_yes, diff_only, keep,
              config, server, username, password, password_stdin, password_file,
              password_prompt, csp_token, log_level, no_color):
    """
    Fetch a file from RaaS, edit it locally in your $EDITOR, then upload it back.

    Downloads REMOTE_PATH from the file server into a temporary file, opens it
    in your editor of choice ($VISUAL, $EDITOR, or a sensible default), and
    after you save & quit, shows a unified diff and uploads the changes back
    to the same path.

    \b
    Examples:
      $ scc edit /states/ntp.sls
      $ scc edit /states/ntp.sls --env vcfsecops
      $ scc edit /pillars/db.sls --editor 'code --wait'
      $ scc edit /new-state.sls --new                 # create a brand new file
      $ scc edit /states/ntp.sls --diff-only          # preview without upload
      $ scc edit /states/ntp.sls --keep ./backup.sls  # save a local backup
    """
    setup_logging(log_level, no_color)

    settings = load_settings(
        config, server, username, password, csp_token,
        password_stdin=password_stdin,
        password_file=password_file,
        password_prompt=password_prompt,
    )

    api_client = connect_client(settings)
    ui_success(f"Connected to {mask_url(settings.server_url)}")

    # Normalize remote path.
    if not remote_path.startswith("/"):
        remote_path = "/" + remote_path

    console.print(f"[bold]Remote path:[/bold] [cyan]{remote_path}[/cyan]")
    console.print(f"[bold]Environment:[/bold] {saltenv}\n")

    # 1. Fetch the current contents (or start blank if --new).
    original_contents: str = ""
    file_exists = False
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task(f"Fetching '{remote_path}'...", total=None)
            exists_resp = api_client.call("fs", "file_exists", path=remote_path, saltenv=saltenv)
            file_exists = bool(exists_resp.success and exists_resp.ret)

            if file_exists:
                get_resp = api_client.call("fs", "get_file", path=remote_path, saltenv=saltenv)
                if not get_resp.success:
                    err = get_resp.error or {}
                    msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
                    console.print(f"[red]✗[/red] Failed to fetch file: {msg}\n")
                    sys.exit(1)
                data = get_resp.ret
                if isinstance(data, dict):
                    original_contents = data.get("contents", "") or ""
                else:
                    original_contents = str(data or "")
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to fetch file: {e}\n")
        sys.exit(1)

    if not file_exists:
        if not new:
            console.print(
                f"[red]✗[/red] File does not exist on the server: [cyan]{remote_path}[/cyan]\n"
                f"[dim]Pass [cyan]--new[/cyan] to create it.[/dim]\n"
            )
            sys.exit(1)
        console.print(f"[yellow]ℹ[/yellow] Creating new file [cyan]{remote_path}[/cyan]\n")

    # 2. Drop contents into a temp file and launch the editor.
    import tempfile

    # Preserve the original extension so syntax highlighting works in editors.
    suffix = Path(remote_path).suffix or ".txt"
    tmp = tempfile.NamedTemporaryFile(
        mode="w",
        suffix=suffix,
        prefix="scc-edit-",
        delete=False,
        encoding="utf-8",
    )
    tmp_path = Path(tmp.name)
    try:
        tmp.write(original_contents)
        tmp.flush()
    finally:
        tmp.close()

    # Allow per-invocation editor override.
    if editor:
        import shlex
        editor_argv = shlex.split(editor) + [str(tmp_path)]
        import subprocess
        rc = subprocess.call(editor_argv)
    else:
        console.print(f"[dim]Opening in editor: {' '.join(_resolve_editor())}[/dim]")
        rc = _open_in_editor(tmp_path)

    if rc != 0:
        console.print(
            f"[yellow]⚠ Editor exited with code {rc}. Aborting upload.[/yellow]\n"
        )
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass
        sys.exit(rc)

    # 3. Read back the edited content.
    try:
        edited_contents = tmp_path.read_text(encoding="utf-8")
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to read edited file: {e}\n")
        sys.exit(1)

    if keep:
        try:
            keep_path = Path(keep).expanduser().resolve()
            keep_path.parent.mkdir(parents=True, exist_ok=True)
            keep_path.write_text(edited_contents, encoding="utf-8")
            console.print(f"[dim]Local copy saved to:[/dim] [cyan]{keep_path}[/cyan]")
        except Exception as e:
            console.print(f"[yellow]⚠ Could not save local copy: {e}[/yellow]")

    # 4. Compare and short-circuit if there's no change.
    if edited_contents == original_contents:
        console.print("[dim]No changes detected — nothing to upload.[/dim]\n")
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass
        return

    # 5. Show a unified diff.
    import difflib
    diff_lines = list(difflib.unified_diff(
        original_contents.splitlines(keepends=False),
        edited_contents.splitlines(keepends=False),
        fromfile=f"raas:{remote_path}",
        tofile=f"raas:{remote_path} (edited)",
        lineterm="",
    ))

    console.print("[bold]Changes:[/bold]\n")
    if not diff_lines:
        console.print("[dim](contents differ only in whitespace)[/dim]\n")
    else:
        from rich.syntax import Syntax
        diff_text = "\n".join(diff_lines)
        try:
            console.print(Syntax(diff_text, "diff", theme="ansi_dark", line_numbers=False, word_wrap=True))
        except Exception:
            for ln in diff_lines:
                if ln.startswith("+++") or ln.startswith("---"):
                    console.print(f"[bold]{ln}[/bold]")
                elif ln.startswith("@@"):
                    console.print(f"[cyan]{ln}[/cyan]")
                elif ln.startswith("+"):
                    console.print(f"[green]{ln}[/green]")
                elif ln.startswith("-"):
                    console.print(f"[red]{ln}[/red]")
                else:
                    console.print(ln)
    console.print()

    if diff_only:
        console.print("[dim]--diff-only: changes were not uploaded.[/dim]\n")
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass
        return

    # 6. Confirm and upload.
    if not assume_yes:
        if not click.confirm(
            f"Upload these changes to '{remote_path}' (env '{saltenv}')?",
            default=True,
        ):
            console.print("[yellow]Aborted. The edited file is kept at:[/yellow] "
                          f"[cyan]{tmp_path}[/cyan]\n")
            sys.exit(1)

    content_type = _get_content_type(Path(remote_path).name)
    operation = "update_file" if file_exists else "save_file"
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task(f"Uploading changes to {remote_path}...", total=None)
            resp = api_client.call(
                "fs", operation,
                path=remote_path,
                contents=edited_contents,
                saltenv=saltenv,
                content_type=content_type,
            )

        if resp.error:
            msg = resp.error.get("message", "unknown error") if isinstance(resp.error, dict) else str(resp.error)
            console.print(f"[red]✗[/red] Upload failed: {msg}\n")
            console.print(f"[dim]Your edits are preserved at:[/dim] [cyan]{tmp_path}[/cyan]\n")
            sys.exit(1)

        verb = "Updated" if file_exists else "Created"
        console.print(f"[green]✓[/green] {verb} [cyan]{remote_path}[/cyan] in env '{saltenv}'\n")

        if resp.ret and isinstance(resp.ret, dict):
            uuid = resp.ret.get("uuid", "")
            if uuid:
                console.print(f"[dim]File UUID: {uuid}[/dim]\n")

        try:
            tmp_path.unlink(missing_ok=True)
        except Exception:
            pass

        console.print(f"[dim]Browse files:[/dim] [cyan]scc fs-list --env {saltenv}[/cyan]\n")

    except Exception as e:
        console.print(f"[red]✗[/red] Failed to upload changes: {e}\n")
        console.print(f"[dim]Your edits are preserved at:[/dim] [cyan]{tmp_path}[/cyan]\n")
        sys.exit(1)
    finally:
        api_client.close()



@cli.command("pull")
@click.argument("name")
@click.option("--dir", "local_dir", default="states", metavar="DIR", help="Local directory for the resource folder.")
@click.option("--source", "source_name", help="Named states source from `scc repo list`.")
@click.option("--repo", metavar="URL", help="One-command repository URL override.")
@click.option("--branch", "ref", metavar="REF", help="One-command branch, tag, or commit override.")
@click.option("--root", metavar="PATH", help="One-command repository root override.")
@click.option("--force", "-f", is_flag=True, help="Replace an existing local resource folder.")
@click.option("--config", "-c", type=click.Path(exists=False), help="Path to RaaS profile configuration file.")
@click.option("--log-level", "-l", type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]), default="INFO")
@click.option("--no-color", is_flag=True, help="Disable colored output.")
def pull_resource(name, local_dir, source_name, repo, ref, root, force, config, log_level, no_color):
    """Fetch and validate one complete Salt resource from a generic Git source.

    This compatibility command now uses the same generic Git/cache layer as
    ``scc deploy``.  It supports GitHub, GitHub Enterprise, GitLab, Bitbucket,
    SSH, tags, and commit SHAs, and copies the complete resource tree rather
    than assuming exactly three files.

    Examples:
      $ scc pull dns
      $ scc pull dns --source vcf-salt
      $ scc pull dns --repo git@github.example.com:org/vcf-salt.git --branch v9.1.1
      $ scc upload states/dns --env vcf-infra
    """
    import shutil
    import tempfile
    from salt_config_cli.core.repositories import RepositorySource, RepositoryStore
    from salt_config_cli.services.git_repository import ContentWorkspaceService, GitRepositoryError, GitRepositoryService

    setup_logging(log_level, no_color)
    effective_config = config or _GLOBAL_CONFIG_PATH
    store = RepositoryStore(connection_config=effective_config)
    try:
        if repo:
            try:
                _, base = store.get(source_name, kind="states")
            except Exception:
                base = RepositorySource(kind="states", url=repo, ref=ref or "main", root=root or "vcf-infra", layout="{resource}")
            source = base.model_copy(update={"url": repo, "ref": ref or base.ref, "root": root or base.root})
            selected_name = source_name or "one-shot-states"
        else:
            selected_name, source = store.get(source_name, kind="states")
            if ref or root:
                source = source.model_copy(update={"ref": ref or source.ref, "root": root or source.root})
    except ValueError as exc:
        ui_error(str(exc), hint="Run `scc repo setup` or pass --repo.")
        raise SystemExit(1) from exc

    command_header(
        "pull",
        f"Fetch Salt resource: {name}",
        description="Sync Git, validate the complete resource tree, and copy it into a local review folder.",
        icon="doc",
        meta=[("Source", selected_name), ("Ref", source.ref), ("Destination", str(Path(local_dir) / name))],
        mode=("LOCAL ONLY", "black on #e6c75a"),
    )
    try:
        with spinner(f"Syncing {selected_name}@{source.ref}…"):
            synced = GitRepositoryService().sync(selected_name, source)
        destination = Path(local_dir) / name
        if destination.exists():
            if not force:
                raise GitRepositoryError(f"{destination} already exists; use --force to replace it")
            shutil.rmtree(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="scc-pull-") as temp_workspace:
            package = ContentWorkspaceService(temp_workspace).build(name, synced)
            shutil.copytree(package.states_dir, destination)
    except GitRepositoryError as exc:
        ui_error(str(exc))
        raise SystemExit(1) from exc

    files = [path for path in destination.rglob("*") if path.is_file()]
    result_summary(
        "Salt resource fetched",
        details=[
            ("Resource", name),
            ("Source", f"{selected_name}@{source.ref}"),
            ("Commit", synced.commit),
            ("Files", len(files)),
            ("Local path", str(destination)),
        ],
    )
    next_steps([
        f"Review files: `find {destination} -type f`",
        f"Publish manually: `scc upload {destination} --path /{package.states_repository_path} --env <salt-env>`",
        f"Or use the guided flow: `scc deploy {name} --mode dry-run --target-group <group>`",
    ])


@cli.command("pull-data")
@click.argument("name")
@click.argument("file", required=False)
@click.option("--dir", "local_dir", default="values", metavar="DIR", help="Local directory for customer values files.")
@click.option("--source", "source_name", help="Named customer-values source from `scc repo list`.")
@click.option("--environment", default="", help="Environment/instance selector used by the source layout.")
@click.option("--version", default="", help="Version selector used by the source layout.")
@click.option("--path", "data_path", help="Explicit relative path inside the data repository.")
@click.option("--repo", metavar="URL", help="One-command data repository URL override.")
@click.option("--branch", "ref", metavar="REF", help="One-command branch, tag, or commit override.")
@click.option("--root", metavar="PATH", help="One-command repository root override.")
@click.option("--force", "-f", is_flag=True, help="Replace an existing local values file.")
@click.option("--config", "-c", type=click.Path(exists=False), help="Path to RaaS profile configuration file.")
@click.option("--log-level", "-l", type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]), default="INFO")
@click.option("--no-color", is_flag=True, help="Disable colored output.")
def pull_data(name, file, local_dir, source_name, environment, version, data_path, repo, ref, root, force, config, log_level, no_color):
    """Fetch one validated customer-specific YAML values file from Git.

    ``FILE`` remains compatible with the old command and maps to the
    ``{values}`` placeholder.  New repositories can use environment/version
    layouts instead, for example ``{environment}/{version}/{resource}/values.yaml``.

    Examples:
      $ scc pull-data dns prod
      $ scc pull-data dns --environment prod --version 9.1.1
      $ scc pull-data dns --path prod/9.1.1/dns/values.yaml
    """
    import shutil
    from salt_config_cli.core.repositories import RepositorySource, RepositoryStore
    from salt_config_cli.services.git_repository import ContentWorkspaceService, GitRepositoryError, GitRepositoryService

    setup_logging(log_level, no_color)
    effective_config = config or _GLOBAL_CONFIG_PATH
    store = RepositoryStore(connection_config=effective_config)
    try:
        if repo:
            try:
                _, base = store.get(source_name, kind="data")
            except Exception:
                base = RepositorySource(kind="data", url=repo, ref=ref or "main", root=root or ".")
            source = base.model_copy(update={"url": repo, "ref": ref or base.ref, "root": root or base.root})
            selected_name = source_name or "one-shot-data"
        else:
            selected_name, source = store.get(source_name, kind="data")
            if ref or root:
                source = source.model_copy(update={"ref": ref or source.ref, "root": root or source.root})
    except ValueError as exc:
        ui_error(str(exc), hint="Run `scc repo setup` or pass --repo.")
        raise SystemExit(1) from exc

    try:
        with spinner(f"Syncing {selected_name}@{source.ref}…"):
            synced = GitRepositoryService().sync(selected_name, source)
        source_file = ContentWorkspaceService().resolve_data_file(
            synced,
            name,
            environment=environment,
            version=version,
            values=file or "",
            explicit_path=data_path,
        )
        destination_dir = Path(local_dir) / name
        destination_dir.mkdir(parents=True, exist_ok=True)
        destination_name = source_file.name if not file else f"{file}.yaml"
        destination = destination_dir / destination_name
        if destination.exists() and not force:
            raise GitRepositoryError(f"{destination} already exists; use --force to replace it")
        shutil.copy2(source_file, destination)
        try:
            os.chmod(destination, 0o600)
        except OSError:
            pass
    except GitRepositoryError as exc:
        ui_error(str(exc))
        raise SystemExit(1) from exc

    result_summary(
        "Customer values fetched",
        details=[
            ("Resource", name),
            ("Source", f"{selected_name}@{source.ref}"),
            ("Commit", synced.commit),
            ("Repository path", source_file.relative_to(synced.path).as_posix()),
            ("Local path", str(destination)),
            ("Persisted to RaaS", "No"),
        ],
    )
    next_steps([
        f"Use only for one run: `scc run /{name}/{name}.sls --target-group <group> --env <salt-env> --pillar-file {destination} --test`",
        f"Use the simpler full workflow: `scc deploy {name} --mode dry-run --target-group <group>`",
    ])


@cli.command("import")
@click.argument("address")
@click.argument("id")
@common_options
@click.pass_context
def import_resource(ctx, address, id, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """
    Import an existing resource into state.
    
    Associates an existing remote resource with a configuration resource.
    
    \b
    Arguments:
      ADDRESS  Resource address (e.g., target_group.web-servers)
      ID       Remote resource ID or name
    
    \b
    Examples:
      $ scc import target_group.web-servers existing-group-uuid
    """
    setup_logging(log_level, no_color)
    
    settings = load_settings(config, server, username, password, csp_token, password_stdin=password_stdin, password_file=password_file, password_prompt=password_prompt)
    
    console.print(f"\n[bold blue]Importing {address}...[/bold blue]\n")
    
    # Parse address
    parts = address.split(".", 1)
    if len(parts) != 2:
        console.print(f"[red]Error:[/red] Invalid address format: {address}")
        console.print("Expected format: resource_type.name")
        sys.exit(1)
    
    resource_type_str, name = parts
    
    # TODO: Fetch resource from server and add to state
    console.print(f"  Resource type: {resource_type_str}")
    console.print(f"  Resource name: {name}")
    console.print(f"  Remote ID: {id}")
    console.print("\n[yellow]Note:[/yellow] Import requires server connection.\n")


@cli.group()
@click.pass_context
def ops(ctx):
    """
    VCF Operations (Ops) integration commands.
    
    Query resources from VCF Operations and map them to Salt minions.
    
    \b
    Commands:
      status     Check Ops connection status
      resources  List Ops resources mapped to minions
    
    \b
    Examples:
      $ scc ops status
      $ scc ops resources
      $ scc ops resources --kind VirtualMachine
    """
    ctx.ensure_object(dict)


@ops.command("status")
@common_options
@click.pass_context
def ops_status(ctx, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """
    Check VCF Operations connection status.
    
    Tests connectivity to the Ops server and displays configuration.
    
    \b
    Examples:
      $ scc ops status
    """
    setup_logging(log_level, no_color)
    
    settings = load_settings(config, server, username, password, csp_token, password_stdin=password_stdin, password_file=password_file, password_prompt=password_prompt)
    
    console.print("\n[bold blue]VCF Operations Status[/bold blue]\n")
    
    ops_config = settings.get_ops_auth_config()
    
    if not ops_config:
        console.print("[yellow]⚠️  Ops server not configured[/yellow]")
        console.print("\nAdd the following to your .scc/config.yaml:")
        console.print("  ops_server_url: https://your-ops-server.example.com")
        console.print("  ops_username: admin")
        console.print("  ops_password: your-password")
        console.print("  ops_ssl_verify: false")
        console.print()
        return
    
    console.print("[bold]Ops Server:[/bold]")
    console.print(f"  URL: {settings.ops_server_url}")
    console.print(f"  Username: {settings.ops_username or '(not set)'}")
    console.print(f"  SSL verify: {settings.ops_ssl_verify}")
    console.print()
    
    console.print("[bold]Connection Test:[/bold]")
    try:
        from salt_config_cli.api.ops_client import OpsClient
        client = OpsClient.from_config(ops_config)
        console.print(f"  [green]✓[/green] Connected successfully")
        console.print(f"  Authenticated: {client.is_authenticated}")
        
        if client.ping():
            console.print(f"  [green]✓[/green] API responding")
        else:
            console.print(f"  [yellow]⚠[/yellow] API ping failed")
            
    except Exception as e:
        console.print(f"  [red]✗[/red] Connection failed: {e}")
    
    console.print()


@ops.command("resources")
@click.option(
    "--kind", "-k",
    help="Filter by resource kind (e.g., VirtualMachine, HostSystem)"
)
@click.option(
    "--adapter", "-a",
    help="Filter by adapter kind (e.g., VMWARE)"
)
@click.option(
    "--grain", "-g", "grains",
    multiple=True,
    help="Filter by minion grain (format: key:value). Can be specified multiple times."
)
@click.option(
    "--show-health", "-H",
    is_flag=True,
    help="Display health status column"
)
@click.option(
    "--show-version", "-V",
    is_flag=True,
    help="Display version and build column (from Ops resource properties)"
)
@click.option(
    "--fetch-version", "-F",
    is_flag=True,
    help="Fetch live version from minions using vcf_version module (requires module sync)"
)
@click.option(
    "--json", "as_json",
    is_flag=True,
    help="Output as JSON"
)
@click.option(
    "--all", "-A", "show_all",
    is_flag=True,
    help="Show all Ops resources, not just those mapped to minions"
)
@click.option(
    "--no-map-minions",
    is_flag=True,
    hidden=True,
    help="Deprecated: use --all instead"
)
@common_options
@click.pass_context
def ops_resources(ctx, kind, adapter, grains, show_health, show_version, fetch_version, as_json, show_all, no_map_minions, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """
    List VCF Operations resources mapped to Salt minions.
    
    By default, only shows Ops resources that are mapped to RaaS minions.
    Use --all to show all Ops resources.
    
    Filter by minion grains using --grain key:value (can be repeated).
    
    The resourceId in Ops matches the minion_id in RaaS.
    
    \b
    Examples:
      $ scc ops resources
      $ scc ops resources --all
      $ scc ops resources --show-health --show-version
      $ scc ops resources --fetch-version
      $ scc ops resources --grain os:VMkernel
      $ scc ops resources --kind VirtualMachine
      $ scc ops resources --json
    """
    setup_logging(log_level, no_color)
    
    if no_map_minions:
        show_all = True
    
    settings = load_settings(config, server, username, password, csp_token, password_stdin=password_stdin, password_file=password_file, password_prompt=password_prompt)
    
    ops_config = settings.get_ops_auth_config()
    
    if not ops_config:
        console.print("[red]Error:[/red] Ops server not configured")
        console.print("\nRun 'scc ops status' for configuration details.")
        sys.exit(1)
    
    minions_map = {}
    grain_filters = {}
    
    for grain_spec in grains:
        if ":" in grain_spec:
            key, value = grain_spec.split(":", 1)
            grain_filters[key] = value
        else:
            console.print(f"[yellow]⚠[/yellow] Invalid grain format: {grain_spec} (expected key:value)")
    
    console.print("\n[bold blue]Fetching minions from RaaS...[/bold blue]")
    try:
        from salt_config_cli.api.client import AriaConfigClient
        raas_client = AriaConfigClient.from_settings(settings)
        minions = raas_client.get_minions()
        minions_map = {m.get("minion_id", m.get("id", "")): m for m in minions}
        console.print(f"  Found {len(minions_map)} minion(s)")
        
        if grain_filters:
            console.print(f"  Applying grain filters: {grain_filters}")
            filtered_minions = {}
            for minion_id, minion in minions_map.items():
                minion_grains = minion.get("grains", {})
                matches = True
                for key, value in grain_filters.items():
                    grain_value = minion_grains.get(key)
                    if isinstance(grain_value, list):
                        if value not in grain_value:
                            matches = False
                            break
                    elif str(grain_value) != value:
                        matches = False
                        break
                if matches:
                    filtered_minions[minion_id] = minion
            minions_map = filtered_minions
            console.print(f"  Filtered to {len(minions_map)} minion(s) matching grains")
    except Exception as e:
        console.print(f"  [yellow]⚠[/yellow] Failed to fetch minions: {e}")
        if not show_all:
            console.print("  [red]Error:[/red] Cannot show mapped resources without minion list.")
            console.print("  Use --all to show all Ops resources.")
            sys.exit(1)
    
    console.print("\n[bold blue]Fetching resources from Ops...[/bold blue]")
    
    try:
        from salt_config_cli.api.ops_client import OpsClient
        ops_client = OpsClient.from_config(ops_config)
        
        if show_version or as_json:
            resources = ops_client.get_resources_with_properties(
                resource_kind=kind,
                adapter_kind=adapter,
            )
            console.print(f"  Found {len(resources)} resource(s) in Ops (with properties)")
        else:
            resources = ops_client.get_resources(
                resource_kind=kind,
                adapter_kind=adapter,
            )
            console.print(f"  Found {len(resources)} resource(s) in Ops")
        
        if not show_all and minions_map:
            resources = [r for r in resources if r.identifier in minions_map]
            console.print(f"  Filtered to {len(resources)} mapped minion(s)")
        
        minion_versions = {}
        if fetch_version and resources:
            console.print("\n[bold blue]Fetching live versions from minions...[/bold blue]")
            try:
                target_minion_ids = [r.identifier for r in resources if r.identifier in minions_map]
                if target_minion_ids:
                    target_expr = ",".join(target_minion_ids)
                    job_result = raas_client.execute_command(
                        target=target_expr,
                        target_type="list",
                        function="vcf_version.get_version",
                        arguments=[],
                        timeout=60,
                    )
                    if job_result and isinstance(job_result, dict):
                        for minion_id, result in job_result.items():
                            if isinstance(result, dict) and not result.get("error"):
                                version = result.get("version", "")
                                build = result.get("build", "")
                                if version and build:
                                    minion_versions[minion_id] = f"{version} ({build})"
                                elif version:
                                    minion_versions[minion_id] = version
                                elif build:
                                    minion_versions[minion_id] = build
                    console.print(f"  Retrieved versions for {len(minion_versions)} minion(s)")
                else:
                    console.print("  [yellow]⚠[/yellow] No mapped minions to fetch versions from")
            except Exception as e:
                console.print(f"  [yellow]⚠[/yellow] Failed to fetch minion versions: {e}")
                console.print("    Ensure vcf_version module is synced: scc exec saltutil.sync_modules")
        
        console.print()
        
        if as_json:
            import json as json_module
            output = []
            for r in resources:
                minion = minions_map.get(r.identifier)
                item = {
                    "identifier": r.identifier,
                    "name": r.name,
                    "resource_kind": r.resource_kind,
                    "adapter_kind": r.adapter_kind,
                    "health": r.health,
                    "version": r.version,
                    "build": r.build,
                    "version_string": r.get_version_string(),
                    "description": r.description,
                    "minion_id": minion.get("minion_id", minion.get("id")) if minion else None,
                }
                if fetch_version and r.identifier in minion_versions:
                    item["live_version"] = minion_versions[r.identifier]
                output.append(item)
            console.print(json_module.dumps(output, indent=2))
        else:
            title = "Ops Resources (Mapped to Minions)" if not show_all else "All Ops Resources"
            table = Table(title=title)
            table.add_column("Minion ID", style="cyan", no_wrap=True, max_width=36)
            table.add_column("Ops Resource Name", style="white")
            table.add_column("Kind", style="blue")
            if show_version:
                table.add_column("Ops Version", style="magenta")
            if fetch_version:
                table.add_column("Live Version", style="green")
            if show_health:
                table.add_column("Health", style="yellow")
            
            for r in resources:
                row = [
                    r.identifier[:36] if len(r.identifier) > 36 else r.identifier,
                    r.name,
                    r.resource_kind,
                ]
                
                if show_version:
                    row.append(r.get_version_string() or "-")
                
                if fetch_version:
                    live_ver = minion_versions.get(r.identifier, "-")
                    row.append(live_ver)
                
                if show_health:
                    health_style = "green" if r.health in ("GREEN", "STARTED") else (
                        "yellow" if r.health in ("YELLOW", "UNKNOWN") else "red"
                    )
                    health_display = f"[{health_style}]{r.health}[/{health_style}]"
                    row.append(health_display)
                
                table.add_row(*row)
            
            console.print(table)
            
            if show_all and minions_map:
                matched = sum(1 for r in resources if r.identifier in minions_map)
                console.print(f"\n[bold]Summary:[/bold] {matched}/{len(resources)} resources mapped to minions")
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    
    console.print()


@cli.command("upload-module")
@click.argument("local_file", type=click.Path(exists=True))
@click.option(
    "--name", "-n",
    help="Module name (default: derived from filename)"
)
@click.option(
    "--env", "-e", "saltenv",
    default="base",
    help="Salt environment (default: base)"
)
@click.option(
    "--sync/--no-sync",
    default=True,
    help="Sync modules to minions after upload (default: sync)"
)
@click.option(
    "--target", "-t",
    default="*",
    help="Target minions for module sync (default: *)"
)
@click.option(
    "--target-type", "-T",
    type=click.Choice(["glob", "grain", "compound", "list", "nodegroup", "pillar", "pcre"]),
    default="glob",
    help="Target type for module sync (default: glob)"
)
@click.option(
    "--force", "-f",
    is_flag=True,
    help="Overwrite if module already exists"
)
@common_options
@click.pass_context
def upload_module(ctx, local_file, name, saltenv, sync, target, target_type, force, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """
    Upload a Salt execution module (.py) to the RaaS file server.
    
    Uploads a Python module to /_modules/ on the file server, making it
    available as a custom Salt execution module.
    
    After upload, run 'scc exec saltutil.sync_modules' to sync to minions
    (done automatically unless --no-sync is specified).
    
    \b
    Examples:
      $ scc upload-module my_module.py
      $ scc upload-module vcf_version.py --sync
      $ scc upload-module custom.py --name my_custom --no-sync
      $ scc upload-module my_module.py --target "web-*"
      $ scc upload-module vcf_version.py --target "vcfops_resource_kind:nsx" -T grain
    """
    setup_logging(log_level, no_color)
    
    settings = load_settings(config, server, username, password, csp_token, password_stdin=password_stdin, password_file=password_file, password_prompt=password_prompt)
    
    if not settings.server_url or settings.server_url == "https://localhost":
        console.print("[red]No server configured. Set server_url in config.[/red]\n")
        sys.exit(1)
    
    api_client = connect_client(settings)
    ui_success(f"Connected to {mask_url(settings.server_url)}")
    
    local_path = Path(local_file)
    
    if not local_path.suffix == ".py":
        console.print(f"[red]Error:[/red] Module must be a .py file, got: {local_path.suffix}\n")
        sys.exit(1)
    
    module_name = name or local_path.stem
    remote_path = f"/_modules/{module_name}.py"
    
    console.print(f"[bold]Local file:[/bold] {local_file}")
    console.print(f"[bold]Module name:[/bold] {module_name}")
    console.print(f"[bold]Remote path:[/bold] {remote_path}")
    console.print(f"[bold]Environment:[/bold] {saltenv}")
    console.print()
    
    try:
        with open(local_file, "r") as f:
            contents = f.read()
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to read local file: {e}\n")
        sys.exit(1)
    
    try:
        resp = api_client.call("fs", "file_exists", path=remote_path, saltenv=saltenv)
        file_exists = resp.success and resp.ret
        
        if file_exists and not force:
            console.print(f"[yellow]⚠[/yellow] Module already exists: {remote_path}")
            console.print("Use --force to overwrite.\n")
            sys.exit(1)
        
        operation = "update_file" if file_exists else "save_file"
        action = "Updating" if file_exists else "Uploading"
        console.print(f"[bold blue]{action} module...[/bold blue]")
        
        resp = api_client.call(
            "fs", operation,
            path=remote_path,
            contents=contents,
            saltenv=saltenv,
            content_type="text/x-python"
        )
        
        if resp.error:
            console.print(f"[red]✗[/red] Upload failed: {resp.error.get('message', 'Unknown error')}\n")
            sys.exit(1)
        
        console.print(f"[green]✓[/green] Module uploaded successfully!\n")
        
        if sync:
            target_display = f"{target}" if target_type == "glob" else f"{target} ({target_type})"
            console.print(f"[bold blue]Syncing modules to minions ({target_display})...[/bold blue]")
            
            tgt_spec = {"*": {"tgt": target, "tgt_type": target_type}}
            sync_resp = api_client.call(
                "cmd", "route_cmd",
                cmd="local",
                tgt=tgt_spec,
                fun="saltutil.sync_modules",
            )
            
            if sync_resp.success:
                console.print(f"[green]✓[/green] Module sync initiated")
                if sync_resp.ret:
                    jid = sync_resp.ret.get("jid") if isinstance(sync_resp.ret, dict) else sync_resp.ret
                    if jid:
                        console.print(f"  Job ID: {jid}")
            else:
                console.print(f"[yellow]⚠[/yellow] Sync may have failed: {sync_resp.error}")
        
        console.print()
        console.print(f"[bold]To use this module:[/bold]")
        console.print(f"  scc exec {module_name}.<function_name>")
        console.print()
        
    except Exception as e:
        console.print(f"[red]✗[/red] Failed: {e}\n")
        sys.exit(1)
    
    api_client.close()


@cli.command("upload-pillar")
@click.argument("local_file", type=click.Path(exists=True))
@click.option(
    "--name", "-n",
    help="Pillar name (default: derived from filename)"
)
@click.option(
    "--description", "-d",
    default="",
    help="Pillar description"
)
@click.option(
    "--target-group", "-g",
    help="Target group to associate pillar with (required for minions to receive pillar)"
)
@click.option(
    "--refresh/--no-refresh",
    default=True,
    help="Refresh pillar on minions after upload (default: refresh)"
)
@click.option(
    "--target", "-t",
    default="*",
    help="Target minions for pillar refresh (default: *)"
)
@click.option(
    "--target-type", "-T",
    type=click.Choice(["glob", "grain", "compound", "list", "nodegroup", "pillar", "pcre"]),
    default="glob",
    help="Target type for pillar refresh (default: glob)"
)
@common_options
@click.pass_context
def upload_pillar(ctx, local_file, name, description, target_group, refresh, target, target_type, config, server, username, password, password_stdin, password_file, password_prompt, csp_token, log_level, no_color):
    """
    Upload a pillar YAML file to RaaS.
    
    Uploads a YAML file as pillar data. To make the pillar available to minions,
    you must associate it with a target group using --target-group.
    
    \b
    Examples:
      $ scc upload-pillar credentials.yaml --target-group "All Minions"
      $ scc upload-pillar vcf_credentials.yaml --target-group ops
      $ scc upload-pillar secrets.yaml --target-group app-servers --no-refresh
    """
    setup_logging(log_level, no_color)
    
    settings = load_settings(config, server, username, password, csp_token, password_stdin=password_stdin, password_file=password_file, password_prompt=password_prompt)
    
    if not settings.server_url or settings.server_url == "https://localhost":
        console.print("[red]No server configured. Set server_url in config.[/red]\n")
        sys.exit(1)
    
    api_client = connect_client(settings)
    ui_success(f"Connected to {mask_url(settings.server_url)}")
    
    local_path = Path(local_file)
    pillar_name = name or local_path.stem
    
    console.print(f"[bold]Local file:[/bold] {local_file}")
    console.print(f"[bold]Pillar name:[/bold] {pillar_name}")
    if target_group:
        console.print(f"[bold]Target group:[/bold] {target_group}")
    console.print()
    
    try:
        with open(local_file, "r") as f:
            contents = f.read()
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to read local file: {e}\n")
        sys.exit(1)
    
    import yaml
    try:
        pillar_data = yaml.safe_load(contents)
        if not isinstance(pillar_data, dict):
            console.print(f"[red]Error:[/red] Pillar must be a YAML dictionary, got: {type(pillar_data).__name__}\n")
            sys.exit(1)
    except yaml.YAMLError as e:
        console.print(f"[red]Error:[/red] Invalid YAML: {e}\n")
        sys.exit(1)
    
    tgt_group_data = None
    if target_group:
        console.print(f"[bold blue]Resolving target group '{target_group}'...[/bold blue]")
        groups = _list_target_groups(api_client)
        for g in groups:
            if isinstance(g, dict) and g.get("name", "").lower() == target_group.lower():
                tgt_group_data = g
                break
        
        if not tgt_group_data:
            console.print(f"[red]✗[/red] Target group not found: {target_group}\n")
            console.print("Available target groups:")
            for g in groups[:10]:
                if isinstance(g, dict):
                    console.print(f"  - {g.get('name', 'unknown')}")
            sys.exit(1)
        console.print(f"[green]✓[/green] Found: {tgt_group_data.get('name')} (UUID: {tgt_group_data.get('uuid', 'unknown')[:8]}...)\n")
    
    try:
        console.print("[bold blue]Saving pillar...[/bold blue]")
        resp = api_client.call(
            "pillar", "save_pillar",
            name=pillar_name,
            pillar=pillar_data,
            pillar_type="static",
            desc=description or f"Uploaded from {local_path.name}"
        )
        
        if resp.error:
            console.print(f"[red]✗[/red] Failed to save pillar: {resp.error.get('message', 'Unknown error')}\n")
            sys.exit(1)
        
        pillar_uuid = resp.ret if isinstance(resp.ret, str) else resp.ret.get("uuid") if isinstance(resp.ret, dict) else None
        console.print(f"[green]✓[/green] Pillar saved!")
        if pillar_uuid:
            console.print(f"  UUID: {pillar_uuid}")
        console.print()
        
        if tgt_group_data and pillar_uuid:
            console.print(f"[bold blue]Associating pillar with target group '{tgt_group_data.get('name')}'...[/bold blue]")
            
            existing_pillars = tgt_group_data.get("pillars", [])
            if pillar_uuid not in existing_pillars:
                existing_pillars.append(pillar_uuid)
            
            tgt_update_resp = api_client.call(
                "tgt", "save_target_group",
                tgt_uuid=tgt_group_data.get("uuid"),
                name=tgt_group_data.get("name"),
                tgt=tgt_group_data.get("tgt", {}),
                pillar_uuids=existing_pillars,
            )
            
            if tgt_update_resp.error:
                error_msg = tgt_update_resp.error.get('message', 'Unknown error')
                if "All Minions" in error_msg or "cannot modify" in error_msg.lower():
                    console.print(f"[yellow]⚠[/yellow] Cannot modify system target group '{tgt_group_data.get('name')}'")
                    console.print()
                    console.print("[bold]You need to create a custom target group. Options:[/bold]")
                    console.print()
                    console.print("  1. Create via scc (targeting all minions):")
                    console.print(f"     scc target-group-create vcf-pillar-group --target '*'")
                    console.print(f"     scc upload-pillar {local_file} --target-group vcf-pillar-group")
                    console.print()
                    console.print("  2. Use an existing custom target group:")
                    groups = _list_target_groups(api_client)
                    custom_groups = [g for g in groups if isinstance(g, dict) and g.get("name") != "All Minions"]
                    if custom_groups:
                        console.print("     Available groups:")
                        for g in custom_groups[:5]:
                            console.print(f"       - {g.get('name')}")
                    else:
                        console.print("     (No custom target groups found)")
                    console.print()
                else:
                    console.print(f"[yellow]⚠[/yellow] Failed to associate pillar: {error_msg}")
            else:
                console.print(f"[green]✓[/green] Pillar associated with target group!\n")
        elif target_group and not pillar_uuid:
            console.print(f"[yellow]⚠[/yellow] Could not get pillar UUID to associate with target group\n")
        
        if refresh:
            target_display = f"{target}" if target_type == "glob" else f"{target} ({target_type})"
            console.print(f"[bold blue]Refreshing pillar on minions ({target_display})...[/bold blue]")
            
            tgt_spec = {"*": {"tgt": target, "tgt_type": target_type}}
            refresh_resp = api_client.call(
                "cmd", "route_cmd",
                cmd="local",
                tgt=tgt_spec,
                fun="saltutil.refresh_pillar",
            )
            
            if refresh_resp.success:
                console.print(f"[green]✓[/green] Pillar refresh initiated")
                if refresh_resp.ret:
                    jid = refresh_resp.ret.get("jid") if isinstance(refresh_resp.ret, dict) else refresh_resp.ret
                    if jid:
                        console.print(f"  Job ID: {jid}")
            else:
                console.print(f"[yellow]⚠[/yellow] Refresh may have failed: {refresh_resp.error}")
        
        console.print()
        if not target_group:
            console.print("[yellow]Note:[/yellow] Pillar saved but NOT associated with a target group.")
            console.print("  Minions will not receive this pillar until you associate it.")
            console.print("  Use: scc upload-pillar <file> --target-group <name>")
            console.print()
        console.print(f"[bold]To verify pillar on minion:[/bold]")
        console.print(f"  scc exec pillar.items")
        console.print()
        
    except Exception as e:
        console.print(f"[red]✗[/red] Failed: {e}\n")
        sys.exit(1)
    
    api_client.close()


# Register named connection-profile and configuration management commands.
cli.add_command(configure_command)
cli.add_command(configure_git_command)  # backward-compatible alias for repository setup
cli.add_command(profile_group)
cli.add_command(config_group)
cli.add_command(theme_group)

# Register generic Git sources and the simplified Git-to-RaaS deployment workflow.
from salt_config_cli.cli.repo_cmds import register as _register_repositories
_register_repositories(cli)

from salt_config_cli.cli.workflow_cmds import register as _register_workflows
_register_workflows(
    cli,
    upload_command=upload_file,
    upload_pillar_command=upload_pillar,
    job_create_command=job_create,
    run_state_command=run_state,
)

# Register static KB-to-SLS solution catalog commands.
from salt_config_cli.cli.kb_cmds import register as _register_kb_catalog
_register_kb_catalog(cli)

# Register production operational extensions (interactive shell, raw RPC, system info)
from salt_config_cli.cli.extended import register as _register_extended
_register_extended(
    cli,
    common_options=common_options,
    load_settings=load_settings,
    connect_client=connect_client,
    setup_logging=setup_logging,
)

# Register discovery commands (commands, search, examples, tutorial, help)
from salt_config_cli.cli.discovery import register as _register_discovery
_register_discovery(cli)


def main():
    """Main entry point with concise, themed top-level error handling."""
    bootstrap_theme()
    install_error_handler()
    try:
        cli(obj={}, standalone_mode=False)
    except click.UsageError as exc:
        # Click versions differ on whether NoArgsIsHelpError is public. Detect
        # it by behavior/class name instead of importing a version-specific
        # symbol so the CLI remains compatible with Click 8.1 through 8.x.
        if exc.__class__.__name__ == "NoArgsIsHelpError":
            if exc.ctx is not None:
                click.echo(exc.ctx.get_help(), nl=False)
            raise SystemExit(0) from exc
        command_hint = "scc help"
        if exc.ctx is not None and exc.ctx.command_path:
            path = exc.ctx.command_path.replace("cli", "scc", 1)
            command_hint = f"{path} --help"
        ui_error(exc.format_message(), hint=f"Review the command syntax with `{command_hint}`.")
        raise SystemExit(exc.exit_code) from exc
    except click.ClickException as exc:
        ui_error(exc.format_message(), hint="Run with --log-level DEBUG for additional diagnostics.")
        raise SystemExit(exc.exit_code) from exc
    except click.Abort as exc:
        ui_warn("Operation cancelled by user.")
        raise SystemExit(1) from exc
    except KeyboardInterrupt as exc:
        ui_warn("Interrupted. Remote work already submitted may still be running.")
        raise SystemExit(130) from exc
    except SystemExit:
        raise
    except Exception as exc:
        if os.getenv("SCC_DEBUG"):
            raise
        ui_error(
            f"Unexpected failure: {exc}",
            hint="Re-run with SCC_DEBUG=1 and --log-level DEBUG, then include the traceback in a bug report.",
        )
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()

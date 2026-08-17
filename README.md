# Salt Config CLI (`scc`)

Salt Config CLI is an interactive and scriptable command-line interface for managing Git-backed Salt configuration through Salt/RaaS.

It provides a safe workflow for:

- connecting to one or more RaaS environments;
- registering reusable Salt-state repositories;
- registering environment-specific values repositories;
- validating Git content before publication;
- planning configuration changes without touching RaaS;
- running Salt states in dry-run mode with `test=True`;
- applying approved changes with `test=False`;
- monitoring the RaaS job ID and per-target results;
- searching reviewed KB-to-Salt mappings;
- working directly with target groups, jobs, pillars, minions, and the RaaS file server.

---

## Table of contents

1. [Core principles](#core-principles)
2. [How SCC works](#how-scc-works)
3. [Capabilities](#capabilities)
4. [Requirements and installation](#requirements-and-installation)
5. [Five-minute quick start](#five-minute-quick-start)
6. [Connection profiles](#connection-profiles)
7. [Git repository model](#git-repository-model)
8. [Repository layouts](#repository-layouts)
9. [Deployment modes](#deployment-modes)
10. [End-to-end execution flow](#end-to-end-execution-flow)
11. [Target groups](#target-groups)
12. [KB-to-Salt solution catalog](#kb-to-salt-solution-catalog)
13. [Low-level RaaS operations](#low-level-raas-operations)
14. [Tutorials and command discovery](#tutorials-and-command-discovery)
15. [Themes and structured output](#themes-and-structured-output)
16. [Configuration files and environment variables](#configuration-files-and-environment-variables)
17. [Security and safety model](#security-and-safety-model)
18. [Automation and CI/CD](#automation-and-cicd)
19. [Troubleshooting](#troubleshooting)
20. [Development and release](#development-and-release)
21. [Docker](#docker)

---

## Core principles

### Repository independence

SCC works with any Git repository that contains valid Salt content or YAML values. The source can be hosted on any Git service supported by the local `git` client.

The following are configurable for each repository:

- repository URL;
- Git reference, branch, tag, or commit;
- repository root;
- path layout;
- authentication mechanism;
- TLS verification;
- source purpose: reusable states or configuration data.

### Separation of reusable logic and environment values

A normal production workflow uses two independently managed sources:

1. **Reusable Salt content**
   - SLS files
   - Jinja mapping files
   - defaults
   - templates
   - supporting files
   - optional KB solution catalog

2. **Environment-specific values**
   - hostnames
   - IP addresses
   - environment settings
   - release-specific values
   - feature flags
   - approved configuration parameters

This separation allows reusable logic to evolve independently from organization-specific configuration.

### Git is the approval system

SCC does not introduce a second approval manifest.

The expected approval path is:

```text
Update values.yaml
        ↓
Create pull request or merge request
        ↓
Review and approve
        ↓
Merge to an approved branch or tag
        ↓
SCC resolves the approved commit and executes it
```

SCC displays the selected repository, reference, exact commit, file path, state entrypoint, and hashes before execution.

### Fail-safe execution

- `plan` is the default mode.
- Salt execution defaults to `test=True`.
- `apply` requires explicit confirmation.
- Customer values are passed as execution-scoped pillar by default.
- A persistent saved job is not created unless `--save-job` is requested.
- Target groups must already exist and should contain only the intended minions.

---

## How SCC works

```text
Reusable Salt repository
        │
        │ clone/fetch, resolve commit, validate files
        ▼
Salt Config CLI
        │
        │ publish reusable state tree only
        ▼
RaaS file server
        │
        │ state.apply
        ▼
Target group / Salt minions
        │
        │ JID and per-target results
        ▼
Salt Config CLI

Configuration-values repository
        │
        │ load approved values.yaml
        ▼
Execution-scoped pillar
```

The values repository is not copied to the RaaS file server during the normal deployment flow. Its YAML mapping is supplied only to the runtime execution.

---

## Capabilities

### Git-backed configuration workflow

- named state and data sources;
- generic Git clone and fetch;
- configurable roots and layouts;
- branch, tag, and commit support;
- SSH, credential-helper, and token authentication;
- exact commit resolution;
- recursive state-tree validation;
- path and symlink safety checks;
- YAML and UTF-8 validation;
- SHA-256 hashing;
- local review workspaces;
- plan, publish, dry-run, and apply modes.

### RaaS operations

- connection profiles;
- status and diagnostics;
- minion listing;
- Salt module execution;
- target-group management;
- file-server browsing, upload, download, and edit;
- pillar upload and assignment;
- saved-job management;
- live runtime execution;
- job-status and result retrieval;
- desired-state drift and remediation workflows;
- guarded raw RPC access for advanced use.

### Operator experience

- interactive setup;
- command search;
- guided tutorials;
- copy-pasteable examples;
- multiple terminal themes;
- plain output;
- JSON and YAML output for automation;
- shell completion.

---

## Requirements and installation

### Requirements

- Python 3.10 or later
- system `git` executable
- network access to the configured Git sources
- network access to the RaaS server
- a RaaS account with the required RPC, file-server, job, and targeting permissions

### Install from a wheel

```bash
python3 -m venv .venv
source .venv/bin/activate

python3 -m pip install --upgrade pip
python3 -m pip install salt_config_cli-<version>-py3-none-any.whl
```

### Install from source

```bash
git clone <salt-config-cli-repository-url>
cd salt-config-cli

python3 -m venv .venv
source .venv/bin/activate

python3 -m pip install --upgrade pip
python3 -m pip install .
```

Verify the installation:

```bash
scc --version
scc --help
```

Equivalent entry points may also be installed:

```text
scc
salt-config
raas
```

---

## Five-minute quick start

### 1. Create a RaaS connection profile

```bash
scc configure --name lab
```

Store the credential securely:

```bash
scc profile login lab
```

Select and test the profile:

```bash
scc profile use lab
scc profile test lab
scc status
scc doctor
```

### 2. Register the Git sources

Guided setup:

```bash
scc repo setup
```

Non-interactive example:

```bash
scc repo add shared-states \
  --kind states \
  --url https://git.example.com/platform/shared-salt-content.git \
  --ref v1.0.0 \
  --root salt \
  --layout '{resource}' \
  --default
```

```bash
scc repo add environment-values \
  --kind data \
  --url ssh://git@git.example.com/operations/config-values.git \
  --ref main \
  --root . \
  --layout '{environment}/{version}/{resource}/values.yaml' \
  --auth ssh \
  --default
```

Test access:

```bash
scc repo test --all
scc repo list
```

### 3. Generate a no-change plan

```bash
scc deploy dns \
  --environment production \
  --version 1.0.0
```

`plan` is the default. It performs local Git retrieval and validation without changing RaaS.

### 4. Run a dry-run

```bash
scc deploy dns \
  --environment production \
  --version 1.0.0 \
  --mode dry-run \
  --target-group production-servers
```

This publishes only the reusable state tree and calls `state.apply` with `test=True`.

### 5. Apply after review

```bash
scc deploy dns \
  --environment production \
  --version 1.0.0 \
  --mode apply \
  --target-group production-servers
```

SCC displays the resolved commits, values path, state, Salt environment, target group, and `test=False`, then requires explicit confirmation.

---

## Connection profiles

Profiles keep connection settings for multiple RaaS environments.

```bash
scc configure --name lab
scc configure --name staging
scc configure --name production
```

Profile operations:

```bash
scc profile list
scc profile show lab
scc profile use lab
scc profile login lab
scc profile test lab
```

Use a profile for one command:

```bash
scc --profile production status
```

Select through an environment variable:

```bash
export SCC_PROFILE=production
scc status
```

A profile normally contains only non-secret settings such as:

```yaml
version: 2
default_profile: lab

profiles:
  lab:
    server_url: https://raas-lab.example.com
    username: automation-user
    auth: password
    ssl_verify: true
    timeout: 60
    default_environment: base
    default_target: "*"
    default_target_type: glob
```

Passwords and tokens should be stored through the OS keychain, secure environment variables, stdin, a protected file, or a masked prompt. They should not be stored in profile YAML.

---

## Git repository model

SCC maintains a non-secret repository source catalog.

Repository kinds:

| Kind | Purpose |
|---|---|
| `states` | Reusable Salt state trees, templates, defaults, and supporting files |
| `data` | Environment-, version-, or instance-specific YAML values |

Common operations:

```bash
scc repo setup
scc repo add <name> --kind states|data --url <url>
scc repo list
scc repo show <name>
scc repo use <name>
scc repo test <name>
scc repo test --all
scc repo sync <name>
scc repo sync --all
scc repo login <name>
scc repo logout <name>
scc repo export --output repositories.yaml
scc repo import repositories.yaml
scc repo remove <name>
scc repo path
```

Repository export and import contain non-secret metadata only.

### Authentication modes

#### SSH

```bash
scc repo add private-values \
  --kind data \
  --url ssh://git@git.example.com/team/config-values.git \
  --auth ssh
```

SCC relies on the normal SSH agent, keys, and `known_hosts`.

#### Git credential helper

```bash
scc repo add shared-states \
  --kind states \
  --url https://git.example.com/team/salt-content.git \
  --auth credential-helper
```

#### OS-keychain token

```bash
scc repo add private-values \
  --kind data \
  --url https://git.example.com/team/config-values.git \
  --auth token

scc repo login private-values
```

A source-specific environment variable can also be used:

```bash
export SCC_GIT_TOKEN_PRIVATE_VALUES='<token>'
```

Repository tokens are not stored in repository YAML or embedded in URLs.

---

## Repository layouts

SCC does not require the repository names or folder names shown below. They are only examples.

### Reusable Salt content

```text
shared-salt-content/
└── salt/
    ├── dns/
    │   ├── dns.sls
    │   ├── default.yaml
    │   ├── map.jinja
    │   └── files/
    │       └── resolver.conf.jinja
    ├── ntp/
    │   ├── ntp.sls
    │   ├── default.yaml
    │   └── map.jinja
    └── application-role/
        ├── application-role.sls
        ├── default.yaml
        └── map.jinja
```

Register this structure with:

```bash
scc repo add shared-states \
  --kind states \
  --url https://git.example.com/platform/shared-salt-content.git \
  --ref v1.0.0 \
  --root salt \
  --layout '{resource}' \
  --default
```

For resource `dns`, SCC resolves:

```text
Repository directory: salt/dns
Default entrypoint:   salt/dns/dns.sls
Salt state:           salt.dns.dns
```

An alternate structure can be configured by changing `--root` and `--layout`.

### Environment-specific values

```text
config-values/
├── development/
│   └── 1.0.0/
│       ├── dns/
│       │   └── values.yaml
│       └── ntp/
│           └── values.yaml
├── staging/
│   └── 1.0.0/
│       └── dns/
│           └── values.yaml
└── production/
    └── 1.0.0/
        ├── dns/
        │   └── values.yaml
        └── application-role/
            └── values.yaml
```

Recommended layout:

```text
{environment}/{version}/{resource}/values.yaml
```

Supported placeholders include:

```text
{resource}
{environment}
{version}
{values}
```

An explicit path can be selected with:

```bash
scc deploy dns \
  --values-path production/current/dns/approved-values.yaml
```

`--data-path` remains a compatibility alias.

### Values example

```yaml
dns:
  servers:
    - 10.10.10.10
    - 10.10.10.11
  search_domains:
    - example.com
  timeout: 5
  attempts: 3
```

The exact keys are owned by the selected Salt resource and its validation contract.

---

## Deployment modes

```bash
scc deploy <resource> [options]
```

| Mode | RaaS file-server change | Salt execution | Test flag | Confirmation |
|---|---:|---:|---:|---:|
| `plan` | No | No | N/A | No |
| `publish` | Yes | No | N/A | May be required for overwrite |
| `dry-run` | Yes | Yes | `test=True` | Review target and plan |
| `apply` | Yes | Yes | `test=False` | Explicit apply confirmation |

### Plan

```bash
scc deploy dns \
  --environment production \
  --version 1.0.0 \
  --mode plan
```

A plan:

- fetches the configured Git references;
- resolves exact commits;
- resolves the complete resource tree;
- resolves the selected values file;
- checks path traversal and symlink safety;
- validates text encoding and YAML;
- validates file and package limits;
- computes hashes;
- displays the state entrypoint and publication path;
- creates a local review workspace;
- makes no RaaS changes.

### Publish only

```bash
scc deploy dns \
  --environment production \
  --version 1.0.0 \
  --mode publish
```

This uploads the reusable state tree but does not run it.

### Dry-run

```bash
scc deploy dns \
  --environment production \
  --version 1.0.0 \
  --mode dry-run \
  --target-group production-servers
```

Dry-run:

- validates and publishes the state tree;
- passes values as execution-scoped pillar;
- invokes `state.apply`;
- sets `test=True`;
- returns a RaaS JID;
- monitors execution;
- displays per-target changes and failures.

### Apply

```bash
scc deploy dns \
  --environment production \
  --version 1.0.0 \
  --mode apply \
  --target-group production-servers
```

Apply:

- refreshes the configured Git references by default;
- validates the content again;
- displays exact state and values commit IDs;
- displays the target group and `test=False`;
- requires explicit confirmation;
- publishes the reusable state tree;
- invokes `state.apply`;
- returns and monitors the new JID;
- displays per-target results.

For reproducible production execution, use an approved tag or commit SHA instead of a moving branch.

### Useful deployment options

```text
--states-source <name>       Select the state repository.
--values-source <name>       Select the values repository.
--without-data               Use state defaults without values.
--environment <name>         Resolve the environment placeholder.
--version <value>            Resolve the version placeholder.
--values <name>              Resolve the values placeholder.
--values-path <path>         Select an explicit YAML file.
--entrypoint <file.sls>      Select a non-default SLS entrypoint.
--target-group <name>        Select an existing RaaS target group.
--salt-env <name>            Select the RaaS file-server environment.
--remote-path <path>         Override the publication path.
--values-mode runtime        Pass values as execution-scoped pillar.
--values-mode pillar         Persist values as a RaaS pillar.
--values-mode none           Do not pass values.
--save-job                   Create or update a reusable safe saved job.
--wait <seconds>             Wait for completion; 0 waits indefinitely.
--refresh / --no-refresh     Control Git refresh.
--force                      Allow state-file overwrite.
--yes                        Skip confirmations in trusted automation only.
```

The recommended values mode is `runtime`.

---

## End-to-end execution flow

### Planning phase

```text
1. Resolve active connection profile
2. Load repository source catalog
3. Select state source
4. Fetch and resolve its Git reference
5. Resolve the resource directory and entrypoint
6. Validate the complete resource tree
7. Select the values source
8. Fetch and resolve its Git reference
9. Resolve and validate values.yaml
10. Display commits, paths, hashes, target, and execution mode
```

### Publication phase

```text
Reusable state directory
        ↓
validated local workspace
        ↓
RaaS file-server environment
```

Only reusable Salt content is published in the normal workflow.

### Execution phase

```text
State reference
+ execution-scoped values
+ target group
+ test=True or test=False
        ↓
RaaS state.apply
        ↓
Runtime JID
        ↓
Per-target status and results
```

### Saved jobs

Direct execution is the default and does not create a persistent saved-job definition.

Create a reusable safe saved job only when required:

```bash
scc deploy dns \
  --environment production \
  --version 1.0.0 \
  --mode dry-run \
  --target-group production-servers \
  --save-job
```

The saved job should remain safe with `test=True`. Customer values are not stored in it.

---

## Target groups

Target groups define which minions receive a module or state execution.

List groups:

```bash
scc target-group-list
```

Create a glob-based group:

```bash
scc target-group-create web-servers \
  --target 'web-*' \
  --target-type glob \
  --description 'Production web-server minions'
```

Create a list-based group:

```bash
scc target-group-create selected-servers \
  --target 'server-01,server-02' \
  --target-type list
```

Create a grain-based group:

```bash
scc target-group-create database-servers \
  --target 'role:database' \
  --target-type grain
```

Before dry-run or apply, verify that the group contains only the intended targets.

---

## KB-to-Salt solution catalog

SCC can search a static, Git-reviewed mapping between knowledge-base entries and existing Salt states.

The catalog is stored in the reusable-state repository, typically as:

```text
repository-root/
├── salt/
│   └── <resource>/
│       ├── <resource>.sls
│       ├── default.yaml
│       └── map.jinja
└── solutions/
    ├── catalog.yaml
    ├── schemas/
    │   └── <resource>-values.schema.yaml
    └── kb-<id>/
        └── solution.yaml
```

The folder name used for Salt states is not fixed. The mapped dotted state and optional entrypoint identify the existing resource.

Use the installed SCC release to create a schema-compatible example:

```bash
scc kb scaffold ./kb-catalog-example
```

Validate and search:

```bash
scc kb validate
scc kb list
scc kb search 'name resolution failed'
scc kb show <solution-id>
```

Plan a mapped state:

```bash
scc kb plan <solution-id> \
  --environment production \
  --version 1.0.0
```

Execute it safely:

```bash
scc kb execute <solution-id> \
  --environment production \
  --version 1.0.0 \
  --target-group production-servers \
  --mode dry-run
```

Apply after review:

```bash
scc kb execute <solution-id> \
  --environment production \
  --version 1.0.0 \
  --target-group production-servers \
  --mode apply
```

KB behavior:

- the mapping is static and read-only at runtime;
- SCC does not infer or generate a state mapping;
- the mapped state must already exist;
- the entry must pass catalog validation;
- apply requires explicit confirmation;
- the normal repository, publication, values, target-group, and JID flow is reused.

Structured output:

```bash
scc kb search 'time synchronization failed' --json
scc kb show <solution-id> --json
```

---

## Low-level RaaS operations

The high-level Git workflow does not remove access to individual RaaS capabilities.

### Browse server resources

```bash
scc list --type minions
scc fs-list --env base
scc target-group-list
scc pillar-list
scc job-list
```

### Execute Salt modules

Read-only examples:

```bash
scc exec test.ping --target '*'
scc exec grains.get --target 'server-01' --arg os
```

### Upload and download file-server content

```bash
scc upload ./salt/dns \
  --path /salt/dns \
  --env base
```

```bash
scc download /salt/dns \
  --output ./downloaded \
  --env base \
  --recursive
```

### Run a state manually

Test mode:

```bash
scc run /salt/dns/dns.sls \
  --target-group production-servers \
  --env base \
  --test
```

Apply mode:

```bash
scc run /salt/dns/dns.sls \
  --target-group production-servers \
  --env base \
  --no-test
```

Potentially mutating operations require confirmation. Manual state execution defaults to test mode.

### Saved jobs

```bash
scc job-list
scc job-create
scc job-run <job-id>
scc job-status <jid>
scc job-results <jid>
scc job-delete <job-id>
```

### Pillars

```bash
scc upload-pillar ./pillar.yaml
scc pillar-list
scc pillar-assign
scc pillar-refresh
```

Use persistent RaaS pillars only when persistence is explicitly required. The high-level deployment flow uses execution-scoped values by default.

### Advanced RPC

```bash
scc rpc <method> [arguments]
```

Raw RPC is an expert escape hatch. It bypasses some high-level workflow protections and should be restricted to reviewed operational procedures.

---

## Tutorials and command discovery

Guided tutorials print the workflow and commands without performing network operations.

```bash
scc tutorial
scc tutorial list
scc tutorial dns
scc tutorial kb-search
scc tutorial gitops
scc tutorial workflow
scc tutorial pull
scc tutorial pull-data
scc tutorial upload
scc tutorial job-create
scc tutorial job-run
```

Non-interactive tutorial output:

```bash
scc tutorial dns --non-interactive
```

Command discovery:

```bash
scc
scc commands
scc search git
scc examples --topic git
scc help deploy
scc workflow
```

Shell completion:

```bash
scc completion
```

---

## Themes and structured output

Themes:

```bash
scc theme list
scc theme preview --all
scc theme use enterprise
scc theme disable
scc theme enable ocean
scc --theme plain status
```

Available themes may include:

```text
ocean
enterprise
graphite
forest
amber
high-contrast
plain
```

JSON and YAML output remain undecorated regardless of theme.

Examples:

```bash
scc repo list --json
scc kb search 'dns failure' --json
scc exec test.ping --target '*' --output json
```

---

## Configuration files and environment variables

Default paths:

```text
~/.scc/config.yaml
~/.scc/repositories.yaml
~/.cache/salt-config-cli/
.scc/work/
```

Purpose:

| Path | Content |
|---|---|
| `~/.scc/config.yaml` | Non-secret RaaS profiles and global UX settings |
| `~/.scc/repositories.yaml` | Non-secret Git source metadata |
| `~/.cache/salt-config-cli/` | Private shallow Git cache and session data |
| `.scc/work/` | Validated local plan and deployment workspaces |

Useful environment variables:

```text
SCC_PROFILE
SCC_CONFIG
SCC_REPOSITORIES_CONFIG
SCC_THEME
SCC_CACHE_DIR
SCC_GIT_TIMEOUT
SCC_GIT_TOKEN_<SOURCE_NAME>
```

Credential resolution can use:

- OS keychain;
- SSH agent;
- Git credential helper;
- source-specific environment variables;
- masked prompt;
- stdin;
- protected password file.

Avoid command-line password arguments because they can appear in shell history and process listings.

---

## Security and safety model

### Secrets

SCC keeps secrets separate from normal YAML configuration.

Do not commit:

- RaaS passwords;
- access tokens;
- SSH private keys;
- customer credentials;
- secrets inside `values.yaml`;
- tokens embedded in Git URLs.

### Git provenance

For each deployment, SCC should show or retain:

- source name;
- repository URL;
- configured Git reference;
- exact resolved commit;
- selected state path;
- selected values path;
- file hashes;
- target group;
- Salt environment;
- execution mode;
- RaaS JID.

### Content validation

Before publication, SCC validates:

- repository-relative path safety;
- symlink behavior;
- regular-file content;
- UTF-8 encoding;
- YAML syntax;
- recursive resource-tree boundaries;
- file and package limits;
- entrypoint existence;
- optional values-schema compatibility.

### Execution controls

- plan before execution;
- dry-run before apply;
- explicit confirmation for apply;
- existing target groups rather than implicit broad targeting;
- state publication separated from customer values;
- direct JID-based execution by default;
- saved jobs only by explicit request;
- pinned tags or commits for production;
- `--yes` only in trusted, reviewed automation.

---

## Automation and CI/CD

Use non-interactive commands, pinned repository references, and structured output.

Example validation stage:

```bash
scc repo test --all
scc kb validate
scc deploy dns \
  --environment production \
  --version 1.0.0 \
  --mode plan
```

Example dry-run stage:

```bash
scc deploy dns \
  --environment production \
  --version 1.0.0 \
  --mode dry-run \
  --target-group production-servers \
  --yes
```

Example apply stage:

```bash
scc deploy dns \
  --environment production \
  --version 1.0.0 \
  --mode apply \
  --target-group production-servers \
  --yes
```

Use `--yes` only after external pipeline approval and only when repositories are pinned to reviewed tags or commits.

Retain the following with the change record:

- pipeline run ID;
- state commit;
- values commit;
- execution plan;
- target group;
- RaaS JID;
- per-target result summary.

---

## Troubleshooting

### Check overall readiness

```bash
scc status
scc doctor
```

### Test a profile

```bash
scc profile test <profile-name>
```

### Test Git sources

```bash
scc repo test --all
```

### Refresh repository caches

```bash
scc repo sync --all
```

### Inspect source configuration

```bash
scc repo list
scc repo show <source-name>
scc repo path
```

### Run with debug logging

```bash
scc --profile lab status --log-level DEBUG
```

For a subcommand that supports local logging options:

```bash
scc repo test --all --log-level DEBUG
```

### Common problems

#### Repository authentication failure

Check:

- SSH agent has the expected key;
- host key exists in `known_hosts`;
- Git credential helper is configured;
- keychain token is present;
- source-specific token environment variable is correctly named;
- repository URL does not contain an expired embedded token.

#### Repository path not found

Check the configured:

- `root`;
- `layout`;
- environment;
- version;
- resource;
- explicit values path;
- Git branch, tag, or commit.

#### Target group not found or empty

```bash
scc target-group-list
```

Confirm the group exists in the active RaaS profile and contains the intended minions.

#### File already exists in RaaS

Review the existing file and planned hash. Use `--force` only after confirming overwrite is safe.

#### Dry-run succeeds but apply fails

Compare:

- resolved Git commits;
- target-group membership;
- credentials and permissions;
- state behavior when `test=False`;
- minion connectivity;
- file-server environment;
- runtime pillar content;
- timeout and job result details.

#### Job timeout

Increase the wait period:

```bash
scc deploy dns \
  --environment production \
  --version 1.0.0 \
  --mode dry-run \
  --target-group production-servers \
  --wait 3600
```

Retrieve results later:

```bash
scc job-status <jid>
scc job-results <jid>
```

#### Clear cached authentication

```bash
scc clear-cache
```

---

## Development and release

Install development dependencies:

```bash
python3 -m pip install -e '.[dev]'
```

Run quality checks:

```bash
pytest -q
ruff check .
python -m compileall -q salt_config_cli
python scripts/check_release.py
```

Build release artifacts:

```bash
python -m build
```

Expected Python distribution artifacts:

```text
dist/salt_config_cli-<version>-py3-none-any.whl
dist/salt_config_cli-<version>.tar.gz
```

Publish SHA-256 checksums with release archives:

```bash
sha256sum dist/* > SHA256SUMS
```

Recommended supporting documentation:

```text
docs/ARCHITECTURE.md
docs/GITOPS_WORKFLOW.md
docs/SAFETY_MODEL.md
docs/RAAS_COMPATIBILITY.md
docs/KB_SOLUTION_CATALOG.md
docs/CUSTOMER_JOURNEYS.md
SECURITY.md
CONTRIBUTING.md
CHANGELOG.md
```

---

## Docker

A sample containerized deployment lives under `docker/`. It builds an image that:

- builds the `salt-config-cli` wheel from this repo and installs it (`scc`/`salt-config`/`raas` entry points);
- installs the system `git` client that SCC shells out to for repo operations;
- runs a small FastAPI server (`docker/api/app.py`) with a single `POST /commands` endpoint that executes `scc` commands and returns the result.

```text
docker/
├── Dockerfile
└── api/
    ├── app.py
    └── requirements.txt
```

### Build

Build from the **repo root** (the Dockerfile copies `pyproject.toml`, `README.md`, `LICENSE`, and `salt_config_cli/` from the build context):

```bash
docker build \
  -f docker/Dockerfile \
  -t salt-cli-api:latest \
  .
```

Corporate networks that block direct PyPI access can point `pip` at an internal mirror via the `PIP_INDEX_URL` build arg (defaults to Broadcom's internal Artifactory):

```bash
docker build \
  -f docker/Dockerfile \
  --build-arg PIP_INDEX_URL=https://packages.vcfd.broadcom.net/artifactory/api/pypi/pypi-virtual/simple \
  -t salt-cli-api:latest \
  .
```

### Run

```bash
docker run --rm -p 8000:8000 salt-cli-api:latest
```

### Use

Health check:

```bash
curl http://localhost:8000/healthz
# {"status":"ok"}
```

Trigger an `scc` command (the `scc`/`salt-config`/`raas` prefix in `command` is optional):

```bash
curl -X POST http://localhost:8000/commands \
  -H 'Content-Type: application/json' \
  -d '{"command": "repo list --json"}'
```

Response shape:

```json
{
  "command": "scc repo list --json",
  "returncode": 0,
  "stdout": "...",
  "stderr": ""
}
```

An optional `timeout` field (seconds, default `60`, max `600`) bounds how long the server waits for the command before returning `504`.

> This API executes `scc` with arguments taken directly from the request body and returns raw stdout/stderr — it is a development/demo convenience, not a hardened production service. Do not expose it on an untrusted network without adding authentication and access controls.

---

## Contributing

Contributions should:

- keep command behavior backward compatible where practical;
- preserve fail-safe defaults;
- keep secrets out of examples and tests;
- keep repository handling generic;
- add tests for new safety behavior;
- add tests for new RaaS RPC behavior;
- document new configuration fields and environment variables;
- include release notes for user-visible changes.

Typical workflow:

```bash
git checkout -b feature/<name>
python3 -m pip install -e '.[dev]'
pytest -q
ruff check .
git commit
git push
```

---

## License

Apache License 2.0. See `LICENSE`.

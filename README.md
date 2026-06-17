# graylog.audit2archive

Export and deploy Graylog pipeline rules that move selected audit/security events into a long-term archive stream.

The project is built for allowlist-style retention: keep normal log volume in the default/short index, and move only selected security/admin events to an archive stream by using Graylog pipeline rules.

## What this repository contains

- `graylog_baseconfig.py` — command line tool for exporting and importing Graylog base objects: index sets, streams, and inputs.
- `graylog_audit2archive.py` — command line tool for exporting and importing Graylog pipeline rules.
- `preset/base-config.yaml` — portable Graylog base configuration mirroring the tested setup: `default`, `short`, and `long` index sets/streams plus Syslog, Beats/Windows, and GELF inputs.
- `preset/audit2archive-preset.yaml` — exported preset with the currently tested audit-to-archive rule set.
- `docs/rule-maintenance.md` — rule/base-config change workflow, precision checklist, and common pitfalls.
- `AGENTS.md` — fast operational guide for Hermes/automation agents working in this repo.
- `requirements.txt` — Python dependency list.

The example preset contains 17 active rules:

### Linux rules

- `linux_ssh` — SSH session open/close plus failed login rows.
- `linux_sudo` — sudo command execution plus exact sudo authentication failures.
- `linux_su` — su session open/close plus exact su authentication failures; deliberately excludes sudo sessions.
- `linux_pkg` — package install/remove/update/upgrade with precise audit guards and apt/dpkg fallbacks.
- `linux_user` — local user create/modify/delete.
- `linux_group` — local group create/modify/delete.

### Windows rules

- `win_logon_failure`
- `win_logon_success`
- `win_privileged_logon`
- `win_user`
- `win_group`
- `win_service`
- `win_task`
- `win_audit_policy`
- `win_defender`
- `win_powershell`
- `win_gpo`

Every rule sets a `pr` field with the rule name before routing, for example `pr=linux_pkg` or `pr=win_gpo`.

## Log delivery dependency

This repository only manages the Graylog archive-routing layer. It assumes that Linux and Windows hosts already deliver logs with the companion Ansible role:

```text
https://github.com/joe-speedboat/ansible.log_forwarder
```

That role is responsible for OS-side log collection and field normalisation:

- Linux hosts: journald/auditd logs are forwarded to Graylog and parsed into fields such as `auth_service`, `auth_session_state`, `auth_result`, `sudo_command`, `log_type`, `audit_type`, `package_action`, and `package_name`.
- Windows hosts: Windows Event Log data is forwarded to Graylog and parsed into fields such as `winlog_event_id`, `winlog_provider_name`, and `winlog_event_data_*`.

The rules in `preset/audit2archive-preset.yaml` depend on those fields. If another forwarder/parser is used, the rules may not match until its output fields are made compatible or the preset is adjusted and retested.

Wiring summary:

```text
Linux/Windows hosts
  -> joe-speedboat/ansible.log_forwarder
  -> Graylog input / Default Stream
  -> tier-long-routing pipeline from this repository
  -> archive stream, for example long
```

## Concept

Graylog pipelines run on source streams. For audit-to-archive routing the pipeline should run on the stream where messages first arrive, normally `Default Stream`.

A matching rule calls:

```graylog
route_to_stream(id:"<archive stream id>", remove_from_default: true);
```

`remove_from_default: true` means matching messages are moved out of the default/short stream into the archive stream. They are not duplicated in both streams.

The repository stores stream and input references by name. The base-config importer creates those named objects first; the pipeline importer resolves names to IDs at deploy time, so the same presets can be used on another Graylog server.

## Base configuration: indices, streams, inputs

Run the base configuration before importing pipeline rules. It manages the Graylog objects that messages need before the archive-routing rules are useful:

| Object type | Preset file | Managed by |
|---|---|---|
| Index sets | `preset/base-config.yaml` | `graylog_baseconfig.py` |
| Streams | `preset/base-config.yaml` | `graylog_baseconfig.py` |
| Inputs | `preset/base-config.yaml` | `graylog_baseconfig.py` |
| Pipeline/rules | `preset/audit2archive-preset.yaml` | `graylog_audit2archive.py` |

The included base preset mirrors the tested setup:

- index sets: `default`, `short`, `long`
- streams: `Default Stream` reference, `short`, `long`
- inputs: `Syslog TCP`, `Syslog UDP`, `Windows`/Beats, `GELF TCP`

Export a live baseline:

```bash
./graylog_baseconfig.py export \
  --api-uri https://graylog.example.com/api \
  --output preset/base-config.yaml
```

Plan/apply/verify base configuration:

```bash
./graylog_baseconfig.py plan   -c preset/base-config.yaml --api-uri https://graylog.example.com/api
./graylog_baseconfig.py apply  -c preset/base-config.yaml --api-uri https://graylog.example.com/api
./graylog_baseconfig.py verify -c preset/base-config.yaml --api-uri https://graylog.example.com/api
```

`Default Stream` is treated as a builtin reference and is not created by the importer. Non-builtin streams are connected to index sets by name; the script resolves the index-set IDs at apply time.

## Install

Use Python 3.9+.

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
```

## For Hermes agents and maintainers

Start with `AGENTS.md`. It captures the repository invariants, safe validation commands, and public-repo safety rules.

For rule changes, follow `docs/rule-maintenance.md`:

1. edit `preset/audit2archive-preset.yaml`
2. run `plan`
3. apply only to an approved/test Graylog server
4. run `verify`
5. generate positive and negative test events for the changed rule
6. search the archive stream by `pr:<rule_name>`

Keep the preset portable: no credentials, no private hostnames, no hardcoded stream IDs.

## Authentication

Do not put secrets into YAML or Git.

Recommended token mode:

```bash
export GRAYLOG_TOKEN='your-graylog-api-token'
```

The tools send Graylog API tokens using Basic auth as `TOKEN:token`.

### Create a Graylog API token from the CLI

Graylog 7's token endpoint takes the **Graylog user id**, not the login name. Do not use `/api/users/admin/tokens/...` directly: on Graylog 7 this can fail with:

```json
{"type":"ApiError","message":"state should be: hexString has 24 characters"}
```

Resolve the user id first, then create the token:

```bash
GRAYLOG_URL="https://graylog.example.com"
GRAYLOG_USER="admin"
GRAYLOG_PASS='CHANGE_ME'
TOKEN_NAME="audit2archive"

USER_ID=$(curl -sk \
  -u "${GRAYLOG_USER}:${GRAYLOG_PASS}" \
  -H "X-Requested-By: cli" \
  "${GRAYLOG_URL}/api/users?per_page=100" \
  | GRAYLOG_USER="${GRAYLOG_USER}" python3 -c 'import json,os,sys; data=json.load(sys.stdin); users=data.get("users", data if isinstance(data, list) else []); wanted=os.environ["GRAYLOG_USER"]; print(next(u["id"] for u in users if u.get("username") == wanted))')

curl -sk \
  -u "${GRAYLOG_USER}:${GRAYLOG_PASS}" \
  -H "X-Requested-By: cli" \
  -H "Content-Type: application/json" \
  -X POST \
  "${GRAYLOG_URL}/api/users/${USER_ID}/tokens/${TOKEN_NAME}"
```

The response contains the token. Save it immediately; Graylog only shows the token value on creation.

Use it with the tools:

```bash
export GRAYLOG_TOKEN='the-token-value'

./graylog_baseconfig.py verify \
  -c preset/base-config.yaml \
  --api-uri "${GRAYLOG_URL}/api" \
  --no-verify-tls
```

If a fresh Graylog 7 install is still in preflight/setup mode, normal user-token endpoints may return `404`. Finish the initial setup first, then create the token.

### Basic auth fallback

For environments that already store a base64-encoded Basic auth value, use:

```bash
--auth-mode basic_b64 --basic-b64-file /path/to/basic-auth-b64
```

Passing only `--basic-b64-file` also implies `basic_b64` mode.

## Export current live rules

Export the active rules from a Graylog pipeline stage:

```bash
./graylog_audit2archive.py export \
  --api-uri https://graylog.example.com/api \
  --pipeline tier-long-routing \
  --source-stream 'Default Stream' \
  --target-stream long \
  --output preset/audit2archive-preset.yaml
```

The exporter:

1. Reads the named pipeline.
2. Reads the active rules in the selected stage.
3. Reads the full source for each rule.
4. Replaces the target stream ID in `route_to_stream()` with `{{ streams.target.id }}`.
5. Writes a portable YAML preset.

The rule sources are otherwise preserved as tested on the source server.

## Plan an import

```bash
./graylog_audit2archive.py plan \
  --config preset/audit2archive-preset.yaml \
  --api-uri https://graylog.example.com/api
```

The plan shows which rules and pipeline objects would be created or updated.

Example output:

```text
OK     rule linux_ssh
UPDATE rule linux_pkg
CREATE rule win_gpo
UPDATE pipeline tier-long-routing stage -> 17 rules
CONNECT pipeline tier-long-routing to stream Default Stream (...)
```

## Apply an import

```bash
./graylog_audit2archive.py apply \
  --config preset/audit2archive-preset.yaml \
  --api-uri https://graylog.example.com/api
```

The importer is idempotent:

- rules are created or updated by rule title/name
- the pipeline is created or updated by pipeline title/name
- the configured stage is rendered from the preset rule list
- the pipeline is connected to the configured source stream

By default the preset uses exact stage management. The target stage becomes exactly the listed rules. Old broad/catchall rules can remain as inactive Graylog rule objects, but they are removed from the active pipeline stage.

## Verify an import

```bash
./graylog_audit2archive.py verify \
  --config preset/audit2archive-preset.yaml \
  --api-uri https://graylog.example.com/api
```

Verification checks that:

- every configured rule exists
- live rule sources match the rendered preset
- the pipeline exists
- the configured stage contains exactly the configured rule list

It does not generate test events. Functional event testing should be done separately against Linux/Windows test hosts.

## Stream and input overrides

The preset stores names:

```yaml
streams:
  source:
    name: Default Stream
  target:
    name: long
```

Override at runtime when another environment uses different stream names:

```bash
./graylog_audit2archive.py apply \
  -c preset/audit2archive-preset.yaml \
  --api-uri https://graylog.example.com/api \
  --stream source='Default Stream' \
  --stream target='archive-long'
```

Inputs can also be resolved by name if a rule source uses `{{ inputs.<alias>.id }}`:

```yaml
inputs:
  windows_beats:
    name: Beats
```

Runtime override:

```bash
--input windows_beats='Beats'
```

## Preset format

Minimal structure:

```yaml
version: 1

graylog:
  api_uri: https://graylog.example.com/api
  verify_tls: true
  timeout: 30

auth:
  mode: token
  token_env: GRAYLOG_TOKEN

streams:
  source:
    name: Default Stream
  target:
    name: long

pipeline:
  name: tier-long-routing
  stage: 0
  match: EITHER
  stage_policy: exact

routing:
  remove_from_default: true
  pr_field: pr

rules:
  - name: linux_ssh
    description: SSH login/logout and failed login
    source: |
      rule "linux_ssh"
      when
        ...
      then
        set_field("pr", "linux_ssh");
        route_to_stream(id:"{{ streams.target.id }}", remove_from_default: true);
      end
```

## Operational notes

- The pipeline should usually be connected to `Default Stream`, not to the archive stream. Pipelines only process messages that are already in connected streams.
- `route_to_stream()` requires a stream ID. The importer resolves the configured target stream name and renders `{{ streams.target.id }}`.
- Keep `remove_from_default: true` for archive routing if you want selected events moved out of the short/default stream.
- Keep rule names stable. They are the idempotency key.
- Keep the `pr` field; it is the simplest way to verify which rule matched a message.

## License

Apache-2.0. See `LICENSE`.

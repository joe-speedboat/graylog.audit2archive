# AGENTS.md — graylog.audit2archive

This repository contains a reusable Graylog pipeline exporter/importer for audit-to-archive routing.

## Goal

Maintain a portable, idempotent Graylog pipeline preset that routes only selected security/admin events to a long-term archive stream.

The core deliverables are:

- `graylog_baseconfig.py` — CLI tool for export/plan/apply/verify of index sets, streams, and inputs.
- `graylog_audit2archive.py` — CLI tool for export/plan/apply/verify of pipeline rules.
- `preset/base-config.yaml` — portable Graylog base object preset.
- `preset/audit2archive-preset.yaml` — portable rule preset.
- `docs/rule-maintenance.md` — safe workflow for changing rules.
- `README.md` — user-facing setup and usage guide.

## Important invariants

1. **Never commit credentials.** Use `GRAYLOG_TOKEN`, `--token-file`, or `--basic-b64-file`.
2. **Use example.com in public docs.** Do not commit internal hostnames, internal domains, real tokens, passwords, or auth-file paths.
3. **Rule names are API identity.** Rules are updated by title/name, so keep names stable.
4. **Preserve `pr` field tagging.** Every rule should set `pr` to its rule name before routing.
5. **Keep archive routing explicit.** Archive rules should route with `remove_from_default: true` unless a change explicitly documents otherwise.
6. **Run pipelines on the source stream.** Usually this is `Default Stream`, not the archive/target stream.
7. **Host log delivery is external.** Linux and Windows hosts must deliver logs with `https://github.com/joe-speedboat/ansible.log_forwarder` or an equivalent forwarder/parser that emits compatible fields.
8. **Preset stream/input names are portable.** Use `{{ streams.target.id }}` and `{{ inputs.<alias>.id }}` placeholders in rules; the importer resolves names to IDs at apply time.
9. **Exact stage semantics.** The preset describes the desired active stage membership. Unlisted old rules may remain as inactive objects but should not remain in the active stage.

## How this repository is wired

```text
Linux/Windows hosts
  -> joe-speedboat/ansible.log_forwarder
  -> Graylog input / Default Stream
  -> tier-long-routing pipeline deployed from preset/audit2archive-preset.yaml
  -> archive stream, for example long
```

This repository does not install host agents. It only exports/imports the Graylog pipeline and rule layer. The current preset expects the parsed fields produced by `ansible.log_forwarder`:

- Linux examples: `auth_service`, `auth_session_state`, `auth_result`, `sudo_command`, `log_type`, `audit_type`, `package_action`, `package_name`.
- Windows examples: `winlog_event_id`, `winlog_provider_name`, `winlog_event_data_*`.

If a rule is not matching, first verify that the sending host is managed by `ansible.log_forwarder` and that the expected parsed fields exist in Graylog before changing the archive rule.

## Fast setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m py_compile graylog_baseconfig.py graylog_audit2archive.py
```

## Typical validation commands

For public/static validation:

```bash
python3 -m py_compile graylog_baseconfig.py graylog_audit2archive.py
python3 - <<'PY'
import yaml
with open('preset/audit2archive-preset.yaml') as f:
    data = yaml.safe_load(f)
assert data['rules']
assert data['graylog']['api_uri'].endswith('example.com/api')
print('preset ok:', len(data['rules']), 'rules')
PY
```

For live validation, use placeholders for private values in any committed text:

```bash
./graylog_baseconfig.py plan \
  -c preset/base-config.yaml \
  --api-uri https://graylog.example.com/api

./graylog_baseconfig.py verify \
  -c preset/base-config.yaml \
  --api-uri https://graylog.example.com/api

./graylog_audit2archive.py plan \
  -c preset/audit2archive-preset.yaml \
  --api-uri https://graylog.example.com/api

./graylog_audit2archive.py verify \
  -c preset/audit2archive-preset.yaml \
  --api-uri https://graylog.example.com/api
```

If using local credentials during development, keep paths and tokens out of commits and PR text.

## When changing base configuration

1. Edit `preset/base-config.yaml`.
2. Keep object names stable (`long`, `short`, `GELF TCP`, `Windows`) unless coordinating matching changes in Graylog and `ansible.log_forwarder`.
3. Run `graylog_baseconfig.py plan` against a test/approved Graylog server.
4. Apply with `graylog_baseconfig.py apply` only after the plan shows intended changes.
5. Run `graylog_baseconfig.py verify`.
6. Then run the pipeline rule `plan`/`verify`; streams and inputs must exist before rules can work.

## When changing rules

1. Edit `preset/audit2archive-preset.yaml`.
2. Keep rule source readable block-style YAML.
3. Verify `route_to_stream(id:"{{ streams.target.id }}", remove_from_default: true)` remains present for archive rules.
4. Run `plan` against a test Graylog server.
5. Generate real test events where possible.
6. Check long/archive stream by `pr:<rule_name>`.
7. Check negative/noise cases.
8. Update `docs/rule-maintenance.md` or README if the workflow changes.

## Public repo safety scan

Before committing:

```bash
git diff --cached --check
# Replace the placeholders below with private domains, token prefixes, local auth paths,
# and test credentials known in your environment before committing.
git diff --cached --name-only -z | \
  xargs -0 grep -InE 'PRIVATE_DOMAIN|TOKEN_PREFIX|LOCAL_AUTH_PATH|TEST_PASSWORD' && exit 1 || true
```

Adapt the pattern for any known private values in your environment.

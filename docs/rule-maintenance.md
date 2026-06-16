# Rule maintenance guide

This guide describes how to maintain `preset/audit2archive-preset.yaml` without breaking the audit-to-archive contract.

## Mental model

The preset is the desired active Graylog pipeline stage. The importer creates or updates rules by name and renders the pipeline stage from the rule list.

```text
source stream, usually Default Stream
  -> pipeline tier-long-routing
     -> stage 0 match EITHER
        -> rule linux_ssh
        -> rule linux_pkg
        -> rule win_gpo
        -> ...
             route_to_stream(id:"{{ streams.target.id }}", remove_from_default: true)
archive stream, usually long
```

## Files to know

- `preset/audit2archive-preset.yaml` — source of truth for active rules.
- `graylog_audit2archive.py` — exporter/importer.
- `README.md` — user-facing usage.
- `AGENTS.md` — agent quickstart and invariants.

## Rule naming

Rule names are stable identities. Do not rename a rule unless you intentionally want a new Graylog rule object and new `pr` value.

Good names:

```text
linux_ssh
linux_pkg
win_gpo
```

Avoid names that encode a temporary implementation detail or event ID unless that is the long-term category name.

## Rule structure

Every archive rule should follow this pattern:

```graylog
rule "linux_example"
when
  <precise conditions>
then
  set_field("pr", "linux_example");
  route_to_stream(id:"{{ streams.target.id }}", remove_from_default: true);
end
```

Requirements:

- `rule "..."` must match the YAML `name`.
- `set_field("pr", "...")` should match the rule name.
- Use `{{ streams.target.id }}` instead of hardcoding a stream ID.
- Use `remove_from_default: true` for move-to-archive behaviour.

## Stream and input portability

Use stream names in YAML:

```yaml
streams:
  source:
    name: Default Stream
  target:
    name: long
```

Use placeholders in rule source:

```graylog
route_to_stream(id:"{{ streams.target.id }}", remove_from_default: true);
```

If a rule must match a specific Graylog input, define an alias:

```yaml
inputs:
  windows_beats:
    name: Beats
```

Then use:

```graylog
to_string($message.gl2_source_input) == "{{ inputs.windows_beats.id }}"
```

Prefer content/field-based rules over input-specific rules when possible.

## Change workflow

### 1. Inspect current state

```bash
./graylog_audit2archive.py plan \
  -c preset/audit2archive-preset.yaml \
  --api-uri https://graylog.example.com/api
```

If the plan does not show `OK` for the expected baseline, understand the live drift before editing.

### 2. Edit the preset

Edit only the rule that needs a change. Keep YAML block scalars for source readability:

```yaml
source: |-
  rule "linux_pkg"
  when
    ...
  then
    ...
  end
```

### 3. Plan

```bash
./graylog_audit2archive.py plan \
  -c preset/audit2archive-preset.yaml \
  --api-uri https://graylog.example.com/api
```

Expected output should show only the intended rule and/or pipeline changes.

### 4. Apply to a test or approved server

```bash
./graylog_audit2archive.py apply \
  -c preset/audit2archive-preset.yaml \
  --api-uri https://graylog.example.com/api
```

### 5. Verify structure

```bash
./graylog_audit2archive.py verify \
  -c preset/audit2archive-preset.yaml \
  --api-uri https://graylog.example.com/api
```

### 6. Verify behaviour

Generate one positive event and one negative/noise event for the changed category.

Search the archive stream for the rule tag:

```text
pr:<rule_name>
```

Confirm:

- the intended event appears in the archive stream
- the intended event has the correct `pr` value
- a single action produces the expected number of archive messages
- known noise does not appear

## Precision checklist

Before accepting a rule change, answer these questions:

- Is the rule allowlist-style, not catchall-style?
- Does it match a stable parsed field where possible?
- If it uses raw `message` text, is the text exact enough to avoid routine noise?
- Does it avoid matching setup/maintenance noise such as dpkg `configure` internals?
- Does it preserve one useful archive message per action where practical?
- Does it exclude machine/service/built-in accounts for Windows logon-style rules where appropriate?
- Does it leave `pr` attribution clear?

## Common pitfalls

### Pipeline connected to the wrong stream

A content-routing pipeline must run on the stream where messages first arrive, usually `Default Stream`. If connected only to the archive stream, it processes messages after they are already archived and will miss routing.

### Hardcoded stream IDs

Do not commit environment-specific stream IDs inside rule source. Use `{{ streams.target.id }}`.

### Broad package matching

Do not route every `package_action:*`. Some systems emit package-management internals such as `configure`; these can produce noisy archive rows. Keep package rules action-specific and test install/remove/update paths plus negative cases.

### Broad Windows PowerShell matching

Do not route every PowerShell 4104 script-block event. Match high-risk keywords or a well-defined allowlist category.

### Removing rule objects vs removing active rules

The importer enforces active stage membership. It does not need to delete old Graylog rule objects. A rule object that is not referenced by the active pipeline stage does not route messages.

## Exporting a new baseline

If the live server is the source of truth after testing, export a fresh baseline:

```bash
./graylog_audit2archive.py export \
  --api-uri https://graylog.example.com/api \
  --pipeline tier-long-routing \
  --source-stream 'Default Stream' \
  --target-stream long \
  --output preset/audit2archive-preset.yaml
```

Before committing the export:

1. Replace private API URIs with `https://graylog.example.com/api`.
2. Confirm no token/auth path was written.
3. Run semantic validation.
4. Run a public-repo safety scan.

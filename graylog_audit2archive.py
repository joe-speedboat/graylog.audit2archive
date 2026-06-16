#!/usr/bin/env python3
"""Export and deploy Graylog audit-to-archive pipeline rules.

This tool is intentionally small and dependency-light except for PyYAML. It manages
Graylog pipeline rules by title/name, resolves environment-specific stream and input
names to IDs at apply time, and keeps tokens out of exported presets.
"""

from __future__ import annotations

import argparse
import base64
import copy
import difflib
import json
import os
import re
import ssl
import sys
import textwrap
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import yaml
except ImportError as exc:  # pragma: no cover - user-facing dependency check
    raise SystemExit("PyYAML is required. Install with: python3 -m pip install -r requirements.txt") from exc

DEFAULT_SOURCE_STREAM = "Default Stream"
DEFAULT_PIPELINE = "tier-long-routing"
DEFAULT_PR_FIELD = "pr"
PLACEHOLDER_TARGET_STREAM_ID = "{{ streams.target.id }}"
PLACEHOLDER_SOURCE_STREAM_ID = "{{ streams.source.id }}"


class GraylogError(RuntimeError):
    pass


@dataclass
class ApiConfig:
    api_uri: str
    verify_tls: bool = True
    timeout: int = 30
    auth_header: str = ""


class GraylogClient:
    def __init__(self, cfg: ApiConfig):
        self.cfg = cfg
        self.ctx = None if cfg.verify_tls else ssl._create_unverified_context()

    def request(self, method: str, path: str, payload: Any = None) -> Any:
        url = self.cfg.api_uri.rstrip("/") + path
        data = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Requested-By": "graylog-audit2archive",
        }
        if self.cfg.auth_header:
            headers["Authorization"] = self.cfg.auth_header
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=self.cfg.timeout) as res:
                body = res.read().decode("utf-8")
                if not body.strip():
                    return None
                return json.loads(body)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise GraylogError(f"{method} {path} failed: HTTP {exc.code}: {body}") from exc
        except urllib.error.URLError as exc:
            raise GraylogError(f"{method} {path} failed: {exc}") from exc

    def get_rules(self) -> List[Dict[str, Any]]:
        return self.request("GET", "/system/pipelines/rule") or []

    def get_pipelines(self) -> List[Dict[str, Any]]:
        return self.request("GET", "/system/pipelines/pipeline") or []

    def get_connections(self) -> List[Dict[str, Any]]:
        return self.request("GET", "/system/pipelines/connections") or []

    def get_streams(self) -> List[Dict[str, Any]]:
        data = self.request("GET", "/streams?limit=100") or {}
        return data.get("streams", [])

    def get_inputs(self) -> List[Dict[str, Any]]:
        data = self.request("GET", "/system/inputs") or {}
        return data.get("inputs", [])

    def create_rule(self, title: str, description: str, source: str) -> Dict[str, Any]:
        return self.request("POST", "/system/pipelines/rule", {
            "title": title,
            "description": description,
            "source": source,
        })

    def update_rule(self, rule_id: str, title: str, description: str, source: str) -> Dict[str, Any]:
        return self.request("PUT", f"/system/pipelines/rule/{rule_id}", {
            "title": title,
            "description": description,
            "source": source,
        })

    def create_pipeline(self, title: str, description: str, source: str, stages: List[Dict[str, Any]]) -> Dict[str, Any]:
        return self.request("POST", "/system/pipelines/pipeline", {
            "title": title,
            "description": description,
            "source": source,
            "stages": stages,
        })

    def update_pipeline(self, pipeline_id: str, title: str, description: str, source: str, stages: List[Dict[str, Any]]) -> Dict[str, Any]:
        return self.request("PUT", f"/system/pipelines/pipeline/{pipeline_id}", {
            "title": title,
            "description": description,
            "source": source,
            "stages": stages,
        })

    def connect_pipeline_to_stream(self, pipeline_id: str, stream_id: str) -> Any:
        return self.request("POST", "/system/pipelines/connections/to_pipeline", {
            "pipeline_id": pipeline_id,
            "stream_ids": [stream_id],
        })


def load_yaml(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


class LiteralString(str):
    """Marker type for block-style YAML output."""


def _literal_string_representer(dumper: yaml.SafeDumper, data: LiteralString) -> yaml.Node:
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")


yaml.SafeDumper.add_representer(LiteralString, _literal_string_representer)


def _mark_multiline_strings(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _mark_multiline_strings(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_mark_multiline_strings(item) for item in value]
    if isinstance(value, str) and "\n" in value:
        return LiteralString(value)
    return value


def dump_yaml(data: Dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(_mark_multiline_strings(data), fh, sort_keys=False, width=120, allow_unicode=False)


def build_auth_header(config: Dict[str, Any], args: argparse.Namespace) -> str:
    auth = copy.deepcopy(config.get("auth", {}))
    if getattr(args, "auth_mode", None):
        auth["mode"] = args.auth_mode
    if getattr(args, "token_env", None):
        auth["token_env"] = args.token_env
    if getattr(args, "token_file", None):
        auth["token_file"] = args.token_file
    if getattr(args, "basic_b64_file", None):
        auth["basic_b64_file"] = args.basic_b64_file
        if not getattr(args, "auth_mode", None):
            auth["mode"] = "basic_b64"
    if getattr(args, "token_file", None) and not getattr(args, "auth_mode", None):
        auth["mode"] = "token"

    mode = auth.get("mode", "token")
    if mode == "none":
        return ""
    if mode == "basic_b64":
        raw = None
        if auth.get("basic_b64"):
            raw = str(auth["basic_b64"]).strip()
        elif auth.get("basic_b64_file"):
            raw = Path(auth["basic_b64_file"]).read_text(encoding="utf-8").strip()
        if not raw:
            raise GraylogError("auth.mode=basic_b64 requires auth.basic_b64 or auth.basic_b64_file")
        return "Basic " + raw
    if mode == "token":
        token = None
        env_name = auth.get("token_env", "GRAYLOG_TOKEN")
        if env_name:
            token = os.environ.get(env_name)
        if not token and auth.get("token_file"):
            token = Path(auth["token_file"]).read_text(encoding="utf-8").strip()
        if not token:
            raise GraylogError(f"Graylog token missing. Set {env_name} or use --token-file/--basic-b64-file")
        return "Basic " + base64.b64encode(f"{token}:token".encode("utf-8")).decode("ascii")
    raise GraylogError(f"Unsupported auth.mode: {mode}")


def api_config_from(config: Dict[str, Any], args: argparse.Namespace) -> ApiConfig:
    graylog = copy.deepcopy(config.get("graylog", {}))
    if getattr(args, "api_uri", None):
        graylog["api_uri"] = args.api_uri
    if getattr(args, "verify_tls", None) is not None:
        graylog["verify_tls"] = args.verify_tls
    api_uri = graylog.get("api_uri")
    if not api_uri:
        raise GraylogError("Graylog API URI missing. Use --api-uri or graylog.api_uri in config.")
    return ApiConfig(
        api_uri=api_uri,
        verify_tls=bool(graylog.get("verify_tls", True)),
        timeout=int(graylog.get("timeout", 30)),
        auth_header=build_auth_header(config, args),
    )


def by_title(items: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {str(item.get("title") or item.get("name")): item for item in items}


def stream_title(stream: Dict[str, Any]) -> str:
    return str(stream.get("title") or stream.get("name") or "")


def resolve_named(items: Iterable[Dict[str, Any]], name: str, kind: str) -> Dict[str, Any]:
    matches = [item for item in items if str(item.get("title") or item.get("name")) == name]
    if len(matches) != 1:
        names = ", ".join(sorted(str(item.get("title") or item.get("name")) for item in items if item.get("title") or item.get("name")))
        raise GraylogError(f"Expected exactly one {kind} named {name!r}, found {len(matches)}. Available: {names}")
    return matches[0]


def resolve_streams(client: GraylogClient, preset: Dict[str, Any], overrides: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
    streams_cfg = copy.deepcopy(preset.get("streams", {}))
    for key, value in overrides.items():
        streams_cfg.setdefault(key, {})["name"] = value
    streams = client.get_streams()
    resolved: Dict[str, Dict[str, Any]] = {}
    for key, cfg in streams_cfg.items():
        if not isinstance(cfg, dict):
            cfg = {"name": cfg}
        name = cfg.get("name")
        if not name:
            continue
        item = resolve_named(streams, name, "stream")
        resolved[key] = {"name": name, "id": item["id"]}
    return resolved


def resolve_inputs(client: GraylogClient, preset: Dict[str, Any], overrides: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
    inputs_cfg = copy.deepcopy(preset.get("inputs", {}))
    for key, value in overrides.items():
        inputs_cfg.setdefault(key, {})["name"] = value
    inputs = client.get_inputs()
    resolved: Dict[str, Dict[str, Any]] = {}
    for key, cfg in inputs_cfg.items():
        if not isinstance(cfg, dict):
            cfg = {"name": cfg}
        name = cfg.get("name")
        if not name:
            continue
        matches = [item for item in inputs if str(item.get("title") or item.get("name")) == name]
        if len(matches) != 1:
            names = ", ".join(sorted(str(item.get("title") or item.get("name")) for item in inputs))
            raise GraylogError(f"Expected exactly one input named {name!r}, found {len(matches)}. Available: {names}")
        resolved[key] = {"name": name, "id": matches[0]["id"]}
    return resolved


def parse_name_override(values: Optional[List[str]], label: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for value in values or []:
        if "=" not in value:
            raise GraylogError(f"{label} override must be ALIAS=NAME, got {value!r}")
        key, name = value.split("=", 1)
        key = key.strip()
        name = name.strip()
        if not key or not name:
            raise GraylogError(f"{label} override must be ALIAS=NAME, got {value!r}")
        result[key] = name
    return result


def render_template(text: str, variables: Dict[str, str]) -> str:
    rendered = text
    for key, value in variables.items():
        rendered = rendered.replace("{{ " + key + " }}", value)
        rendered = rendered.replace("{{" + key + "}}", value)
    unresolved = re.findall(r"\{\{\s*[^}]+\s*\}\}", rendered)
    if unresolved:
        raise GraylogError(f"Unresolved template variables in rule source: {sorted(set(unresolved))}")
    return rendered


def build_variables(streams: Dict[str, Dict[str, str]], inputs: Dict[str, Dict[str, str]], preset: Dict[str, Any]) -> Dict[str, str]:
    variables: Dict[str, str] = {}
    for key, value in streams.items():
        variables[f"streams.{key}.id"] = value["id"]
        variables[f"streams.{key}.name"] = value["name"]
    for key, value in inputs.items():
        variables[f"inputs.{key}.id"] = value["id"]
        variables[f"inputs.{key}.name"] = value["name"]
    routing = preset.get("routing", {})
    variables["routing.pr_field"] = str(routing.get("pr_field", DEFAULT_PR_FIELD))
    variables["routing.remove_from_default"] = "true" if bool(routing.get("remove_from_default", True)) else "false"
    return variables


def desired_rules(preset: Dict[str, Any], variables: Dict[str, str]) -> List[Dict[str, str]]:
    rules: List[Dict[str, str]] = []
    for rule in preset.get("rules", []):
        name = rule.get("name") or rule.get("title")
        source = rule.get("source")
        if not name or not source:
            raise GraylogError("Each rule needs name and source")
        rules.append({
            "title": str(name),
            "description": str(rule.get("description", "Managed by graylog.audit2archive")),
            "source": render_template(str(source), variables),
        })
    return rules


def build_pipeline_source(name: str, stage: int, match: str, rule_titles: List[str]) -> str:
    lines = [f'pipeline "{name}"', f"stage {stage} match {match}"]
    lines += [f'rule "{title}"' for title in rule_titles]
    lines.append("end")
    return "\n".join(lines)


def desired_pipeline(preset: Dict[str, Any], rules: List[Dict[str, str]]) -> Dict[str, Any]:
    pipe_cfg = preset.get("pipeline", {})
    name = pipe_cfg.get("name", DEFAULT_PIPELINE)
    stage = int(pipe_cfg.get("stage", 0))
    match = str(pipe_cfg.get("match", "EITHER")).upper()
    titles = [rule["title"] for rule in rules]
    return {
        "title": name,
        "description": pipe_cfg.get("description", "Managed by graylog.audit2archive"),
        "source": build_pipeline_source(name, stage, match, titles),
        "stages": [{"stage": stage, "match": match, "rules": titles}],
    }


def normalise_source(text: str) -> str:
    return text.strip().replace("\r\n", "\n")


def diff_summary(old: str, new: str) -> str:
    return "\n".join(difflib.unified_diff(
        old.splitlines(), new.splitlines(), fromfile="current", tofile="desired", lineterm=""
    ))


def plan_changes(client: GraylogClient, preset: Dict[str, Any], args: argparse.Namespace) -> Tuple[List[str], List[Tuple[str, Any]]]:
    stream_overrides = parse_name_override(args.stream or [], "stream")
    input_overrides = parse_name_override(args.input or [], "input")
    streams = resolve_streams(client, preset, stream_overrides)
    inputs = resolve_inputs(client, preset, input_overrides)
    variables = build_variables(streams, inputs, preset)
    rules = desired_rules(preset, variables)
    pipeline = desired_pipeline(preset, rules)

    current_rules = by_title(client.get_rules())
    current_pipes = by_title(client.get_pipelines())
    changes: List[str] = []
    actions: List[Tuple[str, Any]] = []

    for rule in rules:
        current = current_rules.get(rule["title"])
        if not current:
            changes.append(f"CREATE rule {rule['title']}")
            actions.append(("create_rule", rule))
        elif normalise_source(current.get("source", "")) != normalise_source(rule["source"]) or current.get("description", "") != rule["description"]:
            changes.append(f"UPDATE rule {rule['title']}")
            actions.append(("update_rule", (current["id"], rule)))
        else:
            changes.append(f"OK     rule {rule['title']}")

    current_pipe = current_pipes.get(pipeline["title"])
    if not current_pipe:
        changes.append(f"CREATE pipeline {pipeline['title']}")
        actions.append(("create_pipeline", pipeline))
    else:
        cur_stage_rules = []
        for stage in current_pipe.get("stages", []):
            if int(stage.get("stage", -1)) == int(pipeline["stages"][0]["stage"]):
                cur_stage_rules = stage.get("rules", [])
        desired_stage_rules = pipeline["stages"][0]["rules"]
        if normalise_source(current_pipe.get("source", "")) != normalise_source(pipeline["source"]) or cur_stage_rules != desired_stage_rules:
            changes.append(f"UPDATE pipeline {pipeline['title']} stage -> {len(desired_stage_rules)} rules")
            if cur_stage_rules != desired_stage_rules:
                removed = [r for r in cur_stage_rules if r not in desired_stage_rules]
                added = [r for r in desired_stage_rules if r not in cur_stage_rules]
                if added:
                    changes.append("  add to stage: " + ", ".join(added))
                if removed:
                    changes.append("  remove from stage: " + ", ".join(removed))
            actions.append(("update_pipeline", (current_pipe["id"], pipeline)))
        else:
            changes.append(f"OK     pipeline {pipeline['title']}")

    if "source" in streams:
        changes.append(f"CONNECT pipeline {pipeline['title']} to stream {streams['source']['name']} ({streams['source']['id']})")
        actions.append(("connect", {"pipeline_title": pipeline["title"], "stream_id": streams["source"]["id"]}))
    return changes, actions


def cmd_plan(args: argparse.Namespace) -> int:
    preset = load_yaml(Path(args.config))
    client = GraylogClient(api_config_from(preset, args))
    changes, _ = plan_changes(client, preset, args)
    print("\n".join(changes))
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    preset = load_yaml(Path(args.config))
    client = GraylogClient(api_config_from(preset, args))
    changes, actions = plan_changes(client, preset, args)
    print("Plan:")
    print("\n".join(changes))
    if args.dry_run:
        print("\nDry-run only; no changes applied.")
        return 0
    pipeline_id_by_title = {p["title"]: p["id"] for p in client.get_pipelines()}
    for action, payload in actions:
        if action == "create_rule":
            client.create_rule(payload["title"], payload["description"], payload["source"])
            print(f"created rule {payload['title']}")
        elif action == "update_rule":
            rule_id, rule = payload
            client.update_rule(rule_id, rule["title"], rule["description"], rule["source"])
            print(f"updated rule {rule['title']}")
        elif action == "create_pipeline":
            res = client.create_pipeline(payload["title"], payload["description"], payload["source"], payload["stages"])
            pipeline_id_by_title[payload["title"]] = res.get("id", pipeline_id_by_title.get(payload["title"], ""))
            print(f"created pipeline {payload['title']}")
        elif action == "update_pipeline":
            pipeline_id, pipe = payload
            client.update_pipeline(pipeline_id, pipe["title"], pipe["description"], pipe["source"], pipe["stages"])
            pipeline_id_by_title[pipe["title"]] = pipeline_id
            print(f"updated pipeline {pipe['title']}")
    # Connect after pipeline create/update, when ID is known.
    for action, payload in actions:
        if action == "connect":
            pipeline_id = pipeline_id_by_title.get(payload["pipeline_title"])
            if not pipeline_id:
                pipeline_id = by_title(client.get_pipelines())[payload["pipeline_title"]]["id"]
            client.connect_pipeline_to_stream(pipeline_id, payload["stream_id"])
            print(f"connected pipeline {payload['pipeline_title']} to stream {payload['stream_id']}")
    return cmd_verify(args)


def cmd_verify(args: argparse.Namespace) -> int:
    preset = load_yaml(Path(args.config))
    client = GraylogClient(api_config_from(preset, args))
    stream_overrides = parse_name_override(args.stream or [], "stream")
    input_overrides = parse_name_override(args.input or [], "input")
    streams = resolve_streams(client, preset, stream_overrides)
    inputs = resolve_inputs(client, preset, input_overrides)
    variables = build_variables(streams, inputs, preset)
    rules = desired_rules(preset, variables)
    pipeline = desired_pipeline(preset, rules)
    current_rules = by_title(client.get_rules())
    current_pipes = by_title(client.get_pipelines())
    errors: List[str] = []
    for rule in rules:
        cur = current_rules.get(rule["title"])
        if not cur:
            errors.append(f"missing rule {rule['title']}")
        elif normalise_source(cur.get("source", "")) != normalise_source(rule["source"]):
            errors.append(f"rule source differs: {rule['title']}")
    cur_pipe = current_pipes.get(pipeline["title"])
    if not cur_pipe:
        errors.append(f"missing pipeline {pipeline['title']}")
    else:
        desired_stage = pipeline["stages"][0]
        cur_stage = None
        for stage in cur_pipe.get("stages", []):
            if int(stage.get("stage", -1)) == int(desired_stage["stage"]):
                cur_stage = stage
        if not cur_stage:
            errors.append(f"missing stage {desired_stage['stage']} in pipeline {pipeline['title']}")
        elif cur_stage.get("rules", []) != desired_stage["rules"]:
            errors.append("pipeline stage rules differ")
    if errors:
        print("VERIFY FAILED")
        for err in errors:
            print("-", err)
        return 1
    print(f"VERIFY OK: {pipeline['title']} with {len(rules)} rules")
    return 0


def sanitise_rule_source(source: str, streams_by_id: Dict[str, Dict[str, str]], target_stream_id: str) -> str:
    out = source
    if target_stream_id:
        out = out.replace(f'id:"{target_stream_id}"', f'id:"{PLACEHOLDER_TARGET_STREAM_ID}"')
        out = out.replace(f'id: "{target_stream_id}"', f'id:"{PLACEHOLDER_TARGET_STREAM_ID}"')
    return out


def cmd_export(args: argparse.Namespace) -> int:
    minimal = {
        "graylog": {"api_uri": args.api_uri, "verify_tls": args.verify_tls},
        "auth": {"mode": args.auth_mode or "token"},
    }
    if args.basic_b64_file:
        minimal["auth"] = {"mode": "basic_b64", "basic_b64_file": args.basic_b64_file}
    if args.token_env:
        minimal["auth"] = {"mode": "token", "token_env": args.token_env}
    if args.token_file:
        minimal["auth"] = {"mode": "token", "token_file": args.token_file}
    client = GraylogClient(api_config_from(minimal, args))
    pipeline_name = args.pipeline
    streams = client.get_streams()
    streams_by_name = {stream_title(s): s for s in streams}
    streams_by_id = {s["id"]: {"name": stream_title(s), "id": s["id"]} for s in streams}
    target_stream = resolve_named(streams, args.target_stream, "target stream")
    source_stream = resolve_named(streams, args.source_stream, "source stream")
    pipeline = resolve_named(client.get_pipelines(), pipeline_name, "pipeline")
    active_rule_titles: List[str] = []
    for stage in pipeline.get("stages", []):
        if int(stage.get("stage", -1)) == args.stage:
            active_rule_titles.extend(stage.get("rules", []))
    if not active_rule_titles:
        raise GraylogError(f"No rules found in pipeline {pipeline_name!r} stage {args.stage}")
    live_rules = by_title(client.get_rules())
    exported_rules = []
    for title in active_rule_titles:
        rule = live_rules.get(title)
        if not rule:
            raise GraylogError(f"Pipeline references missing rule {title!r}")
        exported_rules.append({
            "name": title,
            "description": rule.get("description", ""),
            "source": sanitise_rule_source(rule.get("source", ""), streams_by_id, target_stream["id"]),
        })
    preset = {
        "version": 1,
        "graylog": {
            "api_uri": args.api_uri,
            "verify_tls": args.verify_tls,
            "timeout": 30,
        },
        "auth": {
            "mode": "token",
            "token_env": "GRAYLOG_TOKEN",
        },
        "streams": {
            "source": {"name": stream_title(source_stream)},
            "target": {"name": stream_title(target_stream)},
        },
        "pipeline": {
            "name": pipeline_name,
            "description": pipeline.get("description") or "Audit-to-archive allowlist routing",
            "stage": args.stage,
            "match": "EITHER",
            "stage_policy": "exact",
        },
        "routing": {
            "remove_from_default": True,
            "pr_field": DEFAULT_PR_FIELD,
        },
        "inputs": {},
        "rules": exported_rules,
    }
    dump_yaml(preset, Path(args.output))
    print(f"Exported {len(exported_rules)} rules from {pipeline_name!r} to {args.output}")
    return 0


def add_common_auth_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--api-uri", help="Graylog API URI, for example https://graylog.example.com/api")
    parser.add_argument("--verify-tls", dest="verify_tls", action="store_true", default=None, help="verify TLS certificates")
    parser.add_argument("--no-verify-tls", dest="verify_tls", action="store_false", help="disable TLS verification")
    parser.add_argument("--auth-mode", choices=["token", "basic_b64", "none"], help="authentication mode")
    parser.add_argument("--token-env", help="environment variable containing a Graylog API token")
    parser.add_argument("--token-file", help="file containing a Graylog API token")
    parser.add_argument("--basic-b64-file", help="file containing pre-encoded Basic auth value")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Export/import Graylog audit-to-archive pipeline rules")
    sub = parser.add_subparsers(dest="command", required=True)

    export = sub.add_parser("export", help="export active rules from a live Graylog pipeline")
    add_common_auth_args(export)
    export.add_argument("--pipeline", default=DEFAULT_PIPELINE)
    export.add_argument("--stage", type=int, default=0)
    export.add_argument("--source-stream", default=DEFAULT_SOURCE_STREAM)
    export.add_argument("--target-stream", default="long")
    export.add_argument("--output", required=True)
    export.set_defaults(func=cmd_export)

    for name, help_text, func in [
        ("plan", "show create/update actions without applying", cmd_plan),
        ("apply", "apply a preset idempotently", cmd_apply),
        ("verify", "verify live Graylog matches a preset", cmd_verify),
    ]:
        p = sub.add_parser(name, help=help_text)
        add_common_auth_args(p)
        p.add_argument("--config", "-c", required=True)
        p.add_argument("--stream", action="append", help="override stream alias: ALIAS=STREAM_NAME, e.g. target=long")
        p.add_argument("--input", action="append", help="override input alias: ALIAS=INPUT_TITLE")
        if name == "apply":
            p.add_argument("--dry-run", action="store_true")
        func_attr = func
        p.set_defaults(func=func_attr)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except GraylogError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Export and deploy Graylog base configuration for audit-to-archive.

This tool manages the Graylog objects that must exist before pipeline rules are
useful: index sets, streams, and inputs. It complements graylog_audit2archive.py,
which manages the pipeline/rule layer.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    from graylog_audit2archive import (
        GraylogClient,
        GraylogError,
        api_config_from,
        dump_yaml,
        load_yaml,
    )
except ImportError as exc:  # pragma: no cover
    raise SystemExit("graylog_baseconfig.py must be run from the repository root") from exc

MANAGED_INDEX_SET_FIELDS = [
    "title",
    "description",
    "index_prefix",
    "shards",
    "replicas",
    "index_optimization_max_num_segments",
    "index_optimization_disabled",
    "field_type_refresh_interval",
    "rotation_strategy_class",
    "rotation_strategy",
    "retention_strategy_class",
    "retention_strategy",
    "data_tiering",
    "index_analyzer",
    "use_legacy_rotation",
]

MANAGED_STREAM_FIELDS = [
    "title",
    "description",
    "matching_type",
    "remove_matches_from_default_stream",
    "disabled",
    "rules",
]

MANAGED_INPUT_FIELDS = ["title", "type", "global", "configuration"]
SENSITIVE_INPUT_KEYS = {"tls_key_password", "password", "secret", "token", "key_password"}


def _title(item: Dict[str, Any]) -> str:
    return str(item.get("title") or item.get("name") or "")


def _by_title(items: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {_title(item): item for item in items}


def _normalise(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _normalise(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [_normalise(v) for v in value]
    return value


def _without_none(data: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in data.items() if v is not None}


def _strip_runtime_index_set(item: Dict[str, Any]) -> Dict[str, Any]:
    return _without_none({k: copy.deepcopy(item.get(k)) for k in MANAGED_INDEX_SET_FIELDS})


def _strip_runtime_stream(item: Dict[str, Any], index_sets_by_id: Dict[str, str]) -> Dict[str, Any]:
    result = _without_none({k: copy.deepcopy(item.get(k)) for k in MANAGED_STREAM_FIELDS})
    index_set_id = item.get("index_set_id")
    if index_set_id:
        result["index_set"] = index_sets_by_id.get(index_set_id, index_set_id)
    return result


def _sanitize_input_config(config: Dict[str, Any]) -> Dict[str, Any]:
    sanitized: Dict[str, Any] = {}
    for key, value in config.items():
        lowered = key.lower()
        if key in SENSITIVE_INPUT_KEYS or any(part in lowered for part in ["password", "secret", "token"]):
            if isinstance(value, dict):
                sanitized[key] = {subkey: "" for subkey in value}
            else:
                sanitized[key] = ""
        else:
            sanitized[key] = copy.deepcopy(value)
    return sanitized


def _strip_runtime_input(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "title": item.get("title"),
        "type": item.get("type"),
        "global": bool(item.get("global", True)),
        "configuration": _sanitize_input_config(copy.deepcopy(item.get("attributes") or item.get("configuration") or {})),
    }


def get_index_sets(client: GraylogClient) -> List[Dict[str, Any]]:
    return (client.request("GET", "/system/indices/index_sets") or {}).get("index_sets", [])


def get_index_set(client: GraylogClient, index_set_id: str) -> Dict[str, Any]:
    return client.request("GET", f"/system/indices/index_sets/{index_set_id}") or {}


def get_streams(client: GraylogClient) -> List[Dict[str, Any]]:
    return client.get_streams()


def get_stream(client: GraylogClient, stream_id: str) -> Dict[str, Any]:
    return client.request("GET", f"/streams/{stream_id}") or {}


def get_inputs(client: GraylogClient) -> List[Dict[str, Any]]:
    return client.get_inputs()


def create_index_set(client: GraylogClient, payload: Dict[str, Any]) -> Dict[str, Any]:
    return client.request("POST", "/system/indices/index_sets", payload) or {}


def update_index_set(client: GraylogClient, index_set_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    return client.request("PUT", f"/system/indices/index_sets/{index_set_id}", payload) or {}


def create_stream(client: GraylogClient, payload: Dict[str, Any]) -> Dict[str, Any]:
    return client.request("POST", "/streams", payload) or {}


def update_stream(client: GraylogClient, stream_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    return client.request("PUT", f"/streams/{stream_id}", payload) or {}


def set_stream_enabled(client: GraylogClient, stream_id: str, enabled: bool) -> None:
    client.request("POST", f"/streams/{stream_id}/{'resume' if enabled else 'pause'}")


def create_input(client: GraylogClient, payload: Dict[str, Any]) -> Dict[str, Any]:
    return client.request("POST", "/system/inputs", payload) or {}


def update_input(client: GraylogClient, input_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    return client.request("PUT", f"/system/inputs/{input_id}", payload) or {}


def selected_names(arg_values: Optional[List[str]], default: List[str]) -> List[str]:
    if not arg_values:
        return default
    result: List[str] = []
    for value in arg_values:
        result.extend([part.strip() for part in value.split(",") if part.strip()])
    return result


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
    index_names = selected_names(args.index_set, ["default", "short", "long"])
    stream_names = selected_names(args.stream, ["Default Stream", "short", "long"])
    input_names = selected_names(args.input, [])

    index_sets_summary = get_index_sets(client)
    index_sets_by_title = _by_title(index_sets_summary)
    index_sets_by_id: Dict[str, str] = {}
    exported_index_sets = []
    for name in index_names:
        item = index_sets_by_title.get(name)
        if not item:
            raise GraylogError(f"index set not found: {name}")
        full = get_index_set(client, item["id"])
        index_sets_by_id[item["id"]] = name
        exported_index_sets.append(_strip_runtime_index_set(full))

    # Need all index-set IDs for stream references, not only exported ones.
    for item in index_sets_summary:
        index_sets_by_id[item["id"]] = _title(item)

    streams_by_title = _by_title(get_streams(client))
    exported_streams = []
    for name in stream_names:
        item = streams_by_title.get(name)
        if not item:
            raise GraylogError(f"stream not found: {name}")
        full = get_stream(client, item["id"])
        stream_cfg = _strip_runtime_stream(full, index_sets_by_id)
        if full.get("is_default"):
            stream_cfg["builtin"] = True
        exported_streams.append(stream_cfg)

    inputs = get_inputs(client)
    inputs_by_title = _by_title(inputs)
    if not input_names:
        input_names = [_title(item) for item in inputs]
    exported_inputs = []
    for name in input_names:
        item = inputs_by_title.get(name)
        if not item:
            raise GraylogError(f"input not found: {name}")
        exported_inputs.append(_strip_runtime_input(item))

    preset = {
        "version": 1,
        "metadata": {
            "description": "Graylog base configuration for audit-to-archive.",
            "log_delivery_dependency": "https://github.com/joe-speedboat/ansible.log_forwarder",
            "note": "Create index sets, streams, and inputs before deploying pipeline rules.",
        },
        "graylog": {"api_uri": args.api_uri, "verify_tls": args.verify_tls, "timeout": 30},
        "auth": {"mode": "token", "token_env": "GRAYLOG_TOKEN"},
        "index_sets": exported_index_sets,
        "streams": exported_streams,
        "inputs": exported_inputs,
    }
    dump_yaml(preset, Path(args.output))
    print(f"Exported {len(exported_index_sets)} index sets, {len(exported_streams)} streams, {len(exported_inputs)} inputs to {args.output}")
    return 0


def desired_objects(config: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    return config.get("index_sets", []), config.get("streams", []), config.get("inputs", [])


def _index_set_payload(cfg: Dict[str, Any]) -> Dict[str, Any]:
    return _strip_runtime_index_set(cfg)


def _stream_payload(cfg: Dict[str, Any], index_sets_by_title: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    payload = _without_none({k: copy.deepcopy(cfg.get(k)) for k in MANAGED_STREAM_FIELDS if k != "disabled"})
    index_set_name = cfg.get("index_set")
    if index_set_name:
        item = index_sets_by_title.get(index_set_name)
        if not item:
            raise GraylogError(f"stream {cfg.get('title')} references missing index set {index_set_name!r}")
        payload["index_set_id"] = item["id"]
    return payload


def _input_payload(cfg: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "title": cfg["title"],
        "type": cfg["type"],
        "global": bool(cfg.get("global", True)),
        "configuration": copy.deepcopy(cfg.get("configuration", {})),
    }


def compute_plan(client: GraylogClient, config: Dict[str, Any]) -> Tuple[List[str], List[Tuple[str, Any]]]:
    desired_index_sets, desired_streams, desired_inputs = desired_objects(config)
    live_index_summary = get_index_sets(client)
    live_index_by_title = _by_title(live_index_summary)
    live_stream_by_title = _by_title(get_streams(client))
    live_input_by_title = _by_title(get_inputs(client))

    messages: List[str] = []
    actions: List[Tuple[str, Any]] = []

    # Index sets first.
    for cfg in desired_index_sets:
        title = cfg["title"]
        desired_payload = _index_set_payload(cfg)
        live_summary = live_index_by_title.get(title)
        if not live_summary:
            messages.append(f"CREATE index_set {title}")
            actions.append(("create_index_set", desired_payload))
            continue
        live_full = get_index_set(client, live_summary["id"])
        live_payload = _index_set_payload(live_full)
        if _normalise(live_payload) != _normalise(desired_payload):
            messages.append(f"UPDATE index_set {title}")
            actions.append(("update_index_set", (live_summary["id"], desired_payload)))
        else:
            messages.append(f"OK     index_set {title}")

    # Refresh after potential index-set creates during apply; for plan this is current.
    index_by_title_for_streams = live_index_by_title

    for cfg in desired_streams:
        title = cfg["title"]
        if cfg.get("builtin"):
            messages.append(f"SKIP   builtin stream {title}")
            continue
        desired_payload = _stream_payload(cfg, index_by_title_for_streams)
        live = live_stream_by_title.get(title)
        if not live:
            messages.append(f"CREATE stream {title}")
            actions.append(("create_stream", (cfg, desired_payload)))
            continue
        live_full = get_stream(client, live["id"])
        live_payload = _stream_payload(_strip_runtime_stream(live_full, {idx["id"]: _title(idx) for idx in live_index_summary}), index_by_title_for_streams)
        desired_enabled = not bool(cfg.get("disabled", False))
        live_enabled = not bool(live_full.get("disabled", False))
        if _normalise(live_payload) != _normalise(desired_payload) or desired_enabled != live_enabled:
            messages.append(f"UPDATE stream {title}")
            actions.append(("update_stream", (live["id"], cfg, desired_payload)))
        else:
            messages.append(f"OK     stream {title}")

    for cfg in desired_inputs:
        title = cfg["title"]
        desired_payload = _input_payload(cfg)
        live = live_input_by_title.get(title)
        if not live:
            messages.append(f"CREATE input {title}")
            actions.append(("create_input", desired_payload))
            continue
        live_payload = _strip_runtime_input(live)
        if _normalise(live_payload) != _normalise(desired_payload):
            messages.append(f"UPDATE input {title}")
            actions.append(("update_input", (live["id"], desired_payload)))
        else:
            messages.append(f"OK     input {title}")

    return messages, actions


def cmd_plan(args: argparse.Namespace) -> int:
    config = load_yaml(Path(args.config))
    client = GraylogClient(api_config_from(config, args))
    messages, _ = compute_plan(client, config)
    print("\n".join(messages))
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    config = load_yaml(Path(args.config))
    client = GraylogClient(api_config_from(config, args))
    messages, actions = compute_plan(client, config)
    print("Plan:")
    print("\n".join(messages))
    if args.dry_run:
        print("\nDry-run only; no changes applied.")
        return 0

    for action, payload in actions:
        if action == "create_index_set":
            res = create_index_set(client, payload)
            print(f"created index_set {payload['title']} {res.get('id', '')}")
        elif action == "update_index_set":
            item_id, desired = payload
            update_index_set(client, item_id, desired)
            print(f"updated index_set {desired['title']}")

    # Recompute after index-set changes so stream index_set_id references resolve.
    messages, actions = compute_plan(client, config)
    for action, payload in actions:
        if action == "create_stream":
            cfg, desired = payload
            res = create_stream(client, desired)
            stream_id = res.get("stream_id") or res.get("id")
            print(f"created stream {cfg['title']} {stream_id or ''}")
            if stream_id:
                set_stream_enabled(client, stream_id, not bool(cfg.get("disabled", False)))
        elif action == "update_stream":
            stream_id, cfg, desired = payload
            update_stream(client, stream_id, desired)
            set_stream_enabled(client, stream_id, not bool(cfg.get("disabled", False)))
            print(f"updated stream {cfg['title']}")
        elif action == "create_input":
            res = create_input(client, payload)
            print(f"created input {payload['title']} {res.get('id', '')}")
        elif action == "update_input":
            input_id, desired = payload
            update_input(client, input_id, desired)
            print(f"updated input {desired['title']}")
    return cmd_verify(args)


def cmd_verify(args: argparse.Namespace) -> int:
    config = load_yaml(Path(args.config))
    client = GraylogClient(api_config_from(config, args))
    messages, actions = compute_plan(client, config)
    failures = [message for message in messages if not (message.startswith("OK") or message.startswith("SKIP"))]
    if failures or actions:
        print("VERIFY FAILED")
        print("\n".join(messages))
        return 1
    print(f"VERIFY OK: {sum(1 for m in messages if m.startswith('OK'))} managed objects match; {sum(1 for m in messages if m.startswith('SKIP'))} builtin objects skipped")
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
    parser = argparse.ArgumentParser(description="Export/import Graylog base config: index sets, streams, inputs")
    sub = parser.add_subparsers(dest="command", required=True)

    export = sub.add_parser("export", help="export base config from live Graylog")
    add_common_auth_args(export)
    export.add_argument("--output", required=True)
    export.add_argument("--index-set", action="append", help="index set title to export; repeat or comma-separate")
    export.add_argument("--stream", action="append", help="stream title to export; repeat or comma-separate")
    export.add_argument("--input", action="append", help="input title to export; repeat or comma-separate; default all inputs")
    export.set_defaults(func=cmd_export)

    for name, help_text, func in [
        ("plan", "show base config changes without applying", cmd_plan),
        ("apply", "apply base config idempotently", cmd_apply),
        ("verify", "verify live base config matches preset", cmd_verify),
    ]:
        p = sub.add_parser(name, help=help_text)
        add_common_auth_args(p)
        p.add_argument("--config", "-c", required=True)
        if name == "apply":
            p.add_argument("--dry-run", action="store_true")
        p.set_defaults(func=func)
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

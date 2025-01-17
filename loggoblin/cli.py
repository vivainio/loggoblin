import argparse
import datetime
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
import traceback

import boto3

SUB_FILE = Path("gob_subs.txt")
GROUPS_FILE = Path("gob_groups.txt")
SYNC_PATH = Path("gobs")


def client():
    return boto3.client("logs")


def configure_files(profile: str):
    global SUB_FILE, GROUPS_FILE, SYNC_PATH
    SUB_FILE = Path(f"{profile}_gob_subs.txt")
    GROUPS_FILE = Path(f"{profile}_gob_groups.txt")
    SYNC_PATH = Path(f"{profile}_gobs")


@dataclass
class Msg:
    message: str
    timestamp: int
    parsed: dict | None = None


def list_groups():
    client = boto3.client("logs")
    paginator = client.get_paginator("describe_log_groups")
    res = []
    for page in paginator.paginate():
        for group in page["logGroups"]:
            res.append(group["logGroupName"])
    return res


def subscribe():
    groups = open(GROUPS_FILE).read().splitlines()
    selected = (
        subprocess.check_output(["fzf", "--multi"], input="\n".join(groups), text=True)
        .strip()
        .splitlines()
    )

    if SUB_FILE.exists():
        subs = set(SUB_FILE.read_text().splitlines())
    else:
        subs = set()

    subs.update(selected)
    SUB_FILE.write_text("\n".join(sorted(subs)))


def select_from_sub() -> list[str]:
    subs = SUB_FILE.read_text().splitlines()
    selected = (
        subprocess.check_output(["fzf", "--multi"], input="\n".join(subs), text=True)
        .strip()
        .splitlines()
    )
    return selected


def zoom_in(event: Msg, zoom_parts: list[str]):
    if not event.parsed:
        return event.message

    loaded = event.parsed
    to_render = []
    for part in zoom_parts:
        popped = loaded.pop(part, None)
        if isinstance(popped, str):
            to_render.append(popped)
        elif popped is None:
            ...
        else:
            to_render.append(json.dumps(popped))

    return "\t".join(to_render) + "\t" + json.dumps(loaded)


def trim_event(s: str) -> str:
    head, tail = s.strip().split(None, 1)
    if re.match(r"\d{4}-\d{2}-\d{2}T", head):
        return tail
    s = s.strip()
    # starts with guid?
    if re.match(r"\w{8}-\w{4}-\w{4}-\w{4}-\w{12}", s):
        return s[37:]
    return s


def render_event(event: Msg, zoom_parts):
    if zoom_parts:
        text = zoom_in(event, zoom_parts)
    else:
        text = trim_event(event.message)
    tstamp = event.timestamp
    time_text = datetime.datetime.fromtimestamp(tstamp / 1000).strftime("%H:%M:%S")
    return f"{time_text} {trim_event(text)}"


def sync_logs(args: argparse.Namespace):
    log_groups = select_from_sub()
    for log_group in log_groups:
        try:
            sync_logs_for_group(log_group, args)
        except Exception as e:
            trace = traceback.format_exc()
            print(f"Failed to sync {log_group}: {e} {trace}")


def safe_parse_json(text: str) -> dict:
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        # print(f"Failed to parse json {e}: {text}")
        return {}


def analyze_events(events) -> tuple[list[Msg], list[str], dict]:
    messages = [Msg(ev["message"], ev["timestamp"]) for ev in events]
    json_messages = [msg for msg in messages if msg.message.startswith("{")]
    if not json_messages:
        return messages, [], {}
    longest_json = max(json_messages, key=lambda x: len(x.message)).message

    parsed_longest = safe_parse_json(longest_json)
    if not parsed_longest:
        return messages, [], {}
    tries = ["level", "logLevel", "log_level", "message", "scope", "text", "exception"]
    guessed_zoom = [try_key for try_key in tries if try_key in parsed_longest]
    for msg in json_messages:
        try:
            msg.parsed = json.loads(msg.message)
        except json.JSONDecodeError:
            msg.parsed = {}
    shared_values = {}
    for ev in json_messages:
        if not ev.parsed:
            continue

        for k, v in ev.parsed.items():
            if k not in shared_values:
                shared_values[k] = v
            elif shared_values[k] != v:
                shared_values[k] = None
    return (
        json_messages,
        guessed_zoom,
        {k: shared_values[k] for k in shared_values if shared_values[k] is not None},
    )


def remove_shared_values(events: list[Msg], shared_values):
    for ev in events:
        if not ev.parsed:
            continue
        for k in shared_values:
            if k in ev.parsed:
                ev.parsed.pop(k)


def sync_logs_for_group(log_group: str, args: argparse.Namespace) -> None:
    cl = client()
    streams = cl.describe_log_streams(
        logGroupName=log_group, orderBy="LastEventTime", descending=True
    )
    index = 0
    for stream in streams["logStreams"]:
        index += 1
        timestamp = stream["creationTime"]
        date_as_string = datetime.datetime.fromtimestamp(timestamp / 1000).strftime(
            "%Y-%m-%dT%H"
        )
        log_group_safe = (
            log_group.replace("/", "_").replace("\\", "_").replace("_aws_lambda_", "")
        )
        log_path = SYNC_PATH / f"{log_group_safe}/{index}__{date_as_string}.log"
        src_events = cl.get_log_events(
            logGroupName=log_group, logStreamName=stream["logStreamName"]
        )["events"]
        if not src_events:
            break
        print(f"Syncing {log_path}, {len(src_events)} events")

        events, guess_zoom, shared_values = analyze_events(src_events)
        remove_shared_values(events, set(shared_values.keys()))
        zoom_parts = args.zoom.split(",") if args.zoom else guess_zoom
        all_events = [render_event(ev, zoom_parts) for ev in events]
        log_path.parent.mkdir(exist_ok=True, parents=True)
        preamble = (
            "<SHARED> " + json.dumps(shared_values, indent=2) + "\n"
            if shared_values
            else ""
        )
        log_path.write_text(preamble + "\n".join(all_events))


def main():
    parser = argparse.ArgumentParser(description="CloudWatch Logs helper")
    parser.add_argument(
        "--zoom", help="Zoom in on json key, e.g. --zoom level,tenant,message"
    )
    parser.add_argument("--verbose", help="Verbose output", action="store_true")
    parser.add_argument("-p", "--profile", help="AWS profile to use")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("ls", help="List all log groups")
    sub.add_parser("sub", help="Subscribe a log group")
    sub.add_parser("sync", help="Sync logs to disk")

    args = parser.parse_args()
    if args.profile:
        boto3.setup_default_session(profile_name=args.profile)
        configure_files(args.profile)
    if args.command == "ls":
        groups = list_groups()
        GROUPS_FILE.write_text("\n".join(groups))
        print(f"Written to {GROUPS_FILE}")
    elif args.command == "sub":
        subscribe()
    elif args.command == "sync":
        sync_logs(args)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Send between the two example nodes and verify the version reply."""

import argparse
import json
import os
import subprocess
import time
import uuid
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument(
        "--leaf", action="store_true", help="use the leaf sidecar example"
    )
    modes.add_argument(
        "--host", action="store_true", help="use the separate host-node example"
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    engine = os.environ.get("DOCKER", "docker")
    filename = (
        "docker-compose.leaf.yml" if args.leaf else "docker-compose.federation.yml"
    )
    project = os.environ.get("COMPOSE_PROJECT_NAME", "xmsg-demo")
    compose = [engine, "compose", "-p", project, "-f", str(root / filename)]
    if args.host:
        compose = [
            engine,
            "compose",
            "-p",
            project,
            "-f",
            str(root / "docker-compose.yml"),
            "-f",
            str(root / "docker-compose.host.yml"),
        ]
    sender = "node" if args.host else "node-a"

    def run(*argv, check=True):
        return subprocess.run(
            [*compose, *argv],
            cwd=root,
            capture_output=True,
            text=True,
            check=check,
            timeout=25,
        )

    def cli(service, *argv):
        result = run("exec", "-T", service, "/bin/xmsg", *argv, "--json", check=False)
        if result.returncode:
            return None
        return json.loads(result.stdout)

    deadline = time.monotonic() + 60
    while cli(sender, "list") is None:
        if time.monotonic() > deadline:
            raise SystemExit("node-a did not become ready; inspect compose logs")
        time.sleep(0.25)
    target, name = (
        ("host", "status")
        if args.host
        else (("leaf", "demo") if args.leaf else ("b", "status"))
    )
    if not args.leaf and not args.host:
        while cli("node-b", "list") is None:
            if time.monotonic() > deadline:
                raise SystemExit("node-b did not become ready; inspect compose logs")
            time.sleep(0.25)
        local = cli("node-b", "list")
        if not any(row["address"].startswith("status@") for row in local["recipients"]):
            container = subprocess.run(
                [
                    engine,
                    "ps",
                    "--filter",
                    f"label=com.docker.compose.project={project}",
                    "--filter",
                    "label=com.docker.compose.service=node-b",
                    "--format",
                    "{{.ID}}",
                ],
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            ).stdout.strip()
            if not container or "\n" in container:
                raise SystemExit("expected exactly one node-b container")
            subprocess.run(
                [
                    engine,
                    "exec",
                    "-d",
                    container,
                    "/bin/xmsg",
                    "service",
                    "exec",
                    "--name",
                    "status",
                    "--",
                    "/bin/xmsg",
                    "--version",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
                timeout=10,
            )
    while True:
        listing = cli(sender, "list", "--node", target, "--kind", "service")
        if listing and any(
            row["address"].startswith(name + "@") for row in listing["recipients"]
        ):
            break
        if time.monotonic() > deadline:
            raise SystemExit(
                "remote service did not become ready; inspect compose logs"
            )
        time.sleep(0.25)
    print("LIST " + json.dumps(listing, separators=(",", ":")))
    sent = cli(
        sender,
        "send",
        f"{name}@{target}",
        "version?",
        "--from",
        "docker-demo",
        "--idempotency-key",
        str(uuid.uuid4()),
    )
    if sent is None:
        raise SystemExit("send failed; inspect compose logs")
    print("SEND " + json.dumps(sent, separators=(",", ":")))
    deadline = time.monotonic() + 45
    while True:
        replies = cli(sender, "replies", sent["message_id"], "--wait", "10")
        if replies:
            break
        if time.monotonic() > deadline:
            raise SystemExit("reply did not arrive")
    print("REPLIES " + json.dumps(replies, separators=(",", ":")))
    assert any(
        row["messageId"] == sent["message_id"] and row["text"].startswith("xmsg ")
        for row in replies
    ), "unexpected reply"
    print("PASS: cross-node send and correlated version reply")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Create local demo identities and configuration without replacing existing keys."""

import argparse
import base64
import hashlib
import json
import os
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="ghcr.io/sini/xmsg:latest")
    args = parser.parse_args()
    uid, gid = os.getuid(), os.getgid()
    if uid == 0:
        parser.error("run setup as the non-root user that will own the bind mounts")
    os.umask(0o077)
    root = Path(__file__).resolve().parent
    local = root / ".local"
    openssl = os.environ.get("OPENSSL", "openssl")

    def command(*argv, data=None):
        return subprocess.run(
            [openssl, *argv], input=data, capture_output=True, check=True
        ).stdout

    def write_new(file, content):
        if not file.exists():
            file.write_text(content)

    pins = {}
    names = {}
    for name in ("a", "b", "leaf", "host"):
        directory = local / name
        for child in ("identity", "state", "run", "state/sessions", "state/codex"):
            target = directory / child
            target.mkdir(parents=True, exist_ok=True, mode=0o700)
            target.chmod(0o700)
        key, cert = directory / "identity/node.key", directory / "identity/node.crt"
        if key.exists() != cert.exists():
            parser.error(
                f"incomplete identity in {directory}; restore the matching key/certificate"
            )
        if not key.exists():
            config = directory / "identity/openssl.cnf"
            config.write_text(
                f"[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n[dn]\nCN=xmsg-{name}\n[ext]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\n"
            )
            command(
                "req",
                "-new",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-days",
                "30",
                "-config",
                str(config),
                "-keyout",
                str(key),
                "-out",
                str(cert),
            )
            key.chmod(0o600)
        public = command("x509", "-in", str(cert), "-pubkey", "-noout")
        der = command("pkey", "-pubin", "-outform", "DER", data=public)
        key_public = command("pkey", "-in", str(key), "-pubout", "-outform", "DER")
        if der != key_public:
            parser.error(f"key/certificate mismatch in {directory}")
        digest = hashlib.sha256(der).digest()
        pins[name] = "sha256:" + digest.hex()
        names[name] = base64.b32encode(digest).decode().lower()[:16]
        print(f"{name}: {names[name]}")

    def peers(name, filename, entries):
        write_new(
            local / name / filename, json.dumps({"peers": entries}, indent=2) + "\n"
        )

    def peer(name, address):
        return {
            "address": address,
            "pin": pins[name],
            "allow": ["send", "reply", "list"],
        }

    peers("a", "peers.single.json", {})
    peers("a", "peers.federation.json", {"b": peer("b", "node-b:7788")})
    peers("b", "peers.federation.json", {"a": peer("a", "node-a:7788")})
    peers("a", "peers.host.json", {"host": peer("host", "host.docker.internal:17898")})
    peers("host", "peers.json", {"a": peer("a", "127.0.0.1:17788")})
    peers(
        "a",
        "peers.leaf.json",
        {
            "leaf": {
                "pin": pins["leaf"],
                "leaf": True,
                "allow": ["send", "reply", "list"],
                "principals": ["demo"],
            }
        },
    )
    peers(
        "leaf", "peers.json", {"a": {**peer("a", "node-a:7788"), "default_route": True}}
    )
    write_new(local / "nodes.json", json.dumps(names, indent=2) + "\n")
    write_new(
        root / ".env",
        f"XMSG_IMAGE={args.image}\nXMSG_UID={uid}\nXMSG_GID={gid}\nXMSG_HTTP_PORT=17787\nXMSG_FED_PORT=17788\n",
    )
    print(
        "Kept existing identities/configuration; generated files live in .local/ and .env."
    )
    print(
        "These 30-day self-signed certificates are for the examples; keep keys private."
    )


if __name__ == "__main__":
    main()

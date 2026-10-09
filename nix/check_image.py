#!/usr/bin/env python3
"""Oracle check for xmsg OCI image.

Asserts:
1. User is non-root (not 0, not root, not empty, not 0:0).
2. Entrypoint is the xmsg binary (.../bin/xmsg).
3. No /bin/sh in any layer.
"""

import io
import json
import os
import sys
import tarfile


def check_image(image_tar_path: str):
    if not os.path.exists(image_tar_path):
        print(f"Error: image tarball not found at {image_tar_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[oracle] Loading image tarball from: {image_tar_path}")
    with tarfile.open(image_tar_path, "r:*") as outer_tar:
        try:
            manifest_member = outer_tar.getmember("manifest.json")
        except KeyError:
            print("Error: manifest.json not found in image tarball", file=sys.stderr)
            sys.exit(1)

        manifest = json.load(outer_tar.extractfile(manifest_member))
        if not manifest:
            print("Error: manifest.json is empty", file=sys.stderr)
            sys.exit(1)

        image_meta = manifest[0]
        config_filename = image_meta.get("Config")
        if not config_filename:
            print("Error: No Config found in manifest.json", file=sys.stderr)
            sys.exit(1)

        config_member = outer_tar.getmember(config_filename)
        config_data = json.load(outer_tar.extractfile(config_member))
        cfg = config_data.get("config", {})

        # Assertion 1: User is non-root
        user = cfg.get("User", "")
        print(f"[oracle] Checking User configuration: {user!r}")
        root_users = {"0", "root", "0:0", "root:root"}
        if not user or user in root_users or user.startswith("0:"):
            print(
                f"[FAIL] Oracle check: User must be non-root, got: {user!r}",
                file=sys.stderr,
            )
            sys.exit(1)
        print(f"[oracle] -> User is non-root: {user}")

        # Assertion 2: Entrypoint is the xmsg binary
        entrypoint = cfg.get("Entrypoint", [])
        print(f"[oracle] Checking Entrypoint configuration: {entrypoint!r}")
        if (
            not entrypoint
            or not isinstance(entrypoint, list)
            or not entrypoint[0].endswith("/bin/xmsg")
        ):
            print(
                f"[FAIL] Oracle check: Entrypoint must point to xmsg binary, got: {entrypoint!r}",
                file=sys.stderr,
            )
            sys.exit(1)
        print(f"[oracle] -> Entrypoint is xmsg binary: {entrypoint[0]}")

        # Assertion 3: No /bin/sh in any layer
        layers = image_meta.get("Layers", [])
        print(f"[oracle] Checking {len(layers)} image layer(s) for /bin/sh...")
        found_shells = []
        for layer_name in layers:
            layer_member = outer_tar.getmember(layer_name)
            layer_bytes = outer_tar.extractfile(layer_member).read()
            with tarfile.open(fileobj=io.BytesIO(layer_bytes)) as layer_tar:
                for member in layer_tar.getmembers():
                    norm = member.name.lstrip("./")
                    if norm in ("bin/sh", "usr/bin/sh") or norm.endswith("/bin/sh"):
                        found_shells.append((layer_name, member.name))

        if found_shells:
            print(
                f"[FAIL] Oracle check: Shell (/bin/sh) detected in layers: {found_shells!r}",
                file=sys.stderr,
            )
            sys.exit(1)
        print("[oracle] -> No /bin/sh found in any layer.")

    print(
        "[oracle] ALL ORACLES PASSED: Non-root user, xmsg binary entrypoint, no shell."
    )


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path_to_image_tar_gz>", file=sys.stderr)
        sys.exit(1)
    check_image(sys.argv[1])

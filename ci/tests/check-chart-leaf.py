#!/usr/bin/env python3
"""Render the chart's leaf mode and check the leaf-sidecar pod invariants.

usage: check-chart-leaf.py <chart-dir> <values.yaml>
"""
import ipaddress
import posixpath
import subprocess
import sys

import yaml

failures = []


def check(name, ok, detail=""):
    print(f"{'PASS' if ok else 'FAIL'} {name}{': ' + detail if detail and not ok else ''}")
    if not ok:
        failures.append(name)


def arg(args, flag):
    return args[args.index(flag) + 1] if flag in args else None


def under(p, d):
    return p is not None and posixpath.commonpath([p, d]) == d and p != d


def main():
    chart, values = sys.argv[1:3]
    out = subprocess.run(["helm", "template", "t", chart, "-f", values],
                         check=True, capture_output=True, text=True).stdout
    docs = [d for d in yaml.safe_load_all(out) if d]
    deps = [d for d in docs if d["kind"] == "Deployment"]
    if len(deps) != 1:
        sys.exit(f"FAIL expected one Deployment, got {len(deps)}")
    pod = deps[0]["spec"]["template"]["spec"]
    psc = pod.get("securityContext", {})
    containers = pod["containers"]
    inits = pod.get("initContainers", [])
    xmsg = next(c for c in containers if c["name"] == "xmsg")
    args = xmsg.get("args", [])
    uid = psc.get("runAsUser")

    def c_uid(c):
        return c.get("securityContext", {}).get("runAsUser", uid)

    # The DB's parent must be owned by xmsg's UID with mode 0700; an fsGroup emptyDir is not.
    db = arg(args, "--db-path")
    state_dir = posixpath.dirname(db) if db else None
    prep = [c for c in inits
            if c.get("command", [])[:1] == ["mkdir"] and "0700" in c["command"]
            and state_dir in c["command"]]
    check("init container creates the DB dir 0700 as the xmsg UID",
          len(prep) == 1 and c_uid(prep[0]) == c_uid(xmsg) is not None,
          f"db={db} inits={[c.get('command') for c in inits]}")

    # Both leaf endpoints pinned under the shared runtime dir, the DB under the prepared dir.
    env = {e["name"]: e.get("value") for e in xmsg.get("env", [])}
    rt = env.get("XDG_RUNTIME_DIR")
    check("--agent-sock pinned under XDG_RUNTIME_DIR", under(arg(args, "--agent-sock"), rt or "/"),
          f"{arg(args, '--agent-sock')} vs {rt}")
    check("--leaf-register-sock pinned under XDG_RUNTIME_DIR",
          under(arg(args, "--leaf-register-sock"), rt or "/"),
          f"{arg(args, '--leaf-register-sock')} vs {rt}")
    check("--db-path pinned in the prepared dir", db is not None and len(prep) == 1, f"db={db}")

    # Every container sees the same memory emptyDir at XDG_RUNTIME_DIR.
    vols = {v["name"]: v for v in pod.get("volumes", [])}
    shared = []
    for c in containers:
        cenv = {e["name"]: e.get("value") for e in c.get("env", [])}
        mounts = [m["name"] for m in c.get("volumeMounts", [])
                  if m["mountPath"] == cenv.get("XDG_RUNTIME_DIR")]
        shared.append(mounts[0] if len(mounts) == 1 else None)
    rv = vols.get(shared[0] or "", {})
    check("runtime dir shared by every container (memory emptyDir)",
          len(containers) >= 2 and None not in shared and len(set(shared)) == 1
          and rv.get("emptyDir", {}).get("medium") == "Memory",
          f"mounts={shared}")
    check("every container runs as one UID", len({c_uid(c) for c in containers + inits}) == 1,
          str({c["name"]: c_uid(c) for c in containers + inits}))

    for c in inits + containers:
        sc = c.get("securityContext", {})
        check(f"{c['name']}: readOnlyRootFilesystem", sc.get("readOnlyRootFilesystem") is True)
        check(f"{c['name']}: capabilities drop ALL", "ALL" in sc.get("capabilities", {}).get("drop", []))
        check(f"{c['name']}: runAsNonRoot", sc.get("runAsNonRoot", psc.get("runAsNonRoot")) is True)

    sas = [d for d in docs if d["kind"] == "ServiceAccount"]
    check("pod automountServiceAccountToken false", pod.get("automountServiceAccountToken") is False)
    check("ServiceAccount automountServiceAccountToken false",
          all(s.get("automountServiceAccountToken") is False for s in sas))

    # --leaf requires --listen; it must stay on the pod's loopback, with nothing else exposed.
    listen = arg(args, "--listen")
    loop = False
    if listen:
        try:
            loop = ipaddress.ip_address(listen.rsplit(":", 1)[0].strip("[]")).is_loopback
        except ValueError:
            pass
    check("no TCP listener beyond loopback",
          loop and "--fed-listen" not in args
          and not any(c.get("ports") for c in containers)
          and not any(e["name"] in ("XMSG_LISTEN", "XMSG_FED_LISTEN")
                      for c in containers for e in c.get("env", []))
          and not any(d["kind"] == "Service" for d in docs),
          f"listen={listen}")

    if failures:
        sys.exit(f"{len(failures)} leaf-sidecar invariant(s) failed: {failures}")
    print("leaf-sidecar: all invariants hold")


main()

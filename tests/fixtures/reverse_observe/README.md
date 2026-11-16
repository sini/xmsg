# Actual B0 downgrade fixture

This runs production Store and render code from two independently compiled source
revisions. It is a storage/view compatibility harness, not live OIDC, HTTP polling,
or configuration-loader acceptance. The old helper uses the saved B0 inventory:
ordinary `NodePolicy` fields only, with relay fields removed. Keeping unknown relay
configuration fields is not promised to work with the old loader.

```
python3 tests/fixtures/reverse_observe/run_compat.py \
  --source "$PWD" --old-source /path/to/unmodified/pinned/source \
  --output /path/to/new/private/output --artifact-seed /path/to/dev/target
```

The old source is pinned to `8090f65259ecb947d72cd74382881763fd6b5da6`.
`old-source.json` checks every production source file against that revision before
and after copying. CI supplies it using an exact revision and fixed unpacked hash;
no git/network fetch occurs inside the check. Only the added helper and its
manifest bin stanza differ from the old tree. Per-build cfg selection changes the
helper alone. Cargo dependencies/lock/features remain unchanged.

Each build owns its source and target directories. A dev dependency seed is
optional; package-only clean removes all xmsg artifacts before building. Both the
library and helper must report `fresh=false`, the executable must live under its
own target, and the executed helper must print its embedded per-build nonce.
Receipts retain production, helper, library, manifest, lock and binary SHA-256s.
An actual repeated Cargo build must be refused as cached; separate artifact-guard
controls refuse cached library/helper records and foreign targets.
Fresh output-directory creation refuses a second runner sharing the same output;
different output roots have independent sources, targets, nonces and stores. A
concurrent output-claim control proves exactly one shared claim succeeds and both
separate claims succeed.

The candidate writes neighboring direct and relay events and snapshots. Two
separate databases exercise saved outbound-only inventory and a fresh direct-leaf
configuration. This separation ensures the saved-inventory purge cannot hide a
storage-key collision from the old direct-reader assertion. That branch validates
with the same epoch/scope and an empty page before inspecting the view, so the
startup revalidation mask cannot hide wrongly retained relay history. The direct
control must survive both downgrades. A subsequent candidate restart ingests
fresh relay history and checks via-hub event/snapshot provenance and rendering.
Every phase checks the persisted node count against 64 and compares canonical
stored JSON before downgrade and after the fresh upgrade. Relay history loss on
downgrade is intentional.

`--old-build-only` checks construction, source pinning, executable nonce and
artifact controls without claiming candidate or downgrade acceptance. No fixture
changes SQLite capacity or runs a crash-recovery probe.

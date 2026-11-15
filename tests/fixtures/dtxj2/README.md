# Collector stored-kind compatibility fixture

The helper is not a target in the normal manifest.
The preparation script copies source into two independent trees and registers a
test-only helper there. Only the synthetic newer tree gains a future enum variant;
the working source tree stays unchanged.

Build each helper with an independent target directory and the same pinned
toolchain. The runner executes this sequence:

1. Older `write-known`, then older `read-known`: known-row positive control.
2. Newer `write-newer`: three normal production Store writes, with a future kind
   between two known kinds.
3. Older `read-unknown` on that store: opens it, verifies startup masking, obtains
   fresh scope validation through normal ingestion, then reads/renders Unknown
   while preserving known neighbors, cursor and original receipt times.
4. Newer `read-newer` on the same store: confirms the original private kind survived
   the older reader and is recognizable again after an upgrade.

The pre-fix older reader is expected to fail at the explicit stored-kind assertion;
that is a baseline failure, not a mutation kill. Compilation errors and private
directory setup failures are not valid observations. Helpers use fresh private
child directories and synthetic metadata only. They never use a live service,
credential, primary bus database, or recovery/capacity-change scenario.

The full replay gate must additionally feed repeated future events through the
collector wire path, because a typed public `ExportPage` alone cannot retain an
unrecognized original kind identifier. That gate belongs to implementation after
the base arrives; this fixture does not claim to have measured it.

Run the complete fixture with a pinned Rust toolchain and cached dependencies:

```sh
python3 tests/fixtures/dtxj2/run_compat.py --source . --output /absolute/fresh/output
```

The output directory must not exist. Both builds use `--locked --offline` and
separate target directories. Optional `--artifact-seed /absolute/cargo/target`
copies dependency artifacts into each target, then cleans the xmsg package before
building; candidate helper binaries are never reused. Cargo JSON artifact records
must report a newly built helper. Receipts record source and binary SHA256 values,
the synthetic enum variant, and each mode's exit status. Logs stay in the output
directory. The Linux collector browser CI check also runs this fixture and exports
these receipts and logs alongside its browser log.

#!/usr/bin/env python3
"""Drive recovery and grant replacement faults through the command double."""

import argparse
import os
import runpy
import shutil
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUN = runpy.run_path(str(ROOT / "scripts/mission-control-wire-mutants.py"))["run"]
APPLY = runpy.run_path(str(ROOT / "scripts/mission-control-state-mutants.py"))["apply"]
ISSUER = "src/mission_control.rs"
COMMAND = "src/mission_control/command.rs"
AUTHORITY = "src/mission_control/authority.rs"
CRASH = "mission_control::command_crash_tests::sc14_abrupt_restart"
REPLACE = "mission_control::command_transport_tests::sc16_new_grant_cannot_recover_or_redrive_prior_grant"

MINT = """        let expires_at = grant.expires_at;
        let mut state = self.locked()?;
        self.issue_for_owner(
            &mut state,
            owner,
            at,
            NewRecord {
                class: Class::Delegated,
                parent_record: None,
                grants: Grants::Delegated { grant },
                idle: expires_at,
                absolute: expires_at,
            },
        )
"""
MINT_FIND_PREDECESSORS = """        let expires_at = grant.expires_at;
        let mut state = self.locked()?;
        let predecessors: Vec<_> = state.records.values().filter_map(|entry| {
            let record = &entry.record;
            let Grants::Delegated { grant: previous } = &record.grants else {
                return None;
            };
            (record.on_behalf_of.as_deref() == Some(owner) && previous.holder == grant.holder)
                .then(|| record.principal.clone())
        }).collect();
        let replacement = self.issue_for_owner(
            &mut state,
            owner,
            at,
            NewRecord {
                class: Class::Delegated,
                parent_record: None,
                grants: Grants::Delegated { grant },
                idle: expires_at,
                absolute: expires_at,
            },
        )?;
"""
SPAWN = """    #[cfg(test)]
    fn spawn_command_double("""
REDRIVE = """    #[cfg(test)]
    pub(super) fn mutant_redrive_command(self: &Arc<Self>, row: Reservation) {
        let request: PreparedRequest = serde_json::from_str(&row.request_json).unwrap();
        let slot = self.commands.work_slot(&row.record_id, &self.config).unwrap();
        self.spawn_command_double(row, request, slot);
    }

"""


CASES = {
    "m-sc14-redrive-after-restart": (
        CRASH,
        "first restart redrove a command",
        (
            (
                ISSUER,
                """    pub(crate) fn recover_commands(&self) -> Result<(), Error> {
        let mut state = self.authority.locked().map_err(|_| Error::Unavailable)?;
        command_store::recover(&mut state.conn, command::now_ms())
            .map_err(|_| Error::Unavailable)?;
        Ok(())
    }""",
                """    pub(crate) fn recover_commands(self: &Arc<Self>) -> Result<(), Error> {
        #[cfg(test)]
        if self.commands.available() {
            self.mutant_redrive_submitting();
        }
        let mut state = self.authority.locked().map_err(|_| Error::Unavailable)?;
        command_store::recover(&mut state.conn, command::now_ms())
            .map_err(|_| Error::Unavailable)?;
        Ok(())
    }""",
            ),
            (
                COMMAND,
                SPAWN,
                """    #[cfg(test)]
    pub(super) fn mutant_redrive_submitting(self: &Arc<Self>) {
        if self.commands.double.is_none() {
            return;
        }
        let rows = {
            let state = self.authority.locked().unwrap();
            let mut select = state.conn.prepare(
                "SELECT principal, request_id FROM command_reservations WHERE state = 'submitting'",
            ).unwrap();
            let keys = select.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            }).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            keys.into_iter().map(|(principal, id)| {
                store::reservation(&state.conn, &principal, &id).unwrap().unwrap()
            }).collect::<Vec<_>>()
        };
        for row in rows {
            self.mutant_redrive_command(row);
        }
    }

"""
                + REDRIVE
                + SPAWN,
            ),
        ),
    ),
    "m-sc16d-rekey-replacement": (
        REPLACE,
        "left: 200",
        (
            (
                AUTHORITY,
                MINT,
                MINT_FIND_PREDECESSORS
                + """        let tx = state.conn.transaction()?;
        for original in predecessors {
            tx.execute(
                "UPDATE command_intents SET principal = ?1, record_id = ?2
                 WHERE principal = ?3 AND consumed = 1 AND request_id IN (
                     SELECT request_id FROM command_reservations
                     WHERE principal = ?3 AND state IN ('reserved','held','submitting','effect_unknown')
                 )",
                params![replacement.record.principal, replacement.record.record_id, original],
            )?;
            tx.execute(
                "UPDATE command_reservations SET principal = ?1, record_id = ?2
                 WHERE principal = ?3 AND state IN ('reserved','held','submitting','effect_unknown')",
                params![replacement.record.principal, replacement.record.record_id, original],
            )?;
        }
        tx.commit()?;
        Ok(replacement)
""",
            ),
        ),
    ),
    "m-sc16e-redrive-on-replacement": (
        REPLACE,
        "left: 2",
        (
            (
                AUTHORITY,
                """    _lock: File,
}""",
                """    _lock: File,
    #[cfg(test)]
    pub(super) mutant_command_issuer: Mutex<std::sync::Weak<super::Issuer>>,
}""",
            ),
            (
                AUTHORITY,
                """            _lock: lock,
        }))""",
                """            _lock: lock,
            #[cfg(test)]
            mutant_command_issuer: Mutex::new(std::sync::Weak::new()),
        }))""",
            ),
            (
                AUTHORITY,
                MINT,
                MINT_FIND_PREDECESSORS
                + """        #[cfg(test)]
        {
            let observer = self.mutant_command_issuer.lock().unwrap().upgrade();
            if let Some(issuer) = observer {
                let mut rows = Vec::new();
                for original in &predecessors {
                    let mut select = state.conn.prepare(
                        "SELECT request_id FROM command_reservations
                         WHERE principal = ? AND state = 'effect_unknown'",
                    )?;
                    let ids = select.query_map([original], |row| row.get::<_, String>(0))?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    for id in ids {
                        let mut row = super::command_store::reservation(&state.conn, original, &id)?
                            .expect("selected unresolved command");
                        row.principal = replacement.record.principal.clone();
                        row.record_id = replacement.record.record_id.clone();
                        rows.push(row);
                    }
                }
                drop(state);
                for row in rows {
                    issuer.mutant_redrive_command(row);
                }
            }
        }
        #[cfg(not(test))]
        let _ = predecessors;
        Ok(replacement)
""",
            ),
            (
                ISSUER,
                """            .commands = command::Commands::with_double(fixture, double);
        issuer""",
                """            .commands = command::Commands::with_double(fixture, double);
        *issuer.authority.mutant_command_issuer.lock().unwrap() = Arc::downgrade(&issuer);
        issuer""",
            ),
            (COMMAND, SPAWN, REDRIVE + SPAWN),
        ),
    ),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=tuple(CASES), action="append")
    args = parser.parse_args()
    selected = args.case or tuple(CASES)
    artifacts = ROOT / ".artifacts" / "mission-control-recovery-mutants"
    artifacts.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("CARGO_BUILD_JOBS", "8")
    os.environ.setdefault("CARGO_TARGET_DIR", str(ROOT / "target"))
    with tempfile.TemporaryDirectory(prefix="mission-control-recovery-mutants-") as temp:
        tree = Path(temp)
        for name in ("Cargo.toml", "Cargo.lock"):
            shutil.copyfile(ROOT / name, tree / name)
        for name in ("src", "tests", "assets"):
            shutil.copytree(ROOT / name, tree / name)
        for name in selected:
            test, _, _ = CASES[name]
            RUN(tree, artifacts, f"{name}-control", test)
        for name in selected:
            test, reason, edits = CASES[name]
            originals = APPLY(tree, edits)
            try:
                RUN(tree, artifacts, name, test, reason)
            finally:
                for source, contents in originals.items():
                    source.write_text(contents)
        for name in selected:
            test, _, _ = CASES[name]
            RUN(tree, artifacts, f"{name}-restored", test)
    print(f"mission-control-recovery-mutants-complete: {len(selected)}/{len(CASES)}")


if __name__ == "__main__":
    main()

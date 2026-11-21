use crate::observe::{Config, Observer};
use crate::observe_export::{project_page, ExportQuery, Reason, Scope};
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct Fixture {
    observer: Arc<Observer>,
    _primary: Arc<Mutex<rusqlite::Connection>>,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let primary = Arc::new(Mutex::new(rusqlite::Connection::open_in_memory().unwrap()));
        let observer = Observer::start(
            &primary,
            &directory.path().join("observe.sqlite"),
            "test.node",
            Config::default(),
        );
        assert!(observer.flush_for_test(Duration::from_secs(3)));
        Self {
            observer,
            _primary: primary,
            _directory: directory,
        }
    }

    fn scope(&self) -> Scope {
        Scope::new(self.observer.node(), "owner.collector", None, false).unwrap()
    }

    fn query(&self, scope: &Scope, epoch: Option<String>) -> ExportQuery {
        ExportQuery {
            v: 2,
            epoch,
            after: 0,
            limit: 100,
            scope: Some(scope.fingerprint().into()),
            labels: false,
        }
    }
}

#[test]
fn real_queue_loss_crosses_projection_without_exporting_raw_counters() {
    let fixture = Fixture::new();
    fixture.observer.lost(17);
    assert!(fixture.observer.flush_for_test(Duration::from_secs(3)));
    let scope = fixture.scope();
    let query = fixture.query(&scope, None);
    let source = fixture
        .observer
        .page(query.journal_query(&scope).unwrap())
        .unwrap();
    assert_eq!(
        source.losses.queue, 17,
        "real journal queue-loss fixture was not persisted"
    );
    assert!(
        source
            .gaps
            .iter()
            .any(|gap| gap.reason == "queue_loss" && gap.count == Some(17)),
        "real journal did not expose its known queue-loss source gap"
    );
    let export = project_page(source, &query, &scope, crate::storage::now_epoch_secs()).unwrap();
    assert!(
        !export.gaps.is_empty(),
        "real queue-loss source gap was not forwarded"
    );
    let gap = export
        .gaps
        .iter()
        .find(|gap| gap.reason == Reason::QueueLoss)
        .expect("real queue-loss reason was not preserved");
    assert!(
        !gap.unknown_loss,
        "known queue loss was converted to unknown loss"
    );
    let wire = serde_json::to_value(export).unwrap();
    assert!(
        wire.get("losses").is_none(),
        "raw journal loss counters crossed the export schema"
    );
    assert!(
        wire["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .all(|gap| gap.get("count").is_none()),
        "raw source gap count crossed the export schema"
    );
}

#[test]
fn real_epoch_mismatch_preserves_unknown_loss_on_reset() {
    let fixture = Fixture::new();
    let scope = fixture.scope();
    let query = fixture.query(&scope, Some("different-epoch".into()));
    let source = fixture
        .observer
        .page(query.journal_query(&scope).unwrap())
        .unwrap();
    assert_ne!(
        source.epoch, "different-epoch",
        "epoch reset fixture did not mismatch"
    );
    assert!(
        source
            .gaps
            .iter()
            .any(|gap| gap.reason == "epoch_changed" && gap.unknown_loss && gap.count.is_none()),
        "real journal did not expose its unknown-loss epoch reset"
    );
    let export = project_page(source, &query, &scope, crate::storage::now_epoch_secs()).unwrap();
    let gap = export
        .gaps
        .iter()
        .find(|gap| gap.reason == Reason::EpochChanged)
        .expect("real epoch reset reason was not preserved");
    assert!(
        gap.unknown_loss,
        "real epoch reset unknown-loss flag was erased"
    );
    assert_eq!(
        export.next,
        export.events.last().map_or(0, |event| event.sequence),
        "epoch reset cursor did not follow the exported prefix"
    );
}

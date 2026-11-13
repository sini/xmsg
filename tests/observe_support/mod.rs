use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub fn corrupt_sidecar(database: &Path) {
    let mut name = database.as_os_str().to_os_string();
    name.push(".observe.sqlite");
    let file = std::path::PathBuf::from(name);
    fs::write(&file, b"unavailable observer fixture").unwrap();
    fs::set_permissions(file, fs::Permissions::from_mode(0o600)).unwrap();
}

pub async fn assert_unavailable_http(socket: &Path) {
    let client = reqwest::Client::builder()
        .unix_socket(socket.to_owned())
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let response = loop {
        match client
            .get("http://localhost/v1/observe/events")
            .send()
            .await
        {
            Ok(response) => break response,
            Err(error) => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "observer HTTP did not become ready: {error}"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    };
    assert_eq!(
        response.status(),
        503,
        "corrupt sidecar must be visibly unavailable"
    );
}

pub struct UnavailableObserver {
    pub observer: Arc<xmsg::observe::Observer>,
    _directory: tempfile::TempDir,
}

pub fn attach_unavailable(
    primary: &Arc<Mutex<rusqlite::Connection>>,
    node: &str,
) -> UnavailableObserver {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let database = directory.path().join("primary");
    corrupt_sidecar(&database);
    let observer = xmsg::observe::Observer::start(
        primary,
        &directory.path().join("primary.observe.sqlite"),
        node,
        Default::default(),
    );
    assert!(!observer.flush_for_test(Duration::from_millis(100)));
    assert!(matches!(
        observer.page(Default::default()),
        Err(xmsg::observe::Error::Unavailable)
    ));
    UnavailableObserver {
        observer,
        _directory: directory,
    }
}

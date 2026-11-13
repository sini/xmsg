use crate::enroll::protocol_tests::{enrollment_fingerprint, network_server, Harness};
use crate::{enroll, enroll_cli};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

struct Browser<'a> {
    idp: &'a crate::enroll_oidc::signed_fixture::Fixture,
    calls: AtomicUsize,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}
impl enroll_cli::Browser for Browser<'_> {
    fn interact<'a>(
        &'a self,
        url: &'a str,
        flow: enroll_cli::Flow,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<Option<String>, Box<dyn std::error::Error + Send + Sync>>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let (code, state) = self.idp.authorize(url);
            let url = reqwest::Url::parse(url)?;
            let redirect = url
                .query_pairs()
                .find(|(name, _)| name == "redirect_uri")
                .unwrap()
                .1
                .into_owned();
            let mut redirect = reqwest::Url::parse(&redirect)?;
            redirect
                .query_pairs_mut()
                .append_pair("code", &code)
                .append_pair("state", &state);
            if matches!(flow, enroll_cli::Flow::Paste) {
                return Ok(Some(redirect.into()));
            }
            let task = tokio::spawn(async move {
                let http = reqwest::Client::builder()
                    .no_proxy()
                    .timeout(std::time::Duration::from_secs(5))
                    .build()
                    .unwrap();
                assert!(http
                    .get(redirect)
                    .send()
                    .await
                    .unwrap()
                    .status()
                    .is_success());
            });
            self.tasks.lock().unwrap().push(task);
            Ok(None)
        })
    }
}
impl Browser<'_> {
    async fn finish(&self) {
        let tasks = std::mem::take(&mut *self.tasks.lock().unwrap());
        for task in tasks {
            task.await.unwrap();
        }
    }
}
fn args(
    url: &str,
    fingerprint: String,
    directory: &std::path::Path,
    flow: enroll_cli::Flow,
) -> enroll_cli::Args {
    enroll_cli::Args {
        url: Some(url.into()),
        fingerprint: Some(fingerprint),
        root_file: None,
        provider: Some("idp".into()),
        flow,
        host: Some("laptop".into()),
        state_dir: Some(directory.into()),
        renew: false,
    }
}

#[tokio::test]
async fn production_client_loopback_and_paste_write_verified_identity() {
    for flow in [enroll_cli::Flow::Loopback, enroll_cli::Flow::Paste] {
        let env = Harness::new().await;
        let (url, listener) = network_server(&env, false).await;
        let browser = Browser {
            idp: &env.idp,
            calls: AtomicUsize::new(0),
            tasks: Mutex::new(vec![]),
        };
        let directory = env._directory.path().join("client");
        enroll_cli::run_with_browser(
            args(&url, enrollment_fingerprint(&env), &directory, flow),
            &browser,
        )
        .await
        .unwrap();
        browser.finish().await;
        assert_eq!(browser.calls.load(Ordering::SeqCst), 1);
        for name in [
            "fed.key",
            "fed.crt",
            "root.pem",
            "enroll.json",
            "peers.json",
            "hub-ca.pem",
        ] {
            assert!(directory.join(name).is_file(), "client output missing");
        }
        assert_ne!(
            std::fs::read(directory.join("hub-ca.pem")).unwrap(),
            std::fs::read(directory.join("root.pem")).unwrap(),
            "hub bundle used enrollment root rather than fleet root"
        );
        listener.abort();
        let _ = listener.await;
    }
}

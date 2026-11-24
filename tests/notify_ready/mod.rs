use std::{future::Future, time::Duration};
use tokio::net::UnixDatagram;

/// Waits for serve's READY=1 on `notify`, its NOTIFY_SOCKET. serve sends it only once every
/// listener, http.sock included, is bound. False on timeout, or once `alive` reports serve gone.
pub async fn ready<F, Fut>(notify: &UnixDatagram, wait: Duration, mut alive: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let mut buffer = [0; 512];
    tokio::time::timeout(wait, async {
        loop {
            tokio::select! {
                received = notify.recv(&mut buffer) => {
                    let text = String::from_utf8_lossy(&buffer[..received.unwrap()]).into_owned();
                    if text.lines().any(|line| line == "READY=1") {
                        return true;
                    }
                }
                () = tokio::time::sleep(Duration::from_millis(100)) => if !alive().await {
                    return false;
                },
            }
        }
    })
    .await
    .unwrap_or(false)
}

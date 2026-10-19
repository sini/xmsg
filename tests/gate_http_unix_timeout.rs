//! http.sock client timeout: an expired bound is `TimedOut` naming the socket and
//! the bound, never a raw EAGAIN (`WouldBlock`); an answer inside the bound is OK.
use std::io::Write;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::time::Duration;

/// A one-shot server on `sock` that answers 200 "ok" after `delay`.
fn slow_server(sock: &Path, delay: Duration) {
    let l = UnixListener::bind(sock).unwrap();
    std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        std::thread::sleep(delay);
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        std::thread::sleep(Duration::from_secs(1));
    });
}

#[test]
fn unix_request_timeout_is_timed_out_with_path_and_bound() {
    let dir = tempfile::Builder::new()
        .prefix("ht")
        .tempdir_in("/tmp")
        .unwrap();
    std::env::set_var("HOME", dir.path());
    let bound = Duration::from_millis(200);

    // Answers long after the bound => TimedOut naming the socket and the bound.
    let late = dir.path().join("late.sock");
    slow_server(&late, Duration::from_secs(5));
    let err = xmsg::http::http_request_unix_within(&late, "GET", "/v1/recipients", None, bound)
        .expect_err("a server answering after the bound must time out");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err:?}");
    assert_eq!(err.raw_os_error(), None, "raw os error leaked: {err:?}");
    let msg = err.to_string();
    assert!(msg.contains(&late.display().to_string()), "{msg}");
    assert!(msg.contains(&format!("{bound:?}")), "{msg}");

    // Answers at once, well inside a generous bound => OK. Each case keeps a wide margin
    // on its own side of the bound, so a loaded runner's scheduling delay decides neither.
    let early = dir.path().join("early.sock");
    slow_server(&early, Duration::ZERO);
    let (status, body) =
        xmsg::http::http_request_unix_within(&early, "GET", "/v1/recipients", None, Duration::from_secs(10))
            .expect("a server answering inside the bound must succeed");
    assert_eq!(status.as_u16(), 200);
    assert_eq!(body, "ok");
}

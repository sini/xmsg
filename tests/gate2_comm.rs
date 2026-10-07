#[test]
fn gate2_comm_paren() {
    let t = tempfile::tempdir().unwrap();
    let w = |pid: u32, comm: &str, ppid: u32, st: &str| {
        let d = t.path().join(pid.to_string());
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("stat"),
            format!("{pid} ({comm}) S {ppid} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {st} 0 0\n"),
        )
        .unwrap();
    };

    w(10, "plain", 1, "777");
    w(11, "a) S 99 (b 0 0", 1, "888");

    // Plain comm: live check
    assert!(xmsg::registry::is_pid_live_in(t.path(), 10, "777"));
    assert!(!xmsg::registry::is_pid_live_in(t.path(), 10, "999"));

    // Hostile comm with embedded parentheses and spaces:
    // parser must use the final closing parenthesis rfind(')')
    assert!(xmsg::registry::is_pid_live_in(t.path(), 11, "888"));
    assert!(!xmsg::registry::is_pid_live_in(t.path(), 11, "99"));
    assert_eq!(xmsg::pi::get_proc_starttime(t.path(), 11).unwrap(), "888");
}

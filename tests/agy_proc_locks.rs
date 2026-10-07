use std::fs;
use tempfile::tempdir;
use xmsg::agy::{dev_major, dev_minor, find_lock_holder, parse_locks_line};

#[test]
fn test_parse_locks_line() {
    // 1. Valid FLOCK write line: dev hex 00:2e = 0, 46
    let line1 = "22: FLOCK ADVISORY WRITE 2739763 00:2e:1148992 0 EOF";
    let parsed1 = parse_locks_line(line1);
    assert_eq!(parsed1, Some((2739763, 0, 46, 1148992)));

    // 2. POSIX write line is ignored (FLOCK only)
    let line2 = "1: POSIX ADVISORY WRITE 12345 08:01:99999 0 EOF";
    let parsed2 = parse_locks_line(line2);
    assert_eq!(parsed2, None);

    // 3. READ lock ignored (must be exclusive WRITE)
    let line3 = "2: FLOCK ADVISORY READ 54321 00:2e:1148992 0 EOF";
    assert_eq!(parse_locks_line(line3), None);

    // 4. Invalid formatting
    let line4 = "random garbage";
    assert_eq!(parse_locks_line(line4), None);
}

#[test]
fn test_dev_macros() {
    // Test conversion of makedev / stat dev
    let dev: u64 = 46; // major 0, minor 46
    assert_eq!(dev_major(dev), 0);
    assert_eq!(dev_minor(dev), 46);

    let dev2: u64 = (8 << 8) | 1; // major 8, minor 1
    assert_eq!(dev_major(dev2), 8);
    assert_eq!(dev_minor(dev2), 1);
}

#[test]
fn test_find_lock_holder_from_fixture() {
    let tmp = tempdir().unwrap();
    let locks_file = tmp.path().join("proc_locks");

    let fixture = r#"1: POSIX  ADVISORY  WRITE 1000 08:01:100 0 EOF
2: FLOCK  ADVISORY  WRITE 2000 00:2e:55555 0 EOF
3: FLOCK  ADVISORY  READ  3000 00:2e:66666 0 EOF
4: FLOCK  ADVISORY  WRITE 4000 00:2e:77777 0 EOF
"#;
    fs::write(&locks_file, fixture).unwrap();

    // Match PID 2000 for inode 55555 on 00:2e
    let holder = find_lock_holder(&locks_file, 0, 46, 55555).unwrap();
    assert_eq!(holder, Some(2000));

    // Match PID 4000 for inode 77777 on 00:2e
    let holder4 = find_lock_holder(&locks_file, 0, 46, 77777).unwrap();
    assert_eq!(holder4, Some(4000));

    // Non-existent inode
    let none_holder = find_lock_holder(&locks_file, 0, 46, 99999).unwrap();
    assert_eq!(none_holder, None);

    // Wrong device
    let wrong_dev = find_lock_holder(&locks_file, 1, 46, 55555).unwrap();
    assert_eq!(wrong_dev, None);

    // Read lock on 66666 is ignored
    let read_holder = find_lock_holder(&locks_file, 0, 46, 66666).unwrap();
    assert_eq!(read_holder, None);

    // Multiple distinct FLOCK holders for the same inode return an ambiguity error
    let multi_fixture = r#"1: FLOCK  ADVISORY  WRITE 2000 00:2e:55555 0 EOF
2: FLOCK  ADVISORY  WRITE 3000 00:2e:55555 0 EOF
"#;
    fs::write(&locks_file, multi_fixture).unwrap();
    let multi_err = find_lock_holder(&locks_file, 0, 46, 55555);
    assert!(
        multi_err.is_err(),
        "multiple distinct lock holders must return an error"
    );
}

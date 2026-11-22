//! Bounded compile-time build revision metadata embedded into a dedicated Mach-O section
//! (`__DATA,__xmsg_rev`) on macOS so standalone preflight tooling can verify the exact source
//! revision offline via `otool -s __DATA __xmsg_rev` without executing the binary.

pub const EMBEDDED_REVISION_PREFIX: &[u8] = b"XMSG-REV-V1:";
pub const EMBEDDED_REVISION_LEN: usize = 128;

pub const fn encode_embedded_revision(rev: Option<&str>) -> [u8; EMBEDDED_REVISION_LEN] {
    let mut out = [0u8; EMBEDDED_REVISION_LEN];
    let prefix = EMBEDDED_REVISION_PREFIX;
    let mut i = 0;
    while i < prefix.len() {
        out[i] = prefix[i];
        i += 1;
    }

    let bytes = match rev {
        Some(s) if !s.is_empty() => s.as_bytes(),
        _ => b"unknown",
    };

    // Reserve the final byte for NUL termination so the section is always strictly bounded.
    let max_payload = EMBEDDED_REVISION_LEN - prefix.len() - 1;
    let mut j = 0;
    while j < bytes.len() && j < max_payload {
        let b = bytes[j];
        if b == 0 || !b.is_ascii_graphic() {
            break;
        }
        out[prefix.len() + j] = b;
        j += 1;
    }
    out
}

pub fn decode_embedded_revision(buf: &[u8]) -> Option<&str> {
    let rest = buf.strip_prefix(EMBEDDED_REVISION_PREFIX)?;
    let nul = rest.iter().position(|&b| b == 0)?;
    if nul == 0 {
        return None;
    }
    let slice = &rest[..nul];
    if !slice.iter().all(|b| b.is_ascii_graphic()) {
        return None;
    }
    std::str::from_utf8(slice).ok()
}

#[cfg(target_os = "macos")]
#[used]
#[no_mangle]
#[link_section = "__DATA,__xmsg_rev"]
pub static XMSG_EMBEDDED_REVISION: [u8; EMBEDDED_REVISION_LEN] =
    encode_embedded_revision(option_env!("XMSG_BUILD_REVISION"));

/// Prevents linker dead-stripping (including under LTO + symbol stripping) from discarding
/// `__DATA,__xmsg_rev` in release binaries.
#[inline(never)]
pub fn retain_embedded_revision() {
    #[cfg(target_os = "macos")]
    {
        let ptr: *const [u8; EMBEDDED_REVISION_LEN] = &XMSG_EMBEDDED_REVISION;
        std::hint::black_box(ptr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_revision_encoding_is_bounded_and_round_trips() {
        let sha = "8121a4839fa723bf0c969ca108ed07d3c761ce50";
        let encoded = encode_embedded_revision(Some(sha));
        assert_eq!(encoded.len(), EMBEDDED_REVISION_LEN);
        assert_eq!(encoded[EMBEDDED_REVISION_LEN - 1], 0);
        assert_eq!(decode_embedded_revision(&encoded), Some(sha));

        let unset = encode_embedded_revision(None);
        assert_eq!(decode_embedded_revision(&unset), Some("unknown"));

        let empty = encode_embedded_revision(Some(""));
        assert_eq!(decode_embedded_revision(&empty), Some("unknown"));

        // Overlong input is truncated cleanly with NUL termination preserved.
        let overlong = "a".repeat(256);
        let bounded = encode_embedded_revision(Some(&overlong));
        assert_eq!(bounded[EMBEDDED_REVISION_LEN - 1], 0);
        let decoded = decode_embedded_revision(&bounded).expect("bounded revision decodes");
        assert_eq!(
            decoded.len(),
            EMBEDDED_REVISION_LEN - EMBEDDED_REVISION_PREFIX.len() - 1
        );

        #[cfg(target_os = "macos")]
        {
            retain_embedded_revision();
            let linked = decode_embedded_revision(&XMSG_EMBEDDED_REVISION)
                .expect("linked Mach-O revision must decode cleanly");
            assert!(!linked.is_empty());
        }
    }
}

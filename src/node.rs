//! Node names (A9, B5, D4).
//!
//! A node's name is derived, never assigned by hand:
//! - from a certificate's URI SAN: `.../host/<host>/user/<user>` is `<user>.<host>`,
//!   `.../ns/<ns>/sa/<sa>` is `<sa>.<ns>`;
//! - from a pinned key: the first 16 characters of the lowercase RFC 4648 base32 of the
//!   key's SHA-256 (the pin);
//! - with no federation identity at all: `<user>.<host>` from the OS, never sent anywhere.

/// Length of a key-derived node name.
pub const KEY_NAME_LEN: usize = 16;

const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// The node name in a SPIFFE identity URI.
pub fn node_name_from_uri(uri: &str) -> Result<String, String> {
    let path = uri
        .strip_prefix("spiffe://")
        .and_then(|rest| rest.split_once('/'))
        .map(|(_, p)| p)
        .ok_or_else(|| format!("identity '{uri}' is not a spiffe:// URI with a path"))?;
    let (first, second) = match path.split('/').collect::<Vec<_>>().as_slice() {
        ["host", host, "user", user] => (*user, *host),
        ["ns", ns, "sa", sa] => (*sa, *ns),
        _ => {
            return Err(format!(
                "identity '{uri}' names no node: expected .../host/<host>/user/<user> or .../ns/<ns>/sa/<sa>"
            ))
        }
    };
    for part in [first, second] {
        if part.is_empty() {
            return Err(format!("identity '{uri}' has an empty name part"));
        }
        if part.contains('.') {
            return Err(format!(
                "identity '{uri}': '{part}' contains '.', which separates the parts of a node name"
            ));
        }
    }
    Ok(format!("{first}.{second}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternAliasOwner {
    Unclaimed,
    Unique(String),
    Ambiguous,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AmbiguousAliasClass {
    pub alias: String,
    pub forms: Vec<String>,
    pub multiple_domains: bool,
}

#[derive(Clone, Copy)]
struct NameProjection<'a> {
    domain: &'a str,
    form: &'static str,
    first_keyword: &'static str,
    second_keyword: &'static str,
    first: &'a str,
    second: &'a str,
}

fn name_projections(pattern: &str) -> Vec<NameProjection<'_>> {
    if crate::fed::validate_spiffe_pattern(pattern).is_err() {
        return Vec::new();
    }
    let segments: Vec<_> = pattern
        .strip_prefix("spiffe://")
        .unwrap()
        .split('/')
        .collect();
    let [domain, first_keyword, second, second_keyword, first] = segments.as_slice() else {
        return Vec::new();
    };
    if [first, second]
        .iter()
        .any(|part| part.is_empty() || part.contains('.'))
    {
        return Vec::new();
    }
    [("host", "user", "host/user"), ("ns", "sa", "ns/sa")]
        .into_iter()
        .filter(|(a, b, _)| {
            (*first_keyword == *a || *first_keyword == "*")
                && (*second_keyword == *b || *second_keyword == "*")
        })
        .map(|(a, b, form)| NameProjection {
            domain,
            form,
            first_keyword: a,
            second_keyword: b,
            first,
            second,
        })
        .collect()
}

pub fn pattern_alias_owner(alias: &str, patterns: &[String]) -> PatternAliasOwner {
    let Some((first, second)) = alias.split_once('.') else {
        return PatternAliasOwner::Unclaimed;
    };
    if first.is_empty() || second.is_empty() || second.contains('.') {
        return PatternAliasOwner::Unclaimed;
    }
    let mut witnesses = std::collections::BTreeSet::new();
    for pattern in patterns {
        for projection in name_projections(pattern) {
            let domains: &[&str] = if projection.domain == "*" {
                &["witness-one.invalid", "witness-two.invalid"]
            } else {
                std::slice::from_ref(&projection.domain)
            };
            for domain in domains {
                let uri = format!(
                    "spiffe://{domain}/{}/{second}/{}/{first}",
                    projection.first_keyword, projection.second_keyword
                );
                if crate::fed::spiffe_uri_matches_pattern(&uri, pattern)
                    && node_name_from_uri(&uri).is_ok_and(|name| name == alias)
                {
                    witnesses.insert(uri);
                    if witnesses.len() > 1 {
                        return PatternAliasOwner::Ambiguous;
                    }
                }
            }
        }
    }
    match witnesses.into_iter().next() {
        Some(uri) => PatternAliasOwner::Unique(uri),
        None => PatternAliasOwner::Unclaimed,
    }
}

fn intersect_name_part<'a>(a: &'a str, b: &'a str) -> Option<&'a str> {
    if a == b || b == "*" {
        Some(a)
    } else if a == "*" {
        Some(b)
    } else {
        None
    }
}

pub fn ambiguous_alias_classes(patterns: &[String]) -> Vec<AmbiguousAliasClass> {
    let projections: Vec<_> = patterns
        .iter()
        .flat_map(|pattern| name_projections(pattern))
        .collect();
    let mut classes =
        std::collections::BTreeMap::<String, (std::collections::BTreeSet<String>, bool)>::new();
    for (index, a) in projections.iter().enumerate() {
        for b in &projections[index..] {
            let multiple_domains = a.domain != b.domain || a.domain == "*";
            if a.form == b.form && !multiple_domains {
                continue;
            }
            let (Some(first), Some(second)) = (
                intersect_name_part(a.first, b.first),
                intersect_name_part(a.second, b.second),
            ) else {
                continue;
            };
            let (forms, domains) = classes.entry(format!("{first}.{second}")).or_default();
            forms.insert(a.form.to_owned());
            forms.insert(b.form.to_owned());
            *domains |= multiple_domains;
        }
    }
    classes
        .into_iter()
        .map(|(alias, (forms, multiple_domains))| AmbiguousAliasClass {
            alias,
            forms: forms.into_iter().collect(),
            multiple_domains,
        })
        .collect()
}

/// The key-derived node name of a pin (`sha256:<hex>` or bare hex of the key's SHA-256).
pub fn node_name_from_pin(pin: &str) -> Result<String, String> {
    let norm = crate::fed::normalize_pin(pin);
    let bytes = hex::decode(&norm)
        .ok()
        .filter(|b| b.len() == 32)
        .ok_or_else(|| format!("pin '{pin}' is not a SHA-256 digest (64 hex characters)"))?;
    // 16 base32 characters are 80 bits: the first 10 bytes.
    let mut acc: u128 = 0;
    for b in &bytes[..10] {
        acc = (acc << 8) | u128::from(*b);
    }
    Ok((0..KEY_NAME_LEN)
        .map(|i| BASE32[((acc >> (75 - 5 * i)) & 31) as usize] as char)
        .collect())
}

/// True for a string that could be a key-derived node name.
pub fn is_key_name_shaped(s: &str) -> bool {
    s.len() == KEY_NAME_LEN && s.bytes().all(|b| BASE32.contains(&b))
}

/// The name a node holding this leaf certificate goes by: its URI SAN's name, or with no
/// URI SAN, its key-derived name.
pub fn node_name_from_cert(cert_der: &[u8]) -> Result<String, String> {
    let uris = crate::fed::extract_uri_sans(cert_der)?;
    match uris.as_slice() {
        [] => node_name_from_pin(&crate::fed::spki_sha256_from_der(cert_der)?),
        [uri] => node_name_from_uri(uri),
        _ => Err(format!(
            "certificate carries {} URI SANs; a node identity has exactly one",
            uris.len()
        )),
    }
}

/// A16's user of a SPIFFE identity: `<user>` of `.../host/<host>/user/<user>`, and for a
/// pod, which has no user part, its node name `<sa>.<ns>` (D-8).
pub fn user_from_uri(uri: &str) -> Result<String, String> {
    let name = node_name_from_uri(uri)?;
    // The path is `host/<host>/user/<user>` or `ns/<ns>/sa/<sa>`, as the name's derivation
    // just checked; only a host identity has a user part.
    let host_form = uri
        .strip_prefix("spiffe://")
        .and_then(|rest| rest.split_once('/'))
        .is_some_and(|(_, p)| p.starts_with("host/"));
    Ok(match host_form {
        true => name.split('.').next().unwrap_or_default().to_string(),
        false => name,
    })
}

/// A16's user of the node holding this leaf certificate: its URI SAN's user, or with no URI
/// SAN its key-derived name (a pinned node is a user of its own).
pub fn user_from_cert(cert_der: &[u8]) -> Result<String, String> {
    let uris = crate::fed::extract_uri_sans(cert_der)?;
    match uris.as_slice() {
        [] => node_name_from_pin(&crate::fed::spki_sha256_from_der(cert_der)?),
        [uri] => user_from_uri(uri),
        _ => Err(format!(
            "certificate carries {} URI SANs; a node identity has exactly one",
            uris.len()
        )),
    }
}

/// This node's user (A16): its certificate's, or with no federation identity D4's `<user>`.
pub fn own_user(cert_der: Option<&[u8]>) -> String {
    match cert_der.map(user_from_cert) {
        Some(Ok(user)) => user,
        _ => os_user_name(),
    }
}

/// D4: a node with no federation identity is `<user>.<host>`, from its uid's user name and
/// the OS host name cut at its first `.` (as `hostname -s` does).
pub fn local_node_name() -> String {
    let host = gethostname::gethostname().to_string_lossy().to_string();
    let host = host.split('.').next().unwrap_or_default();
    format!("{}.{host}", os_user_name())
}

fn os_user_name() -> String {
    let uid = unsafe { libc::getuid() };
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16384];
    let mut res: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut res) };
    if rc == 0 && !res.is_null() && !pwd.pw_name.is_null() {
        unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) }
            .to_string_lossy()
            .into_owned()
    } else {
        // ponytail: a uid with no passwd entry (some containers) is named by its number.
        uid.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(
            node_name_from_uri("spiffe://json64.dev/host/bitstream/user/sini").unwrap(),
            "sini.bitstream"
        );
        assert_eq!(
            node_name_from_uri("spiffe://json64.dev/ns/genie/sa/genie-guard").unwrap(),
            "genie-guard.genie"
        );
        assert!(node_name_from_uri("spiffe://json64.dev/host/a.b/user/sini").is_err());
        assert!(node_name_from_uri("spiffe://json64.dev/ns/x").is_err());
        // RFC 4648 test vector: base32("foobar") = "MZXW6YTBOI======"; zero-padded digest here.
        let mut d = [0u8; 32];
        d[..6].copy_from_slice(b"foobar");
        assert_eq!(
            node_name_from_pin(&hex::encode(d)).unwrap(),
            "mzxw6ytboiaaaaaa"
        );
        assert!(node_name_from_pin("sha256:abcd").is_err());
        assert!(is_key_name_shaped("mzxw6ytboiaaaaaa"));
        // A16, D-8: a host identity's user is its user part, a pod's is its node name.
        assert_eq!(
            user_from_uri("spiffe://json64.dev/host/bitstream/user/sini").unwrap(),
            "sini"
        );
        assert_eq!(
            user_from_uri("spiffe://json64.dev/ns/genie/sa/genie-guard").unwrap(),
            "genie-guard.genie"
        );
        assert_eq!(
            user_from_uri("spiffe://json64.dev/ns/host/sa/user").unwrap(),
            "user.host"
        );
        assert!(!is_key_name_shaped("laptop"));
        // D4: `<user>.<host>`, the host cut at its first `.`; the user name may contain `.`.
        let local = local_node_name();
        let host = gethostname::gethostname().to_string_lossy().to_string();
        let host = host.split('.').next().unwrap();
        let user = local.strip_suffix(&format!(".{host}"));
        assert!(user.is_some_and(|u| !u.is_empty()), "{local}");
    }
}

#[cfg(test)]
#[path = "node_authority_tests.rs"]
mod authority_tests;

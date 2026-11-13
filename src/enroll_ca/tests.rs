use super::*;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{pem::PemObject, CertificateDer};
use std::os::unix::fs::PermissionsExt;
const NOW: i64 = 1_800_000_000;
struct Setup {
    _dir: tempfile::TempDir,
    policy: PathBuf,
    dir: PathBuf,
    db: Arc<Mutex<Connection>>,
    ca: EnrollCa,
}
fn policy() -> serde_json::Value {
    serde_json::json!({"trust_domain":"example.org","providers":{"idp":{"issuer":"https://idp.example","clients":{"loopback":{"client_id":"L"},"paste":{"client_id":"P"}}}},"users":[{"provider":"idp","sub":"alice-id","user":"alice"},{"provider":"idp","sub":"other-id","user":"alice"},{"provider":"idp","sub":"bob-id","user":"bob"}],"issue_per_hour":6,"renew_per_hour":6})
}
impl Setup {
    fn new() -> Self {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("policy.json");
        std::fs::write(&file, policy().to_string()).unwrap();
        let dir = d.path().join("ca");
        let db = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
        let ca = EnrollCa::open_at(&dir, db.clone(), &file, "team.hub", NOW).unwrap();
        Self {
            _dir: d,
            policy: file,
            dir,
            db,
            ca,
        }
    }
    fn replace(&self, p: serde_json::Value) {
        std::fs::write(&self.policy, p.to_string()).unwrap();
    }
}
fn claims(sub: &str) -> VerifiedClaims {
    VerifiedClaims {
        provider: "idp".into(),
        iss: "https://idp.example".into(),
        sub: sub.into(),
        email: None,
        email_verified: false,
        hd: None,
        groups: vec![],
        preferred_username: None,
    }
}
fn csr(malicious: bool) -> VerifiedCsr {
    let k = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::default();
    if malicious {
        p.subject_alt_names = vec![rcgen::SanType::URI(
            "spiffe://example.org/host/laptop/user/root"
                .try_into()
                .unwrap(),
        )];
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    }
    VerifiedCsr::parse_pem(&p.serialize_request(&k).unwrap().pem().unwrap()).unwrap()
}
fn chain(pem: &str) -> Vec<Vec<u8>> {
    CertificateDer::pem_slice_iter(pem.as_bytes())
        .map(|c| c.unwrap().to_vec())
        .collect()
}
#[test]
fn fresh_profile_ignores_requested_authority_and_preserves_key() {
    let s = Setup::new();
    let request = csr(true);
    let issued =
        s.ca.issue(&claims("alice-id"), &request, "laptop", &[], NOW)
            .unwrap();
    let certs = chain(&issued.cert_chain_pem);
    let (_, leaf) = x509_parser::parse_x509_certificate(&certs[0]).unwrap();
    assert_eq!(
        crate::node::node_name_from_cert(&certs[0]).unwrap(),
        "alice.laptop"
    );
    assert_eq!(leaf.public_key().raw, request.spki_der());
    assert!(leaf.subject().iter().next().is_none());
    assert!(!leaf.is_ca());
    assert!(crate::fed::parse_ca_bundle_pem(
        issued
            .cert_chain_pem
            .split_inclusive("-----END CERTIFICATE-----")
            .next()
            .unwrap()
            .as_bytes()
    )
    .is_err());
    let sans = leaf
        .extensions()
        .iter()
        .find(|e| {
            matches!(
                e.parsed_extension(),
                x509_parser::extensions::ParsedExtension::SubjectAlternativeName(_)
            )
        })
        .unwrap();
    assert!(
        crate::fed::parse_ca_bundle_pem(s.ca.root_pem().as_bytes()).is_ok(),
        "root anchor positive control failed"
    );
    assert!(sans.critical);
    assert_eq!(
        crate::fed::extract_uri_sans(&certs[0]).unwrap(),
        vec!["spiffe://example.org/host/laptop/user/alice"]
    );
    assert_eq!(leaf.raw_serial().len(), 16);
    assert_eq!(leaf.validity().not_after.timestamp(), NOW + 86400);
    assert_eq!(
        leaf.validity().not_after.timestamp() - leaf.validity().not_before.timestamp(),
        86700
    );
}
#[test]
fn renewal_preserves_uri_spki_new_serial_window_and_grace() {
    let s = Setup::new();
    let a =
        s.ca.issue(&claims("alice-id"), &csr(false), "lap", &[], NOW)
            .unwrap();
    let b =
        s.ca.renew(&chain(&a.cert_chain_pem), NOW + 86400 + 1)
            .unwrap();
    let c =
        s.ca.renew(&chain(&b.cert_chain_pem), NOW + 86400 + 2)
            .unwrap();
    assert_ne!(a.serial, b.serial);
    assert_ne!(b.serial, c.serial);
    assert_eq!(a.uri, c.uri);
    assert_eq!(a.spki_sha256, c.spki_sha256);
    for (v, at) in [(&b, NOW + 86400 + 1), (&c, NOW + 86400 + 2)] {
        let der = chain(&v.cert_chain_pem);
        let (_, p) = x509_parser::parse_x509_certificate(&der[0]).unwrap();
        assert_eq!(p.raw_serial().len(), 16);
        assert_eq!(p.validity().not_after.timestamp(), at + 86400);
        assert_eq!(
            p.validity().not_after.timestamp() - p.validity().not_before.timestamp(),
            86700
        );
    }
    assert!(matches!(
        s.ca.renew(&chain(&a.cert_chain_pem), NOW + 86400 + 604800 + 1),
        Err(Error::ReenrollRequired)
    ));
    let other = Setup::new();
    assert!(matches!(
        other.ca.renew(&chain(&a.cert_chain_pem), NOW + 1),
        Err(Error::ReenrollRequired)
    ));
}
#[test]
fn repeated_renewal_still_requires_fresh_login_at_ninety_days() {
    let s = Setup::new();
    let mut a =
        s.ca.issue(&claims("alice-id"), &csr(false), "lap", &[], NOW)
            .unwrap();
    for day in (7..=84).step_by(7) {
        a =
            s.ca.renew(&chain(&a.cert_chain_pem), NOW + day * 86400)
                .unwrap();
    }
    assert!(matches!(
        s.ca.renew(&chain(&a.cert_chain_pem), NOW + 90 * 86400 + 1),
        Err(Error::ReauthRequired)
    ));
}
#[test]
fn deny_key_survives_renewal_and_reenrollment_supersedes_old_lineage() {
    let s = Setup::new();
    let a =
        s.ca.issue(&claims("alice-id"), &csr(false), "lap", &[], NOW)
            .unwrap();
    let b = s.ca.renew(&chain(&a.cert_chain_pem), NOW + 1).unwrap();
    let mut p = policy();
    p["deny"] = serde_json::json!({"spkis":[a.spki_sha256]});
    s.replace(p);
    assert!(matches!(
        s.ca.renew(&chain(&b.cert_chain_pem), NOW + 2),
        Err(Error::Denied)
    ));
    s.replace(policy());
    let c =
        s.ca.issue(&claims("alice-id"), &csr(false), "lap", &[], NOW + 3)
            .unwrap();
    assert!(c.superseded_serials.contains(&a.serial));
    assert!(c.superseded_serials.contains(&b.serial));
    assert!(matches!(
        s.ca.renew(&chain(&b.cert_chain_pem), NOW + 4),
        Err(Error::Superseded)
    ));
    let mut p = policy();
    p["deny"] = serde_json::json!({"users":["alice"]});
    s.replace(p);
    assert!(matches!(
        s.ca.issue(&claims("alice-id"), &csr(false), "other", &[], NOW + 5),
        Err(Error::Denied)
    ));
    assert!(matches!(
        s.ca.renew(&chain(&c.cert_chain_pem), NOW + 5),
        Err(Error::Denied)
    ));
}
#[test]
fn bindings_aliases_reserved_names_and_unbind_are_authoritative() {
    let s = Setup::new();
    let request = csr(false);
    s.ca.issue(&claims("alice-id"), &request, "lap", &[], NOW)
        .unwrap();
    assert!(matches!(
        s.ca.issue(&claims("other-id"), &csr(false), "lap2", &[], NOW),
        Err(Error::NameBound)
    ));
    s.ca.bind("alice", "idp", "other-id", NOW).unwrap();
    let alias =
        s.ca.issue(&claims("other-id"), &csr(false), "lap2", &[], NOW)
            .unwrap();
    s.ca.issue(&claims("bob-id"), &csr(false), "lap", &[], NOW)
        .unwrap();
    assert!(
        matches!(s.ca.bind("alice","idp","bob-id",NOW),Err(Error::AlreadyPrimary(ref user)) if user=="bob")
    );
    assert!(matches!(
        s.ca.issue(
            &claims("alice-id"),
            &request,
            "lap",
            &["alice.lap".into()],
            NOW
        ),
        Err(Error::ReservedName)
    ));
    let mut p = policy();
    p["users"][0]["user"] = "team".into();
    s.replace(p);
    assert!(matches!(
        s.ca.issue(&claims("alice-id"), &request, "hub", &[], NOW),
        Err(Error::ReservedName)
    ));
    s.ca.unbind("alice").unwrap();
    assert!(matches!(
        s.ca.renew(&chain(&alias.cert_chain_pem), NOW + 1),
        Err(Error::Denied)
    ));
}
#[test]
fn independent_rate_buckets_preserve_enrollment_after_six_renewals() {
    let s = Setup::new();
    let a =
        s.ca.issue(&claims("alice-id"), &csr(false), "lap", &[], NOW)
            .unwrap();
    for _ in 0..6 {
        s.ca.renew(&chain(&a.cert_chain_pem), NOW + 3601).unwrap();
    }
    assert!(matches!(
        s.ca.renew(&chain(&a.cert_chain_pem), NOW + 3601),
        Err(Error::RateLimited)
    ));
    assert!(s
        .ca
        .issue(&claims("alice-id"), &csr(false), "new-lap", &[], NOW + 3601)
        .is_ok());
}
#[test]
fn invalid_policy_keeps_previous_and_recovery_is_visible() {
    let s = Setup::new();
    std::fs::write(&s.policy, b"{").unwrap();
    assert!(s
        .ca
        .issue(&claims("alice-id"), &csr(false), "lap", &[], NOW)
        .is_ok());
    assert!(s.ca.reload_status().degraded);
    let mut p = policy();
    p["users"][0].as_object_mut().unwrap().remove("sub");
    s.replace(p);
    assert!(s
        .ca
        .issue(&claims("alice-id"), &csr(false), "lap2", &[], NOW)
        .is_ok());
    assert!(s.ca.reload_status().degraded);
    s.replace(policy());
    assert!(!s.ca.reload_policy().unwrap());
    assert!(!s.ca.reload_status().degraded);
    let mut v2 = policy();
    v2["lifetime_secs"] = 3600.into();
    s.replace(v2);
    assert!(s.ca.reload_policy().unwrap());
    assert_eq!(s.ca.policy().lifetime_secs, 3600);
}
#[test]
fn key_permissions_and_symlinks_refuse_reopening() {
    let s = Setup::new();
    let k = s.dir.join("root.key");
    std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(matches!(
        EnrollCa::open_at(&s.dir, s.db.clone(), &s.policy, "team.hub", NOW),
        Err(Error::InvalidCaKey)
    ));
    std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::rename(&k, s.dir.join("saved.key")).unwrap();
    std::os::unix::fs::symlink(s.dir.join("saved.key"), &k).unwrap();
    assert!(matches!(
        EnrollCa::open_at(&s.dir, s.db.clone(), &s.policy, "team.hub", NOW),
        Err(Error::InvalidCaKey)
    ));
}
#[test]
fn unsupported_key_charset_and_flow_do_not_gain_authority() {
    let k = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let pem = CertificateParams::default()
        .serialize_request(&k)
        .unwrap()
        .pem()
        .unwrap();
    assert!(matches!(
        VerifiedCsr::parse_pem(&pem),
        Err(Error::UnsupportedKey)
    ));
    let s = Setup::new();
    let mut p = policy();
    p["users"] =
        serde_json::json!([{"provider":"idp","hd":"example.com","user_from":"email_local"}]);
    s.replace(p);
    let mut c = claims("alice-id");
    c.email = Some("alice.smith@example.com".into());
    c.email_verified = true;
    c.hd = Some("example.com".into());
    assert!(matches!(
        s.ca.issue(&c, &csr(false), "lap", &[], NOW),
        Err(Error::InvalidName)
    ));
    assert!(matches!(
        s.ca.policy().provider("idp").unwrap().client(Flow::Device),
        Err(Error::UnsupportedFlow)
    ));
    let mut p = policy();
    p["providers"]["idp"]["clients"]["device"] = serde_json::json!({"client_id":"D"});
    assert!(Policy::from_json(&p.to_string()).is_err());
    c.iss = "accounts.google.com".into();
    assert!(matches!(
        s.ca.issue(&c, &csr(false), "lap", &[], NOW),
        Err(Error::Denied)
    ));
}

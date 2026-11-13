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
        Err(Error::InvalidRuleName(_))
    ));
    assert!(matches!(
        s.ca.policy().provider("idp").unwrap().client(Flow::Device),
        Err(Error::UnsupportedFlow)
    ));
    let mut p = policy();
    p["providers"]["idp"]["clients"]["device"] = serde_json::json!({"client_id":"D"});
    let disabled = Policy::from_json(&p.to_string()).unwrap();
    assert!(!disabled.provider("idp").unwrap().device_enabled());
    assert!(disabled
        .provider("idp")
        .unwrap()
        .client(Flow::Device)
        .is_err());
    p["providers"]["idp"]["device"] = serde_json::json!({"enabled":true});
    let enabled = Policy::from_json(&p.to_string()).unwrap();
    assert_eq!(
        enabled
            .provider("idp")
            .unwrap()
            .client(Flow::Device)
            .unwrap()
            .client_id,
        "D"
    );
    p["providers"]["idp"]["clients"]
        .as_object_mut()
        .unwrap()
        .remove("device");
    assert!(Policy::from_json(&p.to_string()).is_err());
    c.iss = "accounts.google.com".into();
    assert!(matches!(
        s.ca.issue(&c, &csr(false), "lap", &[], NOW),
        Err(Error::Denied)
    ));
}

#[test]
fn bad_proof_of_possession_and_unknown_extensions_are_refused() {
    use base64::Engine;
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let pem = CertificateParams::default()
        .serialize_request(&key)
        .unwrap()
        .pem()
        .unwrap();
    let payload = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    let mut der = base64::engine::general_purpose::STANDARD
        .decode(payload)
        .unwrap();
    *der.last_mut().unwrap() ^= 1;
    let altered = format!(
        "-----BEGIN CERTIFICATE REQUEST-----\n{}\n-----END CERTIFICATE REQUEST-----\n",
        base64::engine::general_purpose::STANDARD.encode(der)
    );
    assert!(matches!(
        VerifiedCsr::parse_pem(&altered),
        Err(Error::InvalidCsr)
    ));
    let mut params = CertificateParams::default();
    params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            &[1, 2, 3, 4],
            vec![5, 0],
        ));
    let unsupported = params.serialize_request(&key).unwrap().pem().unwrap();
    assert!(matches!(
        VerifiedCsr::parse_pem(&unsupported),
        Err(Error::InvalidCsr)
    ));
}
#[test]
fn serial_profile_is_per_certificate_even_for_one_public_key() {
    let s = Setup::new();
    let request = csr(false);
    let uri = "spiffe://example.org/host/lap/user/alice";
    let (a, _, _) = s.ca.sign(&request.key, uri, NOW, 86400).unwrap();
    let (b, _, _) = s.ca.sign(&request.key, uri, NOW + 1, 86400).unwrap();
    let a = chain(&a);
    let b = chain(&b);
    let (_, a) = x509_parser::parse_x509_certificate(&a[0]).unwrap();
    let (_, b) = x509_parser::parse_x509_certificate(&b[0]).unwrap();
    assert_ne!(
        a.raw_serial(),
        b.raw_serial(),
        "same public key reused certificate serial"
    );
    assert_eq!(a.raw_serial().len(), 16);
    assert_eq!(b.raw_serial().len(), 16);
}
#[test]
fn configured_issuer_is_stored_and_bare_google_alias_is_refused() {
    let s = Setup::new();
    let mut p = policy();
    p["providers"]["idp"]["issuer"] = "https://accounts.google.com".into();
    s.replace(p);
    let mut c = claims("alice-id");
    c.iss = "https://accounts.google.com".into();
    s.ca.issue(&c, &csr(false), "lap", &[], NOW).unwrap();
    c.iss = "accounts.google.com".into();
    assert!(matches!(
        s.ca.issue(&c, &csr(false), "lap2", &[], NOW),
        Err(Error::Denied)
    ));
    let rows = s.ca.list().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].iss, "https://accounts.google.com");
}

#[test]
fn public_root_cannot_add_unowned_trust_or_be_writable_by_other_uids() {
    let s = Setup::new();
    let cert = s.dir.join("root.crt");
    std::fs::set_permissions(&cert, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(
        matches!(
            EnrollCa::open_at(&s.dir, s.db.clone(), &s.policy, "team.hub", NOW),
            Err(Error::InvalidCaKey)
        ),
        "world-writable root certificate accepted"
    );
    std::fs::set_permissions(&cert, std::fs::Permissions::from_mode(0o644)).unwrap();
    let other = Setup::new();
    std::fs::write(&cert, format!("{}{}", s.ca.root_pem(), other.ca.root_pem())).unwrap();
    assert!(
        matches!(
            EnrollCa::open_at(&s.dir, s.db.clone(), &s.policy, "team.hub", NOW),
            Err(Error::InvalidCaKey)
        ),
        "extra enrollment trust anchor accepted"
    );
}

#[test]
fn reserved_server_identity_ends_with_root_not_host_lifetime() {
    let s = Setup::new();
    let identity = s.ca.server_identity(NOW).unwrap();
    let (_, leaf) = x509_parser::parse_x509_certificate(&identity.cert_chain_der[0]).unwrap();
    let root = chain(s.ca.root_pem());
    let (_, root) = x509_parser::parse_x509_certificate(&root[0]).unwrap();
    assert_eq!(
        leaf.validity().not_after.timestamp(),
        root.validity().not_after.timestamp()
    );
    assert!(
        leaf.validity().not_after.timestamp() > NOW + 86400,
        "server identity inherited one-day host lifetime"
    );
    assert_eq!(
        crate::fed::extract_uri_sans(&identity.cert_chain_der[0]).unwrap(),
        vec!["spiffe://example.org/xmsg/enroll"]
    );
    assert!(s
        .ca
        .server_identity(root.validity().not_after.timestamp())
        .is_err());
    let mut p = policy();
    p["lifetime_secs"] = 3600.into();
    s.replace(p);
    s.ca.reload_policy().unwrap();
    let another = s.ca.server_identity(NOW + 1).unwrap();
    let (_, leaf) = x509_parser::parse_x509_certificate(&another.cert_chain_der[0]).unwrap();
    assert_eq!(
        leaf.validity().not_after.timestamp(),
        root.validity().not_after.timestamp()
    );
}
#[test]
fn renewal_keeps_old_uri_after_policy_trust_domain_changes() {
    let s = Setup::new();
    let issued =
        s.ca.issue(&claims("alice-id"), &csr(false), "lap", &[], NOW)
            .unwrap();
    let mut p = policy();
    p["trust_domain"] = "other.example".into();
    s.replace(p);
    let renewed = s.ca.renew(&chain(&issued.cert_chain_pem), NOW + 1).unwrap();
    assert_eq!(issued.uri, renewed.uri);
    assert_eq!(
        crate::fed::extract_uri_sans(&chain(&renewed.cert_chain_pem)[0]).unwrap(),
        vec![issued.uri.clone()],
        "renewal certificate drifted to current policy trust domain"
    );
    assert_eq!(renewed.uri, "spiffe://example.org/host/lap/user/alice");
    assert_eq!(issued.spki_sha256, renewed.spki_sha256);
}

#[test]
fn renewal_rejects_other_root_even_with_known_serial_key_and_uri() {
    let s = Setup::new();
    let other = Setup::new();
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let csr = VerifiedCsr::parse_pem(
        &CertificateParams::default()
            .serialize_request(&key)
            .unwrap()
            .pem()
            .unwrap(),
    )
    .unwrap();
    let issued =
        s.ca.issue(&claims("alice-id"), &csr, "lap", &[], NOW)
            .unwrap();
    let mut p = CertificateParams::default();
    p.distinguished_name = rcgen::DistinguishedName::new();
    p.subject_alt_names = vec![rcgen::SanType::URI(issued.uri.clone().try_into().unwrap())];
    p.is_ca = rcgen::IsCa::ExplicitNoCa;
    p.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
    ];
    p.serial_number = Some(rcgen::SerialNumber::from_slice(
        &hex::decode(&issued.serial).unwrap(),
    ));
    p.not_before = time::OffsetDateTime::from_unix_timestamp(NOW - 300).unwrap();
    p.not_after = time::OffsetDateTime::from_unix_timestamp(NOW + 30 * 86400).unwrap();
    let forged = p.signed_by(&key, &other.ca.signer).unwrap();
    let presented = vec![forged.der().to_vec(), other.ca.root_der.clone()];
    let (_, leaf) = x509_parser::parse_x509_certificate(&presented[0]).unwrap();
    assert_eq!(hex::encode(leaf.raw_serial()), issued.serial);
    assert_eq!(spki_hash(leaf.public_key().raw), issued.spki_sha256);
    assert!(
        matches!(
            s.ca.renew(&presented, NOW + 8 * 86400 + 1),
            Err(Error::ReenrollRequired)
        ),
        "foreign-root known-serial certificate renewed"
    );
    assert_eq!(s.ca.list().unwrap().len(), 1);
}
#[test]
fn own_and_concrete_reserved_names_have_no_other_refusal_mask() {
    for own in [false, true] {
        let s = Setup::new();
        let mut p = policy();
        p["users"][0]["user"] = "team".into();
        s.replace(p);
        let reserved = if own { vec![] } else { vec!["team.lap".into()] };
        let host = if own { "hub" } else { "lap" };
        assert!(
            matches!(
                s.ca.issue(&claims("alice-id"), &csr(false), host, &reserved, NOW),
                Err(Error::ReservedName)
            ),
            "reserved name was issued"
        );
        assert!(s.ca.list().unwrap().is_empty());
        assert_eq!(
            s.db.lock()
                .unwrap()
                .query_row("SELECT COUNT(*) FROM enroll_bindings", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}
#[test]
fn each_deny_dimension_blocks_both_issue_and_renew() {
    for kind in ["users", "hosts", "subs", "spkis"] {
        let s = Setup::new();
        let request = csr(false);
        let issued =
            s.ca.issue(&claims("alice-id"), &request, "lap", &[], NOW)
                .unwrap();
        let mut p = policy();
        let value = match kind {
            "users" => "alice".to_string(),
            "hosts" => "lap".into(),
            "subs" => "alice-id".into(),
            _ => issued.spki_sha256.clone(),
        };
        p["deny"] = serde_json::json!({kind:[value]});
        s.replace(p);
        assert!(
            matches!(
                s.ca.issue(&claims("alice-id"), &request, "lap", &[], NOW + 1),
                Err(Error::Denied)
            ),
            "deny {kind} allowed issuance"
        );
        assert!(
            matches!(
                s.ca.renew(&chain(&issued.cert_chain_pem), NOW + 1),
                Err(Error::Denied)
            ),
            "deny {kind} allowed renewal"
        );
    }
}
#[test]
fn explicit_alias_connects_two_verified_provider_bindings() {
    let s = Setup::new();
    let mut p = policy();
    p["providers"]["other"] = serde_json::json!({"issuer":"https://other.example","clients":{"loopback":{"client_id":"other"}}});
    p["users"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({"provider":"other","sub":"other-sub","user":"alice"}));
    s.replace(p);
    s.ca.issue(&claims("alice-id"), &csr(false), "lap", &[], NOW)
        .unwrap();
    let mut c = claims("other-sub");
    c.provider = "other".into();
    c.iss = "https://other.example".into();
    assert!(matches!(
        s.ca.issue(&c, &csr(false), "second", &[], NOW),
        Err(Error::NameBound)
    ));
    s.ca.bind("alice", "other", "other-sub", NOW).unwrap();
    assert!(
        s.ca.issue(&c, &csr(false), "second", &[], NOW).is_ok(),
        "operator alias was refused"
    );
    assert!(s
        .ca
        .list()
        .unwrap()
        .iter()
        .any(|r| r.iss == "https://other.example"));
}
#[test]
fn owner_guard_precedes_loading_nonowned_file_contents() {
    use std::os::unix::fs::MetadataExt;
    let s = Setup::new();
    assert!(read_owned(&s.dir.join("root.crt"), false).is_ok());
    if crate::client::current_uid() == 0 {
        let key = s.dir.join("root.key");
        std::os::unix::fs::chown(&key, Some(65534), None).unwrap();
        assert!(
            read_owned(&key, true).is_err(),
            "nonowned fixture key accepted"
        );
    } else {
        let public_file = ["/etc/hosts", "/etc/protocols", "/etc/services"]
            .iter()
            .filter_map(|p| std::fs::canonicalize(p).ok())
            .find(|p| {
                std::fs::symlink_metadata(p).is_ok_and(|m| {
                    m.is_file()
                        && m.uid() != crate::client::current_uid()
                        && m.len() < 1024 * 1024
                        && m.permissions().mode() & 0o022 == 0
                })
            })
            .expect("nonowned public file control unavailable");
        assert!(
            read_owned(&public_file, false).is_err(),
            "owner check accepted nonowned public input"
        );
    }
}
#[test]
fn preferred_username_and_group_rules_use_only_validated_projection() {
    let s = Setup::new();
    let mut p = policy();
    p["users"] = serde_json::json!([{"provider":"idp","group":"members@example","user_from":"preferred_username"}]);
    s.replace(p);
    let mut c = claims("alice-id");
    c.groups = vec!["members@example".into()];
    c.preferred_username = Some("alice".into());
    assert!(s.ca.issue(&c, &csr(false), "lap", &[], NOW).is_ok());
    c.preferred_username = Some("alice@example".into());
    assert!(matches!(
        s.ca.issue(&c, &csr(false), "lap2", &[], NOW),
        Err(Error::InvalidRuleName(_))
    ));
}

#[test]
fn rsa_csr_is_rejected_as_unsupported_key() {
    assert!(
        matches!(
            VerifiedCsr::parse_pem(include_str!("fixtures/rsa.csr")),
            Err(Error::UnsupportedKey)
        ),
        "RSA CSR admitted"
    );
}

#[test]
fn issue_bucket_refuses_seventh_without_losing_existing_records() {
    let s = Setup::new();
    let request = csr(false);
    for n in 0..6 {
        s.ca.issue(&claims("alice-id"), &request, &format!("lap-{n}"), &[], NOW)
            .unwrap();
    }
    assert!(
        matches!(
            s.ca.issue(&claims("alice-id"), &request, "lap-next", &[], NOW),
            Err(Error::RateLimited)
        ),
        "issuance bucket was bypassed"
    );
    assert_eq!(s.ca.list().unwrap().len(), 6);
}
#[test]
fn unknown_serial_is_refused_even_with_valid_root_key_and_uri() {
    let s = Setup::new();
    let request = csr(false);
    let registered =
        s.ca.issue(&claims("alice-id"), &request, "lap", &[], NOW)
            .unwrap();
    let (unregistered, serial, _) =
        s.ca.sign(&request.key, &registered.uri, NOW, 86400)
            .unwrap();
    assert_ne!(serial, registered.serial);
    assert!(
        matches!(
            s.ca.renew(&chain(&unregistered), NOW + 1),
            Err(Error::ReenrollRequired)
        ),
        "unknown serial borrowed another certificate record"
    );
}
#[test]
fn renewed_leaf_keeps_exact_public_key_and_uri() {
    let s = Setup::new();
    let original =
        s.ca.issue(&claims("alice-id"), &csr(false), "lap", &[], NOW)
            .unwrap();
    let renewed =
        s.ca.renew(&chain(&original.cert_chain_pem), NOW + 1)
            .unwrap();
    let a = chain(&original.cert_chain_pem);
    let b = chain(&renewed.cert_chain_pem);
    let (_, a) = x509_parser::parse_x509_certificate(&a[0]).unwrap();
    let (_, b) = x509_parser::parse_x509_certificate(&b[0]).unwrap();
    assert_eq!(
        a.public_key().raw,
        b.public_key().raw,
        "renewal substituted another public key"
    );
    assert_eq!(
        crate::fed::extract_uri_sans(&chain(&renewed.cert_chain_pem)[0]).unwrap(),
        vec![original.uri]
    );
}
#[test]
fn matcher_count_refuses_both_missing_and_multiple_and_initial_bad_policy() {
    for multiple in [false, true] {
        let s = Setup::new();
        let mut p = policy();
        if multiple {
            p["users"][0]["email"] = "alice@example".into();
        } else {
            p["users"][0].as_object_mut().unwrap().remove("sub");
        }
        s.replace(p);
        assert!(
            s.ca.issue(&claims("alice-id"), &csr(false), "lap", &[], NOW)
                .is_ok(),
            "bad policy replaced previous valid mapping"
        );
        assert!(
            s.ca.reload_status().degraded,
            "invalid matcher-count policy was accepted"
        );
        assert!(
            matches!(
                EnrollCa::open_at(&s.dir, s.db.clone(), &s.policy, "team.hub", NOW),
                Err(Error::InvalidPolicy)
            ),
            "startup accepted invalid matcher-count policy"
        );
    }
}
#[test]
fn invalid_host_segment_is_refused_without_rewriting() {
    let s = Setup::new();
    assert!(
        matches!(
            s.ca.issue(&claims("alice-id"), &csr(false), "bad.host", &[], NOW),
            Err(Error::InvalidName)
        ),
        "invalid host segment was issued"
    );
    assert!(s.ca.list().unwrap().is_empty());
}

fn device_setup() -> Setup {
    let s = Setup::new();
    let mut p = policy();
    p["providers"]["idp"]["clients"]["device"] = serde_json::json!({"client_id":"D"});
    p["providers"]["idp"]["device"] = serde_json::json!({"enabled":true});
    s.replace(p);
    s
}
fn effect_counts(s: &Setup) -> Vec<i64> {
    let db = s.db.lock().unwrap();
    ["enroll_bindings", "enroll_rates", "enroll_certs"]
        .iter()
        .map(|table| {
            db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                .unwrap()
        })
        .collect()
}
#[test]
fn device_projection_is_read_only_and_approved_issue_succeeds() {
    let s = device_setup();
    let request = csr(false);
    let c = claims("alice-id");
    let proposed = s.ca.project_device(&c, &request, "laptop", &[]).unwrap();
    assert_eq!(proposed.user(), "alice");
    assert_eq!(proposed.issuer(), c.iss);
    assert_eq!(proposed.sub(), c.sub);
    assert_eq!(proposed.host(), "laptop");
    assert_eq!(proposed.node_name(), "alice.laptop");
    assert_eq!(proposed.spki_sha256(), spki_hash(&request.spki_der()));
    assert_eq!(
        effect_counts(&s),
        [0, 0, 0],
        "projection spent enrollment effects before approval"
    );
    let issued =
        s.ca.issue_device_approved(&c, &request, "laptop", &[], &proposed, NOW, || true)
            .unwrap();
    assert_eq!(issued.uri, "spiffe://example.org/host/laptop/user/alice");
    assert_eq!(effect_counts(&s), [1, 1, 1]);
}
#[test]
fn device_approval_refuses_each_projection_mismatch_without_effects() {
    let s = device_setup();
    let request = csr(false);
    let c = claims("alice-id");
    let proposed = s.ca.project_device(&c, &request, "laptop", &[]).unwrap();
    for field in [
        "provider",
        "user",
        "issuer",
        "sub",
        "host",
        "node_name",
        "spki_sha256",
        "policy_digest",
    ] {
        let mut altered = proposed.clone();
        match field {
            "provider" => altered.provider.push('x'),
            "user" => altered.user.push('x'),
            "issuer" => altered.issuer.push('x'),
            "sub" => altered.sub.push('x'),
            "host" => altered.host.push('x'),
            "node_name" => altered.node_name.push('x'),
            "spki_sha256" => altered.spki_sha256.push('x'),
            _ => altered.policy_digest.push(0),
        }
        assert!(
            matches!(
                s.ca.issue_device_approved(&c, &request, "laptop", &[], &altered, NOW, || true),
                Err(Error::ApprovalMismatch)
            ),
            "approval accepted changed {field}"
        );
        assert_eq!(
            effect_counts(&s),
            [0, 0, 0],
            "mismatch wrote effects: {field}"
        );
    }
    assert!(
        matches!(
            s.ca.issue_device_approved(
                &claims("other-id"),
                &request,
                "laptop",
                &[],
                &proposed,
                NOW,
                || true
            ),
            Err(Error::ApprovalMismatch)
        ),
        "same-user different principal accepted"
    );
    assert!(
        matches!(
            s.ca.issue_device_approved(&c, &csr(false), "laptop", &[], &proposed, NOW, || true),
            Err(Error::ApprovalMismatch)
        ),
        "different CSR accepted"
    );
    assert_eq!(effect_counts(&s), [0, 0, 0]);
}
#[test]
fn device_approval_invalidated_by_current_policy_and_reserved_name() {
    let s = device_setup();
    let request = csr(false);
    let c = claims("alice-id");
    let proposed = s.ca.project_device(&c, &request, "laptop", &[]).unwrap();
    assert!(matches!(
        s.ca.issue_device_approved(
            &c,
            &request,
            "laptop",
            &["alice.laptop".into()],
            &proposed,
            NOW,
            || true
        ),
        Err(Error::ReservedName)
    ));
    let mut p = policy();
    p["providers"]["idp"]["clients"]["device"] = serde_json::json!({"client_id":"D"});
    p["providers"]["idp"]["device"] = serde_json::json!({"enabled":true});
    p["issue_per_hour"] = 7.into();
    s.replace(p);
    assert!(
        matches!(
            s.ca.issue_device_approved(&c, &request, "laptop", &[], &proposed, NOW, || true),
            Err(Error::ApprovalMismatch)
        ),
        "policy change reused old approval"
    );
    assert_eq!(effect_counts(&s), [0, 0, 0]);
    let fresh = s.ca.project_device(&c, &request, "laptop", &[]).unwrap();
    s.ca.issue_device_approved(&c, &request, "laptop", &[], &fresh, NOW, || true)
        .unwrap();
}
#[test]
fn device_guard_runs_after_database_wait_before_any_effect() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let s = device_setup();
    let request = csr(false);
    let c = claims("alice-id");
    let proposed = s.ca.project_device(&c, &request, "laptop", &[]).unwrap();
    let valid = AtomicBool::new(true);
    let called = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let locked = s.db.lock().unwrap();
        let (sent, recv) = std::sync::mpsc::channel();
        let (s, c, request, proposed, called, valid) =
            (&s, &c, &request, &proposed, &called, &valid);
        let worker = scope.spawn(move || {
            sent.send(()).unwrap();
            s.ca.issue_device_approved(c, request, "laptop", &[], proposed, NOW, || {
                assert!(
                    s.db.try_lock().is_err(),
                    "approval guard ran before SQL mutex acquisition"
                );
                called.store(true, Ordering::SeqCst);
                valid.load(Ordering::SeqCst)
            })
        });
        recv.recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        valid.store(false, Ordering::SeqCst);
        drop(locked);
        assert!(
            matches!(worker.join().unwrap(), Err(Error::ApprovalExpired)),
            "expired guard accepted after SQL wait"
        );
    });
    assert!(called.load(Ordering::SeqCst));
    assert_eq!(
        effect_counts(&s),
        [0, 0, 0],
        "expired approval spent effects"
    );
}

#[test]
fn device_deadline_during_issuance_rolls_back_all_effects_and_supersession() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let s = device_setup();
    let c = claims("alice-id");
    let old = s.ca.issue(&c, &csr(false), "laptop", &[], NOW).unwrap();
    let before = effect_counts(&s);
    let request = csr(false);
    let proposed = s.ca.project_device(&c, &request, "laptop", &[]).unwrap();
    let calls = AtomicUsize::new(0);
    assert!(
        matches!(
            s.ca.issue_device_approved(&c, &request, "laptop", &[], &proposed, NOW, || calls
                .fetch_add(1, Ordering::SeqCst)
                == 0),
            Err(Error::ApprovalExpired)
        ),
        "deadline during signing committed enrollment"
    );
    assert_eq!(effect_counts(&s), before, "expired signing spent effects");
    let superseded: Option<i64> =
        s.db.lock()
            .unwrap()
            .query_row(
                "SELECT superseded_at FROM enroll_certs WHERE serial=?1",
                [&old.serial],
                |r| r.get(0),
            )
            .unwrap();
    assert_eq!(
        superseded, None,
        "expired signing superseded existing certificate"
    );
    s.ca.issue_device_approved(&c, &request, "laptop", &[], &proposed, NOW, || true)
        .unwrap();
}

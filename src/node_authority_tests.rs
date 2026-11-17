use super::*;

fn patterns(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn prospective_host_and_pod_alias_has_no_first_owner() {
    let rules = patterns(&[
        "spiffe://fleet/host/*/user/*",
        "spiffe://fleet/ns/genie/sa/*",
    ]);
    assert_eq!(
        pattern_alias_owner("guard.genie", &rules),
        PatternAliasOwner::Ambiguous,
        "host and pod possibilities must refuse before either arrives"
    );
    assert_eq!(
        pattern_alias_owner("alice.laptop", &rules),
        PatternAliasOwner::Unique("spiffe://fleet/host/laptop/user/alice".into()),
        "unrelated host alias must remain uniquely owned"
    );
}

#[test]
fn trust_domains_and_wildcard_authority_are_identity_distinctions() {
    let rules = patterns(&["spiffe://one/host/*/user/*", "spiffe://two/host/*/user/*"]);
    assert_eq!(
        pattern_alias_owner("alice.laptop", &rules),
        PatternAliasOwner::Ambiguous,
        "distinct trust domains cannot share a derived alias"
    );
    let wildcard = patterns(&["spiffe://*/host/*/user/*"]);
    assert_eq!(
        pattern_alias_owner("alice.laptop", &wildcard),
        PatternAliasOwner::Ambiguous,
        "one wildcard authority must supply distinct identity witnesses"
    );
}

#[test]
fn structural_wildcards_must_consider_both_uri_forms() {
    let rules = patterns(&["spiffe://fleet/*/genie/*/guard"]);
    assert_eq!(
        pattern_alias_owner("guard.genie", &rules),
        PatternAliasOwner::Ambiguous,
        "a single structural-wildcard pattern can admit two URI forms"
    );
    assert_eq!(
        pattern_alias_owner("alice.genie", &rules),
        PatternAliasOwner::Unclaimed,
        "unmatched name components are not claimed"
    );
}

#[test]
fn overlapping_patterns_for_one_uri_are_not_two_owners() {
    let rules = patterns(&[
        "spiffe://fleet/host/*/user/*",
        "spiffe://fleet/host/laptop/user/*",
        "spiffe://fleet/host/*/user/alice",
    ]);
    assert_eq!(
        pattern_alias_owner("alice.laptop", &rules),
        PatternAliasOwner::Unique("spiffe://fleet/host/laptop/user/alice".into()),
        "same full URI must be deduplicated across matching patterns"
    );
    assert!(
        ambiguous_alias_classes(&rules).is_empty(),
        "same-form same-domain overlaps are not ambiguous classes"
    );
}

#[test]
fn disjoint_names_and_non_node_patterns_have_no_false_ambiguity() {
    let rules = patterns(&[
        "spiffe://one/host/*/user/alice",
        "spiffe://two/host/*/user/bob",
        "spiffe://one/xmsg/enroll",
        "spiffe://one/ns/name.with.dot/sa/*",
    ]);
    assert_eq!(
        pattern_alias_owner("alice.laptop", &rules),
        PatternAliasOwner::Unique("spiffe://one/host/laptop/user/alice".into()),
        "disjoint users must remain usable"
    );
    assert!(
        ambiguous_alias_classes(&rules).is_empty(),
        "impossible or disjoint projections must not warn"
    );
    for alias in ["", "alice", ".laptop", "alice.", "alice.a.b"] {
        assert_eq!(
            pattern_alias_owner(alias, &rules),
            PatternAliasOwner::Unclaimed,
            "invalid derived alias has no prospective owner"
        );
    }
}

#[test]
fn diagnostic_classes_are_deduplicated_ordered_and_do_not_expose_uris() {
    let rules = patterns(&[
        "spiffe://private-one/host/*/user/*",
        "spiffe://private-one/ns/genie/sa/*",
        "spiffe://private-one/ns/genie/sa/*",
        "spiffe://private-two/host/*/user/*",
    ]);
    let classes = ambiguous_alias_classes(&rules);
    assert_eq!(
        classes.len(),
        2,
        "each projected alias class is emitted once"
    );
    assert_eq!(
        classes[0].alias, "*.*",
        "diagnostic classes have deterministic alias order"
    );
    assert_eq!(
        classes[1].alias, "*.genie",
        "narrow mixed-form class is retained"
    );
    assert_eq!(
        classes[1].forms,
        vec!["host/user", "ns/sa"],
        "diagnostic uses only fixed colliding-form labels"
    );
    assert!(
        classes[0].multiple_domains && classes[1].multiple_domains,
        "cross-domain class records a fixed multiple-domain flag"
    );
    let encoded = serde_json::to_string(&classes).unwrap();
    assert!(
        !encoded.contains("spiffe://")
            && !encoded.contains("private-one")
            && !encoded.contains("private-two"),
        "diagnostics must not expose full URI witnesses or trust domains"
    );
    let mut reversed = rules.clone();
    reversed.reverse();
    assert_eq!(
        classes,
        ambiguous_alias_classes(&reversed),
        "diagnostic order cannot depend on config order"
    );
}

#[test]
fn wildcard_domain_and_structural_self_classes_are_reported() {
    let classes = ambiguous_alias_classes(&patterns(&["spiffe://*/host/laptop/user/alice"]));
    assert_eq!(
        classes,
        vec![AmbiguousAliasClass {
            alias: "alice.laptop".into(),
            forms: vec!["host/user".into()],
            multiple_domains: true
        }],
        "wildcard authority alone is an ambiguous alias class"
    );
    let classes = ambiguous_alias_classes(&patterns(&["spiffe://fleet/*/genie/*/guard"]));
    assert_eq!(
        classes,
        vec![AmbiguousAliasClass {
            alias: "guard.genie".into(),
            forms: vec!["host/user".into(), "ns/sa".into()],
            multiple_domains: false
        }],
        "structural wildcard alone reports both forms"
    );
}

#[test]
fn percent_spellings_stay_raw_and_are_not_normalized() {
    let rules = patterns(&["spiffe://fleet/host/*/user/*"]);
    assert_eq!(
        pattern_alias_owner("alice.%61", &rules),
        PatternAliasOwner::Unique("spiffe://fleet/host/%61/user/alice".into()),
        "prospective identity preserves raw percent spelling"
    );
}

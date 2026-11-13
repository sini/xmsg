"""Production hub source faults; only named assertion failures are mutant kills."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
CASES = [
    ("resolver-pooling", "src/fed.rs", "if self.hub_certificate_allowed(uri, leaf, intermediates, UnixTime::now()) {", "if hub.patterns.iter().any(|p| spiffe_uri_matches_pattern(uri,p)) && verify_cert_chain(leaf, intermediates, &self.all_ca_anchors(), UnixTime::now(), webpki::KeyUsage::client_auth()).is_ok() {", "pattern_bundle_limits_tls_and_resolver_and_admits_leaf", "resolver pooled enrollment anchors"),
    ("tls-pooling", "src/fed.rs", "if self\n                    .peers\n                    .hub_certificate_allowed(uri, end_entity, intermediates, now)\n                {", "if self.peers.hub.as_ref().unwrap().patterns.iter().any(|p| spiffe_uri_matches_pattern(uri,p)) && verify_cert_chain(end_entity, intermediates, &self.peers.all_ca_anchors(), now, webpki::KeyUsage::client_auth()).is_ok() {", "pattern_bundle_limits_tls_and_resolver_and_admits_leaf", "TLS pooled enrollment anchors"),
    ("name-overlap", "src/fed.rs", "if hub.pattern_cas[a] != hub.pattern_cas[b] {", "if false && hub.pattern_cas[a] != hub.pattern_cas[b] {", "cross_bundle_restart_takeover_cannot_be_configured", "cross-bundle restart takeover observed"),
    ("keyword-stars", "src/fed.rs", "(segments[0] == first || segments[0] == \"*\")\n            && (segments[2] == second || segments[2] == \"*\")", "segments[0] == first && segments[2] == second", "cross_bundle_names_and_spanning_rules_are_refused", "called `Result::unwrap_err()` on an `Ok` value"),
    ("spanning-rule", "src/fed.rs", "if compatible.any(|bundle| bundle != first) {", "if false && compatible.any(|bundle| bundle != first) {", "cross_bundle_names_and_spanning_rules_are_refused", "called `Result::unwrap_err()` on an `Ok` value"),
    ("leaf-rule", "src/fed.rs", "leaf: rule.is_some_and(|r| r.leaf),", "leaf: rule.is_some_and(|r| r.leaf) && false,", "pattern_bundle_limits_tls_and_resolver_and_admits_leaf", "assertion failed: peer.leaf"),
    ("global-rows", "src/storage.rs", "admitted_usage.rows < ?14", "?14 IS NOT NULL", "admitted_global_caps_are_durable_and_leave_concrete_mailboxes_unchanged", "global admitted cap lost across reopen"),
    ("global-bytes", "src/storage.rs", "admitted_usage.stored_bytes <= ?15 - ?12", "?15 >= ?12", "admitted_global_caps_are_durable_and_leave_concrete_mailboxes_unchanged", "global admitted byte sum was not bounded"),
    ("prune-retains-entry", "src/fed.rs", "admitted.remove(&name);", "admitted.get(&name);", "expired_admitted_entry_is_pruned_only_when_mailbox_empty", "assertion failed: peers.get_peer_config(\"carol.lap\").is_none()"),
    ("bare-bundle-ambiguity", "src/fed.rs", "if bundles.len() != 1 {", "if bundles.is_empty() {", "cross_bundle_names_and_spanning_rules_are_refused", "called `Result::unwrap_err()` on an `Ok` value"),
    ("canonical-mailbox-key", "src/fed.rs", "peer: peer_name.to_string(),", "peer: peer_cfg.identities.as_ref().unwrap()[0].clone(),", "admitted_leaf_queues_pulls_acks_and_recovers_after_hub_restart", "admitted mailbox not keyed by canonical name"),
    ("concrete-classification", "src/fed.rs", "let admitted = !current_peers.contains_concrete_name(peer_name);", "let admitted = true;", "queue_classifies_admitted_and_concrete_leaves_for_global_budget", "concrete leaf counted toward aggregate budget"),
    ("admitted-classification", "src/fed.rs", "let admitted = !current_peers.contains_concrete_name(peer_name);", "let admitted = false;", "queue_classifies_admitted_and_concrete_leaves_for_global_budget", "admitted queue bypassed aggregate budget"),
]
LOOKUPS = [
    ("send-admitted-lookup", "pub async fn send_federated_message_with(", ".get_peer_config(peer_name)", ".get(peer_name).cloned()", "called `Result::unwrap()` on an `Err` value: UnknownPeer"),
    ("queue-admitted-lookup", "fn queue_leaf_mailbox_message_in(", ".get_peer_config(peer_name)", ".get(peer_name).cloned()", "called `Result::unwrap()` on an `Err` value: UnknownPeer"),
    ("attachment-admitted-lookup", "pub async fn fetch_attachment_chunk(", ".get_peer_config(upstream)", ".get(upstream).cloned()", "admitted leaf attachment lookup did not enqueue its query"),
]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case',action='append')
    parser.add_argument('--list',action='store_true')
    args=parser.parse_args()
    cases=[dict(label=l,file=f,old=o,new=n,test=t,literal=x,start='') for l,f,o,n,t,x in CASES]
    cases += [dict(label=l,file='src/fed.rs',old=o,new=n,test='admitted_leaf_queues_pulls_acks_and_recovers_after_hub_restart',literal=x,start=start) for l,start,o,n,x in LOOKUPS]
    if args.list:
        print('\n'.join(c['label'] for c in cases));return
    labels={case['label'] for case in cases}
    assert not args.case or set(args.case)<=labels, 'unknown mutant label'
    expected=sum(not args.case or case['label'] in args.case for case in cases)
    assert expected > 0
    out=ROOT/'.artifacts/enroll-hub-mutants';out.mkdir(parents=True,exist_ok=True)
    env={**os.environ,'CARGO_TARGET_DIR':str(ROOT/'target/enroll-hub-mutants'),'CARGO_BUILD_JOBS':'4'}
    receipts=[]
    with tempfile.TemporaryDirectory(prefix='enroll-hub-mutants-') as directory:
        tree=Path(directory)
        with tarfile.open(fileobj=io.BytesIO(subprocess.check_output(['git','-C',str(ROOT),'archive','HEAD']))) as files:files.extractall(tree,filter='data')
        # Include current test-only refinements when preparing a milestone.
        (tree/'tests/enroll_hub.rs').write_bytes((ROOT/'tests/enroll_hub.rs').read_bytes())
        for case in cases:
            if args.case and case['label'] not in args.case:continue
            file=tree/case['file'];original=file.read_text();offset=original.index(case['start']) if case['start'] else 0
            assert original[offset:].count(case['old'])>=1,case['label']
            if not case['start']:assert original.count(case['old'])==1,case['label']
            testfile=tree/'tests/enroll_hub.rs';testsource=testfile.read_text();nonce=uuid.uuid4().hex
            testfile.write_text(re.sub(r'(\bfn '+re.escape(case['test'])+r'\(\)\s*\{)',lambda m:m[0]+'\n eprintln!("enroll-hub-arm:'+nonce+'");',testsource,count=1))
            command=['cargo','test','--locked','--test','enroll_hub',case['test'],'--','--exact','--nocapture']
            def run(arm):
                result=subprocess.run(command,cwd=tree,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=180)
                (out/(case['label']+'-'+arm+'.log')).write_text(result.stdout)
                assert 'enroll-hub-arm:'+nonce in result.stdout,(case['label'],arm,'nonce did not execute')
                return result
            try:
                baseline=run('baseline');assert baseline.returncode==0 and '1 passed; 0 failed' in baseline.stdout,case['label']
                mutated=original[:offset]+original[offset:].replace(case['old'],case['new'],1);file.write_text(mutated)
                red=run('red');assert red.returncode==101 and case['literal'] in red.stdout,(case['label'],'wrong RED',red.stdout[-2500:])
                file.write_text(original);green=run('restored');assert green.returncode==0 and '1 passed; 0 failed' in green.stdout,case['label']
                receipts.append({**case,'nonce':nonce,'production_sha256':hashlib.sha256(mutated.encode()).hexdigest(),'red_exit':101,'restored_exit':0})
                (out/'results.json').write_text(json.dumps(receipts,indent=2)+'\n')
                print(case['label']+': GREEN / assertion RED / restored GREEN',flush=True)
            finally:
                file.write_text(original);testfile.write_text(testsource)
    assert len(receipts)==expected, (len(receipts),expected)
    print('enroll-hub-mutants-complete:'+str(len(receipts)),flush=True)
if __name__=='__main__':main()

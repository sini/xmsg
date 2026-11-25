"""Require every registered runtime fault's isolated semantic RED and restored GREEN."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import shutil
import tempfile
import uuid

CONTROLS = {
    'added_source_refused', 'source_mode_refused', 'source_symlink_refused',
    'artifact_tamper_refused', 'wrong_child_nonce_refused', 'unrelated_session_refused',
    'held_process_group_reaped', 'source_tamper_refused', 'outside_artifact_refused',
    'cached_artifact_refused', 'wrong_nonce_refused',
}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def raw(base, name):
    candidate = base / name
    require(not candidate.is_symlink() and candidate.is_file()
            and candidate.resolve().is_relative_to(base.resolve()), 'unsafe/missing receipt: ' + name)
    return candidate.read_bytes()


def checked_hash(base, name, expected):
    data = raw(base, name)
    require(digest(data) == expected, 'receipt hash mismatch: ' + name)
    return data


def complete(root, artifacts, expected_head):
    require(re.fullmatch(r'[0-9a-f]{40}', expected_head) is not None, 'invalid expected head')
    require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
            == expected_head, 'completion checkout head mismatch')
    manifest_path = root / 'extensions/executor/fixtures/runtime-mutants.json'
    runner_path = root / 'extensions/executor/scripts/control_faults.py'
    cases = json.loads(manifest_path.read_bytes())
    identifiers = [case['id'] for case in cases]
    by_id = {case['id']: case for case in cases}
    require(len(identifiers) == len(set(identifiers)) and len(identifiers) >= 6,
            'runtime registry must contain unique cases for every shard')
    require(all(re.fullmatch(r'[a-z][a-z0-9-]*', name) for name in identifiers), 'unsafe registry ID')
    spec = importlib.util.spec_from_file_location('reviewed_controller', runner_path)
    controller = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(controller)
    contents, modes = controller.inventory(root)
    expected_hashes = {name: digest(data) for name, data in contents.items()}
    expected_modes = json.loads(json.dumps(modes))
    receipts = sorted(artifacts.rglob('shard-receipt.json'))
    require(len(receipts) == 6, 'missing/extra runtime shard receipts')
    seen_shards, nonces, pairs, summaries = set(), set(), set(), []
    for receipt_path in receipts:
        base = receipt_path.parent
        receipt = json.loads(raw(base, receipt_path.name))
        shard = receipt['shard']
        require(type(shard) is int and 0 <= shard < 6 and shard not in seen_shards, 'duplicate/invalid shard')
        seen_shards.add(shard)
        expected_cases = identifiers[shard::6]
        require(receipt['cases'] == expected_cases and bool(expected_cases), 'shard selection mismatch')
        require(receipt['head'] == expected_head, 'shard checkout head mismatch')
        require(receipt['manifest_sha256'] == digest(manifest_path.read_bytes()), 'manifest hash mismatch')
        require(receipt['runner_sha256'] == digest(runner_path.read_bytes()), 'reviewed runner hash mismatch')
        daemon_json = checked_hash(base, 'daemon-build.jsonl', receipt['daemon_compiler_json_sha256'])
        daemon = receipt['fixture_binary_inputs']['XMSG_EXECUTOR_FIXTURE_DAEMON']
        daemon_rows = [row for line in daemon_json.splitlines() if line.startswith(b'{')
                       for row in [json.loads(line)] if row.get('reason') == 'compiler-artifact'
                       and row.get('executable') == daemon['file']]
        require(len(daemon_rows) == 1 and daemon_rows[0]['profile']['test'] is False
                and 'daemon' in daemon_rows[0]['features'] and 'test-hooks' not in daemon_rows[0]['features'], 'candidate daemon compiler receipt mismatch')
        proof = base / 'proof'
        ledger = json.loads(raw(proof, 'results.json'))
        require(ledger['status'] == 'passed' and ledger['head'] == expected_head, 'incomplete/wrong-head ledger')
        require(ledger['protected_hashes'] == expected_hashes and ledger['protected_inventory'] == expected_modes,
                'checkout protected source/type/mode mismatch')
        require(set(ledger['controls']) == CONTROLS and all(v is True for v in ledger['controls'].values()),
                'missing/failed source and cleanup controls')
        require(ledger['fixture_binary_inputs'] == receipt['fixture_binary_inputs'], 'candidate fixture mismatch')
        arms = ledger['arms']
        expected_pairs = {(case, phase) for case in expected_cases for phase in ('red', 'green')}
        actual_pairs = [(arm['case'], arm['phase']) for arm in arms]
        require(len(actual_pairs) == len(expected_pairs) and set(actual_pairs) == expected_pairs, 'missing/duplicate/extra arms')
        for command in ledger['commands']:
            label = command['label']
            require(re.fullmatch(r'[a-z][a-z0-9-]*', label) is not None, 'unsafe command label')
            require(command['status'] == 'exited' and command['parent_reaped'] is True, 'unreaped/incomplete command')
            checked_hash(proof, label + '.stdout', command['stdout_sha256'])
            checked_hash(proof, label + '.stderr', command['stderr_sha256'])
        for arm in arms:
            pair = (arm['case'], arm['phase'])
            require(pair not in pairs, 'case arm repeated across shards')
            pairs.add(pair)
            nonce = arm['nonce']
            require(str(uuid.UUID(nonce)) == nonce and nonce not in nonces, 'duplicate/invalid arm nonce')
            nonces.add(nonce)
            case = by_id[arm['case']]
            require(arm['test'] == case['test_module'] + '::' + case['test'], 'wrong named witness')
            red = arm['phase'] == 'red'
            require(arm['status'] == 'executed' and arm['build_exit'] == 0
                    and arm['exit'] == (101 if red else 0), 'compile/timeout/nonsemantic arm result')
            require(arm['compiler_fresh'] is False and arm['source_and_artifact_guards'] is True
                    and arm['compiled_nonce_observed'] is True
                    and arm['isolated_build_tree_removed_after_receipts'] is True, 'arm proof guard mismatch')
            require(not red or arm['assertion_present'] is True, 'wrong failing assertion')
            if red:
                require(arm['outcome'] == 'semantic_kill', 'RED is not a semantic kill')
            stem = '-'.join(pair)
            log = checked_hash(proof, stem + '.log', arm['log_sha256'])
            require(nonce.encode() in log, 'executed log lacks compiled nonce')
            require(not red or case['assertion'].encode() in log, 'raw log specific assertion mismatch')
            compiler = checked_hash(proof, stem + '-build.jsonl', arm['compiler_json_sha256'])
            checked_hash(proof, stem + '-build.stderr', arm['compiler_stderr_sha256'])
            candidates = [row for line in compiler.splitlines() if line.startswith(b'{')
                          for row in [json.loads(line)] if row.get('reason') == 'compiler-artifact'
                          and row.get('executable') == arm['artifact']]
            require(len(candidates) == 1 and candidates[0]['fresh'] is False
                    and candidates[0]['profile']['test'] is True, 'compiler artifact/freshness mismatch')
            summaries.append({'case': pair[0], 'phase': pair[1], 'nonce': nonce,
                              'log_sha256': arm['log_sha256'], 'artifact_sha256': arm['artifact_sha256']})
    require(seen_shards == set(range(6)) and len(nonces) == len(identifiers) * 2
            and pairs == {(case, phase) for case in identifiers for phase in ('red', 'green')},
            'runtime registry completion mismatch')
    return {'head': expected_head, 'cases': len(identifiers), 'red': len(identifiers),
            'green': len(identifiers), 'nonces': len(nonces),
            'shards': 6, 'controls_per_shard': 11, 'evidence_class': 'fake_only',
            'manifest_sha256': digest(manifest_path.read_bytes()),
            'runner_sha256': digest(runner_path.read_bytes()), 'arms': summaries}



def refusal_controls(root, artifacts, head):
    mutations = (
        ('missing-arm', lambda data: data['arms'].pop()),
        ('duplicate-nonce', lambda data: data['arms'][0].update(nonce=data['arms'][1]['nonce'])),
        ('wrong-head', lambda data: data.update(head='0' * 40)),
        ('failed-control', lambda data: data['controls'].update(source_tamper_refused=False)),
        ('wrong-log-hash', lambda data: data['arms'][0].update(log_sha256='0' * 64)),
        ('cached-artifact', lambda data: data['arms'][0].update(compiler_fresh=True)),
        ('unreaped-command', lambda data: data['commands'][0].update(parent_reaped=False)),
        ('wrong-witness', lambda data: data['arms'][0].update(test='unrelated::test')),
    )
    for name, mutate in mutations:
        with tempfile.TemporaryDirectory(prefix='executor-completion-refusal-') as temporary:
            copied = Path(temporary) / 'receipts'
            shutil.copytree(artifacts, copied)
            ledger_path = sorted(copied.rglob('results.json'))[0]
            data = json.loads(ledger_path.read_bytes())
            mutate(data)
            ledger_path.write_text(json.dumps(data))
            try:
                complete(root, copied, head)
            except (ValueError, KeyError):
                continue
            raise ValueError('completion refusal control survived: ' + name)
    return len(mutations)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--head', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--refusal-controls', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    result = complete(root, args.artifacts.resolve(), args.head)
    if args.refusal_controls:
        result['refusal_controls'] = refusal_controls(root, args.artifacts.resolve(), args.head)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key != 'arms'}, sort_keys=True))


if __name__ == '__main__':
    main()

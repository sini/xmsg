#!/usr/bin/env python3
"""Run scoped source faults, atomically persisting each completed arm."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import uuid


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--case', action='append', default=[])
    args = parser.parse_args()
    crate = Path(__file__).resolve().parent.parent
    root = crate.parent.parent
    cases = json.loads(args.manifest.read_text())
    if args.case:
        cases = [case for case in cases if case['id'] in args.case]
        if set(args.case) != {case['id'] for case in cases}:
            raise ValueError('unknown or duplicate case selection')
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    protected = sorted(list((crate / 'src').glob('*.rs')) + list((crate / 'tests').glob('*.rs')))
    originals = {file: file.read_bytes() for file in protected}
    hashes = {str(file.relative_to(root)): digest(data) for file, data in originals.items()}
    ledger = {'status': 'running', 'production_and_fixture_hashes': hashes, 'arms': []}

    def persist():
        temporary = evidence / 'results.json.new'
        with temporary.open('w') as out:
            json.dump(ledger, out, indent=2)
            out.flush()
            os.fsync(out.fileno())
        temporary.replace(evidence / 'results.json')

    def verify(expected):
        for file, data in expected.items():
            if file.read_bytes() != data:
                raise RuntimeError('source guard failed: ' + str(file.relative_to(root)))

    def arm(case, phase, expected_sources):
        verify(expected_sources)
        nonce = str(uuid.uuid4())
        stem = case['id'] + '-' + phase
        record = {'case': case['id'], 'phase': phase, 'nonce': nonce, 'status': 'building', 'source_hashes': {str(file.relative_to(root)): digest(data) for file, data in expected_sources.items()}}
        ledger['arms'].append(record)
        persist()
        build = subprocess.run(['cargo', 'test', '--manifest-path', str(crate / 'Cargo.toml'), '--locked', '-j4', '--lib', '--no-run', '--message-format=json'], cwd=root, capture_output=True, timeout=180)
        (evidence / (stem + '-build.jsonl')).write_bytes(build.stdout)
        (evidence / (stem + '-build.stderr')).write_bytes(build.stderr)
        record.update({'build_exit': build.returncode, 'status': 'compiled' if build.returncode == 0 else 'compile_failed'})
        persist()
        if build.returncode:
            raise RuntimeError('compilation failure is not a kill: ' + stem)
        artifacts = [json.loads(line) for line in build.stdout.splitlines() if line.startswith(b'{')]
        binaries = [a['executable'] for a in artifacts if a.get('reason') == 'compiler-artifact' and a.get('executable') and a.get('target', {}).get('kind') == ['lib']]
        if len(binaries) != 1:
            raise RuntimeError('expected exactly one library-test executable')
        binary = Path(binaries[0])
        binary_hash = digest(binary.read_bytes())
        test = 'control::tests::' + case['test']
        result = subprocess.run([str(binary), '--exact', test, '--nocapture'], cwd=root, capture_output=True, timeout=30, env={**os.environ, 'XMSG_EXECUTOR_PROOF_NONCE': nonce})
        output = result.stdout + result.stderr
        (evidence / (stem + '.log')).write_bytes(output)
        verify(expected_sources)
        if digest(binary.read_bytes()) != binary_hash:
            raise RuntimeError('executed artifact changed')
        record.update({'test': test, 'exit': result.returncode, 'artifact_sha256': binary_hash, 'artifact': str(binary), 'log_sha256': digest(output), 'assertion_present': case['assertion'].encode() in output, 'source_and_artifact_guards': True})
        record['status'] = 'executed'
        persist()
        if phase == 'red':
            if result.returncode != 101 or not record['assertion_present'] or b'1 failed' not in output:
                raise RuntimeError('fault survived or failed for the wrong reason: ' + stem)
        elif result.returncode or b'1 passed' not in output:
            raise RuntimeError('restored test is not green: ' + stem)
        print(stem + ': exit=' + str(result.returncode) + ' nonce=' + nonce, flush=True)

    persist()
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        for case in cases:
            file = root / case['file']
            original = originals[file]
            needle = case['needle'].encode()
            if original.count(needle) != 1:
                raise RuntimeError('anchor count != 1: ' + case['id'])
            mutant = original.replace(needle, case['replacement'].encode(), 1)
            if mutant == original:
                raise RuntimeError('no-op mutation')
            file.write_bytes(mutant)
            try:
                arm(case, 'red', {**originals, file: mutant})
            finally:
                if file.read_bytes() != mutant:
                    raise RuntimeError('refusing to overwrite external source edit')
                file.write_bytes(original)
            arm(case, 'green', originals)
        ledger['status'] = 'passed'
        ledger['completed_at'] = time.time()
        persist()
    except BaseException as error:
        ledger['status'] = 'failed'
        ledger['error'] = str(error)
        persist()
        raise
    finally:
        verify(originals)


if __name__ == '__main__':
    main()

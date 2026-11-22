#!/usr/bin/env python3
"""Isolate each source-fault arm and atomically persist its provenance."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import signal
import subprocess
import time
import uuid


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify(base, expected):
    for relative, data in expected.items():
        if (base / relative).read_bytes() != data:
            raise RuntimeError('source guard failed: ' + relative)


def artifact(output, target, require_fresh=True):
    records = [json.loads(line) for line in output.splitlines() if line.startswith(b'{')]
    binaries = [a for a in records if a.get('reason') == 'compiler-artifact' and a.get('executable') and a.get('target', {}).get('kind') == ['lib']]
    if len(binaries) != 1:
        raise RuntimeError('expected exactly one library-test executable')
    item = binaries[0]
    binary = Path(item['executable'])
    if binary.is_symlink() or not binary.resolve().is_relative_to(target.resolve()):
        raise RuntimeError('artifact isolation guard failed')
    if require_fresh and item.get('fresh') is not False:
        raise RuntimeError('cached artifact refused')
    return binary, item.get('fresh')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--case', action='append', default=[])
    parser.add_argument('--preflight', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    cases = json.loads(args.manifest.read_text())
    identifiers = [case['id'] for case in cases]
    if len(identifiers) != len(set(identifiers)) or any(not re.fullmatch(r'[a-z][a-z0-9-]*', name) for name in identifiers):
        raise ValueError('case IDs must be unique safe path components')
    for case in cases:
        relative=Path(case['file'])
        if relative.is_absolute() or '..' in relative.parts or relative.parts[0]!='src':
            raise ValueError('mutation must target production source')
        source=(root/relative).read_text()
        if source.count(case['needle'])!=1 or case['needle']==case['replacement']:
            raise ValueError('production anchor is missing, ambiguous or a no-op: '+case['id'])
        offset=source.index(case['needle'])
        for marker in re.finditer(r'#\[cfg\(test\)\]\s*(?:pub\([^)]*\)\s+)?mod\s+tests',source):
            if offset>=marker.start():raise ValueError('test-only mutation refused')
        test_file=case.get('test_file','src/install/mod.rs')
        if (root/test_file).read_text().count('fn '+case['test']+'() {')!=1:
            raise ValueError('killing-function anchor is missing or ambiguous')
    if args.preflight:
        print(json.dumps({'status':'anchors-only-not-compilation','cases':identifiers,'source_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()}))
        return
    if args.case:
        if len(args.case) != len(set(args.case)):
            raise ValueError('duplicate case selection')
        cases = [case for case in cases if case['id'] in args.case]
        if set(args.case) != {case['id'] for case in cases}:
            raise ValueError('unknown case selection')
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    excluded = {'target', '.artifacts', '__pycache__', '.git'}
    files = [root / 'Cargo.toml', root / 'Cargo.lock', Path(__file__).resolve(), args.manifest.resolve()]
    for directory in ['src','tests','assets']:
        files += [p for p in (root/directory).rglob('*') if p.is_file() and not excluded.intersection(p.relative_to(root).parts)]
    files += [root/'ci/tests/module.nix',root/'nix/modules/home-manager.nix']
    originals = {str(file.relative_to(root)): file.read_bytes() for file in sorted(set(files))}
    if subprocess.check_output(['git','status','--porcelain'],cwd=root).strip():
        raise ValueError('source flight requires a clean immutable checkout')
    ledger = {'source_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'status':'running','protected_hashes':{name:digest(data) for name,data in originals.items()},'controls':{},'arms':[]}
    ledger['toolchain']={'cargo':subprocess.check_output(['cargo','--version'],text=True).strip(),'rustc':subprocess.check_output([os.environ.get('RUSTC','rustc'),'-vV'],text=True).strip()}

    def persist():
        temporary = evidence / 'results.json.new'
        with temporary.open('w') as out:
            json.dump(ledger, out, indent=2)
            out.flush()
            os.fsync(out.fileno())
        temporary.replace(evidence / 'results.json')

    def run_build(source, target, nonce, stem):
        environment = {**os.environ, 'CARGO_TARGET_DIR': str(target), 'XMSG_CLAUDE_BUILD_NONCE': nonce}
        result = subprocess.run(['cargo', 'test', '--manifest-path', str(source/'Cargo.toml'), '--locked', '-j4', '--lib', '--no-run', '--message-format=json'], cwd=source, capture_output=True, timeout=300, env=environment)
        (evidence / (stem + '-build.jsonl')).write_bytes(result.stdout)
        (evidence / (stem + '-build.stderr')).write_bytes(result.stderr)
        return result

    def arm(case, phase):
        verify(root, originals)
        nonce = str(uuid.uuid4())
        stem = case['id'] + '-' + phase
        variant = evidence / 'variants' / stem
        source = variant / 'source'
        target = variant / 'target'
        expected = dict(originals)
        name = case['file']
        needle = case['needle'].encode()
        if originals[name].count(needle) != 1:
            raise RuntimeError('anchor count != 1: ' + case['id'])
        if phase == 'red':
            expected[name] = originals[name].replace(needle, case['replacement'].encode(), 1)
            if expected[name] == originals[name]:
                raise RuntimeError('no-op mutation')
        test_file = case.get('test_file', 'src/install/mod.rs')
        if test_file not in originals:
            raise ValueError('test fixture is outside protected inputs')
        function = ('fn ' + case['test'] + '() {').encode()
        if expected[test_file].count(function) != 1:
            raise RuntimeError('exact killing-function anchor is not unique')
        injected = function + b'\nassert_eq!(env!("XMSG_CLAUDE_BUILD_NONCE"), std::env::var("XMSG_CLAUDE_PROOF_NONCE").unwrap(), "compiled nonce mismatch");\nprintln!("control-proof-nonce:{}", env!("XMSG_CLAUDE_BUILD_NONCE"));\n'
        expected[test_file] = expected[test_file].replace(function, injected, 1)
        for relative, data in expected.items():
            destination = source / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        record = {'case': case['id'], 'phase': phase, 'nonce': nonce, 'status': 'building', 'variant_hashes': {name: digest(data) for name, data in expected.items()}}
        ledger['arms'].append(record)
        persist()
        verify(source, expected)
        if not ledger['controls']:
            guard_file = source / test_file
            guard_file.write_bytes(expected[test_file] + b'\n')
            try:
                verify(source, expected)
            except RuntimeError:
                ledger['controls']['source_tamper_refused'] = True
            else:
                raise RuntimeError('source tamper control survived')
            guard_file.write_bytes(expected[test_file])
            try:
                artifact(b'{"reason":"compiler-artifact","target":{"kind":["lib"]},"executable":"/bin/false","fresh":false}', target)
            except RuntimeError:
                ledger['controls']['outside_artifact_refused'] = True
            else:
                raise RuntimeError('isolation control survived')
            persist()
        built = run_build(source, target, nonce, stem)
        record.update({'build_exit':built.returncode,'compiler_json_sha256':digest(built.stdout),'compiler_stderr_sha256':digest(built.stderr),'status':'compiled' if built.returncode==0 else 'compile_failed'})
        persist()
        if built.returncode:
            raise RuntimeError('compilation failure is not a kill: ' + stem)
        record['compiler_json_sha256'] = digest(built.stdout)
        record['compiler_stderr_sha256'] = digest(built.stderr)
        binary, fresh = artifact(built.stdout, target)
        record.update({'artifact': str(binary), 'artifact_sha256': digest(binary.read_bytes()), 'compiler_fresh': fresh})
        persist()
        if 'cached_artifact_refused' not in ledger['controls']:
            cached = run_build(source, target, nonce, stem + '-cache-control')
            if cached.returncode:
                raise RuntimeError('cache positive control did not compile')
            cached_binary, cached_fresh = artifact(cached.stdout, target, require_fresh=False)
            if cached_fresh is not True or cached_binary != binary or digest(cached_binary.read_bytes()) != record['artifact_sha256']:
                raise RuntimeError('cache positive control rebuilt or changed the artifact')
            try:
                artifact(cached.stdout, target)
            except RuntimeError as error:
                if str(error) != 'cached artifact refused':
                    raise
                ledger['controls']['cached_artifact_refused'] = True
            else:
                raise RuntimeError('fresh-cache control was not refused')
            persist()
        module = case.get('test_module', 'install::tests')
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_:]*', module):
            raise ValueError('unsafe test module')
        test = module + '::' + case['test']
        if 'wrong_nonce_refused' not in ledger['controls']:
            if digest(binary.read_bytes()) != record['artifact_sha256']:
                raise RuntimeError('artifact changed before nonce control execution')
            wrong = subprocess.run([str(binary), '--exact', test, '--nocapture'], cwd=source, capture_output=True, timeout=30, env={**os.environ, 'XMSG_CLAUDE_PROOF_NONCE': 'deliberately-wrong-nonce'})
            (evidence / 'compiled-nonce-negative.log').write_bytes(wrong.stdout + wrong.stderr)
            if wrong.returncode != 101 or b'compiled nonce mismatch' not in wrong.stdout + wrong.stderr:
                raise RuntimeError('compiled nonce control survived')
            ledger['controls']['wrong_nonce_refused'] = True
            persist()
        if digest(binary.read_bytes()) != record['artifact_sha256']:
            raise RuntimeError('artifact changed immediately before execution')
        result = subprocess.run([str(binary), '--exact', test, '--nocapture'], cwd=source, capture_output=True, timeout=30, env={**os.environ, 'XMSG_CLAUDE_PROOF_NONCE': nonce})
        output = result.stdout + result.stderr
        (evidence / (stem + '.log')).write_bytes(output)
        verify(source, expected)
        verify(root, originals)
        if digest(binary.read_bytes()) != record['artifact_sha256']:
            raise RuntimeError('executed artifact changed')
        marker = ('control-proof-nonce:' + nonce).encode()
        record.update({'test': test, 'exit': result.returncode, 'log_sha256': digest(output), 'assertion_present': case['assertion'].encode() in output, 'compiled_nonce_observed': marker in output, 'source_and_artifact_guards': True, 'status': 'executed'})
        persist()
        if marker not in output:
            raise RuntimeError('compiled nonce was not observed in killing function')
        if any(marker in output.lower() for marker in [b'timed out', b'elapsed(', b'test-hang', b'running for over']):
            raise RuntimeError('timeout or hung test is not a semantic kill')
        if phase == 'red':
            if case.get('expected_outcome') == 'equivalent':
                if result.returncode or b'1 passed' not in output:
                    raise RuntimeError('equivalence control did not preserve effect invariant: ' + stem)
                record['outcome'] = 'equivalent_survivor_not_kill'
                persist()
            elif result.returncode != 101 or not record['assertion_present'] or b'1 failed' not in output:
                raise RuntimeError('fault survived or failed for the wrong reason: ' + stem)
            else:
                record['outcome'] = 'semantic_kill'
                persist()
        elif result.returncode or b'1 passed' not in output:
            raise RuntimeError('restored test is not green: ' + stem)
        print(stem + ': exit=' + str(result.returncode) + ' nonce=' + nonce, flush=True)
        shutil.rmtree(target)
        shutil.rmtree(source)
        record['isolated_build_tree_removed_after_receipts'] = True
        persist()

    persist()
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        for case in cases:
            arm(case, 'red')
            arm(case, 'green')
        ledger['status'] = 'passed'
        ledger['completed_at'] = time.time()
        persist()
    except BaseException as error:
        ledger['status'] = 'failed'
        ledger['error'] = str(error)
        persist()
        raise
    finally:
        verify(root, originals)


if __name__ == '__main__':
    main()

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
import select
import stat
import subprocess
import sys
import tempfile
import time
import uuid


def digest(data):
    return hashlib.sha256(data).hexdigest()


EXCLUDED = {'target', '.artifacts', '__pycache__', '.git'}


def inventory(base):
    contents, modes = {}, {}

    def visit(item):
        if item.name in EXCLUDED:
            return
        relative = str(item.relative_to(base))
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise RuntimeError('source symlink refused: ' + relative)
        if stat.S_ISDIR(info.st_mode):
            modes[relative] = ('directory', stat.S_IMODE(info.st_mode))
            for child in sorted(item.iterdir()):
                visit(child)
        elif stat.S_ISREG(info.st_mode):
            modes[relative] = ('file', stat.S_IMODE(info.st_mode))
            contents[relative] = item.read_bytes()
        else:
            raise RuntimeError('source type refused: ' + relative)

    for name in ['Cargo.toml', 'Cargo.lock', 'build.rs', '.cargo', 'src', 'tests', 'assets', 'extensions/executor']:
        item = base / name
        if item.exists() or item.is_symlink():
            visit(item)
    return contents, modes


def verify(base, expected, modes):
    current, current_modes = inventory(base)
    if current_modes != modes or set(current) != set(expected):
        raise RuntimeError('source inventory/type/mode guard failed')
    for relative, data in expected.items():
        if current[relative] != data:
            raise RuntimeError('source guard failed: ' + relative)


def safe_group(pid, group, session, expected_session):
    if min(pid, group, session, expected_session) <= 1:
        raise RuntimeError('reserved cleanup identity refused')
    try:
        actual_session, actual_group = os.getsid(pid), os.getpgid(pid)
    except ProcessLookupError:
        try:
            os.killpg(group, 0)
        except ProcessLookupError:
            return False
        raise RuntimeError('helper leader absent; live group ownership is unverifiable')
    if actual_session != session or session != expected_session or actual_group != group:
        raise RuntimeError('unrelated helper session/group refused')
    return True


def stop_group(pid, group, session, expected_session):
    if not safe_group(pid, group, session, expected_session):
        return
    os.killpg(group, signal.SIGTERM)
    deadline = time.monotonic() + 0.5
    while time.monotonic() < deadline:
        try:
            os.killpg(group, 0)
        except ProcessLookupError:
            return
        time.sleep(0.01)
    if safe_group(pid, group, session, expected_session):
        os.killpg(group, signal.SIGKILL)
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            os.killpg(group, 0)
        except ProcessLookupError:
            return
        time.sleep(0.01)
    raise RuntimeError('captured helper group did not disappear after bounded cleanup')


def child_cleanup(receipts, nonce, session):
    if not receipts.exists():
        return 0
    if receipts.is_symlink() or receipts.stat().st_size > 65536:
        raise RuntimeError('child receipt inventory refused')
    rows = [json.loads(line) for line in receipts.read_text().splitlines()]
    if len(rows) > 64:
        raise RuntimeError('too many child receipts')
    seen = set()
    for row in reversed(rows):
        if row['nonce'] != nonce or row['parent_session'] != session:
            raise RuntimeError('child receipt nonce/session refused')
        key = (row['pid'], row['pgid'], row['session'])
        if key in seen:
            continue
        seen.add(key)
        if row['session'] <= 1 or row['pgid'] <= 1:
            try:
                os.kill(row['pid'], 0)
            except ProcessLookupError:
                continue
            raise RuntimeError('live helper has unverifiable ownership')
        stop_group(row['pid'], row['pgid'], row['session'], session)
    return len(seen)


def stop_parent(process):
    if process.poll() is not None:
        return
    if safe_group(process.pid, process.pid, process.pid, process.pid):
        os.killpg(process.pid, signal.SIGTERM)
        time.sleep(0.1)
        if safe_group(process.pid, process.pid, process.pid, process.pid):
            os.killpg(process.pid, signal.SIGKILL)
    process.wait(timeout=3)


def artifact_guard(binary, expected):
    if digest(binary.read_bytes()) != expected:
        raise RuntimeError('artifact byte guard failed')


def witness_region(data, signature):
    start = data.index(signature)
    index = start + len(signature) - 1
    depth = 0
    while index < len(data):
        if data.startswith(b'//', index):
            end = data.find(b'\n', index)
            index = len(data) if end < 0 else end + 1
            continue
        if data.startswith(b'/*', index):
            nesting = 1
            index += 2
            while nesting and index < len(data):
                if data.startswith(b'/*', index):
                    nesting += 1
                    index += 2
                elif data.startswith(b'*/', index):
                    nesting -= 1
                    index += 2
                else:
                    index += 1
            continue
        raw = re.match(rb'r(#{0,255})"', data[index:])
        if raw:
            end = data.find(b'"' + raw[1], index + raw.end())
            if end < 0:
                raise RuntimeError('unclosed raw witness string')
            index = end + 1 + len(raw[1])
            continue
        if data[index:index + 1] == b'"':
            index += 1
            while index < len(data):
                if data[index] == 92:
                    index += 2
                elif data[index] == 34:
                    index += 1
                    break
                else:
                    index += 1
            continue
        character = re.match(rb"'(?:\\.|[^'\n])'", data[index:])
        if character:
            index += character.end()
            continue
        if data[index] == 123:
            depth += 1
        elif data[index] == 125:
            depth -= 1
            if depth == 0:
                return start, index + 1
        index += 1
    raise RuntimeError('unclosed witness function')


def self_controls():
    controls = {}
    with tempfile.TemporaryDirectory(prefix='executor-proof-controls-') as temporary:
        base = Path(temporary)
        (base / 'src').mkdir()
        source = base / 'src/lib.rs'
        source.write_text('pub fn control() {}\n')
        expected, modes = inventory(base)
        added = base / 'src/added.rs'
        added.write_text('pub fn added() {}\n')
        try:
            verify(base, expected, modes)
        except RuntimeError:
            controls['added_source_refused'] = True
        else:
            raise RuntimeError('added-source control survived')
        added.unlink()
        original_mode = source.stat().st_mode & 0o7777
        source.chmod(original_mode ^ 0o100)
        try:
            verify(base, expected, modes)
        except RuntimeError:
            controls['source_mode_refused'] = True
        else:
            raise RuntimeError('source-mode control survived')
        source.chmod(original_mode)
        added.symlink_to(source)
        try:
            inventory(base)
        except RuntimeError:
            controls['source_symlink_refused'] = True
        else:
            raise RuntimeError('source-symlink control survived')
        added.unlink()
        binary = base / 'artifact'
        binary.write_bytes(b'control artifact')
        before = digest(binary.read_bytes())
        binary.write_bytes(b'changed artifact')
        try:
            artifact_guard(binary, before)
        except RuntimeError:
            controls['artifact_tamper_refused'] = True
        else:
            raise RuntimeError('artifact-tamper control survived')
        held = subprocess.Popen([sys.executable, '-u', '-c', 'import sys;print("held",flush=True);sys.stdin.buffer.read(1)'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, start_new_session=True)
        try:
            if not select.select([held.stdout], [], [], 2)[0] or held.stdout.readline() != b'held\n':
                raise RuntimeError('held cleanup control did not reach barrier')
            receipts = base / 'held.jsonl'
            row = {'pid': held.pid, 'pgid': held.pid, 'session': held.pid, 'parent_session': held.pid, 'nonce': 'control'}
            receipts.write_text(json.dumps(row) + '\n')
            try:
                child_cleanup(receipts, 'wrong-nonce', held.pid)
            except RuntimeError:
                controls['wrong_child_nonce_refused'] = held.poll() is None
            else:
                raise RuntimeError('child nonce control survived')
            try:
                safe_group(held.pid, held.pid, held.pid, os.getsid(0))
            except RuntimeError:
                controls['unrelated_session_refused'] = held.poll() is None
            else:
                raise RuntimeError('unrelated-session control survived')
        finally:
            stop_parent(held)
            held.stdin.close()
            held.stdout.close()
        controls['held_process_group_reaped'] = held.poll() is not None
    if not all(controls.values()):
        raise RuntimeError('runner control failed')
    return controls


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
    if sys.argv[1:] == ['--self-test']:
        print(json.dumps(self_controls(), sort_keys=True))
        return
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--case', action='append', default=[])
    args = parser.parse_args()
    crate = Path(__file__).resolve().parent.parent
    root = crate.parent.parent
    if subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all'], cwd=root).strip():
        raise RuntimeError('source flight requires a clean committed HEAD')
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    cases = json.loads(args.manifest.read_text())
    identifiers = [case['id'] for case in cases]
    if len(identifiers) != len(set(identifiers)) or any(not re.fullmatch(r'[a-z][a-z0-9-]*', name) for name in identifiers):
        raise ValueError('case IDs must be unique safe path components')
    if args.case:
        if len(args.case) != len(set(args.case)):
            raise ValueError('duplicate case selection')
        cases = [case for case in cases if case['id'] in args.case]
        if set(args.case) != {case['id'] for case in cases}:
            raise ValueError('unknown case selection')
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    originals, modes = inventory(root)
    tracked = set(subprocess.check_output(['git', 'ls-files'], cwd=root, text=True).splitlines())
    if not set(originals) <= tracked:
        raise RuntimeError('untracked or ignored protected source refused')
    ledger = {'status': 'running', 'head': head, 'protected_inventory': modes, 'protected_hashes': {name: digest(data) for name, data in originals.items()}, 'controls': {}, 'commands': [], 'arms': []}
    ledger['controls'].update(self_controls())
    fixture_inputs = {}
    for variable in ['XMSG_EXECUTOR_FIXTURE_DAEMON', 'XMSG_EXECUTOR_FIXTURE_PYTHON']:
        value = os.environ.get(variable)
        if value:
            file = Path(value).resolve(strict=True)
            fixture_inputs[variable] = {'file': str(file), 'sha256': digest(file.read_bytes())}
    ledger['fixture_binary_inputs'] = fixture_inputs


    def persist():
        temporary = evidence / 'results.json.new'
        with temporary.open('w') as out:
            json.dump(ledger, out, indent=2)
            out.flush()
            os.fsync(out.fileno())
        temporary.replace(evidence / 'results.json')

    def run_build(source, target, nonce, stem):
        environment = {**os.environ, 'CARGO_TARGET_DIR': str(target), 'XMSG_EXECUTOR_BUILD_NONCE': nonce}
        result = command(['cargo', 'test', '--manifest-path', str(source / 'extensions/executor/Cargo.toml'), '--locked', '-j4', '--lib', '--no-run', '--message-format=json'], source, environment, 300, stem + '-compile', nonce)
        (evidence / (stem + '-build.jsonl')).write_bytes(result.stdout)
        (evidence / (stem + '-build.stderr')).write_bytes(result.stderr)
        return result

    def command(argv, cwd, environment, budget, label, nonce):
        output_file, error_file = evidence / (label + '.stdout'), evidence / (label + '.stderr')
        children = evidence / (label + '-children.jsonl')
        environment = {**environment, 'XMSG_EXECUTOR_PROOF_CHILDREN': str(children)}
        record = {'label': label, 'argv': argv, 'budget_seconds': budget, 'status': 'starting'}
        ledger['commands'].append(record)
        persist()
        process = None
        try:
            with output_file.open('wb') as out, error_file.open('wb') as err:
                process = subprocess.Popen(argv, cwd=cwd, stdout=out, stderr=err, env=environment, start_new_session=True)
                record.update({'pid': process.pid, 'pgid': process.pid, 'session': process.pid, 'status': 'running'})
                persist()
                process.wait(timeout=budget)
            record.update({'exit': process.returncode, 'status': 'exited'})
            return subprocess.CompletedProcess(argv, process.returncode, output_file.read_bytes(), error_file.read_bytes())
        except BaseException as failure:
            record.update({'status': 'failed', 'error': type(failure).__name__ + ': ' + str(failure)})
            persist()
            raise
        finally:
            try:
                if process is not None:
                    if process.poll() is None:
                        stop_parent(process)
                    record['captured_helpers_cleaned'] = child_cleanup(children, nonce, process.pid)
                    record['parent_reaped'] = process.poll() is not None
                record['stdout_sha256'] = digest(output_file.read_bytes()) if output_file.exists() else None
                record['stderr_sha256'] = digest(error_file.read_bytes()) if error_file.exists() else None
            except BaseException as failure:
                record.update({'status': 'cleanup_failed', 'cleanup_error': str(failure)})
                persist()
                raise
            persist()

    def arm(case, phase):
        verify(root, originals, modes)
        for item in fixture_inputs.values():
            if digest(Path(item['file']).read_bytes()) != item['sha256']:
                raise RuntimeError('fixture executable input changed')
        nonce = str(uuid.uuid4())
        stem = case['id'] + '-' + phase
        record = {'case': case['id'], 'phase': phase, 'nonce': nonce, 'status': 'preparing'}
        ledger['arms'].append(record)
        persist()
        variant = evidence / 'variants' / stem
        source = variant / 'source'
        target = variant / 'target'
        expected = dict(originals)
        name = case['file']
        needle = case['needle'].encode()
        if originals[name].count(needle) != 1:
            raise RuntimeError('anchor count != 1: ' + case['id'])
        if name.endswith('_tests.rs') or '/tests/' in name:
            raise RuntimeError('production mutation cannot edit a test file')
        if phase == 'red':
            expected[name] = originals[name].replace(needle, case['replacement'].encode(), 1)
            if expected[name] == originals[name]:
                raise RuntimeError('no-op mutation')
        test_file = case.get('test_file', 'extensions/executor/src/control_tests.rs')
        if test_file not in originals:
            raise ValueError('test fixture is outside protected inputs')
        function = ('fn ' + case['test'] + '() {').encode()
        if expected[test_file].count(function) != 1:
            raise RuntimeError('exact killing-function anchor is not unique')
        if name == test_file:
            start, end = witness_region(originals[test_file], function)
            mutation_start = originals[name].index(needle)
            if mutation_start < end and mutation_start + len(needle) > start:
                raise RuntimeError('producer mutation overlaps its killing witness')
        injected = function + b'\nassert_eq!(env!("XMSG_EXECUTOR_BUILD_NONCE"), std::env::var("XMSG_EXECUTOR_PROOF_NONCE").unwrap(), "compiled nonce mismatch");\nprintln!("control-proof-nonce:{}", env!("XMSG_EXECUTOR_BUILD_NONCE"));\n'
        expected[test_file] = expected[test_file].replace(function, injected, 1)
        for relative, data in expected.items():
            destination = source / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            destination.chmod(modes[relative][1])
        for relative, (kind, mode) in modes.items():
            if kind == 'directory':
                (source / relative).mkdir(parents=True, exist_ok=True)
                (source / relative).chmod(mode)
        record.update({'status': 'building', 'variant_hashes': {name: digest(data) for name, data in expected.items()}})
        persist()
        verify(source, expected, modes)
        if 'source_tamper_refused' not in ledger['controls']:
            guard_file = source / test_file
            guard_file.write_bytes(expected[test_file] + b'\n')
            try:
                verify(source, expected, modes)
            except RuntimeError:
                ledger['controls']['source_tamper_refused'] = True
            else:
                raise RuntimeError('source tamper control survived')
            guard_file.write_bytes(expected[test_file])
            persist()
        if 'outside_artifact_refused' not in ledger['controls']:
            try:
                artifact(b'{"reason":"compiler-artifact","target":{"kind":["lib"]},"executable":"/bin/false","fresh":false}', target)
            except RuntimeError:
                ledger['controls']['outside_artifact_refused'] = True
            else:
                raise RuntimeError('isolation control survived')
            persist()
        built = run_build(source, target, nonce, stem)
        record.update({'build_exit': built.returncode, 'status': 'compiled' if built.returncode == 0 else 'compile_failed'})
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
        module = case.get('test_module', 'control::tests')
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_:]*', module):
            raise ValueError('unsafe test module')
        test = module + '::' + case['test']
        if 'wrong_nonce_refused' not in ledger['controls']:
            artifact_guard(binary, record['artifact_sha256'])
            wrong = command([str(binary), '--exact', test, '--nocapture'], source, {**os.environ, 'XMSG_EXECUTOR_PROOF_NONCE': 'deliberately-wrong-nonce'}, 30, stem + '-wrong-nonce', 'deliberately-wrong-nonce')
            (evidence / 'compiled-nonce-negative.log').write_bytes(wrong.stdout + wrong.stderr)
            if wrong.returncode != 101 or b'compiled nonce mismatch' not in wrong.stdout + wrong.stderr:
                raise RuntimeError('compiled nonce control survived')
            ledger['controls']['wrong_nonce_refused'] = True
            persist()
        artifact_guard(binary, record['artifact_sha256'])
        result = command([str(binary), '--exact', test, '--nocapture'], source, {**os.environ, 'XMSG_EXECUTOR_PROOF_NONCE': nonce}, 30, stem + '-execute', nonce)
        output = result.stdout + result.stderr
        (evidence / (stem + '.log')).write_bytes(output)
        verify(source, expected, modes)
        verify(root, originals, modes)
        for item in fixture_inputs.values():
            if digest(Path(item['file']).read_bytes()) != item['sha256']:
                raise RuntimeError('fixture executable input changed after execution')
        artifact_guard(binary, record['artifact_sha256'])
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
        required_controls = {
            'added_source_refused', 'source_mode_refused', 'source_symlink_refused',
            'artifact_tamper_refused', 'wrong_child_nonce_refused',
            'unrelated_session_refused', 'held_process_group_reaped',
            'source_tamper_refused', 'outside_artifact_refused',
            'cached_artifact_refused', 'wrong_nonce_refused',
        }
        if any(ledger['controls'].get(name) is not True for name in required_controls):
            raise RuntimeError('required runner controls did not all fire')
        ledger['status'] = 'passed'
        ledger['completed_at'] = time.time()
        persist()
    except BaseException as error:
        ledger['status'] = 'failed'
        ledger['error'] = str(error)
        if ledger['arms']:
            ledger['arms'][-1].update({'previous_status': ledger['arms'][-1]['status'], 'status': 'failed', 'failure_type': type(error).__name__, 'failure': str(error)})
        persist()
        raise
    finally:
        verify(root, originals, modes)


if __name__ == '__main__':
    main()

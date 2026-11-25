"""Temporary PR315 metadata-only macOS diagnostic driver."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

root = Path('.artifacts/executor-fd').resolve()
root.mkdir(parents=True, exist_ok=True)
(root / 'source-head.txt').write_text(subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True))
for name, args in [('rust', ['rustc', '+1.88', '--version']), ('cargo', ['cargo', '+1.88', '--version']), ('python', [sys.executable, '--version'])]:
    (root / (name + '.txt')).write_bytes(subprocess.check_output(args, stderr=subprocess.STDOUT))
diff = subprocess.check_output(['git', 'diff', '9097ffc9aaa49434ecac9a07b31a4913d191648c', 'HEAD'])
(root / 'diagnostic.diff').write_bytes(diff)
(root / 'diagnostic.sha256').write_text(hashlib.sha256(diff).hexdigest() + '\n')
tests = [
    'supervisor::tests::continuous_native_frames_service_attach_and_strict_steer_before_batch_end',
    'supervisor::tests::prelaunch_failed_request_is_terminal_and_does_not_block_one_slot_after_restart',
    'supervisor::tests::qualified_reconnect_attaches_same_live_owned_lease_without_native_session_or_launch',
    'supervisor::tests::real_acp_bootstrap_uses_inherited_lease_and_observed_model_before_brief',
    'supervisor::tests::unsupported_native_request_gets_bounded_failure_without_human_or_terminal_execution',
    'control::tests::owner_disable_transport_is_independent_of_runtime_qualification_and_human_role',
    'lifecycle_client::tests::lifecycle_request_has_no_credential_or_identity_prefix',
]
for variant in ['normal', 'canonical']:
    for index, test in enumerate(tests):
        destination = root / variant / str(index)
        destination.mkdir(parents=True)
        env = os.environ.copy()
        env['XMSG_EXECUTOR_FD_DIAGNOSTICS'] = str(destination)
        env['XMSG_EXECUTOR_FIXTURE_PYTHON'] = sys.executable
        if variant == 'canonical':
            env['TMPDIR'] = '/private/tmp'
        command = ['cargo', '+1.88', 'test', '--manifest-path', 'extensions/executor/Cargo.toml', '--locked', '--lib', test, '--', '--exact', '--nocapture']
        started = time.monotonic()
        captured = set()
        with (destination / 'output.log').open('wb') as output:
            child = subprocess.Popen(command, env=env, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            expired = False
            while child.poll() is None:
                for receipt in list(destination.glob('parent-*.json')) + list(destination.glob('*.child.json')):
                    try:
                        record = json.loads(receipt.read_text())
                        pid = record['pid']
                        if pid not in captured and pid > 1 and os.getsid(pid) == child.pid:
                            captured.add(pid)
                            with (destination / ('lsof-' + str(pid) + '.txt')).open('wb') as listing:
                                try:
                                    subprocess.run(['/usr/sbin/lsof', '-nP', '-p', str(pid)], stdout=listing, stderr=subprocess.STDOUT, timeout=3, check=False)
                                except (OSError, subprocess.TimeoutExpired) as error:
                                    listing.write(repr(error).encode())
                    except (OSError, ValueError, KeyError):
                        pass
                if time.monotonic() - started > 120:
                    expired = True
                    os.killpg(child.pid, signal.SIGTERM)
                    try:
                        child.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait()
                    break
                time.sleep(.02)
            child.wait()
            for pid in captured:
                try:
                    if pid > 1 and os.getsid(pid) == child.pid and os.getpgid(pid) == pid:
                        os.killpg(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        (destination / 'result.json').write_text(json.dumps({'test': test, 'command': command, 'exit': child.returncode, 'timeout': expired, 'elapsed': time.monotonic()-started, 'TMPDIR': env.get('TMPDIR')}, indent=2))

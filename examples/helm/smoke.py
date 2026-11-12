#!/usr/bin/env python3
"""Verify two example releases federate and return a correlated version reply."""
import argparse
import json
from pathlib import Path
import subprocess
import time
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kubeconfig', required=True)
    parser.add_argument('--namespace', default='xmsg-helm-demo')
    args = parser.parse_args()
    kube = ['kubectl', '--kubeconfig', args.kubeconfig, '-n', args.namespace]
    local = Path(__file__).resolve().parent / '.local'
    values = json.loads((local / 'b/values.json').read_text())

    def cli(pod, *arguments):
        result = subprocess.run([*kube, 'exec', pod, '-c', 'xmsg', '--', '/bin/xmsg',
                                 *arguments, '--json'], check=True, capture_output=True,
                                text=True, timeout=20)
        return json.loads(result.stdout)

    service = None
    deadline = time.monotonic() + 90
    listing = cli('b-xmsg-0', 'list', '--node', values['canonicalNodeName'])
    if not any(row['address'].startswith('status@') for row in listing['recipients']):
        service = subprocess.Popen([*kube, 'exec', 'b-xmsg-0', '-c', 'xmsg', '--',
                                    '/bin/xmsg', 'service', 'exec', '--name', 'status',
                                    '--', '/bin/xmsg', '--version'],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        while True:
            listing = cli('a-xmsg-0', 'list', '--node', 'b', '--kind', 'service')
            if any(row['address'].startswith('status@') for row in listing['recipients']):
                break
            if service is not None and service.poll() is not None:
                raise SystemExit('status service exited before registration')
            if time.monotonic() > deadline:
                raise SystemExit('remote status service did not become ready')
            time.sleep(0.25)
        print('LIST ' + json.dumps(listing, separators=(',', ':')))
        sent = cli('a-xmsg-0', 'send', 'status@b', 'version?', '--from', 'helm-demo',
                   '--idempotency-key', str(uuid.uuid4()))
        print('SEND ' + json.dumps(sent, separators=(',', ':')))
        deadline = time.monotonic() + 45
        while True:
            replies = cli('a-xmsg-0', 'replies', sent['message_id'], '--wait', '10')
            if replies:
                break
            if time.monotonic() > deadline:
                raise SystemExit('correlated reply did not arrive')
        print('REPLIES ' + json.dumps(replies, separators=(',', ':')))
        assert any(row['messageId'] == sent['message_id'] and row['text'].startswith('xmsg ')
                   for row in replies), 'unexpected reply'
        print('PASS: two Helm releases, federated send and correlated version reply')
    finally:
        if service is not None:
            service.terminate()
            try:
                service.wait(timeout=10)
            except subprocess.TimeoutExpired:
                service.kill()
                service.wait(timeout=10)


if __name__ == '__main__':
    main()

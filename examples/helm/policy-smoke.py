#!/usr/bin/env python3
"""Check new federation connections against the disposable example's ingress policy."""
import argparse
import json
from pathlib import Path
import subprocess
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kubeconfig', required=True)
    parser.add_argument('--namespace', default='xmsg-helm-demo')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    local = Path(__file__).resolve().parent / '.local'
    kube = ['kubectl', '--kubeconfig', args.kubeconfig]
    probe = 'policy-smoke-' + uuid.uuid4().hex[:8]
    denied_namespace = probe
    overlay = local / (probe + '.json')
    created_namespace = False
    created_pods = []

    def run(command, **kwargs):
        return subprocess.run(command, check=True, text=True, capture_output=True,
                              timeout=120, **kwargs)

    def upgrade(policy):
        overlay.write_text(json.dumps({'networkPolicy': policy}))
        run(['helm', 'upgrade', 'a', str(root / 'charts/xmsg'),
             '--kubeconfig', args.kubeconfig, '-n', args.namespace,
             '-f', str(local / 'a/values.json'), '-f', str(overlay),
             '--set', 'image.pullPolicy=Never', '--wait', '--timeout', '90s'])

    def connect(namespace, expected):
        result = subprocess.run([*kube, '-n', namespace, 'exec', probe, '--',
                                 'nc', '-z', '-w', '3',
                                 f'a-xmsg.{args.namespace}.svc.cluster.local', '7788'],
                                text=True, capture_output=True, timeout=15)
        assert (result.returncode == 0) == expected, (namespace, result.returncode, result.stderr)
        print(f'new TCP connection namespace={namespace} allowed={expected}')

    try:
        run([*kube, 'create', 'namespace', denied_namespace])
        created_namespace = True
        for namespace in [args.namespace, denied_namespace]:
            document = {'apiVersion': 'v1', 'kind': 'Pod',
                        'metadata': {'name': probe, 'namespace': namespace,
                                     'labels': {'app': probe}},
                        'spec': {'restartPolicy': 'Never', 'containers': [
                            {'name': 'probe', 'image': 'busybox:1.37.0',
                             'command': ['sleep', '300']}]}}
            run([*kube, 'create', '-f', '-'], input=json.dumps(document))
            created_pods.append(namespace)
            run([*kube, '-n', namespace, 'wait', '--for=condition=Ready',
                 f'pod/{probe}', '--timeout=90s'])
        upgrade({'enabled': False, 'allowedPeers': []})
        connect(args.namespace, True)
        connect(denied_namespace, True)
        upgrade({'enabled': True, 'allowedPeers': [{
            'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': args.namespace}},
            'podSelector': {'matchLabels': {'app': probe}}}]})
        connect(args.namespace, True)
        connect(denied_namespace, False)
        run([*kube, '-n', args.namespace, 'label', 'pod', probe, 'app=wrong', '--overwrite'])
        connect(args.namespace, False)
        run([*kube, '-n', args.namespace, 'label', 'pod', probe, f'app={probe}', '--overwrite'])
        connect(args.namespace, True)
        upgrade({'enabled': True, 'allowedPeers': []})
        connect(args.namespace, False)
        print('PASS: namespace, pod, and deny-all ingress controls enforced')
    finally:
        upgrade({'enabled': False, 'allowedPeers': []})
        for namespace in created_pods:
            run([*kube, '-n', namespace, 'delete', 'pod', probe, '--wait=false'])
        if created_namespace:
            run([*kube, 'delete', 'namespace', denied_namespace, '--wait=false'])
        overlay.unlink(missing_ok=True)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Generate disposable demo TLS identities and values without replacing keys."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default='ghcr.io/sini/xmsg:latest')
    parser.add_argument('--namespace', default='xmsg-helm-demo')
    args = parser.parse_args()
    os.umask(0o077)
    openssl = os.environ.get("OPENSSL", "openssl")
    root = Path(__file__).resolve().parent / '.local'
    names, pins = {}, {}
    for name in ('a', 'b'):
        target = root / name
        target.mkdir(parents=True, exist_ok=True)
        cert, key = target / 'node.crt', target / 'node.key'
        if cert.exists() != key.exists():
            parser.error(f'incomplete identity for {name}; restore matching key/certificate')
        if not key.exists():
            subprocess.run([openssl, 'req', '-new', '-x509', '-newkey', 'ec', '-pkeyopt',
                            'ec_paramgen_curve:prime256v1', '-nodes', '-days', '30',
                            '-subj', f'/CN=xmsg-helm-{name}', '-addext', 'basicConstraints=critical,CA:FALSE',
                            '-addext', 'keyUsage=critical,digitalSignature', '-addext',
                            'extendedKeyUsage=serverAuth,clientAuth', '-keyout', str(key),
                            '-out', str(cert)], check=True, capture_output=True)
        public = subprocess.run([openssl, 'x509', '-in', str(cert), '-pubkey', '-noout'],
                                check=True, capture_output=True).stdout
        der = subprocess.run([openssl, 'pkey', '-pubin', '-outform', 'DER'], input=public,
                             check=True, capture_output=True).stdout
        key_der = subprocess.run([openssl, 'pkey', '-in', str(key), '-pubout', '-outform', 'DER'],
                                 check=True, capture_output=True).stdout
        if der != key_der:
            parser.error(f'key/certificate mismatch for {name}')
        key.chmod(0o600)
        digest = hashlib.sha256(der).digest()
        names[name] = base64.b32encode(digest).decode().lower()[:16]
        pins[name] = 'sha256:' + digest.hex()
    repository, separator, tag = args.image.rpartition(':')
    if not separator or '/' not in repository:
        parser.error('--image must include an explicit repository:tag')
    for name, other in (('a', 'b'), ('b', 'a')):
        values = {'image': {'repository': repository, 'tag': tag, 'pullPolicy': 'IfNotPresent'},
                  'canonicalNodeName': names[name], 'tls': {'existingSecret': f'xmsg-{name}-tls'},
                  'trustedServices': {'status': '/bin/xmsg'},
                  'peers': {other: {'address': f'{other}-xmsg.{args.namespace}.svc.cluster.local:7788',
                                    'pin': pins[other], 'allow': ['send', 'reply', 'list']}}}
        output = root / name / 'values.json'
        if not output.exists():
            output.write_text(json.dumps(values, indent=2) + '\n')
    print(json.dumps({'namespace': args.namespace, 'canonical_nodes': names, 'pins': pins}, indent=2))
    print('Kept existing identities and values; disposable 30-day keys are private under .local/.')


if __name__ == '__main__':
    main()

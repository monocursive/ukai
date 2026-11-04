#!/usr/bin/env python3
"""Run the frozen thirteen-case Linux permission lab without a model or API key."""
import argparse
import ipaddress
import json
from pathlib import Path
import sys

from common import read
from experiments import boundary_suite
from m1.runtime import pin
from m1.scoring import UKAI_SHA256

PINS = {
    'ukai': UKAI_SHA256,
    'node': 'e6ec2c188d83d813f81f2de8aea084d74dce603ac1abedd0a30ad941b10087b2',
    'npm': '8e5f6f3429f8cdbe693cdc29904e9d5a7b127a494bd15c804bd54c7403bfcbe7',
    'npm_tree': '4784814e95c834716f00743b98ad839a94fe8a3dd72daa1c937bbaccd7016ce4',
}


def validate_config(config):
    # This public entrypoint accepts no agent or credential configuration.
    if set(config) != {'jail', 'runtimes', 'collector_ip'}:
        raise ValueError('lab configuration accepts only jail, runtimes and collector_ip')
    if set(config['runtimes']) != {'node', 'npm'}:
        raise ValueError('the fixed lab requires exactly node and npm')
    address = ipaddress.ip_address(config['collector_ip'])
    if address.version != 4 or not address.is_global:
        raise ValueError('use the owned Linux worker\'s public IPv4 collector address')
    for name, spec in [('ukai', config['jail']), *config['runtimes'].items()]:
        keys = {'path', 'sha256'} | ({'tree_root', 'tree_sha256'} if name == 'npm' else set())
        if set(spec) != keys or spec['sha256'] != PINS[name]:
            raise ValueError(name + ': configuration differs from the frozen lab')
        if name == 'npm' and spec['tree_sha256'] != PINS['npm_tree']:
            raise ValueError('npm: full tree differs from the frozen lab')
        pin(spec, name, PINS[name])
    return config


def configuration(jail, node, npm, npm_root, collector_ip):
    return validate_config({
        'jail': {'path': str(jail.absolute()), 'sha256': PINS['ukai']},
        'runtimes': {
            'node': {'path': str(node.absolute()), 'sha256': PINS['node']},
            'npm': {'path': str(npm.absolute()), 'sha256': PINS['npm'],
                    'tree_root': str(npm_root.resolve()), 'tree_sha256': PINS['npm_tree']},
        },
        'collector_ip': collector_ip,
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    configure = commands.add_parser('configure', help='check pinned files and write a credential-free config')
    for name in ('jail', 'node', 'npm', 'npm-root'):
        configure.add_argument('--' + name, type=Path, required=True)
    configure.add_argument('--collector-ip', required=True)
    configure.add_argument('--out', type=Path, required=True)
    run = commands.add_parser('run', help='execute the fixed controls on your owned Linux worker')
    run.add_argument('--config', type=Path, required=True)
    run.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == 'configure':
            config = configuration(args.jail, args.node, args.npm, args.npm_root, args.collector_ip)
            with args.out.open('x') as stream:
                stream.write(json.dumps(config, indent=2) + '\n')
            print('Pinned files verified. Configuration contains no credentials; no case executed.')
            return 0
        result = boundary_suite.qualify(validate_config(read(args.config)), args.out)
        print(boundary_suite.report(result))
        return 0 if result['status'] == 'passed' else 1
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print('Lab stopped: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())

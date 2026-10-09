"""Offline first-match network policy simulator; never configures a firewall."""
import argparse
import json


def validate(policy):
    zones = policy['zones']
    if not zones or len(zones) != len(set(zones)) or policy['default'] != 'deny':
        raise ValueError('Unique zones and default deny required')
    ids = set()
    for rule in policy['rules']:
        if rule['id'] in ids:
            raise ValueError('Duplicate rule id')
        ids.add(rule['id'])
        if rule['src'] not in zones or rule['dst'] not in zones:
            raise ValueError('Unknown zone')
        if rule['action'] not in ('allow', 'deny') or rule['protocol'] not in ('tcp', 'udp'):
            raise ValueError('Invalid action/protocol')
        if not rule['ports'] or any(type(p) is not int or not 1 <= p <= 65535 for p in rule['ports']):
            raise ValueError('Invalid ports')


def decision(policy, src, dst, protocol, port):
    validate(policy)
    if src not in policy['zones'] or dst not in policy['zones']:
        raise ValueError('Unknown flow zone')
    if protocol not in ('tcp', 'udp') or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('Invalid flow')
    for rule in policy['rules']:
        if (src, dst, protocol) == (rule['src'], rule['dst'], rule['protocol']) and port in rule['ports']:
            return {'action': rule['action'], 'rule': rule['id']}
    return {'action': policy['default'], 'rule': 'default'}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('policy')
    p.add_argument('src')
    p.add_argument('dst')
    p.add_argument('protocol', choices=['tcp', 'udp'])
    p.add_argument('port', type=int)
    a = p.parse_args()
    with open(a.policy, encoding='utf-8') as f:
        print(json.dumps(decision(json.load(f), a.src, a.dst, a.protocol, a.port), indent=2))

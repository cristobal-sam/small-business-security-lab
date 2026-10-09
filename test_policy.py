import copy
import json
import unittest
from pathlib import Path
from policy_check import decision, validate

POLICY = json.loads(Path(__file__).with_name('policy.json').read_text())


class PolicyTests(unittest.TestCase):
    def test_guest_isolation(self):
        for dst in ('staff', 'servers', 'management'):
            for port in (22, 53, 80, 443, 445, 3389):
                self.assertEqual(decision(POLICY, 'guest', dst, 'tcp', port)['action'], 'deny')

    def test_staff_app(self):
        self.assertEqual(decision(POLICY, 'staff', 'servers', 'tcp', 443)['action'], 'allow')
        self.assertEqual(decision(POLICY, 'staff', 'servers', 'tcp', 22)['action'], 'deny')

    def test_admin_access(self):
        self.assertEqual(decision(POLICY, 'management', 'servers', 'tcp', 22)['rule'], 'admin-ssh')

    def test_no_unsolicited_inbound(self):
        for dst in POLICY['zones']:
            self.assertEqual(decision(POLICY, 'internet', dst, 'tcp', 443)['action'], 'deny')

    def test_first_match(self):
        p = copy.deepcopy(POLICY)
        p['rules'].insert(0, dict(id='exception', src='staff', dst='servers', protocol='tcp', ports=[443], action='deny'))
        self.assertEqual(decision(p, 'staff', 'servers', 'tcp', 443)['action'], 'deny')

    def test_bad_policy(self):
        p = copy.deepcopy(POLICY)
        p['rules'][0]['ports'] = [70000]
        with self.assertRaises(ValueError):
            validate(p)


if __name__ == '__main__':
    unittest.main()

import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import reader_lab as lab


class ReaderLabTests(unittest.TestCase):
    def config(self):
        return {'jail': {'path': '/owned/ukai', 'sha256': lab.PINS['ukai']},
                'runtimes': {'node': {'path': '/owned/node', 'sha256': lab.PINS['node']},
                             'npm': {'path': '/owned/npm/bin/npm-cli.js', 'sha256': lab.PINS['npm'],
                                     'tree_root': '/owned/npm', 'tree_sha256': lab.PINS['npm_tree']}},
                'collector_ip': '8.8.8.8'}  # syntax fixture only; no connection is made

    @patch('reader_lab.pin')
    def test_checks_all_binary_pins(self, pin):
        lab.validate_config(self.config())
        self.assertEqual([c.args[1] for c in pin.call_args_list], ['ukai', 'node', 'npm'])

    @patch('reader_lab.pin')
    def test_rejects_agent_configuration_before_file_access(self, pin):
        config = self.config()
        config['agents'] = {'claude': {'credential_source': '/private/key'}}
        with self.assertRaises(ValueError):
            lab.validate_config(config)
        pin.assert_not_called()

    @patch('reader_lab.pin')
    def test_rejects_changed_binary_or_tree(self, pin):
        for field in ('sha256', 'tree_sha256'):
            config = self.config()
            config['runtimes']['npm'][field] = '0' * 64
            with self.assertRaises(ValueError):
                lab.validate_config(config)

    @patch('reader_lab.pin')
    def test_rejects_local_and_documentation_addresses(self, pin):
        for address in ('127.0.0.1', '192.0.2.1', '10.0.0.1', '::1'):
            config = self.config()
            config['collector_ip'] = address
            with self.assertRaises(ValueError):
                lab.validate_config(config)
        pin.assert_not_called()

    @patch('reader_lab.pin')
    def test_rejects_embedded_credential(self, pin):
        config = self.config()
        config['jail']['credential_source'] = '/private/key'
        with self.assertRaises(ValueError):
            lab.validate_config(config)
        pin.assert_not_called()

    def test_real_binary_pin_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / 'ukai'
            fake.write_text('not the pinned binary')
            config = copy.deepcopy(self.config())
            config['jail']['path'] = str(fake)
            with self.assertRaisesRegex(ValueError, 'binary pin mismatch'):
                lab.validate_config(config)


if __name__ == '__main__':
    unittest.main()

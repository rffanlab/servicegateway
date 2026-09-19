"""Cross-platform deployment regressions; stdlib-only and safe without root/DB.

Run directly with python3 tests/test_line_endings.py, or as part of pytest.
Only a temporary copy is changed. All installer invocations use --dry-run.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def execute(args, cwd):
    return subprocess.run(args, cwd=cwd, capture_output=True, timeout=20)


class DeploymentLineEndings(unittest.TestCase):
    def test_deployment_files_are_lf_utf8_without_bom(self):
        suffixes = {'.sh', '.py', '.service', '.timer', '.conf', '.sql', '.json'}
        paths = [p for p in (ROOT / 'deploy').rglob('*')
                 if p.is_file() and p.suffix in suffixes]
        self.assertTrue(paths)
        for path in paths:
            with self.subTest(path=path.name):
                data = path.read_bytes()
                data.decode('utf-8')
                self.assertFalse(data.startswith(b'\xef\xbb\xbf'), 'Remove UTF-8 BOM')
                self.assertNotIn(b'\r', data, 'Deployment sources must use LF, not CRLF')
                self.assertTrue(data.endswith(b'\n'))

    def test_shell_safety_options_are_preserved(self):
        for path in (ROOT / 'deploy').glob('*.sh'):
            with self.subTest(path=path.name):
                self.assertIn('set -Eeuo pipefail', path.read_text(encoding='utf-8'))

    @unittest.skipUnless(shutil.which('bash'), 'Bash required')
    def test_actual_entrypoint_dry_run(self):
        result = execute(['bash', 'deploy/full-deploy.sh', '--dry-run'], ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('未执行'.encode(), result.stdout)

    @unittest.skipUnless(all(shutil.which(x) for x in ('bash', 'find', 'sed')),
                         'Bash, find and sed required')
    def test_crlf_error_and_documented_repair_preserve_backups(self):
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            deploy = work / 'deploy'
            deploy.mkdir()
            expected = {}
            for path in (ROOT / 'deploy').glob('*.sh'):
                expected[path.name] = path.read_bytes()
                (deploy / path.name).write_bytes(expected[path.name].replace(b'\n', b'\r\n'))
            shutil.copy2(ROOT / 'deploy/bootstrap.py', deploy / 'bootstrap.py')
            broken = execute(['bash', 'deploy/full-deploy.sh', '--dry-run'], work)
            self.assertNotEqual(broken.returncode, 0)
            self.assertIn(b'pipefail\r: invalid option name', broken.stderr)
            # This is the user-facing repair command, not a different test implementation.
            fixed = execute(['bash', '-c', "find deploy -type f -name '*.sh' -exec sed -i.crlf-backup 's/\\r$//' {} + && bash deploy/full-deploy.sh --dry-run"], work)
            self.assertEqual(fixed.returncode, 0, fixed.stderr)
            self.assertIn('未执行'.encode(), fixed.stdout)
            for name, data in expected.items():
                self.assertEqual((deploy / name).read_bytes(), data)
                self.assertEqual((deploy / (name + '.crlf-backup')).read_bytes(),
                                 data.replace(b'\n', b'\r\n'))

    @unittest.skipUnless(shutil.which('git'), 'Git required')
    def test_windows_autocrlf_does_not_convert_deployment_files(self):
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            init = execute(['git', 'init', '-q'], work)
            self.assertEqual(init.returncode, 0, init.stderr)
            shutil.copy2(ROOT / '.gitattributes', work / '.gitattributes')
            payloads = {'deploy/sample.sh': b'#!/bin/bash\nset -Eeuo pipefail\n',
                        'deploy/sample.service': b'[Service]\nType=simple\n',
                        'deploy/bootstrap.py': b'print("test")\n',
                        'binary.dat': b'\0binary\r\nbytes\xff'}
            for name, data in payloads.items():
                path = work / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            added = execute(['git', '-c', 'core.autocrlf=true', 'add', '.'], work)
            self.assertEqual(added.returncode, 0, added.stderr)
            for name in payloads:
                (work / name).unlink()
            checkout = execute(['git', '-c', 'core.autocrlf=true', '-c', 'core.eol=crlf',
                                'checkout-index', '--all', '--force'], work)
            self.assertEqual(checkout.returncode, 0, checkout.stderr)
            for name, data in payloads.items():
                self.assertEqual((work / name).read_bytes(), data, name)


if __name__ == '__main__':
    unittest.main(verbosity=2)

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from devshield.exposure import inspect_exposure, scan_exposure
from devshield.cli import main

class ExposureTests(unittest.TestCase):
    def test_redaction(self):
        with TemporaryDirectory() as d:
            p = Path(d) / 'sample.exe'
            p.write_bytes(b'abc -----BEGIN ' + b'PRIVATE KEY----- supersecret\x00https://build.corp/endpoint')
            report = inspect_exposure(p)
            self.assertEqual({f['rule'] for f in report['findings']}, {'EX001','EX003'})
            self.assertNotIn('supersecret', str(report))
            self.assertNotIn('build.corp', str(report))
    def test_clean(self):
        with TemporaryDirectory() as d:
            p = Path(d) / 'app.dll';p.write_bytes(b'ordinary compiled executable data')
            self.assertEqual(inspect_exposure(p)['findings'], [])
            self.assertEqual(scan_exposure(Path(d))['files_inspected'], 1)
    def test_symlink_rejected(self):
        with TemporaryDirectory() as d:
            p = Path(d) / 'a.bin';p.write_bytes(b'hello')
            q = Path(d) / 'link.bin'
            try:q.symlink_to(p)
            except OSError:self.skipTest('symlinks unavailable')
            with self.assertRaises(ValueError): inspect_exposure(q)
    def test_fail_threshold(self):
        with TemporaryDirectory() as d:
            p=Path(d)/'a.dll';p.write_bytes((b'-----BEGIN ' + b'PRIVATE KEY-----'))
            self.assertEqual(main(['exposure-scan',str(p),'--fail-on','high']),1)
            self.assertEqual(main(['exposure-scan',str(p),'--fail-on','critical']),0)
if __name__ == '__main__':unittest.main()

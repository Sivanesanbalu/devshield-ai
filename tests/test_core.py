import tempfile
import unittest
from pathlib import Path
from devshield.core import scan, release_manifest, verify_manifest

class ScannerTests(unittest.TestCase):
    def test_secret_redaction_and_deterministic_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'config.py'
            secret = 'topsecretvalue123456'
            p.write_text('api_key = "' + secret + '"\n')
            out = scan(Path(tmp))
            self.assertEqual(out['summary']['high'], 1)
            self.assertNotIn(secret, str(out))

    def test_ignores_symlinks_and_dependency_folders(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'node_modules').mkdir()
            (root/'node_modules'/'x.py').write_text('api_key = "topsecretvalue123456"')
            (root/'link.py').symlink_to(root/'node_modules'/'x.py')
            self.assertEqual(scan(root)['files_scanned'], 0)

    def test_manifest_detects_modified_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'app.exe'
            p.write_bytes(b'binary-1')
            report = release_manifest(Path(tmp))
            self.assertTrue(verify_manifest(Path(tmp), report)['verified'])
            p.write_bytes(b'binary-2')
            self.assertFalse(verify_manifest(Path(tmp), report)['verified'])

if __name__ == '__main__':
    unittest.main()

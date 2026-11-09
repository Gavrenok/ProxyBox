"""Public release boundary and reproducibility; never touches a live system."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('release_builder', Path(__file__).parents[1] / 'build_release.py')
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class ReleaseBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for relative in builder.FILES.values():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('synthetic source: ' + relative + '\n').encode())

    def archive(self, name='release.tar.gz'):
        output = self.root / name
        result = builder.build(output, self.root)
        return output, result

    def test_release_excludes_unreviewed_files_even_beside_allowed_sources(self):
        for relative in ('analysis/private.json', 'geobox.img.xz', 'pi/step13-panel.sh',
                         'pi/app/proxy.json', 'pi/app/remote_phone.plist',
                         'pi/app/unreviewed.py', 'pi/app/__pycache__/secrets.pyc',
                         'pi/system/credentials.conf', 'singbox/vendor.bin'):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'PRIVATE-CONTAMINATION-MARKER')
        output, _ = self.archive()
        with tarfile.open(output) as archive:
            self.assertEqual(set(archive.getnames()), set(builder.FILES) | {'manifest.json'})
            for member in archive.getmembers():
                self.assertTrue(member.isfile())
                self.assertNotIn(b'PRIVATE-CONTAMINATION-MARKER', archive.extractfile(member).read())

    def test_manifest_matches_exact_payload_and_no_self_reference(self):
        output, result = self.archive()
        self.assertEqual(result['sha256'], hashlib.sha256(output.read_bytes()).hexdigest())
        with tarfile.open(output) as archive:
            manifest = json.load(archive.extractfile('manifest.json'))
            self.assertEqual(manifest['format'], 1)
            self.assertEqual(set(manifest['files']), set(builder.FILES))
            for name, expected in manifest['files'].items():
                self.assertEqual(hashlib.sha256(archive.extractfile(name).read()).hexdigest(), expected)

    def test_reproducible_despite_source_timestamps_and_output_filename(self):
        first, _ = self.archive('first.tar.gz')
        import os
        for name in builder.FILES.values():
            os.utime(self.root / name, (123456789, 123456789))
        second, _ = self.archive('second.tar.gz')
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with tarfile.open(second) as archive:
            for member in archive.getmembers():
                self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 0))
                self.assertEqual((member.uname, member.gname), ('', ''))
                self.assertEqual(member.mode, 0o755 if member.name.endswith('.sh') or member.name == 'install.py' else 0o644)

    def test_missing_source_preserves_existing_artifact(self):
        output = self.root / 'existing.tar.gz'
        output.write_bytes(b'last-known-good')
        (self.root / 'pi/ios_pairing_worker.py').unlink()
        with self.assertRaisesRegex(ValueError, 'missing'):
            builder.build(output, self.root)
        self.assertEqual(output.read_bytes(), b'last-known-good')

    def test_output_cannot_overwrite_source(self):
        source = self.root / 'README.md'
        before = source.read_bytes()
        with self.assertRaisesRegex(ValueError, 'overwrite'):
            builder.build(source, self.root)
        self.assertEqual(source.read_bytes(), before)

    def test_symlink_source_is_rejected(self):
        source = self.root / 'README.md'
        original = self.root / 'outside-secret.txt'
        original.write_bytes(b'secret')
        source.unlink()
        try:
            source.symlink_to(original)
        except OSError:
            self.skipTest('Host does not permit creating symlinks')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.archive()

    def test_symlink_source_directory_is_rejected(self):
        directory = self.root / 'pi/system'
        moved = self.root / 'moved-system'
        directory.rename(moved)
        try:
            directory.symlink_to(moved, target_is_directory=True)
        except OSError:
            self.skipTest('Host does not permit creating directory symlinks')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.archive()


if __name__ == '__main__':
    unittest.main()

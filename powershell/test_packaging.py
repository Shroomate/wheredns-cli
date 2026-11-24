"""Offline package integrity tests; fixture binaries are deliberately inert."""
import hashlib
import importlib.util
import io
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

spec = importlib.util.spec_from_file_location('builder', Path(__file__).with_name('build-module.py'))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.artifacts = self.root / 'archives'
        self.artifacts.mkdir()
        self.names = []
        sums = []
        for target in builder.TARGETS:
            windows = target.endswith('msvc')
            name = f'wheredns-v1.2.3-{target}'
            archive = self.artifacts / (name + ('.zip' if windows else '.tar.gz'))
            data = target.encode()
            if windows:
                with zipfile.ZipFile(archive, 'w') as bundle:
                    bundle.writestr(name + '/wheredns.exe', data)
            else:
                with tarfile.open(archive, 'w:gz') as bundle:
                    info = tarfile.TarInfo('./wheredns')
                    info.size = len(data)
                    bundle.addfile(info, io.BytesIO(data))
            self.names.append(archive)
            sums.append(f'{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}')
        (self.artifacts / 'SHA256SUMS').write_text('\n'.join(sums))

    def test_all_targets_and_version_are_bundled(self):
        module = builder.build(self.artifacts, self.root / 'output', '1.2.3')
        self.assertIn("ModuleVersion = '1.2.3'", (module / 'WhereDNS.psd1').read_text())
        for target in builder.TARGETS:
            binary = module / 'bin' / target / ('wheredns.exe' if target.endswith('msvc') else 'wheredns')
            self.assertEqual(binary.read_bytes(), target.encode())
        self.assertTrue((module / 'LICENSE').is_file())

    def test_corruption_rejected_before_staging(self):
        self.names[-1].write_bytes(b'corrupt')
        with self.assertRaisesRegex(ValueError, 'Checksum'):
            builder.build(self.artifacts, self.root / 'output', '1.2.3')
        self.assertFalse((self.root / 'output/WhereDNS').exists())

    def test_missing_platform_rejected(self):
        self.names[-1].unlink()
        with self.assertRaises(FileNotFoundError):
            builder.build(self.artifacts, self.root / 'output', '1.2.3')

    def test_existing_module_not_overwritten(self):
        module = builder.build(self.artifacts, self.root / 'output', '1.2.3')
        with self.assertRaises(FileExistsError):
            builder.build(self.artifacts, self.root / 'output', '1.2.3')
        self.assertTrue((module / 'WhereDNS.psd1').exists())

    def test_invalid_version_rejected(self):
        with self.assertRaises(ValueError):
            builder.stage_module(self.root / 'output', '../bad')


if __name__ == '__main__':
    unittest.main()

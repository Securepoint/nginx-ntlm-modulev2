import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest


@unittest.skipUnless(shutil.which("bash"), "build helpers require Bash")
class BuildDownloadTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="ntlm-build-utils-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        self.archive = self.path / "fixture.tar.gz"
        with tarfile.open(self.archive, "w:gz") as archive:
            data = b"verified source"
            entry = tarfile.TarInfo("source.txt")
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
        self.checksum = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.output = self.path / "output"
        self.output.mkdir()
        binary = self.path / "bin"
        binary.mkdir()
        curl = binary / "curl"
        curl.write_text(
            '#!/bin/sh\n'
            'if [ "${TEST_DOWNLOAD_FAIL:-0}" = 1 ]; then exit 22; fi\n'
            'while [ "$#" -gt 0 ]; do\n'
            '    if [ "$1" = -o ]; then\n'
            '        cp "$TEST_ARCHIVE" "$2"\n'
            '        exit $?\n'
            '    fi\n'
            '    shift\n'
            'done\n'
            'exit 1\n',
            encoding="ascii",
        )
        curl.chmod(0o755)
        self.environment = dict(
            os.environ,
            PATH=str(binary) + os.pathsep + os.environ["PATH"],
            TEST_ARCHIVE=str(self.archive),
            TEST_DOWNLOAD_FAIL="0",
        )

    def download(self):
        helper = Path(__file__).resolve().parents[1] / "utils" / "build_common.sh"
        return subprocess.run(
            ["bash", "-c",
             'source "$1"; download_source https://example.invalid/source.tar.gz "$2" .',
             "test-download", str(helper), self.checksum],
            cwd=self.output, env=self.environment,
            capture_output=True, text=True, timeout=5,
        )

    def test_verified_archive_is_extracted(self):
        result = self.download()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.output / "source.txt").read_bytes(), b"verified source")
        self.assertFalse((self.output / "source.tar.gz").exists())

    def test_modified_archive_is_not_extracted(self):
        with self.archive.open("ab") as archive:
            archive.write(b"modified")
        result = self.download()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.output / "source.txt").exists())

    def test_failed_download_does_not_extract_a_stale_archive(self):
        shutil.copyfile(self.archive, self.output / "source.tar.gz")
        self.environment["TEST_DOWNLOAD_FAIL"] = "1"
        result = self.download()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.output / "source.txt").exists())


if __name__ == "__main__":
    unittest.main()

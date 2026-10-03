"""Independent changed-byte and raw-metadata controls for the build identity gate."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile


TOOL = Path(__file__).resolve().parents[1] / "tools/verify_install.py"
SPEC = importlib.util.spec_from_file_location("package_gate", TOOL)
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class Distribution:
    version = "0.1.2"

    def __init__(self, root, names):
        self.root, self.files = root, [Path(name) for name in names]

    def locate_file(self, entry):
        return self.root / entry


class PackageGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.root = Path(self.temp.name)
        self.source, self.installed = self.root / "source", self.root / "installed"
        self.wheel = self.root / "test.whl"
        self.metadata_name = "evtx_recovery_review-0.1.2.dist-info/METADATA"
        self.files, rows = {}, []
        self.source.mkdir(parents=True)
        (self.source / "pyproject.toml").write_text('[project]\nversion = "0.1.2"\n')
        # This independent fake distribution supplies 20 module identities; a
        # real built/installed consumer is separately checked after final build.
        for index in range(20):
            relative = "src/evtx_recovery_review/module%d.py" % index
            raw = b"VALUE = 1\n"
            source = self.source / relative
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(raw)
            rows.append({"kind": "runtime", "path": relative, "bytes": len(raw),
                         "sha256": hashlib.sha256(raw).hexdigest()})
            self.files[relative[4:]] = raw
        self.files[self.metadata_name] = b"Name: evtx-recovery-review\r\nVersion: 0.1.2\r\n\r\n"
        for name in ("LICENSE", "NOTICE"):
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"ENTIRE_LICENSE_BYTES\n")
            self.files[self.metadata_name[:-8] + "licenses/" + name] = path.read_bytes()
        manifest = self.source / "evidence/source-review.json"
        manifest.parent.mkdir()
        manifest.write_text(json.dumps({"files": rows}))
        self.write_wheel()
        for name, raw in self.files.items():
            path = self.installed / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.distribution = Distribution(self.installed, self.files)

    def tearDown(self):
        self.temp.cleanup()

    def write_wheel(self):
        with zipfile.ZipFile(self.wheel, "w") as archive:
            for name, raw in self.files.items():
                archive.writestr(name, raw)

    def verify(self):
        return GATE.verify(self.wheel, self.source, self.distribution)

    def test_matching_raw_bytes_and_CRLF_metadata(self):
        result = self.verify()
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["runtime_modules"], 20)
        self.assertEqual(result["raw_metadata_sha256"], hashlib.sha256(self.files[self.metadata_name]).hexdigest())
        self.assertEqual(len(result["licenses"]), 2)

    def test_changed_source_bytes_are_rejected(self):
        (self.source / "src/evtx_recovery_review/module0.py").write_bytes(b"VALUE = 2\n")
        with self.assertRaisesRegex(ValueError, "runtime_source_wheel_installed_mismatch"):
            self.verify()

    def test_changed_built_bytes_are_rejected(self):
        self.files["evtx_recovery_review/module0.py"] = b"VALUE = 2\n"
        self.write_wheel()
        with self.assertRaisesRegex(ValueError, "runtime_source_wheel_installed_mismatch"):
            self.verify()

    def test_changed_installed_bytes_and_line_endings_are_rejected(self):
        (self.installed / "evtx_recovery_review/module0.py").write_bytes(b"VALUE = 1\r\n")
        with self.assertRaisesRegex(ValueError, "runtime_source_wheel_installed_mismatch"):
            self.verify()

    def test_raw_metadata_normalization_does_not_pass(self):
        (self.installed / self.metadata_name).write_bytes(self.files[self.metadata_name].replace(b"\r\n", b"\n"))
        with self.assertRaisesRegex(ValueError, "raw_metadata_identity"):
            self.verify()

    def test_full_license_changed_bytes_are_rejected(self):
        (self.installed / (self.metadata_name[:-8] + "licenses/LICENSE")).write_bytes(b"PARTIAL_LICENSE")
        with self.assertRaisesRegex(ValueError, "complete_license_identity"):
            self.verify()

    def test_missing_installed_metadata_is_rejected(self):
        self.distribution.files.remove(Path(self.metadata_name))
        with self.assertRaisesRegex(ValueError, "installed_file_identity_missing_or_duplicate"):
            self.verify()

    def test_runtime_manifest_requires_all_modules(self):
        manifest = self.source / "evidence/source-review.json"
        value = json.loads(manifest.read_text())
        value["files"].pop()
        manifest.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "runtime_manifest_count_mismatch"):
            self.verify()


if __name__ == "__main__":
    unittest.main()

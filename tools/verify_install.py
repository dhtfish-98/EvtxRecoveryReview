"""Build-only source/wheel/installed identity gate; no target input is executed."""
import hashlib
from importlib import metadata
import json
from pathlib import Path
import sys
import zipfile


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def raw_file(path, cap):
    with Path(path).open("rb") as stream:
        raw = stream.read(cap + 1)
    if len(raw) > cap:
        raise ValueError("identity_file_budget")
    return raw


def installed_raw(distribution, name, cap):
    entries = [entry for entry in (distribution.files or ()) if str(entry) == name]
    if len(entries) != 1:
        raise ValueError("installed_file_identity_missing_or_duplicate")
    return raw_file(distribution.locate_file(entries[0]), cap)


def verify(wheel, root, distribution=None):
    root = Path(root)
    raw_manifest = raw_file(root / "evidence/source-review.json", 256 * 1024)
    manifest = json.loads(raw_manifest)
    distribution = metadata.distribution("evtx-recovery-review") if distribution is None else distribution
    if distribution.version != "0.1.0":
        raise ValueError("installed_version_mismatch")
    if Path(wheel).stat().st_size > 8 * 1024 * 1024:
        raise ValueError("wheel_budget")
    checked = []
    with zipfile.ZipFile(wheel) as archive:
        infos = archive.infolist()
        names = [row.filename for row in infos]
        if (len(names) > 512 or len(set(names)) != len(names) or
                sum(row.file_size for row in infos) > 8 * 1024 * 1024 or
                any(row.file_size > 1024 * 1024 or ".." in Path(row.filename).parts or
                    row.filename.startswith("/") for row in infos)):
            raise ValueError("wheel_members_budget_or_identity")
        runtime = [row for row in manifest["files"] if row["kind"] == "runtime"]
        if len(runtime) != 20:
            raise ValueError("runtime_manifest_count_mismatch")
        for row in runtime:
            name = row["path"]
            if not name.startswith("src/evtx_recovery_review/") or ".." in Path(name).parts:
                raise ValueError("runtime_manifest_path_mismatch")
            module = name[4:]
            source = raw_file(root / name, 65536)
            built = archive.read(module)
            installed = installed_raw(distribution, module, 65536)
            if source != built or built != installed or sha(source) != row["sha256"] or len(source) != row["bytes"]:
                raise ValueError("runtime_source_wheel_installed_mismatch")
            checked.append((module, sha(source)))
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata_names) != 1:
            raise ValueError("wheel_metadata_identity")
        metadata_name = metadata_names[0]
        metadata_raw = archive.read(metadata_name)
        if len(metadata_raw) > 65536 or metadata_raw != installed_raw(distribution, metadata_name, 65536):
            raise ValueError("raw_metadata_identity")
        licenses = []
        for name in ("LICENSE", "NOTICE", "licenses/EVTXtract-Apache-2.0.txt", "licenses/python-evtx-Apache-2.0.txt"):
            source = raw_file(root / name, 65536)
            target = metadata_name[:-8] + "licenses/" + name
            if archive.read(target) != source or installed_raw(distribution, target, 65536) != source:
                raise ValueError("complete_license_identity")
            licenses.append({"path": name, "bytes": len(source), "sha256": sha(source)})
    return {"status": "PASS", "runtime_modules": len(checked), "source_wheel_installed": "IDENTICAL",
            "runtime_module_hashes_sha256": sha(json.dumps(checked, separators=(",", ":")).encode()),
            "source_review_sha256": sha(raw_manifest), "wheel_sha256": sha(raw_file(wheel, 8 * 1024 * 1024)),
            "raw_metadata_sha256": sha(metadata_raw), "raw_metadata_bytes": len(metadata_raw), "licenses": licenses}


def main():
    try:
        if len(sys.argv) != 2:
            raise ValueError("one_built_wheel_required")
        result = verify(sys.argv[1], Path(__file__).resolve().parent.parent)
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, metadata.PackageNotFoundError):
        print(json.dumps({"status": "FAIL", "code": "artifact_identity_rejected"}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

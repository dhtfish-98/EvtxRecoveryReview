"""Shared batch snapshot-reader pattern; every component is opened without links."""

import os
from pathlib import Path
import stat


def read_local(path, limit):
    dir_fd_support = getattr(os, "supports_dir_fd", None)
    if (any(type(getattr(os, name, None)) is not int or getattr(os, name, None) <= 0 for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK"))
            or type(dir_fd_support) not in (set, frozenset)
            or os.open not in dir_fd_support):
        raise ValueError("platform_secure_open_unsupported")
    value = os.fspath(path)
    if type(value) is not str or ":" in value or value == "-" or "\0" in value:
        raise ValueError("explicit_local_file_required")
    absolute = Path(os.path.abspath(value))
    # Reject traversal in the submitted spelling rather than normalizing it away.
    if ".." in Path(value).parts or len(absolute.parts) > 64:
        raise ValueError("bounded_direct_path_required")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor = None
    try:
        for component in absolute.parts[1:-1]:
            next_directory = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                     dir_fd=directory)
            os.close(directory)
            directory = next_directory
        descriptor = os.open(absolute.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError("regular_bounded_snapshot_required")
        chunks, length = [], 0
        while True:
            chunk = os.read(descriptor, min(65536, limit - length + 1))
            if not chunk:
                break
            chunks.append(chunk)
            length += len(chunk)
            if length > limit:
                raise ValueError("snapshot_byte_budget")
        after = os.fstat(descriptor)
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if not stat.S_ISREG(after.st_mode) or identity(before) != identity(after) or length != after.st_size:
            raise ValueError("snapshot_changed_or_short_read")
        return b"".join(chunks)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)

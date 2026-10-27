#!/usr/bin/env python3
"""Cross-compile and package the six supported Certainted release binaries."""

import argparse
import gzip
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parent.parent
TARGETS = (
    ("darwin", "amd64"),
    ("darwin", "arm64"),
    ("linux", "amd64"),
    ("linux", "arm64"),
    ("windows", "amd64"),
    ("windows", "arm64"),
)


def package_tar(binary: Path, archive: Path) -> None:
    with archive.open("wb") as output:
        with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as tar:
                info = tarfile.TarInfo(binary.name)
                info.size = binary.stat().st_size
                info.mode = 0o755
                info.mtime = 0
                with binary.open("rb") as source:
                    tar.addfile(info, source)


def package_zip(binary: Path, archive: Path) -> None:
    with zipfile.ZipFile(archive, mode="w") as zip_file:
        info = zipfile.ZipInfo(binary.name, date_time=(1980, 1, 1, 0, 0, 0))
        info.create_system = 3
        info.external_attr = 0o755 << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        with binary.open("rb") as source, zip_file.open(info, mode="w") as target:
            while chunk := source.read(1024 * 1024):
                target.write(chunk)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", help="release tag, for example v0.1.0")
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", args.version):
        parser.error("version must be a stable tag such as v0.1.0")

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        parser.error(f"output directory must be empty: {output}")

    assets = []
    with tempfile.TemporaryDirectory(prefix="certainted-build-") as temporary:
        for goos, goarch in TARGETS:
            binary = Path(temporary) / ("certainted.exe" if goos == "windows" else "certainted")
            environment = os.environ.copy()
            environment.update(CGO_ENABLED="0", GOOS=goos, GOARCH=goarch)
            # No build ID or checkout paths are embedded in the executable.
            subprocess.run(
                ["go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid=", "-o", str(binary), "."],
                cwd=ROOT,
                env=environment,
                check=True,
            )
            stem = f"certainted_{goos}_{goarch}"
            if goos == "windows":
                archive = output / f"{stem}.zip"
                package_zip(binary, archive)
            else:
                archive = output / f"{stem}.tar.gz"
                package_tar(binary, archive)
            assets.append(archive)
            print(f"Built {archive.name}", flush=True)

    with (output / "checksums.txt").open("w", encoding="ascii") as checksums:
        for asset in sorted(assets):
            checksums.write(f"{sha256(asset)}  {asset.name}\n")


if __name__ == "__main__":
    main()

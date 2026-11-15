"""Prepare isolated older-reader/newer-writer source fixtures; never build or deploy."""
import argparse
from pathlib import Path
import shutil


def prepare(source, destination, newer):
    destination.mkdir(parents=True, exist_ok=False)
    for filename in ("Cargo.toml", "Cargo.lock"):
        shutil.copy2(source / filename, destination / filename)
    for directory in ("src", "tests"):
        shutil.copytree(source / directory, destination / directory,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    if newer:
        file = destination / "src/observe_export.rs"
        text = file.read_text()
        needle = "closed_enum!(EventKind {\n"
        assert text.count(needle) == 1 and "FutureWriterFixture" not in text
        file.write_text(text.replace(needle, needle + "    FutureWriterFixture,\n", 1))
    manifest = destination / "Cargo.toml"
    manifest.write_text(manifest.read_text() + '''
[[bin]]
name = "dtxj2-store-compat"
path = "tests/fixtures/dtxj2/store_compat.rs"
required-features = ["daemon"]
''')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    prepare(args.source, args.output / "older", False)
    prepare(args.source, args.output / "newer", True)
    print("prepared two independent source trees; no build performed")


if __name__ == "__main__":
    main()

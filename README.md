# binsbom

A tiny, pluggable binary scanner that emits an **SBOM** (CycloneDX JSON by default).

## MVP Features

- Walk a file or directory and identify file types by magic bytes:
  - ELF / PE / Mach-O binaries
  - JAR/WAR/EAR (reads MANIFEST + Maven `pom.properties` → name/version/purl)
- Compute SHA-256 file hashes
- Emit **CycloneDX JSON** SBOM using `cyclonedx-python-lib`

## Dependencies graph

- The ELF detector uses **LIEF** to extract `DT_NEEDED` and emits dependency edges in CycloneDX.
- Try on Linux: `binsbom scan /bin -o sbom.json` and inspect `dependencies`.

## Install

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .
```

## Usage

```bash
binsbom scan /path/to/dir --out sbom.json --format cyclonedx-json
```

## Notes

- If `lief` is not installed or parsing fails, the ELF detector falls back gracefully.
- Extend PE/Mach-O similarly to attach imports and `LC_LOAD_DYLIB` data.
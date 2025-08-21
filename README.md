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

## Windows (PE) imports

- The PE detector uses **pefile** to extract imported DLLs and adds them as dependencies.
- It also captures `imphash` and basic version info (Company/Product/FileVersion) when present.


## PE import → purl mapping
- A simple lookup lives at `binsbom/data/pe_purl_map.json` and a few **regex heuristics** in `detectors/windows_map.py`.
- Customize the JSON to map DLL names (lowercased) to `purl`s, e.g. `"libcrypto-3-x64.dll": {"purl": "pkg:generic/openssl/libcrypto@3"}`.
- During scanning, imported DLLs will carry `purl` when a mapping is found.


## macOS (Mach-O) dylibs
- The Mach-O detector uses **LIEF** to parse `LC_LOAD_DYLIB` and `LC_ID_DYLIB`.
- It maps common libraries (OpenSSL, zlib, curl, sqlite, libpng, libjpeg, Qt) to **purl** identifiers.
- Dependencies are added to the CycloneDX SBOM as components with bom-refs and purls.


## Go build-info enrichment
- Scans binaries for embedded Go module strings (similar to `go version -m` output).
- Adds each module as a dependency with purl `pkg:golang/<module>@<version>`.
- Stores light evidence under `go_build_info` (main module path and count).


## SPDX 3.0 JSON output
- Emit an SPDX document with **packages**, **files**, and **relationships** (DESCRIBES, DEPENDS_ON, CONTAINS).
- Usage: `binsbom scan <path> --format spdx-json -o sbom.spdx.json`
- Notes: IDs are deterministic from content where possible; `purl` appears in `externalRefs`.


## License detection & source enumeration
- The SPDX writer now:
  - Detects LICENSE/NOTICE files next to binaries and inside ZIP/JAR archives
  - Attempts a simple SPDX ID classification (Apache-2.0, MIT, BSD-2/3, GPL/LGPL, MPL-2.0)
  - Enumerates files inside ZIP/JAR and adds them to the SPDX `files` section
    - Classifies files as SOURCE/TEXT/BINARY by extension

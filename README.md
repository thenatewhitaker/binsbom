# binsbom (starter)

A tiny, pluggable binary scanner that emits an **SBOM** (CycloneDX JSON by default). Designed as a teaching/research scaffold you can extend in Python.

## Features (MVP)

- Walk a file or directory and identify file types by magic bytes:
  - ELF / PE / Mach-O binaries (basic info)
  - JAR/WAR/EAR (reads MANIFEST and Maven `pom.properties`)
- Compute SHA-256 file hashes
- Emit **CycloneDX JSON** SBOM using `cyclonedx-python-lib`
- Optional deep parsing:
  - **ELF / Mach-O** via `lief` or `pyelftools`
  - **PE** via `pefile`

> This starter focuses on structure. You’ll expand detectors to extract **dependencies** (DT_NEEDED, imports, LC_LOAD_DYLIB, etc.), and attach them as components with `dependsOn` relationships.

## Install

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .
```

## Usage

```bash
binsbom scan /path/to/dir --out sbom.json --format cyclonedx-json
# or a single file
binsbom scan /bin/ls -o ls-sbom.json
```

## Roadmap ideas

- Parse ELF `.dynamic` (DT_NEEDED), `.note.gnu.build-id` (build-id)
- Parse PE import table + VERSIONINFO
- Parse Mach-O LC_LOAD_DYLIB
- Extract Go build-info; enrich with module versions
- Emit SPDX 3.0 in addition to CycloneDX
- Add evidence + confidence scores per component
- Support container images / firmware (binwalk) as inputs
- VEX emission (OpenVEX / CycloneDX / CSAF)

MIT License.
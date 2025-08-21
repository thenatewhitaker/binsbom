
from __future__ import annotations
import pathlib, hashlib
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from .detectors.core import sniff_type, FileType
from .detectors.java import detect_java_component
from .detectors.elf import detect_elf_component
from .detectors.pe import detect_pe_component
from .detectors.macho import detect_macho_component
from .detectors.go import enrich_with_go_modules
from .detectors.go_external import enrich_with_go_version_m


@dataclass
class ComponentFinding:
    name: str
    version: Optional[str]
    type: str  # library/application/framework/other
    purl: Optional[str] = None
    supplier: Optional[str] = None
    hashes: Dict[str, str] = field(default_factory=dict)
    evidence: Dict[str, Any] = field(default_factory=dict)
    bom_ref: Optional[str] = None  # populated by writer
    path: Optional[str] = None     # file path on disk


class Scanner:
    def __init__(self) -> None:
        pass

    def scan_path(self, path: pathlib.Path) -> List[ComponentFinding]:
        findings: List[ComponentFinding] = []
        if path.is_file():
            findings.extend(self._scan_file(path))
        else:
            for p in path.rglob("*"):
                if p.is_file():
                    findings.extend(self._scan_file(p))
        return findings

    def _sha256(self, p: pathlib.Path) -> str:
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 16), b""):
                h.update(chunk)
        return h.hexdigest()

    def _scan_file(self, p: pathlib.Path) -> List[ComponentFinding]:
        try:
            ftype = sniff_type(p)
        except Exception:
            return []

        if ftype == FileType.UNKNOWN:
            return []

        sha256 = self._sha256(p)
        common = dict(hashes={"SHA-256": sha256}, path=str(p))

        findings: List[ComponentFinding] = []

        if ftype == FileType.JAVA_ARCHIVE:
            jf = detect_java_component(p, **common)
            if jf:
                enrich_with_go_modules(jf, p)
                enrich_with_go_version_m(jf, p)
                findings.append(jf)

        elif ftype == FileType.ELF:
            ef = detect_elf_component(p, **common)
            if ef:
                enrich_with_go_modules(ef, p)
                enrich_with_go_version_m(ef, p)
                findings.append(ef)

        elif ftype == FileType.PE:
            pf = detect_pe_component(p, **common)
            if pf:
                enrich_with_go_modules(pf, p)
                enrich_with_go_version_m(pf, p)
                findings.append(pf)

        elif ftype == FileType.MACHO:
            mf = detect_macho_component(p, **common)
            if mf:
                enrich_with_go_modules(mf, p)
                enrich_with_go_version_m(mf, p)
                findings.append(mf)

        else:
            findings.append(ComponentFinding(
                name=p.name, version=None, type="file", **common
            ))

        return findings

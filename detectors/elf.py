
from __future__ import annotations
import pathlib
from typing import Optional
from ..scanner import ComponentFinding

def detect_elf_component(p: pathlib.Path, **common) -> Optional[ComponentFinding]:
    """
    Minimal ELF detector. For deep dependency extraction, install 'lief' or 'pyelftools' and extend here.
    For MVP, we just mark it as an application/library with the filename as name.
    """
    name = p.name
    version = None
    evidence = {"format": "ELF"}
    # TODO: Use LIEF to extract SONAME, DT_NEEDED, build-id, etc.
    return ComponentFinding(name=name, version=version, type="application", evidence=evidence, **common)

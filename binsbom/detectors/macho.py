
from __future__ import annotations
import pathlib
from typing import Optional
from ..scanner import ComponentFinding

def detect_macho_component(p: pathlib.Path, **common) -> Optional[ComponentFinding]:
    name = p.name
    version = None
    evidence = {"format": "Mach-O"}
    # TODO: use LIEF to extract LC_LOAD_DYLIB and versions
    return ComponentFinding(name=name, version=version, type="application", evidence=evidence, **common)

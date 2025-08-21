
from __future__ import annotations
import pathlib
from typing import Optional
from ..scanner import ComponentFinding

def detect_pe_component(p: pathlib.Path, **common) -> Optional[ComponentFinding]:
    """
    Minimal PE detector. Extend using 'pefile' to read imports and VERSIONINFO.
    """
    name = p.name
    version = None
    evidence = {"format": "PE"}
    # TODO: pefile parsing (imports, version resource, company name, product version, etc.)
    return ComponentFinding(name=name, version=version, type="application", evidence=evidence, **common)

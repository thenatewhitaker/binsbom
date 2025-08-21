
from __future__ import annotations
import pathlib
from typing import Optional
from ..scanner import ComponentFinding

def detect_pe_component(p: pathlib.Path, **common) -> Optional[ComponentFinding]:
    name = p.name
    version = None
    evidence = {"format": "PE"}
    # TODO: use pefile to extract imports & VERSIONINFO
    return ComponentFinding(name=name, version=version, type="application", evidence=evidence, **common)

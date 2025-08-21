
from __future__ import annotations
import pathlib, re
from typing import Optional, List, Dict, Any

from ..scanner import ComponentFinding

def _parse_version_from_soname(soname: str) -> Optional[str]:
    m = re.search(r"\.so(?:\.\d+(?:\.\d+)*)$", soname)
    if m:
        return soname[soname.find(".so.") + 4:]
    return None

def detect_elf_component(p: pathlib.Path, **common) -> Optional[ComponentFinding]:
    name = p.name
    version = None
    evidence: Dict[str, Any] = {"format": "ELF"}
    deps: List[Dict[str, Any]] = []
    comp_type = "application"

    try:
        import lief
        b = lief.parse(str(p))
        if b is None:
            return ComponentFinding(name=name, version=version, type=comp_type, evidence=evidence, **common)

        # Build-id
        build_id = None
        try:
            for n in getattr(b, "notes", []):
                if hasattr(n, "name") and "GNU" in str(n.name):
                    desc = getattr(n, "description", None) or getattr(n, "content", None)
                    if isinstance(desc, (bytes, bytearray)):
                        build_id = desc.hex()
                    elif isinstance(desc, str):
                        build_id = desc.strip()
        except Exception:
            pass
        if build_id:
            evidence["build_id"] = build_id

        # SONAME
        try:
            soname = getattr(b, "soname", None)
            if soname:
                name = soname
                version = _parse_version_from_soname(soname) or version
                comp_type = "library"
                evidence["soname"] = soname
        except Exception:
            pass

        # DT_NEEDED
        try:
            if hasattr(b, "libraries"):
                for lib in b.libraries:
                    dep = {"name": lib}
                    dv = _parse_version_from_soname(lib)
                    if dv:
                        dep["version"] = dv
                    deps.append(dep)
        except Exception:
            pass

        # RPATH/RUNPATH
        try:
            rpath = None
            runpath = None
            for de in getattr(b, "dynamic_entries", []):
                tag = getattr(de, "tag", None)
                if str(tag).endswith("RPATH"):
                    rpath = getattr(de, "name", None) or getattr(de, "value", None)
                if str(tag).endswith("RUNPATH"):
                    runpath = getattr(de, "name", None) or getattr(de, "value", None)
            if rpath:
                evidence["rpath"] = str(rpath)
            if runpath:
                evidence["runpath"] = str(runpath)
        except Exception:
            pass

        # Interpreter
        try:
            interp = getattr(b, "interpreter", None)
            if interp:
                evidence["interpreter"] = interp
        except Exception:
            pass

    except Exception:
        pass

    if deps:
        evidence["dependencies"] = deps

    return ComponentFinding(name=name, version=version, type=comp_type, evidence=evidence, **common)

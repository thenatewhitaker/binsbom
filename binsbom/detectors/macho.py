
from __future__ import annotations
import pathlib, re
from typing import Optional, List, Dict, Any
from ..scanner import ComponentFinding

def _parse_version_from_dylib(libname: str) -> Optional[str]:
    # e.g., libssl.3.dylib → 3 ; libcrypto.1.1.dylib → 1.1
    m = re.search(r"\.(\d+(?:\.\d+)*)\.dylib$", libname)
    return m.group(1) if m else None

def _map_dylib_to_purl(libname: str) -> Optional[str]:
    lname = libname.lower()
    if lname.startswith("libssl."):
        ver = _parse_version_from_dylib(lname) or ""
        return f"pkg:generic/openssl/libssl@{ver}" if ver else "pkg:generic/openssl/libssl"
    if lname.startswith("libcrypto."):
        ver = _parse_version_from_dylib(lname) or ""
        return f"pkg:generic/openssl/libcrypto@{ver}" if ver else "pkg:generic/openssl/libcrypto"
    if lname.startswith("libz."):
        return "pkg:generic/zlib"
    if lname.startswith("libcurl."):
        return "pkg:generic/curl"
    if lname.startswith("libsqlite3."):
        return "pkg:generic/sqlite"
    if lname.startswith("libpng") and lname.endswith(".dylib"):
        return "pkg:generic/libpng"
    if lname.startswith("libjpeg") and lname.endswith(".dylib"):
        return "pkg:generic/libjpeg-turbo"
    if lname.startswith("qt") and lname.endswith(".dylib"):
        # guess Qt major version
        m = re.match(r"^qt(\d+)", lname)
        if m:
            return f"pkg:generic/qt/qtbase@{m.group(1)}"
        return "pkg:generic/qt/qtbase"
    return None

def detect_macho_component(p: pathlib.Path, **common) -> Optional[ComponentFinding]:
    name = p.name
    version = None
    comp_type = "application"
    evidence: Dict[str, Any] = {"format": "Mach-O"}
    deps: List[Dict[str, Any]] = []

    try:
        import lief
        b = lief.parse(str(p))
        if b is None:
            return ComponentFinding(name=name, version=version, type=comp_type, evidence=evidence, **common)

        # ID (for dylib itself)
        try:
            if hasattr(b, "name") and b.name:
                name = b.name
                version = _parse_version_from_dylib(b.name) or version
                comp_type = "library"
                evidence["id_dylib"] = b.name
        except Exception:
            pass

        # LC_LOAD_DYLIB commands
        try:
            if hasattr(b, "libraries"):
                for lib in b.libraries:
                    dep = {"name": lib}
                    v = _parse_version_from_dylib(lib)
                    if v:
                        dep["version"] = v
                    purl = _map_dylib_to_purl(lib)
                    if purl:
                        dep["purl"] = purl
                    deps.append(dep)
                if deps:
                    evidence["load_dylibs"] = b.libraries
        except Exception:
            pass

        # Build version / minos
        try:
            if hasattr(b, "build_version"):
                evidence["build_version"] = str(b.build_version)
            if hasattr(b, "minos"):
                evidence["minos"] = str(b.minos)
        except Exception:
            pass

    except Exception:
        pass

    if deps:
        evidence["dependencies"] = deps

    return ComponentFinding(name=name, version=version, type=comp_type, evidence=evidence, **common)

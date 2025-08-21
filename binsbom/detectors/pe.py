
from __future__ import annotations
import pathlib, datetime
from typing import Optional, List, Dict, Any
from ..scanner import ComponentFinding
from .windows_map import map_dll_to_purl

IMAGE_FILE_DLL = 0x2000

def _safe_decode(b) -> str:
    try:
        if isinstance(b, bytes):
            return b.decode("utf-8", errors="ignore")
        return str(b) if b is not None else ""
    except Exception:
        return ""

def detect_pe_component(p: pathlib.Path, **common) -> Optional[ComponentFinding]:
    name = p.name
    version = None
    supplier = None
    comp_type = "application"
    evidence: Dict[str, Any] = {"format": "PE"}
    deps: List[Dict[str, Any]] = []

    try:
        import pefile
        pe = pefile.PE(str(p), fast_load=True)
        try:
            pe.parse_data_directories(
                directories=[
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']
                ]
            )
        except Exception:
            pass

        # Type
        try:
            if pe.FILE_HEADER.Characteristics & IMAGE_FILE_DLL:
                comp_type = "library"
        except Exception:
            pass

        # Basic metadata
        try:
            evidence["machine"] = pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
            evidence["subsystem"] = pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, pe.OPTIONAL_HEADER.Subsystem)
            evidence["compile_ts"] = int(pe.FILE_HEADER.TimeDateStamp)
        except Exception:
            pass

        # Imports → dependencies list
        try:
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                dlls = []
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = _safe_decode(entry.dll).lower()
                    if not dll:
                        continue
                    dep = {"name": dll}
                    # Map to purl when possible
                    purl = map_dll_to_purl(dll)
                    if purl:
                        dep["purl"] = purl
                    deps.append(dep)
                    dlls.append(dll)
                if dlls:
                    evidence["imported_dlls"] = dlls
        except Exception:
            pass

        # imphash
        try:
            ih = pe.get_imphash()
            if ih:
                evidence["imphash"] = ih.lower()
        except Exception:
            pass

        # VERSIONINFO
        try:
            if hasattr(pe, "FileInfo"):
                for fileinfo in pe.FileInfo:
                    if getattr(fileinfo, "Key", b"") == b"StringFileInfo":
                        for st in getattr(fileinfo, "StringTable", []):
                            entries = getattr(st, "entries", {})
                            def g(k: str) -> Optional[str]:
                                for kb, vb in entries.items():
                                    if _safe_decode(kb).lower() == k.lower():
                                        return _safe_decode(vb).strip() or None
                                return None
                            original = g("OriginalFilename")
                            product = g("ProductName")
                            company = g("CompanyName")
                            prodver = g("ProductVersion")
                            filever = g("FileVersion")
                            if original:
                                name = original
                            elif product:
                                name = product
                            if prodver or filever:
                                version = (prodver or filever)
                            if company:
                                supplier = company
                            evidence["versioninfo"] = {k: g(k) for k in ["ProductName","CompanyName","FileDescription","ProductVersion","FileVersion","OriginalFilename"]}
        except Exception:
            pass

    except Exception:
        pass

    if deps:
        evidence["dependencies"] = deps

    return ComponentFinding(name=name, version=version, type=comp_type, supplier=supplier, evidence=evidence, **common)


from __future__ import annotations
import json, re, pathlib
from typing import Optional, Dict, Any

_MAP_CACHE: Optional[Dict[str, Dict[str, str]]] = None
_REGEX_RULES = [
    # libssl/libcrypto with major version
    (re.compile(r"^lib(ssl|crypto)-(?P<maj>\d)(?:[_-]\d+)?-?(x86|x64)?\.dll$"), lambda m: f"pkg:generic/openssl/lib{m.group(1)}@{m.group('maj')}"),
    # libpngXY-Z.dll -> libpng@1.6 (best guess if starts with 16)
    (re.compile(r"^libpng(?P<xy>\d\d)-(?P<z>\d+)\.dll$"), lambda m: "pkg:generic/libpng@1.6" if m.group('xy').startswith('16') else "pkg:generic/libpng"),
    # qt DLLs -> qtbase major
    (re.compile(r"^qt(?P<maj>[56])\w+\.dll$"), lambda m: f"pkg:generic/qt/qtbase@{m.group('maj')}"),
    # vcruntime/msvcp variations with 14.*
    (re.compile(r"^(vcruntime|msvcp)\d+(?:_\d+)?\.dll$"), lambda m: f"pkg:generic/microsoft/{m.group(1)}@14"),
    # zlib
    (re.compile(r"^zlib\d*\.dll$"), lambda m: "pkg:generic/zlib"),
    # sqlite
    (re.compile(r"^sqlite3?\.dll$"), lambda m: "pkg:generic/sqlite"),
    # libcurl
    (re.compile(r"^libcurl(?:-x64)?\.dll$"), lambda m: "pkg:generic/curl"),
]

def _load_map() -> Dict[str, Dict[str, str]]:
    global _MAP_CACHE
    if _MAP_CACHE is not None:
        return _MAP_CACHE
    here = pathlib.Path(__file__).resolve().parent.parent / "data" / "pe_purl_map.json"
    try:
        _MAP_CACHE = json.loads(here.read_text(encoding="utf-8"))
    except Exception:
        _MAP_CACHE = {}
    return _MAP_CACHE

def map_dll_to_purl(dll_name: str) -> Optional[str]:
    """
    Returns a purl string if a mapping is known, else None.
    - First tries an exact lowercased filename match in pe_purl_map.json
    - Then applies regex heuristics to guess a reasonable purl
    """
    dll = dll_name.lower()
    m = _load_map().get(dll)
    if m and isinstance(m, dict) and m.get("purl"):
        return m["purl"]
    # Heuristics
    for rx, fn in _REGEX_RULES:
        mm = rx.match(dll)
        if mm:
            try:
                return fn(mm)
            except Exception:
                continue
    return None

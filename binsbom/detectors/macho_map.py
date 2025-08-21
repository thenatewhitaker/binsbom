
from __future__ import annotations
import json, re, pathlib, os
from typing import Optional, Dict

_MAP_CACHE = None

_REGEX_RULES = [
    # OpenSSL dylibs: libssl.<maj>.dylib, libcrypto.<maj>.dylib
    (re.compile(r"^lib(ssl|crypto)\.(?P<maj>\d+)\.dylib$"), lambda m: f"pkg:generic/openssl/lib{m.group(1)}@{m.group('maj')}"),
    # libpng16.*.dylib -> libpng@1.6
    (re.compile(r"^libpng16\.\d+\.dylib$"), lambda m: "pkg:generic/libpng@1.6"),
    # libjpeg-turbo or libjpeg numeric
    (re.compile(r"^libjpeg-turbo\.(?P<maj>\d+)\.dylib$"), lambda m: f"pkg:generic/libjpeg-turbo@{m.group('maj')}"),
    (re.compile(r"^libjpeg\.(?P<maj>\d+)\.dylib$"), lambda m: f"pkg:generic/libjpeg@{m.group('maj')}"),
    # zlib
    (re.compile(r"^libz(\.\d+)?\.dylib$"), lambda m: "pkg:generic/zlib"),
    # curl
    (re.compile(r"^libcurl(\.\d+)?\.dylib$"), lambda m: "pkg:generic/curl"),
    # Qt frameworks via rpath paths: @rpath/QtCore.framework/... or libQt5Core.dylib
    (re.compile(r"^(?:@rpath/)?Qt(?P<maj>[56])\w+\.framework/"), lambda m: f"pkg:generic/qt/qtbase@{m.group('maj')}"),
    (re.compile(r"^libQt(?P<maj>[56])\w+\.dylib$"), lambda m: f"pkg:generic/qt/qtbase@{m.group('maj')}"),
    # libc++.1.dylib
    (re.compile(r"^libc\+\+\.1\.dylib$"), lambda m: "pkg:generic/llvm/libc++@1"),
    # Apple libSystem (leave generic apple coord)
    (re.compile(r"^libSystem\.B\.dylib$"), lambda m: "pkg:generic/apple/libsystem.b"),
]

def _load_map() -> Dict[str, Dict[str, str]]:
    global _MAP_CACHE
    if _MAP_CACHE is not None:
        return _MAP_CACHE
    here = pathlib.Path(__file__).resolve().parent.parent / "data" / "macho_purl_map.json"
    try:
        _MAP_CACHE = json.loads(here.read_text(encoding="utf-8"))
    except Exception:
        _MAP_CACHE = {}
    return _MAP_CACHE

def map_dylib_to_purl(load_name: str) -> Optional[str]:
    """
    Map a Mach-O LC_LOAD_DYLIB 'name' (may include @rpath, absolute or relative paths)
    to a purl. We match on the basename first, then try regex heuristics on both
    the basename and the full load path (to catch Qt frameworks).
    """
    nm = load_name.strip()
    base = os.path.basename(nm).lower()
    m = _load_map().get(base)
    if m and isinstance(m, dict) and m.get("purl"):
        return m["purl"]

    # Try regex rules on basename
    for rx, fn in _REGEX_RULES:
        mm = rx.match(base)
        if mm:
            try:
                return fn(mm)
            except Exception:
                pass

    # Try regex rules on full path (handles @rpath/Qt*.framework/...)
    for rx, fn in _REGEX_RULES:
        mm = rx.match(nm)
        if mm:
            try:
                return fn(mm)
            except Exception:
                pass

    return None

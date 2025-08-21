
from __future__ import annotations
import pathlib, re
from typing import Dict, Any, List

# Heuristic regexes inspired by `go version -m` output patterns present in binaries.
# We look for lines like:
#   "mod\t<module>\t<version>\t<h1:...>"
#   "dep\t<module>\t<version>\t<h1:...>"
# and optionally "path\t<mainmodule>"
_RX_MOD = re.compile(rb"(?:^|[\x00-\x1F])mod\t([^\t\r\n]+)\t([^\t\r\n]+)", re.MULTILINE)
_RX_DEP = re.compile(rb"(?:^|[\x00-\x1F])dep\t([^\t\r\n]+)\t([^\t\r\n]+)", re.MULTILINE)
_RX_PATH = re.compile(rb"(?:^|[\x00-\x1F])path\t([^\t\r\n]+)", re.MULTILINE)

def _read_bytes(p: pathlib.Path, max_bytes: int = 50_000_000) -> bytes:
    # Read up to max_bytes to avoid huge firmware images; adjust as needed.
    with p.open("rb") as f:
        return f.read(max_bytes)

def enrich_with_go_modules(finding, p: pathlib.Path) -> None:
    """
    If the binary appears to be a Go program (has module info strings),
    append module dependencies to finding.evidence['dependencies'] and add a
    concise evidence block 'go_modules' with main path.
    """
    try:
        data = _read_bytes(p)
    except Exception:
        return

    mods = _RX_MOD.findall(data)
    deps = _RX_DEP.findall(data)
    main_path = None
    m = _RX_PATH.search(data)
    if m:
        try:
            main_path = m.group(1).decode("utf-8", errors="ignore")
        except Exception:
            main_path = None

    if not mods and not deps:
        return

    # Normalize to str and build dependency records
    new_deps: List[Dict[str, Any]] = []
    def add_pair(pkg_b: bytes, ver_b: bytes) -> None:
        try:
            pkg = pkg_b.decode("utf-8", errors="ignore")
            ver = ver_b.decode("utf-8", errors="ignore")
        except Exception:
            return
        dep = {"name": pkg, "version": ver, "purl": f"pkg:golang/{pkg}@{ver}"}
        new_deps.append(dep)

    for pkg_b, ver_b in mods:
        add_pair(pkg_b, ver_b)
    for pkg_b, ver_b in deps:
        add_pair(pkg_b, ver_b)

    if not new_deps:
        return

    ev = finding.evidence or {}
    existing = ev.get("dependencies") or []
    ev["dependencies"] = existing + new_deps
    # add a light evidence block
    ginfo = {"main_path": main_path, "modules_count": len(new_deps)}
    ev["go_build_info"] = ginfo
    finding.evidence = ev

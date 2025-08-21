
from __future__ import annotations
import subprocess, shutil, pathlib, re
from typing import List, Dict, Any, Optional

# Parses `go version -m <binary>` output.
# Example:
#   <binary>: go1.22.2
#       path    example.com/my/app
#       mod     example.com/my/app   v0.0.0-...    h1:...
#       dep     golang.org/x/sys     v0.18.0       h1:...
#       dep     github.com/foo/bar   v1.2.3         h1:...

_LINE_RE = re.compile(r'^\s*(path|mod|dep)\s+([^\s]+)(?:\s+([^\s]+))?')

def _have_go() -> bool:
    return shutil.which("go") is not None

def run_go_version_m(bin_path: pathlib.Path) -> Optional[Dict[str, Any]]:
    if not _have_go():
        return None
    try:
        cp = subprocess.run(
            ["go", "version", "-m", str(bin_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            text=True,
            encoding="utf-8",
        )
    except Exception:
        return None

    if cp.returncode != 0 or not cp.stdout:
        return None

    mods: List[Dict[str, str]] = []
    deps: List[Dict[str, str]] = []
    main_path: Optional[str] = None

    for line in cp.stdout.splitlines():
        m = _LINE_RE.match(line)
        if not m:
            continue
        kind, a, b = m.group(1), m.group(2), m.group(3)
        if kind == "path":
            main_path = a
        elif kind == "mod":
            # main module line includes module + version
            if b:
                mods.append({"name": a, "version": b})
            else:
                mods.append({"name": a})
        elif kind == "dep":
            if b:
                deps.append({"name": a, "version": b})
            else:
                deps.append({"name": a})

    if not mods and not deps and not main_path:
        return None

    return {"path": main_path, "mods": mods, "deps": deps}

def enrich_with_go_version_m(finding, p: pathlib.Path) -> None:
    """
    If `go` is installed, call `go version -m` and merge results into finding.evidence and dependencies.
    """
    info = run_go_version_m(p)
    if not info:
        return

    ev = finding.evidence or {}
    existing_deps = ev.get("dependencies") or []

    def to_dep(d: Dict[str, str]) -> Dict[str, str]:
        name = d.get("name")
        ver = d.get("version")
        dep = {"name": name}
        if ver:
            dep["version"] = ver
            dep["purl"] = f"pkg:golang/{name}@{ver}"
        else:
            dep["purl"] = f"pkg:golang/{name}"
        return dep

    new_deps = [to_dep(d) for d in (info.get("mods") or []) + (info.get("deps") or [])]

    ev["dependencies"] = existing_deps + new_deps
    gb = ev.get("go_build_info") or {}
    if info.get("path"):
        gb["main_path"] = info["path"]
    gb["source"] = "go version -m"
    gb["modules_count"] = len(new_deps)
    ev["go_build_info"] = gb

    finding.evidence = ev

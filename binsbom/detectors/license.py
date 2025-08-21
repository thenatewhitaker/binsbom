
from __future__ import annotations
import pathlib, zipfile, re
from typing import List, Dict, Optional

_LICENSE_FILES = [
    "LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING", "COPYING.txt", "NOTICE", "NOTICE.txt"
]
_LICENSE_PATTERNS = [re.compile(rf"^{name}$", re.IGNORECASE) for name in _LICENSE_FILES]

# Very small heuristic mapping based on common phrases
_HEURISTIC = [
    (re.compile(r"apache license[, ]+version 2\.0", re.I), "Apache-2.0"),
    (re.compile(r"mit license", re.I), "MIT"),
    (re.compile(r"bsd 2-clause", re.I), "BSD-2-Clause"),
    (re.compile(r"bsd 3-clause", re.I), "BSD-3-Clause"),
    (re.compile(r"gnu general public license\s*version\s*2", re.I), "GPL-2.0-only"),
    (re.compile(r"gnu general public license\s*version\s*3", re.I), "GPL-3.0-only"),
    (re.compile(r"gnu lesser general public license\s*version\s*2\.1", re.I), "LGPL-2.1-only"),
    (re.compile(r"gnu lesser general public license\s*version\s*3", re.I), "LGPL-3.0-only"),
    (re.compile(r"mozilla public license\s*2\.0", re.I), "MPL-2.0"),
]

def _classify(text: str) -> Optional[str]:
    for rx, spdx in _HEURISTIC:
        if rx.search(text):
            return spdx
    return None

def find_dir_license(path: pathlib.Path) -> List[Dict[str, str]]:
    """Look for LICENSE/NOTICE files in the file's directory."""
    res: List[Dict[str, str]] = []
    d = path.parent if path.is_file() else path
    try:
        for p in d.iterdir():
            if not p.is_file():
                continue
            for rx in _LICENSE_PATTERNS:
                if rx.match(p.name):
                    try:
                        txt = p.read_text(encoding="utf-8", errors="ignore")
                    except Exception:
                        txt = ""
                    spdx = _classify(txt) or "NOASSERTION"
                    res.append({"path": str(p), "spdx_id": spdx})
                    break
    except Exception:
        pass
    return res

def find_zip_license(path: pathlib.Path) -> List[Dict[str, str]]:
    """Look for license files inside a ZIP/JAR under META-INF/ or root."""
    res: List[Dict[str, str]] = []
    try:
        with zipfile.ZipFile(path, "r") as z:
            for n in z.namelist():
                base = n.split("/")[-1]
                if any(rx.match(base) for rx in _LICENSE_PATTERNS):
                    try:
                        with z.open(n) as f:
                            txt = f.read(100_000).decode("utf-8", errors="ignore")
                    except Exception:
                        txt = ""
                    spdx = _classify(txt) or "NOASSERTION"
                    res.append({"path": f"{path}!/{n}", "spdx_id": spdx})
    except Exception:
        pass
    return res

def detect_licenses_for_path(path: pathlib.Path) -> List[Dict[str, str]]:
    out = find_dir_license(path)
    # ZIP/JAR internal matches
    try:
        with path.open("rb") as f:
            head = f.read(4)
        if head == b"PK\x03\x04":
            out.extend(find_zip_license(path))
    except Exception:
        pass
    return out

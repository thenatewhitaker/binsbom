
from __future__ import annotations
import pathlib, zipfile
from typing import Optional
from ..scanner import ComponentFinding

def detect_java_component(p: pathlib.Path, **common) -> Optional[ComponentFinding]:
    name = p.name
    version = None
    supplier = None
    purl = None
    evidence = {}

    try:
        with zipfile.ZipFile(p, "r") as z:
            # MANIFEST
            try:
                with z.open("META-INF/MANIFEST.MF") as mf:
                    text = mf.read().decode("utf-8", errors="replace")
                    evidence["manifest"] = text
                    for line in text.splitlines():
                        if line.lower().startswith("implementation-title:"):
                            name = line.split(":", 1)[1].strip() or name
                        elif line.lower().startswith("implementation-version:"):
                            version = line.split(":", 1)[1].strip() or version
                        elif line.lower().startswith("implementation-vendor:"):
                            supplier = line.split(":", 1)[1].strip() or supplier
            except KeyError:
                pass

            # Maven pom.properties
            maven_props = [n for n in z.namelist() if n.lower().startswith("meta-inf/maven/") and n.lower().endswith("pom.properties")]
            for prop_path in maven_props:
                with z.open(prop_path) as pf:
                    text = pf.read().decode("utf-8", errors="replace")
                    evidence["pom.properties"] = text
                    props = {}
                    for line in text.splitlines():
                        if "=" in line and not line.strip().startswith("#"):
                            k, v = line.split("=", 1)
                            props[k.strip()] = v.strip()
                    gid = props.get("groupId")
                    aid = props.get("artifactId")
                    ver = props.get("version")
                    if aid:
                        name = aid
                    if ver:
                        version = ver
                    if gid and aid and ver:
                        purl = f"pkg:maven/{gid}/{aid}@{ver}"
                        break
    except Exception:
        pass

    return ComponentFinding(
        name=name, version=version, type="library", supplier=supplier, purl=purl, evidence=evidence, **common
    )

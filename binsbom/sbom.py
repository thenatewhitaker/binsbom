
from __future__ import annotations
import json, datetime, uuid
from typing import List, Dict, Any, Tuple
from .scanner import ComponentFinding

def _bomref_for_file(path: str, sha256: str) -> str:
    return f"urn:sha256:{sha256}"

def _bomref_for_dep(name: str, version: str | None) -> str:
    key = f"{name}@{version}" if version else name
    ns = uuid.UUID("12345678-1234-5678-1234-567812345678")
    return f"urn:uuid:{uuid.uuid5(ns, key)}"

class BomWriter:
    def __init__(self, format: str = "cyclonedx-json") -> None:
        self.format = format

    def write(self, findings: List[ComponentFinding], root: str) -> str:
        if self.format == "cyclonedx-json":
            try:
                return self._write_cdx(findings, root)
            except Exception:
                return self._write_cdx_min(findings, root)
        else:
            raise ValueError(f"Unsupported format: {self.format}")

    def _collect_components_and_deps(self, findings: List[ComponentFinding]) -> tuple[dict, list[tuple[str, list[str]]]]:
        comps: Dict[str, Dict[str, Any]] = {}
        deps_edges: List[Tuple[str, List[str]]] = []

        for f in findings:
            bom_ref = _bomref_for_file(f.path or f.name, f.hashes.get("SHA-256", ""))
            f.bom_ref = bom_ref
            comp = {
                "name": f.name,
                "version": f.version,
                "type": f.type,
                "purl": f.purl,
                "hashes": [{"alg": k, "content": v} for k, v in f.hashes.items()]
            }
            comps.setdefault(bom_ref, comp)

        for f in findings:
            parent = f.bom_ref or _bomref_for_file(f.path or f.name, f.hashes.get("SHA-256", ""))
            children_refs: List[str] = []
            deps = (f.evidence or {}).get("dependencies") or []
            for d in deps:
                dname = d.get("name")
                dver = d.get("version")
                if not dname:
                    continue
                child_ref = _bomref_for_dep(dname, dver)
                if child_ref not in comps:
                    comps[child_ref] = {
                        "name": dname,
                        "version": dver,
                        "type": "library",
                        "purl": d.get("purl"),
                        "hashes": []
                    }
                children_refs.append(child_ref)
            if children_refs:
                deps_edges.append((parent, children_refs))

        return comps, deps_edges

    def _write_cdx(self, findings: List[ComponentFinding], root: str) -> str:
        from cyclonedx.model.bom import Bom
        from cyclonedx.model.component import Component, ComponentType, HashType
        from cyclonedx.model.component import HashAlgorithm as HAlgLegacy
        from cyclonedx.model.dependency import Dependency
        from cyclonedx.output import make_outputter, OutputFormat

        comps, deps_edges = self._collect_components_and_deps(findings)
        bom = Bom()
        bom.metadata.component = None

        for ref, c in comps.items():
            ctype = ComponentType.LIBRARY if c["type"] == "library" else ComponentType.APPLICATION if c["type"] == "application" else ComponentType.FILE
            comp = Component(name=c["name"], version=c["version"], type=ctype, bom_ref=ref, purl=c.get("purl"))
            hashes = []
            for h in c.get("hashes", []):
                if h.get("alg") == "SHA-256":
                    hashes.append(HashType(alg=HAlgLegacy.SHA_256, content=h.get("content", "")))
            if hashes:
                comp.hashes = hashes
            bom.components.add(comp)

        for parent_ref, child_refs in deps_edges:
            d = Dependency(ref=parent_ref, depends_on=child_refs)
            bom.dependencies.add(d)

        return make_outputter(bom, OutputFormat.JSON).output_as_string()

    def _write_cdx_min(self, findings: List[ComponentFinding], root: str) -> str:
        comps, deps_edges = self._collect_components_and_deps(findings)
        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
                "tools": [{"vendor": "binsbom", "name": "binsbom-starter", "version": "0.1.1"}],
                "component": None
            },
            "components": [],
            "dependencies": []
        }
        for ref, c in comps.items():
            item = {
                "bom-ref": ref,
                "type": c["type"],
                "name": c["name"],
                "version": c["version"],
                "purl": c.get("purl"),
                "hashes": c.get("hashes", [])
            }
            bom["components"].append(item)
        for parent_ref, child_refs in deps_edges:
            bom["dependencies"].append({"ref": parent_ref, "dependsOn": child_refs})
        return json.dumps(bom, indent=2)

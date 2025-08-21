
from __future__ import annotations
import json, datetime, uuid, hashlib
from typing import List, Dict, Any, Tuple
from .scanner import ComponentFinding
from .detectors.license import detect_licenses_for_path

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
        elif self.format in ("spdx-json",):
            return self._write_spdx(findings, root)
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

    

def _spdx_filetype_for_name(name: str) -> str:
    lower = name.lower()
    # Simple extension-based classification
    source_exts = (".c",".cc",".cpp",".cxx",".h",".hpp",".hh",".m",".mm",".swift",".rs",".go",".py",".rb",".js",".ts",".java",".cs",".kt",".scala",".php",".hs",".cob",".mli",".ml",".clj",".lua",".r",".sh",".ps1")
    text_exts = (".md",".txt",".rst",".cfg",".ini",".yml",".yaml",".json",".xml",".toml",".csv",".tsv",".properties",".gradle",".pom",".license",".notice")
    binary_exts = (".class",".o",".a",".so",".dylib",".dll",".bin",".dat",".jar",".zip",".7z",".gz",".xz",".lz",".bz2",".png",".jpg",".jpeg",".gif",".bmp",".pdf")
    if any(lower.endswith(ext) for ext in source_exts):
        return "SOURCE"
    if any(lower.endswith(ext) for ext in text_exts):
        return "TEXT"
    if any(lower.endswith(ext) for ext in binary_exts):
        return "BINARY"
    # default
    return "TEXT"

def _enumerate_archive_files(archive_path: str, limit: int = 5000) -> list[dict]:
    """
    Enumerate files inside a ZIP/JAR for SPDX 'files' section.
    Returns a list of dicts with keys: name, type, sha256 (None if unavailable).
    """
    import zipfile, io, hashlib, os
    files = []
    p = pathlib.Path(archive_path)
    if not p.is_file():
        return files
    try:
        with p.open("rb") as fh:
            sig = fh.read(4)
        if sig != b"PK\x03\x04":
            return files
    except Exception:
        return files

    try:
        with zipfile.ZipFile(p, "r") as z:
            for i, n in enumerate(z.namelist()):
                if i >= limit:
                    break
                if n.endswith("/"):
                    continue
                try:
                    ftype = _spdx_filetype_for_name(n)
                    sha256 = None
                    # Hash small files (<1MB) to avoid heavy cost
                    info = z.getinfo(n)
                    if info.file_size <= 1_000_000:
                        with z.open(n, "r") as f:
                            data = f.read()
                            sha256 = hashlib.sha256(data).hexdigest()
                    files.append({"name": n, "type": ftype, "sha256": sha256})
                except Exception:
                    continue
    except Exception:
        pass
    return files
def _write_spdx(self, findings: List[ComponentFinding], root: str) -> str:
        """
        SPDX 3.0-ish JSON writer (packages, files, relationships).
        - Generates SPDXRef IDs deterministically from SHA-256 where possible.
        - Adds packages for each component (root binaries and dependencies).
        - Adds files for each scanned file and CONTAINS relationships.
        - Adds DEPENDS_ON edges based on evidence-derived dependencies.
        """
        import uuid, datetime

        # Reuse the same component/dependency build logic
        comps, deps_edges = self._collect_components_and_deps(findings)

        # Helpers for IDs
        def file_spdxid(sha256: str) -> str:
            return f"SPDXRef-File-{sha256[:16]}" if sha256 else f"SPDXRef-File-{uuid.uuid4().hex[:16]}"

        def pkg_spdxid(name: str, version: str | None, bom_ref: str | None = None) -> str:
            key = (bom_ref or f"{name}@{version}") if version else (bom_ref or name)
            sid = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
            return f"SPDXRef-Package-{sid}"

        # Build packages / map bom_ref -> pkg SPDXID
        packages = []
        # map bom_ref -> finding for extra context
        _finding_by_ref = { (f.bom_ref or f"urn:sha256:{f.hashes.get('SHA-256','')}") : f for f in findings }
        pkg_id_map = {}
        for ref, c in comps.items():
            pid = pkg_spdxid(c["name"], c["version"], bom_ref=ref)
            pkg_id_map[ref] = pid
            pkg = {
                "SPDXID": pid,
                "name": c["name"],
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
            }
            if c.get("version"):
                pkg["versionInfo"] = c["version"]
            # ExternalRefs: purl
            if c.get("purl"):
                pkg["externalRefs"] = [{
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": c["purl"]
                }]
            # Checksums (if any; usually for root files)
            checks = []
            for h in c.get("hashes", []):
                if h.get("alg") == "SHA-256" and h.get("content"):
                    checks.append({"algorithm": "SHA256", "checksumValue": h["content"]})
            if checks:
                pkg["checksums"] = checks
            # License detection
            try:
                fctx = _finding_by_ref.get(ref)
                if fctx and fctx.path:
                    lic_list = detect_licenses_for_path(pathlib.Path(fctx.path))
                    if lic_list:
                        # Pick first concrete SPDX id if available
                        first = next((l for l in lic_list if l.get('spdx_id') and l['spdx_id'] != 'NOASSERTION'), None)
                        if first:
                            pkg['licenseDeclared'] = first['spdx_id']
                        # stash evidence to be added as files later
                        pkg.setdefault('_license_files', lic_list)
            except Exception:
                pass
            packages.append(pkg)

        # Build files for each real scanned file (only from findings)
        files = []
        # convenience to add a file record
        def _add_file_record(path: str, ftype: str, sha256: str | None) -> str:
            fid = f"SPDXRef-File-{(sha256 or hashlib.sha256(path.encode('utf-8')).hexdigest())[:16]}"
            entry = {"SPDXID": fid, "fileName": path, "fileTypes": [ftype], "checksums": []}
            if sha256:
                entry["checksums"].append({"algorithm": "SHA256", "checksumValue": sha256})
            files.append(entry)
            return fid
        file_relationships = []
        for f in findings:
            sha256 = f.hashes.get("SHA-256", "")
            fid = file_spdxid(sha256)
            path = f.path or f.name
            file_entry = {
                "SPDXID": fid,
                "fileName": path,
                "fileTypes": ["BINARY"],
                "checksums": []
            }
            if sha256:
                file_entry["checksums"].append({"algorithm": "SHA256", "checksumValue": sha256})
            files.append(file_entry)
            # Package CONTAINS File
            # Find the package that corresponds to this finding (by bom_ref)
            pref = f.bom_ref
            if not pref:
                pref = f"urn:sha256:{sha256}"
            pkg_id = pkg_id_map.get(pref)
            if pkg_id:
                file_relationships.append({
                    "spdxElementId": pkg_id,
                    "relationshipType": "CONTAINS",
                    "relatedSpdxElement": fid
                })


        # Add inner files for archives and license files as text files
        for ref, c in comps.items():
            # Add archive inner files
            fctx = _finding_by_ref.get(ref)
            if fctx and fctx.path:
                inner = _enumerate_archive_files(fctx.path)
                if inner:
                    pkg_id = pkg_id_map.get(ref)
                    for item in inner:
                        fid = _add_file_record(f"{fctx.path}!/{item['name']}", item["type"], item["sha256"])
                        if pkg_id:
                            file_relationships.append({
                                "spdxElementId": pkg_id,
                                "relationshipType": "CONTAINS",
                                "relatedSpdxElement": fid
                            })
            # Add license files collected earlier
            # We stored them transiently in the package dict as _license_files
            for pkg in packages:
                if pkg_id_map.get(ref) == pkg.get("SPDXID") and pkg.get("_license_files"):
                    for lic in pkg["_license_files"]:
                        fid = _add_file_record(lic["path"], "TEXT", None)
                        file_relationships.append({
                            "spdxElementId": pkg["SPDXID"],
                            "relationshipType": "CONTAINS",
                            "relatedSpdxElement": fid
                        })
                    # cleanup
                    del pkg["_license_files"]
            # Relationships: DOCUMENT DESCRIBES each top-level package (the "root" findings)
        relationships = []
        doc_spdxid = "SPDXRef-DOCUMENT"

        # Consider every finding's package as described by the document
        seen_doc_desc = set()
        for f in findings:
            pref = f.bom_ref or f"urn:sha256:{f.hashes.get('SHA-256','')}"
            pkg_id = pkg_id_map.get(pref)
            if pkg_id and pkg_id not in seen_doc_desc:
                relationships.append({
                    "spdxElementId": doc_spdxid,
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": pkg_id
                })
                seen_doc_desc.add(pkg_id)

        # Dependency relationships
        for parent_ref, child_refs in deps_edges:
            parent_id = pkg_id_map.get(parent_ref)
            if not parent_id:
                continue
            for cr in child_refs:
                child_id = pkg_id_map.get(cr)
                if not child_id:
                    continue
                relationships.append({
                    "spdxElementId": parent_id,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": child_id
                })

        # Merge file relationships
        relationships.extend(file_relationships)

        # Compose document
        doc = {
            "spdxVersion": "SPDX-3.0",
            "dataLicense": "CC0-1.0",
            "SPDXID": doc_spdxid,
            "name": f"binsbom-{uuid.uuid4()}",
            "documentNamespace": f"urn:uuid:{uuid.uuid4()}",
            "creationInfo": {
                "created": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
                "creators": ["Tool: binsbom-starter/0.1.2"]
            },
            "packages": packages,
            "files": files,
            "relationships": relationships
        }
        return json.dumps(doc, indent=2)
    
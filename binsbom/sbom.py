
from __future__ import annotations
import json, datetime, uuid
from typing import List, Dict, Any
from .scanner import ComponentFinding

class BomWriter:
    def __init__(self, format: str = "cyclonedx-json") -> None:
        self.format = format

    def write(self, findings: List[ComponentFinding], root: str) -> str:
        if self.format == "cyclonedx-json":
            try:
                return self._write_cdx(findings, root)
            except Exception as e:
                # Fallback to a tiny hand-rolled JSON if cyclonedx lib isn't available
                return self._write_cdx_min(findings, root)
        else:
            raise ValueError(f"Unsupported format: {self.format}")

    def _write_cdx(self, findings: List[ComponentFinding], root: str) -> str:
        # Prefer modern cyclonedx-python-lib API (v6+)
        try:
            from cyclonedx.model.bom import Bom
            from cyclonedx.model.component import Component, ComponentType, HashAlgorithm, HashType
            from cyclonedx.model import ExternalReference, ExternalReferenceType
            from cyclonedx.output import make_outputter, OutputFormat
        except Exception as e:
            raise

        bom = Bom()
        bom.metadata.component = None  # we treat as a "document" of components

        # Add components
        for f in findings:
            ctype = ComponentType.LIBRARY if f.type == "library" else ComponentType.APPLICATION if f.type == "application" else ComponentType.FILE
            comp = Component(
                name=f.name,
                version=f.version or None,
                type=ctype,
                purl=f.purl or None,
                # bom_ref can be set, but library will generate if omitted
            )
            # Hashes
            try:
                from cyclonedx.model import HashAlgorithm as HAlg, Hash as Ht
                # Newer API uses different types; to stay broadly compatible, fallback to older if needed
                pass
            except Exception:
                pass

            # Hashes using legacy API object (works on v4/v5/v6 via HashType)
            from cyclonedx.model.component import HashType
            from cyclonedx.model.component import HashAlgorithm as HAlgLegacy
            if f.hashes.get("SHA-256"):
                comp.hashes = [HashType(alg=HAlgLegacy.SHA_256, content=f.hashes["SHA-256"])]

            # supplier (if any) as an external reference
            if f.supplier:
                try:
                    comp.external_references = [ExternalReference(type=ExternalReferenceType.VCS, url=f"about:{f.supplier}")]
                except Exception:
                    pass

            bom.components.add(comp)

        out = make_outputter(bom, OutputFormat.JSON).output_as_string()
        return out

    def _write_cdx_min(self, findings: List[ComponentFinding], root: str) -> str:
        # Minimal CycloneDX-like structure (not full spec-compliant; use only as fallback)
        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
                "tools": [{"vendor": "binsbom", "name": "binsbom-starter", "version": "0.1.0"}],
                "component": None
            },
            "components": []
        }
        for f in findings:
            ctype = "library" if f.type == "library" else "application" if f.type == "application" else "file"
            comp = {
                "type": ctype,
                "name": f.name,
                "version": f.version,
                "purl": f.purl,
                "hashes": [{"alg": k, "content": v} for k, v in f.hashes.items()]
            }
            bom["components"].append(comp)
        return json.dumps(bom, indent=2)

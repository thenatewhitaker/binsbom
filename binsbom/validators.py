
from __future__ import annotations
import json, pathlib
from typing import Tuple

def _load_schema(path: pathlib.Path):
    try:
        import jsonschema  # type: ignore
    except Exception:
        return None, "jsonschema not installed"
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
        return schema, None
    except Exception as e:
        return None, f"failed to read schema: {e}"

def validate_spdx(doc: dict, data_dir: pathlib.Path) -> Tuple[bool, str]:
    """
    Try strict JSON Schema validation if schema & jsonschema are present,
    otherwise perform lightweight structural checks.
    """
    schema_path = data_dir / "spdx-3.0.schema.min.json"
    schema, err = _load_schema(schema_path)
    if schema:
        try:
            import jsonschema  # type: ignore
            jsonschema.validate(instance=doc, schema=schema)
            return True, "SPDX: schema validation passed"
        except Exception as e:
            return False, f"SPDX: schema validation failed: {e}"
    # Fallback checks
    mandatory = ["spdxVersion", "SPDXID", "creationInfo", "packages", "relationships"]
    missing = [k for k in mandatory if k not in doc]
    if missing:
        return False, f"SPDX: missing keys {missing}"
    if not isinstance(doc.get("packages"), list):
        return False, "SPDX: 'packages' must be a list"
    if not isinstance(doc.get("relationships"), list):
        return False, "SPDX: 'relationships' must be a list"
    return True, "SPDX: basic validation passed (no schema)"

def validate_cyclonedx(doc: dict, data_dir: pathlib.Path) -> Tuple[bool, str]:
    schema_path = data_dir / "cyclonedx-1.4.schema.min.json"
    schema, err = _load_schema(schema_path)
    if schema:
        try:
            import jsonschema  # type: ignore
            jsonschema.validate(instance=doc, schema=schema)
            return True, "CycloneDX: schema validation passed"
        except Exception as e:
            return False, f"CycloneDX: schema validation failed: {e}"
    # Fallback checks
    if doc.get("bomFormat") != "CycloneDX":
        return False, "CycloneDX: 'bomFormat' must equal 'CycloneDX'"
    if "components" in doc and not isinstance(doc["components"], list):
        return False, "CycloneDX: 'components' must be a list"
    return True, "CycloneDX: basic validation passed (no schema)"

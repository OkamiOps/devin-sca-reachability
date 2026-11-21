from pathlib import Path
from typing import Any

from sca_reachability.errors import InputError
from sca_reachability.json_io import load_json_file
from sca_reachability.models import Component


def parse_cyclonedx(data: Any) -> tuple[Component, ...]:
    if not isinstance(data, dict):
        raise InputError("SBOM root must be a JSON object")
    if data.get("bomFormat") != "CycloneDX":
        raise InputError("SBOM must declare bomFormat 'CycloneDX'")

    raw_components = data.get("components", [])
    if not isinstance(raw_components, list):
        raise InputError("SBOM components must be a JSON array")

    components = []
    for index, raw_component in enumerate(raw_components):
        location = f"SBOM components[{index}]"
        if not isinstance(raw_component, dict):
            raise InputError(f"{location} must be a JSON object")

        nested_components = raw_component.get("components")
        if nested_components not in (None, []):
            raise InputError(
                f"{location} contains nested components; only the supported flat "
                "CycloneDX subset is accepted"
            )

        purl = raw_component.get("purl")
        if (
            not isinstance(purl, str)
            or not purl.strip().startswith("pkg:")
            or not purl.strip()[4:]
        ):
            raise InputError(f"{location} must include a package URL in 'purl'")

        version = raw_component.get("version")
        if not isinstance(version, str) or not version.strip():
            raise InputError(f"{location} must include a non-empty 'version'")

        name = raw_component.get("name")
        if name is not None and not isinstance(name, str):
            raise InputError(f"{location} 'name' must be a string when provided")
        components.append(
            Component(purl=purl.strip(), version=version.strip(), name=name)
        )

    return tuple(components)


def load_components(path: Path) -> tuple[Component, ...]:
    return parse_cyclonedx(load_json_file(path, "SBOM"))

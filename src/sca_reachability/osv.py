from typing import Any

from sca_reachability.errors import InputError
from sca_reachability.models import Component, Vulnerability


def _validate_query_echo(data: dict[str, Any], components: tuple[Component, ...]) -> None:
    if "queries" not in data:
        return
    queries = data["queries"]
    if not isinstance(queries, list):
        raise InputError("OSV response 'queries' echo must be a JSON array")
    if len(queries) != len(components):
        raise InputError(
            "OSV response query echo count "
            f"({len(queries)}) does not match SBOM component count ({len(components)})"
        )

    for index, (query, component) in enumerate(zip(queries, components, strict=True)):
        if not isinstance(query, dict) or not isinstance(query.get("package"), dict):
            raise InputError(f"OSV response queries[{index}] must include a package object")
        package = query["package"]
        if package.get("purl") != component.purl or query.get("version") != component.version:
            raise InputError(
                f"OSV response queries[{index}] does not match SBOM components[{index}]"
            )


def parse_batch_response(
    data: Any, components: tuple[Component, ...]
) -> tuple[tuple[Vulnerability, ...], ...]:
    if not isinstance(data, dict):
        raise InputError("OSV querybatch response root must be a JSON object")

    _validate_query_echo(data, components)
    results = data.get("results")
    if not isinstance(results, list):
        raise InputError("OSV querybatch response must include a 'results' JSON array")
    if len(results) != len(components):
        raise InputError(
            "OSV querybatch result count "
            f"({len(results)}) does not match SBOM component count ({len(components)})"
        )

    parsed_results = []
    for index, result in enumerate(results):
        if not isinstance(result, dict):
            raise InputError(f"OSV response results[{index}] must be a JSON object")
        if "error" in result:
            raise InputError(
                f"OSV response results[{index}] contains an error; "
                "the supplied response is incomplete"
            )
        if result.get("next_page_token"):
            raise InputError(
                f"OSV response results[{index}] contains a non-empty "
                "next_page_token; paginated responses are not supported"
            )
        raw_vulnerabilities = result.get("vulns", [])
        if not isinstance(raw_vulnerabilities, list):
            raise InputError(f"OSV response results[{index}].vulns must be a JSON array")

        vulnerabilities = []
        for vulnerability_index, raw_vulnerability in enumerate(raw_vulnerabilities):
            location = f"OSV response results[{index}].vulns[{vulnerability_index}]"
            if not isinstance(raw_vulnerability, dict):
                raise InputError(f"{location} must be a JSON object")

            vulnerability_id = raw_vulnerability.get("id")
            if not isinstance(vulnerability_id, str) or not vulnerability_id.strip():
                raise InputError(f"{location} must include a non-empty 'id'")

            aliases = raw_vulnerability.get("aliases", [])
            if not isinstance(aliases, list) or not all(
                isinstance(alias, str) for alias in aliases
            ):
                raise InputError(f"{location}.aliases must be an array of strings")

            summary = raw_vulnerability.get("summary")
            if summary is not None and not isinstance(summary, str):
                raise InputError(f"{location}.summary must be a string when provided")

            vulnerabilities.append(
                Vulnerability(
                    id=vulnerability_id.strip(),
                    aliases=tuple(aliases),
                    summary=summary,
                )
            )
        parsed_results.append(tuple(vulnerabilities))

    return tuple(parsed_results)

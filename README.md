# Devin SCA Reachability

An initial, offline scaffold for a future Software Composition Analysis (SCA) and dependency reachability bot. The current implementation reads local CycloneDX and OSV querybatch JSON; it does not connect to services or claim to establish whether vulnerable code is reachable.

## Current offline demo

- Reads the supported flat subset of CycloneDX JSON and requires each component to have a package URL (purl) and version. This is not full CycloneDX schema validation; non-empty nested component arrays are rejected rather than silently ignored.
- Reads a local OSV querybatch response. Its results array must contain exactly one result per SBOM component, in the same order. The optional queries echo is custom fixture metadata, not part of the native OSV querybatch response; when it is absent, the caller must ensure ordering because count alone cannot verify component identity. Error results and non-empty pagination tokens are rejected as incomplete input.
- Preserves every supplied advisory and reports reachability as **unknown**. Imports or dependency presence alone are not treated as proof that a vulnerable code path executes.
- Emits a JSON report to stdout. Input errors go to stderr with a non-zero exit status.

An empty result means **no findings in the supplied data**, not that the project or its dependencies are safe. The included DEMO-0001 advisory and fictional package are illustrative fixtures, not real vulnerability data.

## Setup and commands

Requires Python 3.11 or newer. There are no runtime third-party dependencies.

~~~sh
python -m pip install .

# Optional package build (the build tool is development-only)
python -m pip install build
python -m build

# Standard-library tests
python -m unittest discover -s tests -v

# Offline demo
sca-reachability analyze \
  --sbom fixtures/demo-sbom.json \
  --osv-response fixtures/demo-osv-response.json

# Equivalent module entry point
python -m sca_reachability analyze \
  --sbom fixtures/demo-sbom.json \
  --osv-response fixtures/demo-osv-response.json
~~~

Malformed JSON, unsupported SBOM formats, missing component purl/version, unsupported nested components, invalid OSV response shapes, incomplete results, and count or echoed-query mismatches are reported as input errors. The response order is significant; result counts are validated and the optional custom query echo is checked before pairing.

## Project layout

- src/sca_reachability/: input parsing, OSV response adapter, reachability interface/default, pipeline, reporting, and CLI.
- fixtures/: harmless local CycloneDX and synthetic OSV JSON examples.
- tests/: standard-library unit and CLI tests.
- .github/workflows/tests.yml: read-only-permission CI matrix for Python 3.11–3.13.

## Not implemented yet

The README's longer-term direction remains to generate CycloneDX SBOMs (for example with Syft or cdxgen), query OSV.dev's /v1/querybatch, perform static reachability analysis (potentially with call graphs, Semgrep or CodeQL), and provide reports. This scaffold does **not** generate SBOMs, make network requests, implement a static analyzer, suppress findings as “not in use,” open alerts/PRs, or schedule weekly reports. Its default analyzer returns unknown until a defensible analyzer is supplied.

## Links

- OkamiOps: https://okamiops.com
- Organization: https://github.com/OkamiOps
- Related: [okami-sentinel](https://github.com/OkamiOps/okami-sentinel) | [secops-baseline](https://github.com/OkamiOps/secops-baseline)

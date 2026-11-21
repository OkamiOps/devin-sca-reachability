# Devin SCA Reachability

A defensive SCA pilot with an unchanged offline CLI and an optional GitHub branch-monitoring server. Reachability remains **unknown**: dependency presence and AI explanations do not prove vulnerable code executes.

## Optional branch-monitoring server

Requires Python 3.11+. Start the completely offline demonstration:

~~~sh
python -m pip install '.[server]'
SCA_MODE=demo SCA_DATABASE_PATH=./demo.sqlite3 sca-reachability-serve
~~~

Open http://127.0.0.1:8000 and sign in with `local-demo` (accepted **only** in explicit demo mode). The fictional installation/repository offers main, develop, and release. Main starts selected with one completed synthetic scan. Select release and simulate a push to compare fictional package 1.0.0 (DEMO-0001) with 1.1.0 (no matching synthetic advisory). Demo uses the same inventory/queue/correlation pipeline with local adapters and never calls GitHub, OSV, or AI.

Live is the default mode and denies installation access until configured. It supports read-only GitHub dependency metadata, branch selections, signed/idempotent webhooks, a durable SQLite worker, exact-version OSV correlation, scoped history, and optional sanitized AI explanations. It never clones or executes repository code or provisions a GitHub App.

See [backend setup and security boundaries](docs/backend.md), [dashboard behavior](docs/dashboard.md), and [optional AI explanations](docs/ai-explanations.md). This is a single-operator pilot, not multi-tenant SaaS authentication.

## Current offline demo

- Reads the supported flat subset of CycloneDX JSON and requires each component to have a package URL (purl) and version. This is not full CycloneDX schema validation; non-empty nested component arrays are rejected rather than silently ignored.
- Reads a local OSV querybatch response. Its results array must contain exactly one result per SBOM component, in the same order. The optional queries echo is custom fixture metadata, not part of the native OSV querybatch response; when it is absent, the caller must ensure ordering because count alone cannot verify component identity. Error results and non-empty pagination tokens are rejected as incomplete input.
- Preserves every supplied advisory and reports reachability as **unknown**. Imports or dependency presence alone are not treated as proof that a vulnerable code path executes.
- Emits a JSON report to stdout. Input errors go to stderr with a non-zero exit status.

An empty result means **no findings in the supplied data**, not that the project or its dependencies are safe. The included DEMO-0001 advisory and fictional package are illustrative fixtures, not real vulnerability data.

## Setup and commands

Requires Python 3.11 or newer. The offline CLI has no runtime third-party dependencies. Server tests require the server extra and are skipped when it is absent.

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

The longer-term direction remains CycloneDX SBOM generation (for example with Syft or cdxgen) and defensible static reachability analysis. The offline CLI does not make network requests; the optional live server reads GitHub dependency metadata and queries OSV. Neither surface generates SBOMs, implements a static analyzer, suppresses findings as “not in use,” opens alerts/PRs, or schedules weekly reports. Reachability stays unknown.

## Links

- OkamiOps: https://okamiops.com
- Organization: https://github.com/OkamiOps
- Related: [okami-sentinel](https://github.com/OkamiOps/okami-sentinel) | [secops-baseline](https://github.com/OkamiOps/secops-baseline)

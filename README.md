# Devin SCA Reachability

A defensive SCA pilot with an unchanged offline CLI and an optional GitHub branch-monitoring server. The server classifies each finding as **reachable**, **unreachable**, or **unknown** by static analysis of npm (JavaScript/TypeScript) and Python sources, with file/line evidence in the report. Monitored code is only read, never executed. **Unknown is never safe**, unreachable holds only for the analyzed commit, and AI explanations never change the classification.

## Optional branch-monitoring server

Requires Python 3.11+. Start the completely offline demonstration:

~~~sh
python -m pip install '.[server]'
SCA_MODE=demo SCA_DATABASE_PATH=./demo.sqlite3 sca-reachability-serve
~~~

Open http://127.0.0.1:8000 and sign in with `local-demo` (accepted **only** in explicit demo mode). The fictional installation/repository offers main, develop, and release. Main starts selected with one completed synthetic scan. Its report shows all three reachability states with evidence: DEMO-0001 is reachable (`src/server.js` imports and calls `renderTemplate`), DEMO-0002 is unreachable (`worker/jobs.py` imports the package but never calls `unsafe_load`), and DEMO-0003 is unknown (`src/plugins.js` uses a dynamic `require`). Select release and simulate a push to compare fictional package 1.0.0 with 1.1.0. Demo uses the same inventory/queue/correlation pipeline with local adapters and never calls GitHub, OSV, or AI.

Live is the default mode and denies installation access until configured. It supports read-only GitHub dependency metadata, branch selections, signed/idempotent webhooks, a durable SQLite worker, exact-version OSV correlation, scoped history, and optional sanitized AI explanations. It never clones or executes repository code or provisions a GitHub App.

For real public repositories without credentials or a GitHub App, set `SCA_MODE=public`, `SCA_PUBLIC_REPOSITORIES=OWASP/NodeGoat` (up to 10 comma-separated `owner/name` entries), `SCA_DASHBOARD_TOKEN` (at least 32 characters), and `SCA_PUBLIC_ORIGIN`. Sync installations, then scan the selected default branch. This mode uses GitHub smart HTTP and bounded, in-memory codeload snapshots (never api.github.com), real OSV, and the existing static analysis pipeline. Webhooks and simulated pushes are disabled; unknown is never safe.

Public npm scans also trace static imports through bounded, integrity-checked registry tarballs pinned by the lockfile. Reports show versioned package/file/line paths; import-level reachability never claims a vulnerable-symbol call or exploitation. Unsupported entries, dynamic loads and exhausted budgets remain unknown. Package code is never installed, executed, imported or written to disk.

See [backend setup and security boundaries](docs/backend.md), [dashboard behavior](docs/dashboard.md), and [optional AI explanations](docs/ai-explanations.md). This is a single-operator pilot, not multi-tenant SaaS authentication.

## Current offline demo

- Reads the supported flat subset of CycloneDX JSON and requires each component to have a package URL (purl) and version. This is not full CycloneDX schema validation; non-empty nested component arrays are rejected rather than silently ignored.
- Reads a local OSV querybatch response. Its results array must contain exactly one result per SBOM component, in the same order. The optional queries echo is custom fixture metadata, not part of the native OSV querybatch response; when it is absent, the caller must ensure ordering because count alone cannot verify component identity. Error results and non-empty pagination tokens are rejected as incomplete input.
- Preserves every supplied advisory and reports reachability as **unknown** (the CLI receives no source code; static analysis runs in the server). Imports or dependency presence alone are not treated as proof that a vulnerable code path executes.
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
- .github/workflows/tests.yml: read-only-permission CI matrix for Python 3.11–3.13 on self-hosted runners (labels from the `CI_RUNS_ON` repository variable, a JSON array, default `["self-hosted","linux"]`); pull requests from forks are skipped.

## Not implemented yet

The longer-term direction remains CycloneDX SBOM generation (for example with Syft or cdxgen) and defensible static reachability analysis. The offline CLI does not make network requests; the optional live server reads GitHub dependency metadata and queries OSV. Neither surface generates SBOMs, implements a static analyzer, suppresses findings as “not in use,” opens alerts/PRs, or schedules weekly reports. Reachability stays unknown.

## Links

- OkamiOps: https://okamiops.com
- Organization: https://github.com/OkamiOps
- Related: [okami-sentinel](https://github.com/OkamiOps/okami-sentinel) | [secops-baseline](https://github.com/OkamiOps/secops-baseline)

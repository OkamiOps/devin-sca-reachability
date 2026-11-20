# Devin SCA Reachability

Continuous Software Composition Analysis (SCA) bot that combines SBOM generation, OSV vulnerability data, and reachability analysis to eliminate false positive dependency alerts.

Built with Devin Bot for always-on supply chain posture.

## What it does

- Generates CycloneDX SBOMs on every relevant change (using tools like Syft or cdxgen)
- Cross-references dependencies against the OSV.dev database (`/v1/querybatch`)
- Performs reachability analysis via call graphs and import/usage detection to determine if vulnerable code is actually exercised
- Only raises alerts or opens PRs for vulnerabilities that are both present **and** reachable
- Produces weekly reports of "not in use" findings to reduce noise

## Why reachability matters

Most SCA tools (including basic Dependabot-style scanners) flag every vulnerable dependency version regardless of whether the vulnerable function or code path is ever called. This bot filters those out using static analysis (call graphs, AST-based import tracking, and rules via Semgrep/CodeQL where appropriate).

## Status

Public starting point. The Devin Bot will own continuous improvement, integration into OkamiOps repositories, and expansion of reachability coverage across stacks.

## Links

- OkamiOps: https://okamiops.com
- Organization: https://github.com/OkamiOps
- Related: [okami-sentinel](https://github.com/OkamiOps/okami-sentinel) | [secops-baseline](https://github.com/OkamiOps/secops-baseline)

---

Part of the OkamiOps public AppSec tooling.
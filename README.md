# Devin SCA Reachability Bot

Continuous Software Composition Analysis (SCA) bot with reachability filtering for OkamiOps.

This bot owns the outcome of **reducing noise in dependency vulnerability alerts** by combining SBOM generation, OSV matching, and call-graph reachability analysis. Only vulnerabilities that are actually reachable in application code generate pull requests or high-priority alerts.

## What it does

- Generates CycloneDX SBOMs on every relevant push / schedule (`syft` or equivalent).
- Cross-references the SBOM against [OSV.dev](https://osv.dev) (`/v1/querybatch`).
- Runs reachability analysis (call graphs + import analysis) to determine whether the vulnerable code is actually used.
- Opens PRs or alerts **only** for reachable findings.
- Produces weekly posture reports of filtered (unreachable) findings.

## Status

Early stage. The bot is being built with a Devin Bot and will live in this repository.

Public by design — part of the OkamiOps AppSec tooling.

## Related

- [OkamiOps](https://okamiops.com)
- [Okami Sentinel](https://sentinel.okamiops.com)
- [secops-baseline](https://github.com/OkamiOps/secops-baseline)

---

Built with Devin Bots. Not a tuned Dependabot.
# Optional AI explanations

The explanation module adds Portuguese explanatory text without changing SCA
findings or classifications. It is not an analyzer and does not investigate
source code, repositories, advisories, or dependency trees.

## API

`explain_report(report, *, provider=None)` returns an object with `status`,
`text`, and `source`:

- No provider passed: `disabled` / `deterministic` Portuguese fallback.
- Provider returns valid text: `available` / `ai`.
- Malformed report, provider exception, refusal, or invalid/oversized provider
  output: `unavailable` / `deterministic` fallback.

The function accepts both report formats currently used by callers: nested
`vulnerability.id` and `reachability.status`, and flat `advisory_id` and
`reachability`. It never edits the input report. Empty findings are not described
as proof that a project has no vulnerabilities; unknown reachability is not
treated as safe. AI text is prefixed with a factual boundary derived from the
finding list.

`provider_configuration(environ=None)` reports only `enabled`, `configured`,
and a diagnostic `reason`: `disabled`, `missing_credentials`, `missing_model`,
`sdk_unavailable`, `initialization_failed`, or `ready`. It never returns the
credential. `create_provider_from_env(environ=None)` creates the optional
provider only after the explicit opt-in and required settings are present; it
returns `None` for disabled, incomplete, or unavailable configurations and does
not make a request during initialization.

The AI provider interface is a callable accepting a metadata dictionary and
returning plain text. The explanation function itself does not inspect process
environment variables or create a provider implicitly.

## Data sent to the provider

The provider receives a newly constructed, versioned allowlist only:

- Counts calculated from the full findings list: total, included, and omitted
  counts; counts by normalized severity and reachability.
- At most the first 50 findings, each with normalized severity and reachability,
  an optional regex-validated public `CVE-...` or `GHSA-...` advisory identifier,
  and an optional ecosystem from a fixed enum.
- Ecosystem may be derived locally from a package URL type, but the package URL
  itself is never sent.

Package names, versions, fixed versions, purls, summaries, aliases, reachability
reasons, repository/branch/commit identifiers, component lists, warnings,
manifest/source/internal paths, secrets, and other arbitrary text are omitted.
Invalid severity or reachability is normalized to `unknown`; invalid advisory
IDs and ecosystems are omitted. Counts include all findings even when the
provider excerpt is capped at 50.

## Server deployment and safe use

The optional provider uses the lazily imported OpenAI Python SDK and the Responses
API (`openai>=1.68.2,<3`). Version 1.68.2 is an official released SDK tag whose
`OpenAI` client exposes `responses.create` and whose request type includes the
Responses parameters used here. Install that SDK only in the trusted server
runtime where AI explanations are required. The configured model must be
available to the account and support text generation through the Responses API.
No SDK import or API request occurs merely by importing this module; creating a
provider initializes a reusable client but does not send a request. The provider uses the fixed official endpoint
`https://api.openai.com/v1`, the explicit `SCA_AI_API_KEY`, and
`SCA_AI_MODEL`; it does not use an environment-selected API key or base URL. It
sets a 15-second timeout, zero retries, a 400-token output limit, and
`store=False`. The request supplies no tools, disallows tool choice, and rejects
refusals, tool calls, non-text responses, and output over 2,000 characters.

Configure these values only in the trusted server environment; use the server's
secret manager for the key. These are placeholders, not usable credentials:

```text
SCA_AI_ENABLED=true
SCA_AI_API_KEY=<server-side-secret>
SCA_AI_MODEL=<responses-api-compatible-model>
```

`SCA_AI_ENABLED=true` is the explicit opt-in. Keep `SCA_AI_API_KEY` only in
server-side secret storage. Do not expose the key or provider object to a browser
or client. Call `create_provider_from_env()` only in trusted server code, and
close the returned provider once during server shutdown to release its SDK
client. Invoke
`explain_report` once when producing or saving a scan explanation—not on a GET
or report-render request. Surface configuration diagnostics only as needed and
never log credentials or provider exception text.

Render explanation text as untrusted plain text (escape it for any HTML
context). Keep the original report classifications separate and authoritative;
AI text can be incorrect even with the factual boundary and constrained prompt.
The fallback is deterministic Portuguese and recommends review and verification
before considering a compatible fixed version. It performs no automated
investigation and includes no exploit or test instructions.

The request shape follows the official OpenAI Responses API documentation:

- https://platform.openai.com/docs/api-reference/responses/create
- https://platform.openai.com/docs/guides/text?api-mode=responses
- https://github.com/openai/openai-python/releases/tag/v1.68.2
- https://github.com/openai/openai-python/blob/v1.68.2/src/openai/_client.py
- https://github.com/openai/openai-python/blob/v1.68.2/src/openai/resources/responses/responses.py

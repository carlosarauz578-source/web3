# Testing and verification

## Local checks

```bash
python -m pip install -e '.[dev]'
ruff check app tests
pytest
pip-audit
```

CI runs the same lint, test and dependency audit commands on Python 3.12.

## Automated coverage

- Bootstrap, login, password hashing, cookie-backed session and logout revocation.
- Anonymous rejection, role checks, project membership, organization isolation, cross-tenant 404 behavior, and denial of unassigned same-organization project artifacts.
- Conversation creation, message persistence/recovery, owner and tenant isolation, current project membership rechecks, role injection rejection, content/secret-pattern validation, and paginated history.
- Opt-in code-review route with explicitly simulated provider responses, provider configuration/error states, response schema and source-evidence validation, server-only assistant roles, persisted idempotent responses, request limits, prompt-injection framing, duplicate-key JSON blocking, recursive JSON secret blocking/redaction, direct-adapter guards, sensitive provider-output rejection, and quota settlement for known pretransport versus ambiguous/post-transport errors. Synthetic historical evidence tests verify redaction and hash scope without rewriting stored audit evidence.
- Provider destination policy rejects local/private literal URLs and DNS answers; mocked DNS and connection tests cover public-IP pinning, disabled proxies, and rejected redirects. Synthetic-key request tests verify provider-specific authentication headers; error tests verify that remote response bodies and configured test keys are absent from surfaced exceptions. Persistence-failure tests ensure an assistant result is never claimed as saved when its database write fails.
- Abandoned review handling covers stale-lease recovery, `inconclusive` status persistence, no automatic provider re-call, explicit retry with a new idempotency key, and rejection of concurrent duplicate processing.
- Dashboard structure/API wiring, consent-gated review controls, unique conversation control IDs, expected API paths/error states, same-origin credentials, safe text rendering, and no fake agent replies (static source checks only).
- Legacy SQLite-row preservation across all versioned migrations, conversation schema application, forward migration of existing messages, and migration idempotence.
- SQLite connection handling when a transient WAL/SHM sidecar disappears during permission hardening.
- Source validation, recorded audit state, retained source, normalized findings, raw execution evidence and hash-chain events, including persistence of inconclusive output-limit and cleanup-error states.
- Explicit Docker-unavailable and timeout behavior; bounded worker-output tests; mocked Docker invocation checks network isolation, read-only mounts, dropped capabilities and Slither's `--fail-none`.
- Approval identity is taken from the authenticated account rather than a caller-supplied reviewer field.
- EVM `not_configured`, JSON-RPC response validation, known chain-ID mismatch, and unverified custom-chain behavior. RPC replies are mocked in unit tests; they do not establish live node connectivity.
- Plan catalog validation, UTC period boundaries, quota release/confirmation, concurrent SQLite reservations, platform-admin plan assignment, and idempotent quota usage.
- Persistent agent runs, requester/project isolation, task registration, source-citation validation, and explicit external-AI consent.
- Stellar Soroban `getHealth` request shape, health response validation, unconfigured and private-endpoint rejection. EVM and Stellar RPC transport is mocked in tests; no real chain call is made.

Conversation tests exercise the authenticated API and SQLite persistence using the test database. AI tests use an explicitly simulated provider client and do not establish live provider connectivity or verify provider-side retention. Dashboard checks are static source/HTML checks, not browser interactions: Node.js and browser automation are unavailable in this environment.

## Manual worker verification

On a host with Docker Engine:

```bash
docker build -f Dockerfile.worker -t aegis-slither-worker:0.1.0 .
docker image inspect aegis-slither-worker:0.1.0
export AEGIS_WORKER_IMAGE=aegis-slither-worker:0.1.0
export AEGIS_BOOTSTRAP_TOKEN='set-a-long-random-secret'
export AEGIS_COOKIE_SECURE=false  # localhost only
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Bootstrap an organization, create a project, submit only authorized lab code, then retrieve `/api/runs`, `/api/audits/{id}/report.json`, and `/api/evidence/{id}` with the same browser session. Confirm that `tool_unavailable`, `not_configured`, `timeout` and `engine_error` remain inconclusive. Verify the source and evidence hashes outside the service against retained artifacts. The container invocation is not manually executed in environments without Docker.

## Authorized live AI provider smoke test

The adapter requires `AEGIS_AI_API_KEY` and `AEGIS_AI_MODEL`; `AEGIS_AI_PROVIDER`
selects `openai` (the default), `gemini`, or `groq` from backend configuration only.
`AEGIS_AI_API_URL` is an optional OpenAI-only override and defaults to the OpenAI Chat
Completions URL shown in `.env.example`; configured URLs must use HTTPS and resolve
only to public addresses. Gemini uses `generateContent` and an API-key header at the
fixed Google Generative Language endpoint. Groq uses compatible Chat Completions and
bearer authentication at its fixed API endpoint. The adapters do not assume identical
authentication or response envelopes.
The backend model allowlist is deliberately fail-closed: OpenAI currently allows only
`gpt-4o-2024-08-06`, and Groq only `llama-3.3-70b-versatile`, based on the vendors'
published JSON-mode documentation for the request formats used here. Gemini's list is
empty because the available documentation did not establish compatibility for this
adapter's exact `generateContent` request and `responseMimeType` option. Such a
configuration is rejected before transport.

To add a model, first check the vendor's current documentation for the exact API
endpoint and the precise JSON-output option used by its adapter. Record a versioned or
dated documentation URL and evidence that the exact model supports it; then add the
provider/model pair to `SUPPORTED_MODELS`, add configuration tests asserting rejection
of unlisted models and the request-format tests for the enabled model, and update this
section. Never treat a syntactically valid model name, a model alias, or support for a
different endpoint/structured-output feature as compatibility evidence. Do not
enable a model based solely on a mocked response.

Evidence checked for the current allowlist:

- OpenAI [Structured Outputs and JSON mode](https://developers.openai.com/api/docs/guides/structured-outputs)
  lists `gpt-4o-*` as JSON-mode compatible; this adapter uses Chat Completions
  `response_format: json_object`.
- Groq [Structured Outputs](https://console.groq.com/docs/structured-outputs) documents
  JSON Object Mode with `response_format: json_object` and uses
  `llama-3.3-70b-versatile` in its example.
- Gemini's [structured output guide](https://ai.google.dev/gemini-api/docs/structured-output)
  now demonstrates its Interactions API; it does not establish the exact model and
  `generateContent` option combination used in this adapter.

The transport executes DNS resolution, connection setup, and response reading in a
killable spawned worker. The parent enforces one wall-clock deadline and terminates
the worker on expiry, so DNS stalls and trickling response bodies cannot keep the API
request waiting indefinitely. As with any OS process timeout, scheduler delays and
process cleanup are not a hard real-time guarantee.
Use a trusted secret manager or a process environment injection mechanism to provide
the key. Do not commit it, put it in browser storage, or include it in shell commands,
logs, screenshots, or test output. Do not use a shared `.env` file unless its access
permissions and exclusion from version control have been verified.

Only run a live smoke test after explicit authorization for the provider, endpoint,
account, and expected cost. Use an isolated temporary database, a test account and
project, and synthetic source such as `contract SmokeTest {}`. Sign in through the
normal UI, create a Code Auditor conversation, and explicitly select the AI review
consent control before sending that synthetic snippet. Verify that the user message
is stored, the provider response passes backend schema/evidence validation, the
assistant result is persisted and returned on a subsequent history read, and any
finding remains marked `pending_validation`. Do not send project history or real
source code during this smoke test.

Exercise timeout, malformed response, provider errors, and persistence failures with
the simulated provider in automated tests; do not trigger repeated billable live
requests to test these failures. Confirm in the mocked request test that the adapter
sends only its configured Bearer credential, system prompt and explicitly supplied
snippet, with no browser cookie or session token. A successful mock test does not
establish provider connectivity, and a live smoke test does not establish model
correctness, retention behavior, or production readiness.

## Not yet covered

There is no live Docker worker integration in this environment, no Foundry runner/corpus, no real EVM node/testnet integration, no live AI provider integration, no frontend browser automation, no performance/load tests, and no recovery drill. Mocked model responses validate interface/error handling and schema/evidence checks only, not model correctness, provider connectivity, or retention behavior. Add these checks to CI/integration infrastructure before a pilot.

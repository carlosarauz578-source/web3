# Architecture

## Current request and analysis flow

1. An operator supplies `AEGIS_BOOTSTRAP_TOKEN`; the first administrator creates an organization and is marked as the platform administrator. Only this initial platform administrator can provision further organizations, each with a separate initial organization admin.
2. Users authenticate with email/password. Passwords are salted PBKDF2-HMAC-SHA256 hashes. Sessions use random opaque tokens; only SHA-256 token hashes and expiry are stored. The browser receives the token only in an HttpOnly, SameSite=Strict cookie.
3. Users and projects are scoped to an organization. Client/collaborator users can only list and use projects explicitly assigned to them. Backend routes enforce roles and organization IDs.
4. An authorized user submits a single Solidity source file and project ID. The API validates size/name/consent, stores the exact source and SHA-256, creates a unique SQLite audit row and chained event, then schedules a local FastAPI background task.
5. The Slither adapter refuses host execution. It requires a configured Docker CLI and trusted `AEGIS_WORKER_IMAGE`, mounts only the submitted file read-only, disables network, drops capabilities, uses a read-only root filesystem, limits CPU/memory/PIDs, and applies a 60-second timeout.
6. Tool findings are normalized with detector, severity, confidence, description, and source line locations. Source, record, result and event hashes are retained. Worker stdout/stderr are drained without buffering unbounded output in memory; exceeding 1 MB stdout or 20 KB stderr terminates the analysis and yields an inconclusive `output_limit` result with no findings. The retained preview's digest covers only that preview, not bytes discarded after the cap.
7. Authenticated organization/project readers can retrieve status, source, findings and JSON evidence. Admins/auditors can record a review decision.
8. The optional EVM connector reads `eth_chainId` from an operator-configured HTTPS RPC URL; the Stellar connector reads Soroban `getHealth`. Callers choose only registered network names; they cannot submit arbitrary URLs or sign transactions. The shared guarded transport pins public DNS results, disables proxies/redirects, bounds response size, and applies a killable total deadline.

## Conversation persistence

The authenticated API stores user-owned conversations associated with one organization and project. SQLite composite foreign keys keep the owner and project in the same organization. Every conversation/message operation rechecks the current organization, owner, and project membership; an unowned or inaccessible ID returns the same 404. New user messages have an idempotency UUID, and only server code can create `assistant` messages.

Conversation routes support listing, metadata retrieval, paginated history, and user-message insertion. Existing short-window abuse limits remain, while the plan service applies per-user/per-organization daily quotas with transactional reservations and idempotency. Review states are `running`, `completed`, `failed`, and `inconclusive`, with SQL constraints and transition guards. A completed row must reference a persisted assistant result from the same conversation; migrations preserve prior messages and mark inconsistent legacy results inconclusive. The opt-in code auditor sends only the submitted snippet (not conversation history or session cookie) with a fixed prompt to the configured HTTPS provider. Content is untrusted; the model has no tools, cannot modify policy, and does not execute code. Responses are schema-validated, findings must cite submitted source lines/evidence, and remain AI hypotheses. No provider request is automatically retried. Provider response/report sizes are bounded. Secret detection is heuristic; provider retention is governed by the provider account. Conversation contents are plaintext in SQLite, with no retention workflow or application-level encryption.

`POST /api/agent-runs` executes only backend-registered tasks and persists run/subtask states, input/result hashes and idempotency keys. `blockchain_health` invokes only the EVM chain-ID or Stellar health connector. `code_review` requires explicit external-AI consent, then runs the code auditor and citation validator sequentially. `validate_review` reads only a completed AI result that the requester can access. The deterministic validator checks whether reported evidence appears at the cited source lines; it does not establish vulnerability truth, and supported findings stay unconfirmed. Runs remain scoped to organization, project, and requester; stale `running` runs become inconclusive rather than being retried. These API capabilities are not yet wired to dashboard controls.

## Persistence and trust

SQLite migration scripts are under `app/migrations/` and are applied once by filename. Existing audit tables and conversation messages are preserved; new plan and agent-run tables are additive. Source, raw tool output, conversation messages, and agent results are stored in SQLite and should be protected as sensitive data.

The local hash chain is tamper-evident only relative to independently retained hashes. It is not immutable and does not protect against a database administrator rewriting rows, hashes and the chain. There is no signing key, external timestamp, append-only service or artifact storage.

## Worker boundary

The web API does not fall back to an in-process Slither or host subprocess. `Dockerfile.worker` builds the Slither/solc worker. The application container intentionally does not mount `/var/run/docker.sock`: a Docker socket is effectively host-root access. A secure deployment needs a separate authenticated worker service that accepts a narrow job protocol and returns signed/hashed outputs. Current local `BackgroundTasks` is not durable and can lose in-flight jobs on process exit.

Foundry is not invoked by the current API. The accepted input is one `.sol` file, not a repository archive containing `foundry.toml`, dependencies, tests, or fuzz harnesses. Adding Forge requires a separate restricted runner and an explicit validated project bundle format.

## Extension points

- `app/engines.py`: Slither adapter and normalized result contract.
- `app/connectors/`: read-only chain connectors with explicit configuration state.
- `app/providers/common.py` and `app/providers/`: internal completion contract, guarded
  transport, and independent OpenAI, Gemini, and Groq adapters selected only by backend
  configuration.
- `app/agents/`: the code auditor, deterministic source-citation validator, read-only blockchain analyst, common finding contract, and explicit task registry/orchestrator.
- The plan catalog uses development-only default quotas. `AEGIS_PLAN_LIMITS` can override all plan/metric values; assignments are made only by the platform administrator. There is no pricing, billing, token-cost accounting, or provider-credit guarantee.

## Deployment boundary

The web Dockerfile runs as a non-root UID and stores the database under `/data`. It does not include a worker RPC client or worker service. A deployment must configure HTTPS, secure cookies, secrets, persistent encrypted backups, a trusted worker boundary, rate limits, monitoring, and restore procedures before being exposed to users.

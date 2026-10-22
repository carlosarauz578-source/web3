# Aegis-Web3 Core

Aegis-Web3 Core is an early-stage, organization-scoped Solidity analysis platform. It has a FastAPI backend, an authenticated responsive dashboard, SQLite migrations, and an isolated Slither worker adapter. It is **not production-ready, an audit certification, or a replacement for independent security review**.

Current verified status and explicit gaps: [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md).

## Requirements

- Python 3.11 or newer.
- Docker Engine and a trusted local worker image to execute analyses. Without Docker, jobs end in `tool_unavailable`; the API never falls back to running Slither on the web host.
- An optional read-only EVM JSON-RPC endpoint. No endpoint is configured by default.

## Local setup

```bash
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell:
# .venv\Scripts\Activate.ps1
python -m pip install -e '.[dev]'
cp .env.example .env
```

Set a unique `AEGIS_BOOTSTRAP_TOKEN` in the process environment. For plain HTTP on a local development machine only, set `AEGIS_COOKIE_SECURE=false`; use HTTPS and `AEGIS_COOKIE_SECURE=true` outside local development. Load `.env` explicitly with your preferred environment manager; the application does not read `.env` automatically.

Build the analysis worker from this repository:

```bash
docker build -f Dockerfile.worker -t aegis-slither-worker:0.1.0 .
```

Set `AEGIS_WORKER_IMAGE` to that trusted image reference. Pin the image by digest for reproducible use. The worker runs without network access, drops Linux capabilities, has a read-only root filesystem, and has memory, CPU, PID, and timeout limits. Do not mount the Docker socket into the web application container: access to that socket can confer host-root privileges. The current Dockerfile for the web app intentionally does not provide a Docker CLI/socket connection, so container-to-container worker dispatch still needs a separately authenticated worker service.

Run the API and dashboard:

```bash
export AEGIS_BOOTSTRAP_TOKEN='set-a-long-random-secret'
export AEGIS_COOKIE_SECURE=false
export AEGIS_WORKER_IMAGE='aegis-slither-worker:0.1.0'
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>. Create the first organization using the bootstrap token, then sign in. Bootstrap can create only the initial platform administrator; only that account can provision additional organizations. Organization administrators can create users, projects, and project assignments inside their own organization. Passwords are PBKDF2-HMAC-SHA256 hashes; session cookies are HttpOnly, SameSite=Strict, expire after 12 hours, and can be revoked by logout or account deactivation.

Build and run the web container with persistent SQLite storage:

```bash
docker build -t aegis-web3-core:local .
docker run --rm -p 8000:8000 \
  -v aegis-data:/data \
  -e AEGIS_BOOTSTRAP_TOKEN='set-a-long-random-secret' \
  -e AEGIS_COOKIE_SECURE=false \
  aegis-web3-core:local
```

This web container has no Docker socket or worker dispatch client. Its analysis jobs will report `tool_unavailable`; run the API on a trusted host with Docker CLI access for the local worker adapter, or deploy a separately authenticated worker service. Do not grant the web container host Docker-daemon access to make the status appear configured.

## Data and migrations

SQLite lives at `AEGIS_DB_PATH` (default `./aegis.db`). Versioned migrations run at startup and do not drop existing audit rows. Take a consistent backup before upgrades or file moves:

```bash
sqlite3 "$AEGIS_DB_PATH" ".backup 'aegis-backup.db'"
```

Restore by stopping the application, keeping a copy of the current database, and replacing the configured SQLite file with the verified backup. SQLite WAL/SHM files are runtime state; do not copy them as a substitute for a consistent database backup.

## Plans and quotas

Organizations start on the backend-assigned `free` plan. Only the initial platform administrator can change an organization's plan through `POST /api/organizations/{id}/plan`; clients cannot set plans or limits. The backend catalog has `free`, `pro`, and `enterprise` entries, with safe development defaults for daily audit, AI review, agent-run, conversation-message, and conversation-creation counts. These are application development limits, not prices, provider credits, or commercial promises.

Operators can replace the full catalog with `AEGIS_PLAN_LIMITS`, a JSON object containing all three plan IDs and all five integer metrics (`audits`, `ai_reviews`, `agent_runs`, `conversation_messages`, `conversation_creations`); malformed or incomplete configuration fails closed. Each configured integer is enforced independently against both the user's and organization's UTC-calendar-day counters. Cost and tokens are not estimated or reported. SQLite transactions serialize reservations; idempotent conversation messages and agent runs are not charged twice. `GET /api/usage` returns the authenticated user's and organization's counters. No billing integration, automatic paid-provider fallback, or payment processing exists.

## Read-only blockchain connectors

`AEGIS_EVM_RPC_URLS` is a JSON object mapping operator-chosen network names to HTTPS JSON-RPC endpoints, for example:

```text
AEGIS_EVM_RPC_URLS={"ethereum":"https://your-read-only-rpc"}
```

The connector only calls `eth_chainId`, uses a five-second total deadline, rejects non-public destinations, pins the DNS result, disables proxies and redirects, bounds responses, does not echo the endpoint, and never sends transactions. The known names `ethereum`, `base`, `arbitrum`, `optimism`, `polygon`, and `avalanche` are checked against their expected chain IDs. A mismatch reports `chain_mismatch`; custom names report `chain_unverified` because their identity has no built-in mapping. The endpoint is trusted operator configuration; do not accept it from an API caller. No EVM RPC is configured by default.

`AEGIS_STELLAR_RPC_URL` optionally configures one Soroban RPC endpoint. The read-only `GET /api/blockchains/stellar/status` route calls only `getHealth` and labels the result `endpoint_health_only`; it does not prove network identity or query accounts, contracts, transactions, or events. It applies the same HTTPS/public-address-pinned transport and does not accept an endpoint from callers. No Stellar endpoint is configured by default.

## Private conversations API

Authenticated project users can create a private conversation with one of the stored specialty labels (`code_auditor`, `blockchain_analyst`, `independent_validator`), list their own conversations, and persist user messages. The dashboard uses these API routes to select a project, create/open a conversation, page through history, and save messages:

- `POST /api/conversations`
- `GET /api/conversations`
- `GET /api/conversations/{id}`
- `GET /api/conversations/{id}/messages`
- `POST /api/conversations/{id}/messages`

Every read/write checks the authenticated owner, organization, and current project access. Message roles are assigned by the server; client-supplied roles are rejected. Only `code_auditor` can request a code review, and only after explicit dashboard consent. Configure `AEGIS_AI_PROVIDER` (`openai`, `gemini`, or `groq`), `AEGIS_AI_API_KEY`, and the backend-only `AEGIS_AI_MODEL`; OpenAI remains the default. `AEGIS_AI_API_URL` optionally overrides the OpenAI Chat Completions endpoint only and must use HTTPS with public DNS; Gemini `generateContent` and Groq Chat Completions use fixed provider endpoints. Provider and model selection are not client-controlled. The adapter sends only the submitted snippet and its fixed system prompt, with a 30-second timeout, bounded input/output, and no automatic retries. It does not send cookies or conversation history. The returned JSON is schema-checked, source-line/evidence checked, stored as a server-created `assistant` message, and labeled as an AI hypothesis pending human validation; no tools are executed and no code is changed. A missing or invalid provider configuration is reported without fabricating a response.

**Offline demo without credentials:** set `AEGIS_AI_PROVIDER=simulated` to run the dashboard section “Auditoría con agentes” with a deterministic rule-based reviewer (`tx.origin`, `delegatecall`, `selfdestruct`, `eval(`). It uses no model and no network, and every run and agent is labelled `execution_mode: simulated` in the API and the dashboard. Other values: `real` (operation completed), `inconclusive` (not configured/connected) and `failed`. It is a demonstration aid, not an AI review; never use it as evidence of code quality. The independent validator only checks that each finding's cited lines contain its evidence.

Submitted snippets are sent to the configured external provider only after explicit user consent. Configure the provider account's retention and data-use policy before enabling it; this application does not set a provider retention mode. Provider destinations must use HTTPS and resolve only to globally routable addresses; redirects and environment proxies are disabled. Messages remain plaintext in SQLite, and retention/deletion workflows and application-level encryption are not implemented. Common labeled credentials, AWS key formats, PEM private-key headers, token formats, and private-key-shaped strings are rejected heuristically before transmission; this is not complete secret detection, so never submit secrets, private keys, seed phrases, or code you are not authorized to share.

`POST /api/agent-runs` and `GET /api/agent-runs/{id}` provide persistent, idempotent backend tasks for:

- `blockchain_health`: the registered blockchain analyst calls only the configured EVM `eth_chainId` or Stellar `getHealth` read check.
- `code_review`: the existing code auditor runs only with `acknowledge_external_ai=true`; a deterministic independent validator checks its source citations afterward.
- `validate_review`: the independent validator rechecks a completed, persisted AI review accessible to the requester.

The independent validator verifies citation support, not whether a vulnerability is true. Every finding remains unconfirmed. The orchestrator dispatches only server-registered task types; it does not execute model-supplied tools, commands, or endpoints. A run abandoned for more than five minutes is marked inconclusive rather than automatically repeated. Code-review run inputs and results are stored in SQLite as sensitive plaintext, subject to the same database-protection requirements as conversations. The dashboard displays quotas and can start the read-only blockchain health task; the code-review orchestration and persisted-review validation task remain API-only.

## Tests and quality checks

```bash
ruff check app tests
pytest
pip-audit
```

CI runs lint, tests, and dependency vulnerability checks on Python 3.12. The local test suite covers password/session flows, RBAC, organization/project and conversation isolation, quota reservations and concurrency, persisted/idempotent agent tasks, mocked provider request/error/schema handling, dashboard/API wiring contracts, migration of existing rows, evidence hashes, job failure handling, the worker command boundary, and EVM/Stellar connector configuration and response validation. Mocked provider and RPC tests do not verify live connectivity or provider/account behavior. Docker execution, live RPCs, and browser interactions remain environment-dependent integration checks; dashboard interactions were not browser-tested in this environment.

## Security boundaries

- The bootstrap secret must be managed outside source control and rotated by operators. Do not put secrets into `.env` tracked files, logs, audit source, or reports.
- Do not submit private keys, seed phrases, credentials, or unauthorized third-party code.
- The application is not multi-process job-queue infrastructure; its in-process background task is a development implementation, not a durable worker scheduler.
- Hash chains and SQLite evidence help detect changes when compared with a separately trusted copy. A database administrator can rewrite the local database and chain.
- Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), and [docs/TESTING.md](docs/TESTING.md) before extending or deploying the service.

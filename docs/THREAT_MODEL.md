# Threat model

## Assets

- Private Solidity source, raw analyzer output, organization/project metadata, audit decisions and user credentials.
- User conversation content, including potentially sensitive project context.
- Session tokens and the bootstrap secret.
- Integrity and provenance of analysis jobs and evidence.
- Availability of the API, SQLite database and analysis worker.

## Trust boundaries

- Browser to FastAPI: all client input is untrusted. The API owns authentication, role checks, organization scoping, project membership, filename/source bounds and consent checks.
- Conversation content is untrusted user data. It is persisted as plain text. Only an explicit code-review request for the `code_auditor` specialty can send the submitted snippet to the configured provider.
- API to SQLite: parameterized SQL is used; SQLite file access remains privileged and can rewrite all locally stored evidence.
- API to worker: only a single source file is mounted read-only. The analysis tool processes adversarial source and must run without network and with resource limits.
- API to EVM node: only operator-supplied HTTP(S) RPC endpoints are accepted from environment configuration; this is trusted operator input, not caller input.
- Model provider: the operator-configured HTTPS provider receives only an explicitly submitted code snippet and a fixed system prompt. The provider-specific API key is sent in its authentication header; application session cookies and conversation history are not sent.

## Implemented mitigations

- Random, revocable DB-backed sessions; only token hashes are stored. Cookies are HttpOnly, SameSite=Strict, and Secure by default. Set `AEGIS_COOKIE_SECURE=false` only on local HTTP development.
- PBKDF2-HMAC-SHA256 password hashing with per-user random salt and 600,000 rounds; invalid-user attempts perform a dummy hash verification.
- Bootstrap token compared in constant time; bootstrap is single-use. Login attempts are throttled per client address in SQLite.
- Only the initial platform administrator can provision organizations; organization-scoped administrators cannot create tenants or disable the platform administrator.
- Role and tenant checks in backend routes, project membership for client/collaborator roles, and generic 404s for cross-tenant identifiers.
- Conversation reads/writes require owner identity and current organization/project authorization. The database constrains conversation owner/project organization consistency; client roles are rejected and server-only code may persist validated assistant reports.
- Conversation endpoints have per-user creation/message throttles, bounded message sizes, and reject common credential-label, token, and private-key-shaped patterns before persistence. Only an explicit code-review request with consent can transmit a snippet; recognized patterns are blocked before persistence and again at the shared provider boundary. A provider response matching a recognized pattern is rejected before it is stored as an assistant message.
- The opt-in code auditor has a separate request limit, 16 KB source limit, 30-second provider timeout, bounded response/report sizes, no automatic retry, strict JSON schema validation, source-line/evidence checks, and generic errors without remote response bodies. Provider destinations must use HTTPS, redirects are rejected, proxies are disabled, and DNS resolution is pinned to a globally routable address; local/private destinations and mixed public/private DNS answers are rejected. Findings are explicitly hypotheses pending human validation, and no tools or commands are executed.
- Source size/name validation, authorization acknowledgement, SQL parameters, no arbitrary RPC URL parameter, and no transaction methods.
- Slither runs only in a configured Docker worker with no network, read-only root and input mount, dropped capabilities, no-new-privileges, CPU/memory/PID ceilings and a timeout.
- Analysis failure states remain explicit; no findings are fabricated and no “safe” verdict is emitted.
- Output/code hashes and chained events; a note makes local rewrite limitations explicit.

## Known gaps and abuse cases

- No independent security review, MFA, password reset, account recovery, refresh-token rotation, organization deletion policy or distributed throttling.
- No CSRF token. SameSite=Strict is a mitigation for the same-origin dashboard, not a substitute for a deployment-specific CSRF review.
- Bootstrap token provisioning/rotation and HTTPS termination are operator responsibilities.
- No durable queue or worker crash recovery. FastAPI background jobs can be lost on restart.
- Docker API/socket access would be a host privilege escalation boundary; do not mount the host Docker socket in the web service. A separately authenticated worker service remains pending.
- The worker image is only as trustworthy as its build and configuration. Pin by digest, verify build provenance and keep toolchains current.
- No compiler-version selection allowlist for user-provided pragmas; worker has a fixed solc and can return an explicit engine error.
- Code and raw outputs are plaintext in SQLite. Disk encryption, backup encryption, retention, deletion and access monitoring are deployment responsibilities.
- Conversation messages are plaintext in SQLite, have no retention/deletion workflow, and are not encrypted at application level. Pattern-based secret rejection includes PEM private-key headers, `0x`-prefixed 64-hex values, common AWS key formats, authorization headers and JWT-shaped tokens, but does not reliably recognize arbitrary credentials, unprefixed key material or unlabelled seed phrases; users must not submit secrets. SHA-256 values in fields ending in `_sha256` are treated as digests, not secrets. This detector is defense in depth, not comprehensive secret detection, and consent to code review is not consent to transmit a recognized credential.
- API audit submissions are rejected before persistence when the pattern detector recognizes a secret. Valid JSON strings and nested maps/lists are examined recursively. Stored audit/agent evidence remains unchanged for integrity and is redacted in HTTP responses when it matches a recognized pattern; response flags distinguish transformed content and original hashes from hashes of returned values. Historical records can therefore still contain sensitive content in SQLite; access control remains necessary, and scanner misses remain possible.
- Provider quota releases are limited to failures known to occur before a local HTTP write attempt (for example, worker startup, DNS resolution, or connection opening). A shared worker state distinguishes confirmed pre-send, local send-attempt-started, and unknown. Unknown states are charged conservatively to avoid free retries, without claiming that the provider received or billed the request. The local send-attempt signal is set before socket write and cannot prove remote receipt.
- The dashboard clears private rendered data when returning to authentication and waits for the next account's data before showing it. This does not erase server-side records or protect against a browser already compromised by script injection.
- When explicitly requested, the submitted snippet and fixed prompt leave the service for the configured model provider. Provider-side retention and training controls are determined by the operator's provider account and are not configured by this application. The review is a model-generated hypothesis, may be incomplete or wrong, and has no independent semantic validation; the citation checker only verifies source references.
- A privileged database operator can rewrite results, audit events and hash chains. There are no signatures or external immutable anchors.
- RPC configuration can expose server network access if misconfigured; only configure trusted read-only endpoints and restrict egress.
- No live chain security claims, on-chain transaction execution, wallet connection, or private-key handling are implemented. The blockchain analyst only checks EVM chain ID or Soroban endpoint health; the validator only checks source citations, not vulnerability semantics. Orchestration is synchronous and does not provide a durable worker queue or independent multi-provider analysis.

## Operational controls required before exposure

Use HTTPS, Secure cookies, a high-entropy bootstrap secret, restricted RPC egress, encrypted persistent storage/backups, a separately isolated worker service, monitoring, incident response, restore drills, dependency review, a penetration test, and explicit retention/consent policies. Production readiness remains false.

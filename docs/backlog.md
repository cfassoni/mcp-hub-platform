# Operational Backlog — MCP Hub Platform

Canonical operational task queue in `en-US`, distilled from the preliminary design docs in the Obsidian Vault (`02-PROJECTS/mcp-hub-platform/`).

- **Standard tier tasks:** Author an inline micro-spec (<50 lines) under the task entry before Step 2 (QA red-test).
- **Complex tier tasks:** Author a standalone spec under `docs/architecture/` before Step 2.
- **Status Legend:** `todo` | `in-progress` | `blocked` | `done`

---

## Phase 0 — Governance & Repository Bootstrap

| ID | Task | Tier | Status | Dependencies | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TSK-00.1** | Governance & Agent Constraints Bootstrap (`AGENTS.md`, `CLAUDE.md`, `.gitignore`, `docs/`) | Trivial | done | None | Aligns governance with Vault architecture and `ai-memory` routing. |
| **TSK-00.2** | Day-0 Git & GitHub Bootstrap (`git init -b main`, `github-app init`, remote repo, branch protection) | Trivial | done | TSK-00.1 | Single Day-0 initial `main` commit per `AGENTS.md §2`; subsequent work uses branch + PR + `Closes #<issue>`. |

---

## Epic 01 — Monorepo Infrastructure & Platform Core (Phase 1)

| ID | Task | Tier | Status | Dependencies | Acceptance Criteria (DoD) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TSK-01.1** (#1) | Monorepo Scaffold (`npm workspaces`, TypeScript, Hono, `npm run gate`) | Standard | done | TSK-00.2 | Workspaces `apps/*`, `packages/*`, `plugins/*` wired with unified `lint`, `format:check`, `typecheck`, `test:coverage` via `npm run gate`. |
| **TSK-01.2** (#3) | `@mcphub/core` Contracts (`IMcpPlugin`, `IStorageDriver`, OAuth/Session types) | Complex | todo | TSK-01.1 | Strict TypeScript contracts in `packages/mcp-core` matching `docs/rules/core-invariants.md`. |
| **TSK-01.3** (#4) | AES-256-GCM Encryption Engine (`crypto.subtle`) | Complex | todo | TSK-01.2 | Web Crypto AES-256-GCM module with 12-byte random IV, auth tag verification, env master key; 100% statement coverage. |
| **TSK-01.4** (#5) | SQLite Storage Driver (Node.js 26 `node:sqlite`, WAL mode) | Standard | todo | TSK-01.3 | `IStorageDriver` implementation covering `users`, `user_credentials`, `oauth_clients`, `oauth_tokens`, `web_sessions` with `ON DELETE CASCADE`; 100% coverage. |
| **TSK-01.5** (#6) | Cloudflare D1 Storage Driver | Standard | todo | TSK-01.2 | `IStorageDriver` implementation targeting Cloudflare D1 with identical schema and 100% coverage. |

### Micro-Spec: `TSK-01.1` (#1) — Monorepo Scaffold & Quality Gate

1. **Scope & Explicit Non-Scope:**
   - *Scope:* Root `npm workspaces` (`apps/*`, `packages/*`, `plugins/*`), shared `tsconfig.base.json`, ESLint 9 flat config, Prettier (ignoring `*.md`/`docs/`), Vitest + `@vitest/coverage-v8` (100% statement threshold), minimal `@mcphub/core` health payload helper, minimal `@mcphub/gateway` Hono `GET /health` vertical slice verifying cross-workspace ESM resolution, and `plugins/.gitkeep`.
   - *Non-Scope:* `IMcpPlugin`/`IStorageDriver` contracts (`TSK-01.2`), AES-256-GCM (`TSK-01.3`), SQLite/D1 drivers (`TSK-01.4`/`TSK-01.5`), OAuth endpoints, and GitHub Actions CI (`TSK-06.2`).
2. **Input/Output Contract:**
   - `@mcphub/core` exports `PLATFORM_NAME = 'mcp-hub-platform'`, `HealthPayload`, and `createHealthPayload(): HealthPayload` returning `{ status: 'ok', service: PLATFORM_NAME }`.
   - `@mcphub/gateway` exports `createApp(): Hono` handling `GET /health` with `200 OK` JSON matching `createHealthPayload()` (plus default export `createApp()`).
   - Root `npm run gate` runs `lint`, `format:check`, `typecheck`, and `test:coverage`.
3. **Invariants & Failure Modes:**
   - Strict TypeScript (`strict`, `noUncheckedIndexedAccess`, `verbatimModuleSyntax`, `NodeNext` ESM) and Web Standards only in `src/` (no Node-only APIs).
   - Custom export condition `@mcphub/source` resolves workspace TypeScript source during `typecheck` and Vitest runs; `npm run build` emits ESM `.js` + `.d.ts` into `dist/` without cross-workspace `rootDir` leaks.
   - `npm run gate` fails closed on any lint, format, type, or `<100%` statement coverage error.
4. **Verification Criteria:**
   - Pre-implementation `npm test` fails reproducibly on missing `src/` modules.
   - Post-implementation `npm run build` and `npm run gate` exit `0` with `100%` statement coverage on `packages/mcp-core/src` and `apps/mcp-gateway/src`.

---

## Epic 02 — Universal OAuth 2.1 Gateway (Phase 1)

| ID | Task | Tier | Status | Dependencies | Acceptance Criteria (DoD) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TSK-02.1** | Discovery Metadata Endpoints (RFC 8414 & RFC 9728) | Standard | todo | TSK-01.2 | `GET /.well-known/oauth-authorization-server` and `GET /.well-known/oauth-protected-resource` returning spec-compliant JSON. |
| **TSK-02.2** | Canonical MCP Challenge (`WWW-Authenticate`) | Standard | todo | TSK-02.1 | Anonymous calls to `/:slug/mcp` return `401` with `WWW-Authenticate: Bearer resource_metadata="..."`. |
| **TSK-02.3** | CIMD Validator with Anti-SSRF (Claude Web) | Complex | todo | TSK-02.1 | HTTPS-only metadata fetch rejecting private/loopback/link-local IPs & unsafe redirects, 64 KB cap, 5s timeout, 1h TTL cache. |
| **TSK-02.4** | Dynamic Client Registration — DCR RFC 7591 (Gemini / VS Code) | Standard | todo | TSK-01.4 | `POST /oauth/register` validating and persisting dynamic clients via `IStorageDriver`. |
| **TSK-02.5** | Static Pre-Configured Clients (ChatGPT) | Trivial | todo | TSK-02.1 | Validates static `client_id="chatgpt"` strictly against official OpenAI callback origins. |
| **TSK-02.6** | OAuth 2.1 Handshake with PKCE S256 & Token Exchange | Complex | todo | TSK-02.3, TSK-02.4 | `/oauth/authorize` and `/oauth/token` enforcing PKCE `S256`, hashed token storage, and scoped issuance. |
| **TSK-02.7** | SSO Session Management (`mcphub_session` Cookie & 1-Click Consent) | Complex | todo | TSK-02.6 | `HttpOnly`, `Secure`, `SameSite=Lax` 30–60d cookie; 1-click consent view with account switch flow. |
| **TSK-02.8** | Token Auto-Rotation & Hygiene | Standard | todo | TSK-02.6 | Revokes previous tokens for the same `(user_id, client_id)` pair upon new issuance. |

---

## Epic 03 — Dynamic Plugin Routing & Streamable HTTP Transport (Phase 1)

| ID | Task | Tier | Status | Dependencies | Acceptance Criteria (DoD) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TSK-03.1** | Multi-Tenant Slug Router (`/:slug/mcp`) | Standard | todo | TSK-01.2 | Dynamic Hono router dispatching requests to registered `IMcpPlugin` instances by slug. |
| **TSK-03.2** | Official Streamable HTTP Transport (`MCP 2026-07-28`) | Complex | todo | TSK-03.1 | Bidirectional Streamable HTTP MCP transport with SEP-973 metadata; zero legacy SSE endpoints. |
| **TSK-03.3** | Auth Middleware & Decrypted Session Injection | Complex | todo | TSK-02.6, TSK-03.1 | Validates Bearer token, updates `last_activity_at`, decrypts tenant credentials, injects scoped plugin context. |

---

## Epic 04 — FIA Invest Connector (`plugins/fiainvest`) (Phase 2)

> **Locale Note:** Per `AGENTS.md` Core Protocol, user-facing MCP tool/resource/prompt names and descriptions for `plugins/fiainvest` use `pt-BR` as defined in the Vault plugin specification (`02-PROJECTS/mcp-hub-platform/plugins/fiainvest/`).

| ID | Task | Tier | Status | Dependencies | Acceptance Criteria (DoD) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TSK-04.1** | Resilient `FiaInvestClient` & Real JSON Fixtures | Standard | todo | TSK-01.2 | Typed `fetch` client (`AbortSignal.timeout(30_000)`), JWT login, transparent 401 refresh, sanitized `UpstreamClientError`, offline JSON fixtures. |
| **TSK-04.2** | Dynamic Wallet & Option Expiration Discovery | Standard | todo | TSK-04.1 | Resolves friendly wallet names via `simplified_list` and nearest option expiration via `option_expiration_dates` (no guessing). |
| **TSK-04.3** | 8 Passive Context Resources (`fiainvest://*`) | Standard | todo | TSK-04.1 | Exposes all 8 `fiainvest://` resources with pass-through fidelity and 100% statement coverage. |
| **TSK-04.4** | 13 Operational & Analytical Tools (`pt-BR`) | Complex | todo | TSK-04.2 | Implements all 13 FIA Invest tools validated against real fixtures with 100% statement coverage. |
| **TSK-04.5** | 2 Guided Prompts (`rotina-diaria-fia`, `analise-cenario-vencimento`) | Standard | todo | TSK-04.4 | Exposes both guided workflows orchestrating the corresponding tools. |

---

## Epic 05 — Onboarding Web Portal (`apps/hub-web`) (Phase 3)

| ID | Task | Tier | Status | Dependencies | Acceptance Criteria (DoD) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TSK-05.1** | Hub Landing Page & Connector Catalog | Standard | todo | TSK-01.1 | Responsive portal presenting the platform and active connectors (`pt-BR` user-facing copy). |
| **TSK-05.2** | Onboarding Card & Client Connection Snippets | Trivial | todo | TSK-05.1 | Direct MCP URL copy + setup snippets for Claude Desktop, Claude Web, ChatGPT, Cursor. |
| **TSK-05.3** | Responsive Authorization & Consent UI | Standard | todo | TSK-02.7 | Clean upstream login and 1-click agent authorization views. |

---

## Epic 06 — Operations, CI & Hardening (Phase 4)

| ID | Task | Tier | Status | Dependencies | Acceptance Criteria (DoD) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TSK-06.1** | 60-Day Inactivity Purge Worker | Standard | todo | TSK-01.4, TSK-01.5 | Scheduled job (Docker cron + Cloudflare Cron Trigger) cascading deletion for `last_activity_at < NOW() - 60 days`. |
| **TSK-06.2** (#2) | GitHub Actions CI Pipeline | Standard | done | TSK-01.1 | Automated workflow running `npm run gate` and security/SCA checks on PRs. |
| **TSK-06.3** | End-to-End Multi-Client Homologation | Complex | todo | TSK-04.5, TSK-05.3 | Verified live connections from Claude Desktop, Claude Web, ChatGPT, and Cursor. |

### Micro-Spec: `TSK-06.2` (#2) — GitHub Actions CI Pipeline

1. **Scope & Explicit Non-Scope:**
   - *Scope:* Add `.github/workflows/ci.yml` running automated verification on PRs and pushes to `main`, plus a repository-level contract test `test/ci-workflow.test.ts` included in `vitest.config.ts`, and cross-OS LF parity (`.gitattributes` + `.prettierrc.json` `endOfLine: "auto"`).
   - *Non-Scope:* Deployment/CD pipelines, container image publishing, SAST/CodeQL setup, or unrelated backlog updates (`#10`).
2. **Input/Output Contract:**
   - Triggers on `pull_request` and `push` targeting `main`, cancels superseded runs via `concurrency`, and enforces least-privilege `contents: read`.
   - Runs on `ubuntu-latest` with Node.js `26` and npm cache, executing `npm ci`, `npm run build`, `npm run gate`, and `npm audit --audit-level=high`.
3. **Invariants & Failure Modes:**
   - Any lint, format, typecheck, `<100%` statement coverage, workspace build, or high/critical vulnerability fails the CI job with non-zero exit code.
   - Including `test/**/*.test.ts` in `vitest.config.ts` `test.include` does not alter `coverage.include` scope (`packages/*/src`, `apps/mcp-gateway/src`, `plugins/*/src`).
4. **Verification Criteria:**
   - Pre-fix `npm test` fails reproducibly on `test/ci-workflow.test.ts` while `.github/workflows/ci.yml` is absent.
   - Post-fix `npm run build` and `npm run gate` exit `0` with all suites passing and `100%` statement coverage.

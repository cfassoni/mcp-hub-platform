# Core Engineering & Security Invariants

Canonical non-negotiable constraints for `mcp-hub-platform`. Architect, QA, Coder, Reviewer, and Security roles MUST validate all specs, implementations, and PRs against these invariants.

## 1. Protocol & Transport Fidelity

- **Streamable HTTP Only:** Expose plugins dynamically at `/:slug/mcp` using the official MCP Streamable HTTP (`2026-07-28`) transport. Do not implement legacy SSE transport.
- **Canonical Auth Challenge:** Unauthenticated requests to `/:slug/mcp` MUST return `HTTP 401 Unauthorized` with `WWW-Authenticate: Bearer resource_metadata="https://<host>/.well-known/oauth-protected-resource"`.
- **Ratified Discovery Only:** Expose `GET /.well-known/oauth-protected-resource` (RFC 9728), `GET /.well-known/oauth-authorization-server` (RFC 8414), and SEP-973 in-protocol metadata. Never invent ad-hoc manifest endpoints (e.g., `/.well-known/mcp-app.json`).

## 2. OAuth 2.1, Universal Client Triad & Anti-SSRF

- **PKCE S256 Mandatory:** `/oauth/authorize` and `/oauth/token` MUST enforce OAuth 2.1 with PKCE `S256` (`code_challenge` / `code_verifier` SHA-256 verification).
- **Universal Client Triad:**
  1. **CIMD (Claude Web):** Resolving HTTPS `client_id` metadata documents MUST enforce strict Anti-SSRF (HTTPS only; reject loopback, RFC 1918 private ranges, link-local, cloud metadata IPs, and unsafe redirects), a 64 KB response size cap, a 5-second timeout, and a 1-hour TTL cache.
  2. **DCR (RFC 7591 — Gemini Web / VS Code):** `POST /oauth/register` persists validated `client_id` metadata and `redirect_uris` via `IStorageDriver`.
  3. **Static Clients (ChatGPT):** Pre-configured `client_id` MUST validate callbacks strictly against official OpenAI callback origins (`https://chat.openai.com/aip/...`, `https://chatgpt.com/aip/...`).
- **Authoritative Public Origin (`cloudflared` / Proxy):** Derive all public OAuth URLs (RFC 9728, RFC 8414, `WWW-Authenticate`, redirect URIs) strictly from the configured `APP_BASE_URL` HTTPS origin, never from internal plain-HTTP `req.url` or untrusted forwarding headers.
- **SSO Session Cookie:** Issue `mcphub_session` as a host-only cookie (omit `Domain` attribute) with `HttpOnly`, `Secure`, `SameSite=Lax` (30–60 day TTL), isolating staging and friendly-user production subdomains while enabling 1-click consent and account switching.
- **Token Hygiene:** Store only cryptographic hashes (`token_hash`, `cookie_hash`) in persistence — never plaintext tokens. Issuing a new access token for `(user_id, client_id)` MUST revoke prior active tokens for that pair.

## 3. Multi-Tenant Vault, Cryptography & Zero-Trust Privacy

- **Tenant Isolation:** Isolate stored credentials, sessions, and tokens strictly by `(user_id, plugin_slug)`. Cross-tenant reads or credential leakage are critical defects.
- **Encryption at Rest (AES-256-GCM):** Encrypt all upstream credentials/tokens using Web Crypto (`crypto.subtle`) AES-256-GCM with an environment-injected `ENCRYPTION_MASTER_KEY`, a fresh cryptographically random 12-byte IV per write, and stored/verified authentication tag. Never store upstream credentials in plaintext.
- **60-Day Inactivity Purge:** Track `last_activity_at` per user. A scheduled purge job (`USER_INACTIVITY_TTL_DAYS=60`) MUST permanently delete inactive users with cascading removal (`ON DELETE CASCADE`) of credentials, sessions, and tokens.

## 4. Secrets, Logging & Memory Hygiene

- **Zero Secret Leakage:** Never commit, log, return in MCP tool/error responses, or write to `ai-memory` any passwords, upstream credentials, JWTs, Bearer tokens, `ENCRYPTION_MASTER_KEY`, GitHub App private keys, or customer PII.
- **Sanitized Error Boundary:** Wrap upstream failures in `UpstreamClientError` with credentials, auth headers, and sensitive tokens scrubbed before returning to clients or logs.

## 5. Upstream Contract Inviolability & Resilience

- **Transparent Pass-Through:** Preserve authentic upstream schemas and values. Never synthesize ghost fields, invent undocumented parameters, round/alter numerical values, or fabricate defaults.
- **Dynamic Discovery over Guessing:** Resolve optional MCP tool parameters required by upstream via official upstream discovery endpoints (e.g., mapping friendly names to IDs or querying valid expiration dates), never via static assumptions.
- **Resilience:** Implement transparent upstream token refresh on HTTP `401` where supported, and set explicit HTTP timeouts (`AbortSignal.timeout(30_000)` minimum for heavy analytical endpoints).

## 6. Isomorphic Portability & Plugin Decoupling

- **Web Standards Core:** `packages/*`, `apps/mcp-gateway`, and `plugins/*` MUST use TypeScript and Web Standards (`Request`, `Response`, `fetch`, `crypto.subtle`) with zero Node-only APIs in core business logic.
- **Storage Abstraction & Runtime Targets:** All database access goes through `IStorageDriver`. Primary MVP deployment targets rootless OCI containers on Podman (VPS running Node.js 26 + `node:sqlite` WAL mode behind `cloudflared` HTTPS tunnels across isolated staging and friendly-user production instances); Cloudflare Workers/D1 implementation is deferred to Post-MVP while preserving strict Web Standards + `IStorageDriver` portability.
- **Plugin Isolation:** Every connector implements `IMcpPlugin` under `plugins/<slug>/` without modifying gateway routing or core auth logic.
- **User-Facing Locale Scope:** Engineering artifacts remain `en-US`; user-facing MCP primitive names/descriptions and portal copy MAY use `pt-BR` when explicitly specified for Brazilian connectors/UI.

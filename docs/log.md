# Audit & Decision Log

Chronological record of governance updates, specification milestones, and architectural changes (`AGENTS.md §3`).

- **2026-11-23 (Day-0 Governance Bootstrap):** Adapted `AGENTS.md` for `mcp-hub-platform` (en-US repo artifacts with explicit `pt-BR` exception for BR user-facing plugin/UI surfaces; Node.js 26 + `node:sqlite` + `npm workspaces` targeting Docker and Cloudflare Workers/D1; self-contained native multi-agent pipeline; 100% coverage in core/gateway/plugins and logic-focused coverage in `apps/hub-web`; GitHub + `github-app` governance with Day-0 bootstrap exception; canonical `ai-memory` compact routing block + `.ai-memory.toml` scope). Created `CLAUDE.md`, `.gitignore`, `docs/rules/core-invariants.md`, `docs/backlog.md`, and `docs/log.md`.
- **2026-11-23 (`TSK-00.2` Day-0 Git Bootstrap):** Initialized `main` branch, bound `origin` to `https://github.com/cfassoni/mcp-hub-platform.git` via `github-app` (`cfassoni-ai[bot]`), and pushed the single Day-0 bootstrap commit per `AGENTS.md §2`.
- **2026-11-23 (`TSK-01.1` #1 Monorepo Scaffold):** Configured `npm workspaces` (`apps/*`, `packages/*`, `plugins/*`), strict TypeScript ESM builds, ESLint 9, Prettier, Vitest V8 100% coverage gate (`npm run gate`), and minimal `@mcphub/core` + `@mcphub/gateway` `/health` slice.

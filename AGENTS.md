# Repository Guidelines

## Project Structure & Module Organization
- Backend (Go): entry `main.go`; CLI in `cmd/` (`server`, `migrate`, `eject`); app wiring in `application/`; HTTP in `routers/` and `middleware/`; domain and utilities in `pkg/`; ORM code in `ent/`; business logic in `service/`.
- Frontend (React + Vite): `assets/` with `src/`, `public/`, and build output in `assets/build`.
- CI/Release: `.goreleaser.yaml`, Dockerfile; config defaults in `pkg/conf/`.

## Build, Test, and Development Commands
- Release build (embed frontend):
  - `./.build/build-assets.sh $(git describe --tags)` — builds frontend and creates `application/statics/assets.zip`.
  - `GOCACHE=$(pwd)/.gocache go build -a -o cloudreve \`
    `-ldflags "-s -w -X 'github.com/cloudreve/Cloudreve/v4/application/constants.BackendVersion=$(git describe --tags)' -X 'github.com/cloudreve/Cloudreve/v4/application/constants.LastCommit=$(git rev-parse --short HEAD)'"` — builds backend with version/commit injected and embeds assets.
- Run server: `./cloudreve server -c conf.ini` (or `go run . server -c conf.ini`) — listens on `:5212`.
- DB migration (v3→v4): `go run . migrate -c conf.ini --v3-conf /path/to/v3/conf.ini`.
- Frontend dev: `cd assets && npm ci && npm run dev` — Vite dev server with API proxy to `http://localhost:5212`.
- Tests (Go): `go test ./... -race -cover` — run unit tests across packages.

## Coding Style & Naming Conventions
- Go: use `go fmt ./...` and `go vet ./...`; package names lower_snake; exported identifiers use Go’s PascalCase.
- Frontend: TypeScript + React; run `npm run lint` and `npm run format` (ESLint/Prettier). File names: `PascalCase.tsx` for components, `camelCase.ts` for utils.
- Keep handlers thin; place reusable logic under `pkg/` and services under `service/`.

## Testing Guidelines
- Framework: Go `testing` with files named `*_test.go` next to sources.
- Scope: cover new logic in `pkg/`, middleware, and services; prefer table-driven tests.
- Run locally: `go test ./... -race -cover`; target ≥80% coverage for new code when practical.

## Commit & Pull Request Guidelines
- Commits: follow Conventional Commits (e.g., `feat(scope): ...`, `fix(scope): ...`).
- PRs: include summary, rationale, and linked issues; note breaking changes; add screenshots for UI changes in `assets/`; ensure `go build`, `go test`, and `npm run build` pass.

## Security & Configuration Tips
- Config file: pass with `-c` (defaults to `conf.ini`).
- Env overrides: `CR_CONF_{Section}.{Key}=Value` (e.g., `CR_CONF_System.Debug=true`).
- Do not commit secrets; prefer environment variables or external config volumes.

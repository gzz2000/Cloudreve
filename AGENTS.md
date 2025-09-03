# Repository Guidelines

## Project Structure & Module Organization
- Backend (Go): entry `main.go`; CLI in `cmd/` (`server`, `migrate`, `eject`); app wiring in `application/`; HTTP in `routers/` and `middleware/`; domain and utilities in `pkg/`; ORM code in `ent/`; business logic in `service/`.
- Frontend (React + Vite): `assets/` with `src/`, `public/`, and build output in `assets/build`.
- CI/Release: `.goreleaser.yaml`, Dockerfile; config defaults in `pkg/conf/`.

## Build, Test, and Development Commands
- Release build (embed frontend):
  - `./.build/build-assets.sh $(git describe --tags)` — builds frontend and creates `application/statics/assets.zip`.
  - `go build -a -o cloudreve \`
    `-ldflags "-s -w -X 'github.com/cloudreve/Cloudreve/v4/application/constants.BackendVersion=$(git describe --tags)' -X 'github.com/cloudreve/Cloudreve/v4/application/constants.LastCommit=$(git rev-parse --short HEAD)'"` — builds backend with version/commit injected and embeds assets.
- Run server: `./cloudreve server -c conf.ini` (or `go run . server -c conf.ini`) — listens on `:5212`.
- DB migration (v3→v4): `go run . migrate -c conf.ini --v3-conf /path/to/v3/conf.ini`.

## Coding Style & Naming Conventions
- Backend Go use TAB for indentation instead of spaces.
- Go: use `go fmt ./...` and `go vet ./...`; package names lower_snake; exported identifiers use Go’s PascalCase.
- Frontend: TypeScript + React; run `npm run lint` and `npm run format` (ESLint/Prettier). File names: `PascalCase.tsx` for components, `camelCase.ts` for utils.
- Keep handlers thin; place reusable logic under `pkg/` and services under `service/`.

## Agent Build & Escalation Notes
-	Frontend compile: run `./.build/build-assets.sh 4.5.1` — this calls `yarn build` and zips the result into `application/statics/assets.zip`.
-	Backend compile: use the following command (ldflags are required and this also packs the last-compiled frontend assets zip into the binary):

```
go build -a -o cloudreve \
	-ldflags "-s -w -X 'github.com/cloudreve/Cloudreve/v4/application/constants.BackendVersion=$(git describe --tags)' -X 'github.com/cloudreve/Cloudreve/v4/application/constants.LastCommit=$(git rev-parse --short HEAD)'"
```

-	Escalation: both commands require escalation; you can safely ask the user for approval to run them. When code changes are made, use the appropriate command to verify the code compiles. You can set command execution timeout to 10 minutes or more.
-	Indentation: remember to use TAB instead of spaces. TAB is the convention of this repo.
-       When you are trying to apply code patches, always use apply_patch tool and refrain from using python or shell scripts.

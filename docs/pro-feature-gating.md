# Cloudreve Community vs. Pro — Feature Gating Summary

This document summarizes how Pro features are omitted or disabled in the Community (OSS) edition across backend and frontend.

## Overview
- Community build compiles with `IsPro=false` and ships non‑Pro frontend assets.
- Pro‑only business logic, schema, and routes are omitted from the community codebase; the frontend still shows discoverable entry points but gates interactions with an upsell dialog.

## Backend Mechanisms
- Build flags
  - `application/constants/constants.go`: `IsPro = "false"`, `IsProBool` derived and used throughout.
  - Banner prints version/commit and `Pro=`: `application/application.go`.
  - `Ping` returns version with `-pro` suffix only when Pro: `routers/controllers/site.go`.
- Dependency manager
  - DI accepts `WithProFlag` and `WithLicenseKey` but community passes `isPro=false`; `licenseKey` is stored but unused: `application/dependency/options.go`, `dependency.go`.
  - Pro only affects statics FS and DB schema version suffix:
    - Statics FS: `statics.NewServerStaticFS(logger, fs, isPro)`.
    - DB schema mark adds `-pro` suffix when Pro; migrations trim `-pro` for patching: `application/dependency/dependency.go` and `inventory/migration.go`.
- License plumbing (not enforced in community)
  - Getter exists: `pkg/setting/provider.go: License(ctx)`.
  - Error code reserved: `CodeDomainNotLicensed = 40087` (`pkg/serializer/error.go`). Community code never emits it.
  - CLI flag `--license-key` accepted in `cmd/server.go` but unused in OSS logic.
- Omission of Pro domain and APIs
  - Ent schema lacks VAS/payment/orders/audit/events/abuse models; only core entities (file/entity/user/group/policy/node/share/task): `ent/schema/*`.
  - Router has no endpoints for those Pro features: `routers/router.go`.

## Frontend Mechanisms
- Static package name and version
  - Community frontend `assets/package.json` has name `cloudreve-frontend`.
  - Vite writes `version.json` with `{ name, version }`: `assets/vite.config.ts`.
  - Server validates static assets match backend’s Pro flag and version: `application/statics/statics.go`.
- Global Pro flag exposure
  - Admin summary API returns `version.pro` (bool): `service/admin/site.go`, `service/admin/response.go`.
  - Admin Home renders Pro chip if `summary.version.pro` and shows “Buy Pro” upsell when not Pro: `assets/src/component/Admin/Home/Home.tsx`.
- UI gates & upsell
  - Reusable `ProDialog` (learn more): `assets/src/component/Admin/Common/ProDialog.tsx`.
  - `SettingForm` accepts `pro` prop, shows a Pro chip, and intercepts clicks to open the dialog: `assets/src/component/Pages/Setting/SettingForm.tsx`.
  - Side navigation items for Pro pages flagged with `pro: true`; clicking opens the dialog instead of navigating: `assets/src/component/Frame/NavBar/PageNavigation.tsx`.
  - Example gates:
    - Storage Policy “Load Balance” provider is marked Pro in UI (via `PolicyPropsMap[type].pro`) and is not implemented in backend `PolicyType`: `assets/src/component/Admin/StoragePolicy/StoragePolicySetting.tsx`, `inventory/types/types.go`.
    - File dialog primary storage policy selection labeled as Pro: `assets/src/component/Admin/File/FileDialog/FileForm.tsx`.
    - VAS/Shop/Payment settings are displayed read‑only with Pro chips: `assets/src/component/Admin/Settings/VAS/VAS.tsx`.
    - Certain email templates and admin sections (payments/events/abuse) are marked Pro in nav/UI.
- Error handling awareness
  - Frontend recognizes `DomainNotLicensed` (40087) in `assets/src/api/request.ts`; unused in Community backend but supports shared code with Pro builds.

## Asset Consistency Enforcement
- `application/statics/statics.go` verifies:
  - Static package name: `cloudreve-frontend` for OSS, `cloudreve-frontend-pro` for Pro.
  - Version equality with backend `BackendVersion`.
  - Mismatch logs clear errors, instructing to delete `statics/` and rebuild.

## Summary
- Community disables Pro by compile‑time flag, by omitting backend models/routes, and by enforcing asset identity.
- Frontend keeps discoverability with clear gating/upsell, while backend guarantees that Pro features cannot be invoked because they don’t exist server‑side.


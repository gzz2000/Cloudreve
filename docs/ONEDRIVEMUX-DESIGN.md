# OneDrive Mux Policy — Design Notes

## Overview
Goal: Add a new storage policy type `onedrivemux` that aggregates many OneDrive subaccounts into a single policy. The server selects a subaccount per upload based on available capacity, while each file’s entity keeps a stable reference to the chosen subaccount for later reads/deletes.

## Data Model (no DB schema changes)
- `ent.StoragePolicy.Type`: `onedrivemux`.
- `ent.StoragePolicy.Settings` (JSON) extends with:
  - `od_mux_accounts`: array of subaccounts
    - `{ id:int64, email:string, refresh_token:string, od_driver:string, total:int64, used:int64, remaining:int64, disabled:bool, created_at:int64, updated_at:int64, last_quota_sync:int64 }`
  - `od_mux_strategy`: string, default `lowest_free_that_fits`.
  - `od_mux_next_id`: int64 (monotonic allocator; ids never reused).
- `Entity.Source`: prefix with `acc/{id}/...` to encode the subaccount used (enables correct routing without schema change).

## Selection & Safety Margin
- During `DBFS.PrepareUpload`, if policy is `onedrivemux`:
  - Filter subaccounts where `disabled == false`.
  - Ensure up-to-date or safe values: if `remaining < size + 1 MiB` or `last_quota_sync` is stale, call OneDrive quota API for that subaccount and persist.
  - Choose the account with the lowest `remaining` that still satisfies `remaining ≥ size + 1 MiB` (default strategy).
  - Compose `req.Props.SavePath = "acc/{id}/" + generateSavePath(...)`.
  - If none fits: return clear error.

## Quota Sync on Mutations
- After successful `CompleteUpload`: refresh quota for the affected subaccount via OneDrive and persist exact `{total, used, remaining}`. If API fails, fall back to arithmetic update and mark stale.
- On physical delete (in `RecycleEntities`): group by `acc/{id}`; refresh quota per-subaccount (fallback on failure) after provider deletion.
- On upload quota errors (insufficient storage): force immediate refresh and return actionable error.

## Driver & Credentials
- New driver `pkg/filemanager/driver/onedrivemux`:
  - Parse `acc/{id}/...` in Token/Put/Delete/Source/Thumb and delegate to the existing OneDrive client configured with that subaccount.
  - Capabilities mirror `onedrive`.
- CredManager key per subaccount: `cred_odmux_{policyID}_{subID}` with refresh that writes back the new `refresh_token` to the right subaccount in Settings.

## Admin UX
- “OneDrive Mux” provider card.
- Subaccount table (email, total/used/remaining, last sync, status). Actions: Authorize (append), Disable/Enable, Sync Quota. No delete.
- OAuth callback for mux appends a new subaccount (id = `od_mux_next_id++`), initializes quota via API, and registers credential.

## Backend Touch Points
- `inventory/types/types.go`: add `PolicyTypeOdMux` and Settings fields.
- `pkg/filemanager/fs/dbfs/upload.go`: selection + safety margin + save path.
- `pkg/filemanager/driver/onedrivemux/*`: new wrapper driver.
- `pkg/filemanager/driver/onedrive/client.go`: add `GetDriveQuota(ctx)`.
- `pkg/credmanager`: mux credential implementation + startup registration.
- `pkg/filemanager/manager/upload.go` and `manager/recycle.go`: post-op quota refresh hooks.
- `service/admin/policy.go`: mux-aware create/update, OAuth append, disable/enable, sync.
- Frontend: add `PolicyType.onedrivemux`; use OneDrive uploader; admin subaccounts UI.

## OneDrive Quota API
- Endpoint: `GET {base}/drive` (where `{base}` derives from policy server, e.g., `https://graph.microsoft.com/v1.0/me/drive` or China: `https://microsoftgraph.chinacloudapi.cn/v1.0/me/drive`).
- Response contains `quota` object with fields like `total`, `used`, `remaining`, `deleted`, `state`.

## Next Steps
1) Add type/setting structs + quota API + cred.
2) Implement onedrivemux driver + selection logic.
3) Post-op quota refresh hooks.
4) Admin API + frontend for subaccounts.
5) Tests + manual E2E.

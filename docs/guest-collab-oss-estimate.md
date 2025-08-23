# Guest Collaboration via Share Links (OSS) — Scope & Estimates

This document outlines effort to bring a Pro feature — allowing guests to upload/edit in a shared link without login — into the Community edition.

## Goal
Enable unauthenticated visitors with the share URL (and password if set) to contribute content under the shared subtree, with server‑side guardrails and without requiring an account.

## Current State (Gaps)
- Share schema: `ent/schema/share.go` with JSON `props` only contains view flags (`share_view`, `show_read_me`). No ACL.
- Share capabilities: `shareNavigatorCapability` disables write operations (`create_file`, `upload_file`, `rename_file`, `delete_file`, `soft_delete`, `restore`): `pkg/filemanager/fs/dbfs/navigator.go`.
- Upload/Create logic: `DBFS` enforces owner‑only on write paths and all mutating explorer routes require login (`routers/router.go`).

## Option A — Minimal “Upload‑only Dropbox” inside Share
A safe first step that permits uploads (and optionally new folders) into the share root or a designated subfolder.

- Data model (0.5 day)
  - Extend `inventory/types.ShareProps` with:
    - `allow_upload: bool`
    - `allow_create_folder: bool`
  - No schema migration; reuse existing JSON column.

- Backend capabilities (1–1.5 days)
  - Derive per‑share capability dynamically in `share_navigator.go` instead of the static `shareNavigatorCapability`:
    - If `allow_upload` → enable `NavigatorCapabilityUploadFile`.
    - If `allow_create_folder` → enable `NavigatorCapabilityCreateFile` (for folders only).
  - Constrain writes to share subtree (share root or chosen child), and forbid climbing out.

- Upload flow & routes (1–1.5 days)
  - Add unauth share‑scoped upload endpoint(s), e.g. `POST /api/v4/share/:id/upload` (and optional `PUT /create-folder`).
  - Guard by share id/password; in handler, set a context flag to bypass owner check and operate as the share owner within the share FS.
  - Capacity/quota and policy validations already enforced when acting as owner.

- Frontend (0.5–1 day)
  - Share creation dialog: add “Allow uploads” (+ “Allow folders”) toggles; include in `ShareCreateService`.
  - Share page (public): if capability includes `upload_file`, show Upload button (and “New folder” if allowed) using unauth requests (with share password when required).

- Security & abuse hardening (0.5–1 day)
  - Rate limiting per share; optional daily cap; file size/type policy validation leveraged from parent folder policy.
  - Server logs and event counters (full audit log not present in OSS).

- Estimate: ~3–4.5 days engineering + 0.5–1 day testing/docs.

## Option B — Full Guest Edit (rename/move/delete/metadata) inside Share
Allows broader collaboration within the share subtree.

- Data model (0.5–1 day)
  - Extend `ShareProps` with granular flags, e.g.: `allow_rename`, `allow_delete`, `allow_move`, `allow_metadata`.

- Backend capabilities and checks (1.5–2 days)
  - Compute per‑share capabilities from props in `share_navigator.go`.
  - Update DBFS operations (rename/move/delete/patch) to permit share‑guest paths when guarded by a valid share and confined to subtree.
  - Maintain proper locking; deny operations that escape subtree or violate policy.

- Routing/middleware (0.5–1 day)
  - Add share‑scoped, unauth variants of the required explorer operations (or carefully allow the existing ones when a share context is provided and `LoginRequired` would otherwise block).

- Frontend (1–1.5 days)
  - Share dialog: granular toggles.
  - Share page: enable context‑menu actions according to capability from `props`.

- Security & safety (1–2 days)
  - Optional restrictions: root‑only uploads, recycle‑only deletes, per‑share throttling, operation provenance (tag edit origin as “share guest”).

- Tests & stabilization (1–2 days)
  - Unit tests for capability derivation and negative paths (invalid password, escape attempts, capacity exceeded).

- Estimate: ~5–8 days engineering + 1–2 days testing/docs.

## Milestones (suggested)
1. Schema/props extension and per‑share capability derivation.
2. Share‑scoped unauth upload API and UI wiring (Option A).
3. Harden limits and logging; documentation.
4. Optional: incremental full‑edit capabilities (Option B) in small, testable slices.

## Risks & Considerations
- Authorization model: Mutations currently assume “requester is owner”; share‑guest flows must impersonate owner while authorizing via share id/password and confining to the share subtree.
- Abuse surface: Add rate limits, caps, and clear owner controls to disable guest uploads per share.
- Upstream divergence: This was a Pro feature; maintaining an OSS fork adds future merge overhead.

## Open Questions
- Should uploads land in a dedicated child (e.g., `Uploads/`) to separate guest content?
- Do we need per‑share quotas or rely solely on owner’s group/policy limits?
- How much of edit surface (rename/move/delete/metadata) is truly required beyond uploads?


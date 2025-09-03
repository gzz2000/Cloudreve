# Cloudreve Cold Backup (Design Spec)

## Overview
- Purpose: Periodically back up immutable file blobs and the application database to a separate backup target exposed via WebDAV as a cold, encrypted archive to mitigate risk from primary storage/policy failures. This keeps Cloudreve agnostic to specific providers (we can later point WebDAV at a local proxy that mirrors a TeraBox drive).
- Scope: Backup only (no restore yet). Streamed uploads, encrypted, segmented into files; per-run limits to avoid massive initial uploads.

## Core Requirements
- Automatic periodic execution via cron.
- Back up:
  - Newly-created blobs (immutable entities) since the last watermark.
  - Database: Cloudreve DB file (SQLite) or dump for other DBs (later phase).
- Transparent encryption with a configured key (restore can be added later).
- Stream-from-source, minimal local disk usage.
- Upload to WebDAV with large-object segmentation (e.g., 1 GB segments) to handle provider file size limits and improve resume-ability.
- Per-run limits (~500 blobs, ~20 GB) to throttle initial sync.
- Task result summarization: uploaded sizes, counts, estimated remaining backlog.

## Terminology and Data Model
- Cloudreve distinguishes File vs Blob (Entity):
  - File (`ent/schema/file.go`) is a logical object that can have multiple versions.
  - Entity/Blob (`ent/schema/entity.go`) represents the immutable data blob. A new version is a new entity linked to the File.
- Backup unit = Entity (blob). The DB contains the mapping File⇔Entity, so we do not need extra backup-side metadata; blob ID (entity ID) suffices as the unique key.

## High-Level Flow
1. Cron triggers the Cold Backup task at a configurable interval when enabled.
2. The task determines the next entities to upload using a monotonic watermark: `next_to_upload_blob_id`.
   - Enumerate entities with `id >= next_to_upload_blob_id` ordered by `(id ASC)`.
   - Stop when either per-run item count or byte size limit is reached.
3. For each entity:
   - Obtain an `EntitySource` via FileManager and stream data directly from the primary policy.
   - Encrypt on the fly (AES-CTR with 256-bit key).
   - Segment entity into ≤ `segment_size` (default 1 GB) parts; upload each segment as an independent WebDAV object via HTTP `PUT`.
   - Ensure destination folders exist via `MKCOL` (recursive ensure) if required by the server.
   - Advance watermark as entities complete (and persist on progress to avoid redo on crashes).
4. Back up the database:
   - For SQLite: read `DBFile` path from loaded config (`-c conf.ini`), stream encrypt, upload.
   - For non-sqlite (mysql/postgres/mssql): planned later (dump to stream); configurable to skip for now.
5. Compute summary: uploaded counts/bytes and estimate remaining counts/bytes based on maximal entity ID and total size beyond the watermark.

## WebDAV Integration
- Interface: Implement a minimal WebDAV client in Go, supporting streaming `PUT` for files and `MKCOL` to create directories (recursively ensuring parent paths), with optional `HEAD`/`PROPFIND` for health checks.
- Auth: HTTP Basic (username/password) and optional custom headers.
- TLS: Optional insecure skip verify for local proxies (not recommended for production).
- Upload specifics:
  - Upload each segment as an independent object via `PUT`.
  - Segment size default 1 GB; suitable for generic backends and future TeraBox-backed WebDAV.
  - Retries with exponential backoff on transient network/server errors.

## Storage Layout on WebDAV
- Remote root: configurable (default `/cloudreve-backups`).
- Blobs:
  - Folder: `${root}/blobs/<entityID>/` (per-entity folder to keep listings manageable).
  - Files: `${root}/blobs/<entityID>/<entityID>.p<4-digit-seg>.enc`
    - Examples: `.../blobs/123/123.p0001.enc`, `.../blobs/123/123.p0002.enc`.
    - One segment per ~1 GB (configurable `segment_size`).
- Database:
  - `${root}/db/<YYYY-MM-DD>/<UNIXTS>-cloudreve.db.enc` (SQLite).
  - For other DBs later: dump filename accordingly.

## Encryption
- Algorithm: AES-CTR (AES-256-CTR), stream friendly.
- Key: 32-byte secret from settings.
- IV/Nonce derivation: HMAC-SHA256(key, entityID || segmentIndex)[:16]. This deterministic IV avoids storing headers while staying unique per segment.
- No headers or metadata embedded; restore logic can recompute the IVs using entityID, segmentIndex and the configured key.

## Watermarking and Backlog
- Watermark: `next_to_upload_blob_id` (persisted in settings store).
  - Selection: `SELECT entities WHERE id >= watermark ORDER BY id ASC`.
  - Update watermark as each entity finishes; on task resume, continue from the last incomplete entity ID.
- Remaining estimation:
  - Counts and bytes can be computed with two queries after the last processed entity ID.

## Limits, Concurrency, and Retries
- Per-run limits (configurable):
  - `files_per_run` default 500
  - `bytes_per_run` default 20 GB
- Upload parameters (configurable):
  - `segment_size` default 1 GB (helps with large file handling and resumability at segment granularity)
  - `concurrency` default 2 (parallel segment uploads if desired)
- Retries with exponential backoff for `PUT`/`MKCOL` transient errors.
- If one entity/segment fails:
  - Log and continue; the blob remains pending and will be retried in next task run.

## Cron + Queue Wiring
- Cron:
  - Add `CronTypeColdBackup` with setting key `cron_cold_backup` (default `@every 6h`).
  - Cron handler checks `enabled` and enqueues a `cold_backup` task.
- Queue:
  - Introduce `ColdBackupTaskType = "cold_backup"`.
  - Implement as a resumable DB-backed task (so crashes don’t lose state) on a suitable queue (I/O intensive queue).

## Settings (Minimized Keys)
- Consolidate backup configuration into a single JSON-like setting `cold_backup_config` to reduce new keys:
  - `enabled`: boolean
  - `remote_root`: string (e.g., "/cloudreve-backups")
  - `encrypt_key`: string (32-byte secret; base64 or hex)
  - `webdav_url`: string (base URL to WebDAV root)
  - `webdav_username`: string
  - `webdav_password`: string
  - `webdav_headers`: map[string]string (optional)
  - `webdav_insecure_tls`: bool (default false)
  - `files_per_run`: int (default 500)
  - `bytes_per_run`: int64 bytes (default 21474836480)
  - `segment_size`: int64 bytes (default 1*1024*1024*1024)
  - `concurrency`: int (default 2)
  - `include_db`: bool (default true)
  - `db_mode`: enum {"sqlite","dump","skip"} (default "sqlite")
  - `next_to_upload_blob_id`: int (managed watermark)
- Separate cron key: `cron_cold_backup` under cron settings (existing provider supports per-cron keys).

## Task State and Reporting
- Public state recorded to Task:
  - `uploaded_files`: int
  - `uploaded_bytes`: int64
  - `remaining_files`: int
  - `remaining_bytes`: int64
  - `db_backup_done`: bool
  - `last_blob_id_processed`: int
- Progress:
  - Per-entity segment progress (optional), coarse-grained totals.

## Database Backup Details
- SQLite:
  - Read `DBFile` path from effective config (`-c conf.ini` is already resolved into `conf.ConfigProvider()`), stream encrypt, upload.
- Other DBs:
  - Future: invoke SQL dump for vendor and stream; for now respect `db_mode` == "skip" or log a warning.

## Error Handling and Observability
- Validate config on task start (credentials/URL present, key length).
- Log per-entity success/failure with correlation ID.
- Abort only on configuration errors; otherwise continue best-effort.

## Security Considerations
- Never log credentials or keys.
- Keep `webdav_*` credentials and `encrypt_key` only in settings store (KV/DB); suppress from APIs.
- AES-CTR requires unique IV per segment; derivation uses entityID + segment index to guarantee uniqueness.

## Implementation Plan (Phased)
1. Settings + Cron + Task Scaffolding
   - Add `CronTypeColdBackup` and default `cron_cold_backup`.
   - Add `cold_backup_config` JSON setting read/write helpers and validation.
   - Add queue task type `cold_backup` and register factory.
2. WebDAV Client (Go)
   - Minimal methods: recursive `MKCOL`, streaming `PUT`, optional `HEAD`.
   - Support basic auth, custom headers, TLS options; backoff on transient errors.
3. Crypto + Streaming
   - AES-CTR stream wrapper with HMAC-SHA256 based IV derivation.
   - Segmenter which produces encrypted segment readers over `EntitySource` by seeking.
4. Entity Selection + Watermark
   - Selector that paginates by `id >= watermark`, respecting `files_per_run` and `bytes_per_run`.
   - Persist `next_to_upload_blob_id` after each entity is fully uploaded.
5. Database Backup
   - SQLite path from `conf.ConfigProvider().Database().DBFile`; stream-encrypt and upload.
   - Log if non-sqlite and `db_mode=skip`.
6. Reporting + Tests
   - Public state, progress, and summary reporting.
   - Unit tests for IV derivation and segmentation; smoke test the WebDAV client against a local server.

## Operational Notes
- Configure a WebDAV endpoint (`webdav_url`, credentials). For TeraBox, you can run a local WebDAV proxy backed by a TeraBox drive and point `webdav_url` to it.
- Initial run may upload large volume; adjust schedule and limits as needed.
- Verify presence of backups via the WebDAV server/provider UI; files appear under `remote_root`.

## Future Work
- Restore flow: Download + decrypt segments, reassemble to original blob content; ensure entity-to-file re-linking using DB.
- WebDAV mirror over TeraBox: run a local WebDAV proxy backed by a TeraBox drive and point `webdav_url` to it.
- Alternate backup targets via WebDAV bridges.
- DB dumps for non-sqlite databases with proper credentials.
- Integrity manifest per blob (optional) to allow quick verification.


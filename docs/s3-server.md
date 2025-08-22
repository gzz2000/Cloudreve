S3 Server Design and Implementation Plan

Overview

- Goal: Expose a minimal S3-compatible API that lets third-party clients (e.g., rclone, awscli) browse and synchronize user files stored in Cloudreve, similar in spirit to our WebDAV server but speaking the S3 protocol.
- Non-goals (MVP): Multipart uploads, ACLs, versioning, tagging, CORS, server-side encryption, virtual-host style buckets. These can follow incrementally.
- Storage vs Server: This S3 server is an interoperability surface over Cloudreve’s DB-backed filesystem. It does not replace or interfere with storage policies (S3/COS/OSS/etc.) that back file entities.

Auth Model

- AccessKeyId: Use the login user’s account identifier for compatibility. Initially set to the user’s email address. If we later discover client compatibility issues, we can add per-user aliases and/or generated keys without breaking the model.
- SecretAccessKey: Use the corresponding WebDAV account’s password (random 32 chars) to distinguish different mounts for the same user.
- Why this works: S3 SigV4 uses AccessKeyId to identify the principal and the secret to validate the signature. We will:
  - Identify the user by AccessKeyId (email).
  - Identify the target WebDAV account by the requested bucket name (see Bucket Mapping below).
  - Validate the signature using the secret from that specific WebDAV account.
- Presigned URLs: Support SigV4 query auth with an allowed clock skew window (e.g., ±5 minutes) and expiration enforcement.
- Permissions: Reuse existing group permission `GroupPermissionWebDAV` for access gating. Enforce DAV account’s read-only option for write APIs.

Bucket and Object Mapping

- One bucket per WebDAV account for a user. ListBuckets returns all of the user’s DAV accounts as buckets.
- Bucket name: a DNS-safe slug of `DavAccount.Name`. We will require unique DAV account names per user for unambiguous routing. If duplicates exist, we will return 409 Conflict on management endpoints and reject ambiguous S3 requests in server path.
- Object key: path relative to the DAV account’s root `URI` (`cloudreve://my|share/...`).
- Resolution: `cloudreve://...` URI = `account.URI.JoinRaw(key)` followed by `FileManager.SharedAddressTranslation` to handle shares/symlinks.

API Surface (MVP)

- Service Metadata:
  - ListBuckets (GET /): Returns all DAV accounts as buckets for the authenticated user.
  - HeadBucket (HEAD /{bucket}): 200 if bucket exists for the user, otherwise 404.
- Objects:
  - ListObjectsV2 (GET /{bucket}): Support `prefix`, `delimiter`, `continuation-token`, `max-keys`. Emit `IsTruncated` and `NextContinuationToken`.
  - GetObject (GET /{bucket}/{key}): Range, ETag, Content-Type, Content-Length.
  - HeadObject (HEAD /{bucket}/{key}): Same headers as GetObject without body.
  - PutObject (PUT /{bucket}/{key}): Single-part overwrite. Creates parent folders as needed. Returns ETag on success.
  - DeleteObject (DELETE /{bucket}/{key}): Removes the file. Returns 204.
- Later (not MVP): CopyObject, Multipart Upload, Tags, ACLs, CORS, virtual-host style routing.

Protocol and Signature

- Implement AWS Signature V4:
  - Header-based: Authorization, SignedHeaders, X-Amz-Date, X-Amz-Content-Sha256 (support `UNSIGNED-PAYLOAD` in GET/HEAD; require hashed payload in PUT by default).
  - Query-based (presigned URL): X-Amz-Algorithm, X-Amz-Credential, X-Amz-Signature, X-Amz-SignedHeaders, X-Amz-Date, X-Amz-Expires.
  - Region: single configurable region (default `us-east-1`). Service = `s3`.
  - Clock skew: configurable tolerance (default 5 minutes).
  - Key selection: AccessKeyId → user; bucket → DAV account; secret = DAV account password.

Read/Write Execution

- Listing:
  - Buckets: enumerate DAV accounts for user.
  - Objects: map to List or Walk:
    - If `delimiter` is set, produce CommonPrefixes and object Contents accordingly.
    - Use cursor pagination to back `NextContinuationToken`.
- Read:
  - Resolve target via `FileManager.GetEntitySource` and stream through EntitySource.Serve. Set ETag from primary entity ID, Content-Type via mime detector.
  - No external redirect for S3 (serve/proxy internally to match S3 semantics).
- Write:
  - PutObject → `FileManager.Update` with overwrite mode. Enforce read-only at middleware.
  - DeleteObject → `FileManager.Delete`.
  - CopyObject (later) → `FileManager.MoveOrCopy` with `isCopy=true` and `x-amz-copy-source` parsing.

Permissions and Read-only

- Access gate: user must have `GroupPermissionWebDAV`.
- Read-only DAV accounts: block PUT/DELETE (and later COPY, multipart, PROPPATCH-equivalent) with AccessDenied.
- Admin bypass remains unchanged; we keep parity with WebDAV authorization decisions where applicable.

Routing and Middleware

- Path-style routing under `/s3` (MVP):
  - `GET    /s3/` → ListBuckets
  - `HEAD   /s3/:bucket` → HeadBucket
  - `GET    /s3/:bucket` → ListObjectsV2
  - `GET|HEAD /s3/:bucket/*key` → Get/HeadObject
  - `PUT    /s3/:bucket/*key` → PutObject
  - `DELETE /s3/:bucket/*key` → DeleteObject
- Middleware `S3Auth`:
  - Parse SigV4 header or presigned query.
  - Identify user by AccessKeyId (email), ensure active.
  - For bucket-scoped operations, resolve bucket → DAV account; choose secret = DAV account password; verify signature.
  - For ListBuckets (no bucket), accept any DAV account’s secret for signature validation by iterating accounts or allow an optimization path (e.g., special credential scope). We prefer iteration given typical small account counts.
  - Enforce permissions and read-only policy based on chosen DAV account.
  - Inject user and DAV account into context for handlers.

Error Mapping

- Map internal errors to S3 XML errors:
  - 404/NotFound → NoSuchBucket / NoSuchKey
  - Permission → AccessDenied
  - SigV4 → SignatureDoesNotMatch / InvalidRequest / RequestTimeTooSkewed / InvalidArgument
  - Unimplemented → NotImplemented
  - Conflicts (locks) → 423 map to AccessDenied or PreconditionFailed where appropriate

Data Model and Reuse

- Reuse existing `ent.DavAccount` and its password as the secret.
- Reuse current filesystem (`dbfs`) and `FileManager` flows for read/write, including upload session handling and entity creation.
- Management API: continue using `/api/v3/devices/dav` to create/update/delete accounts. We will optionally expose derived AccessKeyId (email) in list responses as a convenience hint.

Configuration

- New settings (with sane defaults):
  - `S3.Region` (default `us-east-1`)
  - `S3.ClockSkewTolerance` (default 5m)
  - `S3.RoutePrefix` (default `/s3`)

Phased Delivery

1) Foundations
   - Create `pkg/s3server` with request parsing, SigV4, XML serializers, and bucket/key → URI mapping.
   - Add `middleware.S3Auth()` and wire `/s3` routes.

2) Read APIs
   - Implement ListBuckets, HeadBucket, ListObjectsV2, GetObject, HeadObject.

3) Write APIs
   - Implement PutObject, DeleteObject.
   - (Optional) CopyObject using `x-amz-copy-source`.

4) Robustness
   - Error XML formatting, content headers, ETag generation parity with WebDAV.
   - Enforce read-only DAV options and group permissions.

5) Tests and Docs
   - Unit tests: SigV4 (header + presign), bucket/key mapping, permission checks, ListObjectsV2 pagination.
   - Manual validation with rclone and awscli against a local node and a simple policy (local storage).
   - Update user docs with configuration and usage examples.

Open Questions / Future Work

- Virtual-host style buckets (vhost) based on `Host` header.
- Multipart Upload mapping to `fs.UploadSession` for large files.
- Server-side encryption and per-bucket policies.
- Bucket naming policy and uniqueness enforcement UX on DAV account creation.
- Optional second factor for S3 access (per-account token constraints).


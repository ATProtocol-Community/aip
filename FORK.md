# AIP — OIDC `picture` from the atproto profile avatar (feature branch)

Standalone feature on top of upstream `v2.2.3` (this repo's `main`): AIP
mirrors the user's atproto profile avatar (`app.bsky.actor.profile` →
`avatar` blob) into an S3-compatible store and emits the standard OIDC
`picture` claim. Backlog: bringyourowncomputer/ovhproxmox **OVHP-117**.

## What it changes

- **userinfo** (profile scope + atproto session):
  1. `com.atproto.repo.getRecord` on `app.bsky.actor.profile` (rkey `self`) of
     the user's PDS → read the `avatar` blob ref (CID + mimeType);
  2. `com.atproto.sync.getBlob` — an **unauthenticated GET first** (profile
     blobs are public; hosted PDSs like bluesky.network reject DPoP-signed
     blob fetches with 401), with a DPoP-signed fallback for private blobs;
  3. upload the bytes to the configured **S3-compatible store keyed by the
     blob CID** (idempotent; overwrite = identical bytes);
  4. emit `picture` = `{EXTERNAL_BASE}/oauth/avatar/{cid}`.
- **`GET /oauth/avatar/{cid}`** streams the stored object back through AIP
  (the store has no anonymous reads) with the blob mimeType and an immutable
  cache header.
- **Fail-open everywhere:** no avatar → no `picture` claim; any fetch/storage
  error logs a warning and omits the claim; missing storage config disables
  the feature entirely.

## Env

Read from the process env (not `Config`), so the feature self-disables when
unconfigured:

```
AVATAR_STORAGE_ENDPOINT=http://10.0.0.11:3900   # cluster Garage
AVATAR_STORAGE_REGION=garage
AVATAR_STORAGE_BUCKET=aip-avatars
AVATAR_STORAGE_ACCESS_KEY=…
AVATAR_STORAGE_SECRET_KEY=…
```

## Scope note

Only the avatar/picture feature is included here. The BYOC deployment
additionally carries other fork work (at_hash/c_hash truncation, the People
network allow-list gate, RFC 7662 introspection, app-password userinfo email)
— none of that is part of this branch.
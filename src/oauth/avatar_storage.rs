//! Avatar blob storage — cluster Garage (S3-compatible), env-configured.
//!
//! AIP mirrors the user's atproto profile avatar (`app.bsky.actor.profile`
//! → `avatar` blob) into an S3-compatible store (Garage, `aip-avatars`
//! bucket) at userinfo time and exposes it as the standard OIDC `picture`
//! claim (OVHP-117). Garage has no anonymous reads, so AIP streams the
//! object itself at `/oauth/avatar/{cid}`.
//!
//! Config is read from the process env (the `aip.env` the unit loads) —
//! deliberately NOT through `Config`, so the avatar feature stays
//! self-contained (no claim when the store isn't configured):
//!
//! ```text
//! AVATAR_STORAGE_ENDPOINT=http://10.0.0.11:3900
//! AVATAR_STORAGE_REGION=garage
//! AVATAR_STORAGE_BUCKET=aip-avatars
//! AVATAR_STORAGE_ACCESS_KEY=…
//! AVATAR_STORAGE_SECRET_KEY=…
//! ```
//!
//! Fail-open by design: every fetch/storage error just omits the claim.

use std::env;
use std::sync::Arc;

use bytes::Bytes;
use s3::creds::Credentials;
use s3::{Bucket, Region};

/// S3-compatible avatar storage handle (Garage, path-style).
#[derive(Clone)]
pub struct AvatarStorage {
    bucket: Arc<Bucket>,
}

impl AvatarStorage {
    /// Build storage from the environment; `None` when not fully configured.
    pub fn from_env() -> Option<Self> {
        let endpoint = env::var("AVATAR_STORAGE_ENDPOINT").ok()?;
        let region = env::var("AVATAR_STORAGE_REGION")
            .unwrap_or_else(|_| "garage".to_string());
        let bucket_name = env::var("AVATAR_STORAGE_BUCKET").ok()?;
        let access_key = env::var("AVATAR_STORAGE_ACCESS_KEY").ok()?;
        let secret_key = env::var("AVATAR_STORAGE_SECRET_KEY").ok()?;

        if endpoint.is_empty()
            || bucket_name.is_empty()
            || access_key.is_empty()
            || secret_key.is_empty()
        {
            return None;
        }

        let credentials = match Credentials::new(
            Some(&access_key),
            Some(&secret_key),
            None,
            None,
            None,
        ) {
            Ok(credentials) => credentials,
            Err(e) => {
                tracing::warn!(error = %e, "avatar storage: credentials failed to parse");
                return None;
            }
        };

        let mut bucket = match Bucket::new(
            &bucket_name,
            Region::Custom { region, endpoint },
            credentials,
        ) {
            Ok(bucket) => bucket,
            Err(e) => {
                tracing::warn!(error = %e, "avatar storage: bucket init failed");
                return None;
            }
        };
        // Garage is path-style S3.
        bucket.set_path_style();

        Some(Self {
            bucket: Arc::new(bucket),
        })
    }

    /// Upload (idempotent by design — objects are keyed by their atproto blob
    /// CID, so re-uploading the same avatar overwrites with identical bytes).
    pub async fn put(&self, cid: &str, bytes: &[u8], content_type: &str) -> Result<(), String> {
        let response = self
            .bucket
            .put_object_with_content_type(cid, bytes, content_type)
            .await
            .map_err(|e| format!("avatar storage put failed: {}", e))?;
        if !(200..300).contains(&response.status_code()) {
            return Err(format!(
                "avatar storage put -> HTTP {}",
                response.status_code()
            ));
        }
        Ok(())
    }

    /// Fetch an object; returns `(bytes, content_type)`. Non-2xx (including
    /// Garage XML error bodies, which rust-s3 returns as `Ok`) maps to `Err`
    /// so the caller can 404 instead of streaming an error document.
    pub async fn get(&self, cid: &str) -> Result<(Bytes, String), String> {
        let data = self
            .bucket
            .get_object(cid)
            .await
            .map_err(|e| format!("avatar storage get failed: {}", e))?;
        if !(200..300).contains(&data.status_code()) {
            return Err(format!(
                "avatar storage get -> HTTP {}",
                data.status_code()
            ));
        }
        let mime = data
            .headers()
            .get("content-type")
            .cloned()
            .unwrap_or_else(|| "application/octet-stream".to_string());
        Ok((data.bytes().clone(), mime))
    }
}

/// The claim URL AIP serves the avatar at (browser-friendly, AIP-hosted).
pub fn picture_url(cid: &str) -> Option<String> {
    let external_base = env::var("EXTERNAL_BASE").ok()?;
    Some(format!("{}/oauth/avatar/{}", external_base, cid))
}
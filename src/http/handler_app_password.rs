//! Handles POST /api/atprotocol/app-password - Creates or updates app passwords for authenticated users

use axum::{
    extract::{Form, State},
    http::StatusCode,
    response::Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::context::AppState;
use super::utils_error::{
    StorageOptionExt, StorageResultExt, bad_request, not_found, server_error, unauthorized,
};
use crate::{
    http::middleware_auth::ExtractedAuth, oauth::utils_app_password::create_app_password_session,
    storage::traits::AppPassword,
};

/// App password form submission
#[derive(Debug, Deserialize)]
pub struct AppPasswordForm {
    /// The app password to store
    #[serde(rename = "app-password")]
    pub app_password: String,
}

/// App password response
#[derive(Debug, Serialize)]
pub struct AppPasswordResponse {
    /// OAuth client ID
    pub client_id: String,
    /// ATProtocol DID
    pub did: String,
    /// Success message
    pub message: String,
    /// When the password was created/updated
    pub timestamp: String,
}

/// Check if app password exists
/// GET /api/atprotocol/app-password
///
/// Returns 204 No Content if an app password exists for the authenticated user
/// and the OAuth client, or 404 Not Found if it doesn't exist.
pub async fn get_app_password_handler(
    State(state): State<AppState>,
    ExtractedAuth(access_token): ExtractedAuth,
) -> Result<StatusCode, (StatusCode, Json<Value>)> {
    // Extract DID from the access token
    let did = access_token
        .user_id
        .as_ref()
        .ok_or_else(|| unauthorized("Token missing user_id (DID)"))?;

    // Check if app password exists
    let existing = state
        .oauth_storage
        .get_app_password(&access_token.client_id, did)
        .await
        .to_http_error("Failed to check app password")?;

    if existing.is_some() {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(not_found("App password for this client and user"))
    }
}

/// Create or update app password
/// POST /api/atprotocol/app-password
///
/// Accepts a form submission with an "app-password" field and stores it
/// for the authenticated user. If a password already exists for this
/// client/user combination, it will be replaced.
pub async fn create_app_password_handler(
    State(state): State<AppState>,
    ExtractedAuth(access_token): ExtractedAuth,
    Form(form): Form<AppPasswordForm>,
) -> Result<Json<AppPasswordResponse>, (StatusCode, Json<Value>)> {
    // Extract DID from the access token
    let did = access_token
        .user_id
        .as_ref()
        .ok_or_else(|| unauthorized("Token missing user_id (DID)"))?;

    // Validate app password is not empty
    if form.app_password.trim().is_empty() {
        return Err(bad_request("App password cannot be empty"));
    }

    // Store the app password as clear text
    let app_password = form.app_password;

    let now = Utc::now();

    // Check if app password already exists
    let existing = state
        .oauth_storage
        .get_app_password(&access_token.client_id, did)
        .await
        .to_http_error("Failed to check existing password")?;

    let is_update = existing.is_some();

    // If this was an update, delete all associated sessions
    if is_update {
        state
            .oauth_storage
            .delete_app_password_sessions(&access_token.client_id, did)
            .await
            .to_http_error("Failed to delete existing sessions")?;
    }

    // Create app password entry
    let app_password_entry = AppPassword {
        client_id: access_token.client_id.clone(),
        did: did.clone(),
        app_password: app_password.clone(),
        created_at: now,
        updated_at: now,
    };

    // Store the app password
    state
        .oauth_storage
        .store_app_password(&app_password_entry)
        .await
        .to_http_error("Failed to store app password")?;

    // Get the DID document to extract PDS endpoint for session creation
    let document = state
        .document_storage
        .get_document_by_did(did)
        .await
        .map_err(|e| server_error(format!("Failed to get DID document: {}", e)))?
        .require("DID document")?;

    // Get PDS endpoint from document
    let pds_endpoints: Vec<String> = document
        .pds_endpoints()
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    let pds_endpoint = pds_endpoints
        .first()
        .ok_or_else(|| bad_request("No PDS endpoint found in DID document"))?;

    // Create app-password session before storing the password
    create_app_password_session(
        &state,
        &access_token.client_id,
        did,
        did, // Use DID as identifier for authentication
        &app_password,
        pds_endpoint,
    )
    .await
    .map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "authentication_failed",
                "error_description": format!("Failed to create app-password session: {}", e)
            })),
        )
    })?;

    let response = AppPasswordResponse {
        client_id: access_token.client_id,
        did: did.clone(),
        message: if is_update {
            "App password updated successfully".to_string()
        } else {
            "App password created successfully".to_string()
        },
        timestamp: now.to_rfc3339(),
    };

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_password_form_deserialization() {
        let json = r#"{"app-password": "test-password-123"}"#;
        let form: AppPasswordForm = serde_json::from_str(json).unwrap();
        assert_eq!(form.app_password, "test-password-123");
    }

    #[test]
    fn test_app_password_response_serialization() {
        let response = AppPasswordResponse {
            client_id: "test-client".to_string(),
            did: "did:plc:test123".to_string(),
            message: "App password created successfully".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("test-client"));
        assert!(json.contains("did:plc:test123"));
        assert!(json.contains("App password created successfully"));
    }
}

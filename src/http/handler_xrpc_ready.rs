//! Handles XRPC requests to GET /xrpc/tools.graze.aip.ready

use atproto_xrpcs::authorization::Authorization;
use axum::http::StatusCode;
use axum::response::Json;
use serde_json::{Value, json};

/// Simple readiness check endpoint that requires authentication
pub async fn xrpc_ready_handler(
    authorization: Option<Authorization>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Require authentication
    if authorization.is_none() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "AuthenticationRequired",
                "message": "Authentication required"
            })),
        ));
    }

    Ok(Json(json!({})))
}

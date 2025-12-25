//! Handles POST /oauth/authorize/app-password - App-password login for OAuth flow

use axum::{
    Form,
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_template::TemplateEngine;
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;

use super::context::AppState;
use super::utils_oauth::normalize_login_hint;
use crate::oauth::{
    auth_server::AuthorizationServer,
    types::{AuthorizationRequest, ResponseType},
    utils_app_password::create_app_password_session,
};
use crate::storage::traits::AppPassword;

/// Form data for app-password login
#[derive(Debug, Deserialize)]
pub struct AppPasswordLoginForm {
    /// Handle or DID
    pub login_hint: String,
    /// App password
    pub app_password: String,
    /// OAuth parameters (hidden fields)
    pub client_id: String,
    pub redirect_uri: Option<String>,
    pub response_type: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub request_uri: Option<String>,
    pub nonce: Option<String>,
    pub prompt: Option<String>,
}

/// POST /oauth/authorize/app-password
/// Handles app-password login form submission within OAuth flow
pub async fn handle_app_password_login(
    State(state): State<AppState>,
    Form(form): Form<AppPasswordLoginForm>,
) -> Response {
    // 1. Validate login_hint
    let normalized_hint = match normalize_login_hint(&form.login_hint) {
        Ok(h) => h,
        Err(_) => {
            return render_error("Invalid handle or DID format", &form, &state);
        }
    };

    // 2. Resolve identity to get DID and PDS endpoint
    let document = match state.identity_resolver.resolve(&normalized_hint).await {
        Ok(doc) => doc,
        Err(_) => {
            return render_error("Could not find that identity", &form, &state);
        }
    };

    // Store document for later use
    let _ = state.document_storage.store_document(document.clone()).await;

    let did = document.id.clone();
    let pds_endpoints: Vec<String> = document
        .pds_endpoints()
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    let pds_endpoint = match pds_endpoints.first() {
        Some(ep) => ep.clone(),
        None => {
            return render_error("Could not determine PDS for this identity", &form, &state);
        }
    };

    // 3. Validate required OAuth parameters
    let redirect_uri = match &form.redirect_uri {
        Some(uri) if !uri.is_empty() => uri.clone(),
        _ => {
            return render_error("Missing required redirect_uri parameter", &form, &state);
        }
    };

    // 4. Store app-password for future re-authentication
    let now = Utc::now();
    let app_password_entry = AppPassword {
        client_id: form.client_id.clone(),
        did: did.clone(),
        app_password: form.app_password.clone(),
        created_at: now,
        updated_at: now,
    };

    if let Err(e) = state
        .oauth_storage
        .store_app_password(&app_password_entry)
        .await
    {
        tracing::error!("Failed to store app password: {}", e);
        return render_error("Failed to store credentials", &form, &state);
    }

    // 5. Authenticate with PDS and create app-password session
    match create_app_password_session(
        &state,
        &form.client_id,
        &did,
        &normalized_hint,
        &form.app_password,
        &pds_endpoint,
    )
    .await
    {
        Ok(_session) => {
            // Session created successfully
        }
        Err(e) => {
            // Authentication failed - clean up stored app password
            let _ = state
                .oauth_storage
                .delete_app_password(&form.client_id, &did)
                .await;

            let error_msg = if e.to_string().contains("401")
                || e.to_string().to_lowercase().contains("unauthorized")
            {
                "Invalid app password"
            } else {
                "Authentication failed. Please check your credentials."
            };
            return render_error(error_msg, &form, &state);
        }
    }

    // 6. Build AuthorizationRequest from form data
    let auth_request = AuthorizationRequest {
        response_type: vec![ResponseType::Code],
        client_id: form.client_id.clone(),
        redirect_uri: redirect_uri.clone(),
        scope: form.scope.clone(),
        state: form.state.clone(),
        code_challenge: form.code_challenge.clone(),
        code_challenge_method: form.code_challenge_method.clone(),
        login_hint: Some(normalized_hint),
        nonce: form.nonce.clone(),
    };

    // 7. Create authorization server and authorize
    let auth_server = AuthorizationServer::new(
        state.oauth_storage.clone(),
        state.config.external_base.clone(),
    );

    // session_id is None because AppPasswordSession is looked up by (client_id, did)
    match auth_server.authorize(auth_request, did.clone(), None).await {
        Ok(crate::oauth::auth_server::AuthorizeResponse::Redirect(url)) => {
            Redirect::to(&url).into_response()
        }
        Ok(crate::oauth::auth_server::AuthorizeResponse::Error { description, .. }) => {
            render_error(&description, &form, &state)
        }
        Err(e) => render_error(&e.to_string(), &form, &state),
    }
}

/// Build a query string from a HashMap of parameters
fn build_query_string(params: &HashMap<String, String>) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params.iter())
        .finish()
}

/// Render the app-password login form with an error message
fn render_error(error: &str, form: &AppPasswordLoginForm, state: &AppState) -> Response {
    // Reconstruct query_params for hidden fields
    let mut query_params = HashMap::new();
    query_params.insert("client_id".to_string(), form.client_id.clone());
    if let Some(ref redirect_uri) = form.redirect_uri {
        query_params.insert("redirect_uri".to_string(), redirect_uri.clone());
    }
    if let Some(ref response_type) = form.response_type {
        query_params.insert("response_type".to_string(), response_type.clone());
    }
    if let Some(ref scope) = form.scope {
        query_params.insert("scope".to_string(), scope.clone());
    }
    if let Some(ref state_param) = form.state {
        query_params.insert("state".to_string(), state_param.clone());
    }
    if let Some(ref code_challenge) = form.code_challenge {
        query_params.insert("code_challenge".to_string(), code_challenge.clone());
    }
    if let Some(ref code_challenge_method) = form.code_challenge_method {
        query_params.insert(
            "code_challenge_method".to_string(),
            code_challenge_method.clone(),
        );
    }
    if let Some(ref request_uri) = form.request_uri {
        query_params.insert("request_uri".to_string(), request_uri.clone());
    }
    if let Some(ref nonce) = form.nonce {
        query_params.insert("nonce".to_string(), nonce.clone());
    }
    if let Some(ref prompt) = form.prompt {
        query_params.insert("prompt".to_string(), prompt.clone());
    }

    // Build alternate auth URL for switching to handle-based OAuth
    let mut alt_query_params = query_params.clone();
    alt_query_params.remove("prompt"); // Remove prompt to go to handle form
    let alt_query_string = build_query_string(&alt_query_params);
    let alt_auth_url = format!("/oauth/authorize?{}", alt_query_string);
    let alt_auth_label = "sign in with ATProtocol OAuth".to_string();

    let template_data = json!({
        "title": "AIP - ATProtocol Identity Provider",
        "version": state.config.version,
        "query_params": query_params,
        "client_name": form.client_id,
        "scope": form.scope,
        "redirect_uri": form.redirect_uri,
        "error": error,
        "login_hint_value": form.login_hint,
        "alt_auth_url": alt_auth_url,
        "alt_auth_label": alt_auth_label,
    });

    match state.template_env.render("login_app_password.html", &template_data) {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!("Template rendering failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_form_deserialization() {
        let json = r#"{
            "login_hint": "user.bsky.social",
            "app_password": "xxxx-xxxx-xxxx-xxxx",
            "client_id": "https://example.com/client",
            "redirect_uri": "https://example.com/callback",
            "response_type": "code",
            "scope": "atproto",
            "state": "test-state",
            "code_challenge": "challenge123",
            "code_challenge_method": "S256",
            "nonce": "nonce123"
        }"#;

        let form: AppPasswordLoginForm = serde_json::from_str(json).unwrap();
        assert_eq!(form.login_hint, "user.bsky.social");
        assert_eq!(form.app_password, "xxxx-xxxx-xxxx-xxxx");
        assert_eq!(form.client_id, "https://example.com/client");
        assert_eq!(form.redirect_uri, Some("https://example.com/callback".to_string()));
        assert_eq!(form.response_type, Some("code".to_string()));
        assert_eq!(form.scope, Some("atproto".to_string()));
        assert_eq!(form.state, Some("test-state".to_string()));
        assert_eq!(form.code_challenge, Some("challenge123".to_string()));
        assert_eq!(form.code_challenge_method, Some("S256".to_string()));
        assert_eq!(form.nonce, Some("nonce123".to_string()));
    }

    #[test]
    fn test_form_deserialization_minimal() {
        let json = r#"{
            "login_hint": "user.bsky.social",
            "app_password": "xxxx-xxxx-xxxx-xxxx",
            "client_id": "https://example.com/client"
        }"#;

        let form: AppPasswordLoginForm = serde_json::from_str(json).unwrap();
        assert_eq!(form.login_hint, "user.bsky.social");
        assert_eq!(form.app_password, "xxxx-xxxx-xxxx-xxxx");
        assert_eq!(form.client_id, "https://example.com/client");
        assert!(form.redirect_uri.is_none());
        assert!(form.response_type.is_none());
        assert!(form.scope.is_none());
        assert!(form.state.is_none());
    }
}

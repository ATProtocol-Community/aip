//! Handles POST /oauth/introspect - RFC 7662 token introspection endpoint.
//!
//! The introspection endpoint lets a resource server validate an access token
//! and obtain its metadata (subject, client, scope, expiration). Access tokens
//! are opaque bearer tokens stored in the OAuth storage, so the token store is
//! the authoritative source of truth.

use axum::{
    Form, Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::context::AppState;
use crate::oauth::auth_server::{TokenForm, extract_client_auth, validate_client_assertion};
use crate::oauth::types::ClientAuthMethod;

/// Form data for the introspection endpoint (RFC 7662 Section 2.1)
#[derive(Debug, Deserialize)]
pub struct IntrospectForm {
    /// The token to introspect (required)
    pub token: String,
    /// Optional token type hint ("access_token" or "refresh_token")
    ///
    /// AIP only issues access tokens; the hint is accepted for compatibility
    /// but does not change lookup behavior (RFC 7662 Section 2.1).
    pub token_type_hint: Option<String>,
    /// Client authentication via form parameters (client_secret_post)
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    /// JWT client assertion for private_key_jwt authentication (RFC 7523)
    pub client_assertion: Option<String>,
    pub client_assertion_type: Option<String>,
}

fn error_response(
    status: StatusCode,
    error: &str,
    description: &str,
) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({
            "error": error,
            "error_description": description
        })),
    )
}

fn invalid_client(description: &str) -> (StatusCode, Json<Value>) {
    error_response(StatusCode::UNAUTHORIZED, "invalid_client", description)
}

fn invalid_request(description: &str) -> (StatusCode, Json<Value>) {
    error_response(StatusCode::BAD_REQUEST, "invalid_request", description)
}

fn server_error(description: &str) -> (StatusCode, Json<Value>) {
    error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error", description)
}

/// Handle RFC 7662 token introspection requests
/// POST /oauth/introspect
pub async fn handle_introspect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<IntrospectForm>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if form.token.is_empty() {
        return Err(invalid_request("Missing token parameter"));
    }

    // Mirror the token endpoint's client authentication (HTTP Basic or form),
    // reusing the same extraction so introspection behaves identically.
    let token_form = TokenForm {
        grant_type: String::new(),
        code: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: None,
        device_code: None,
        client_id: form.client_id.clone(),
        client_secret: form.client_secret.clone(),
        scope: None,
        client_assertion: form.client_assertion.clone(),
        client_assertion_type: form.client_assertion_type.clone(),
    };
    let client_auth = match extract_client_auth(&headers, &token_form) {
        Some(auth) => auth,
        None => return Err(invalid_client("Client authentication required")),
    };

    // The introspection endpoint requires an authenticated confidential client
    // (RFC 7662 Section 2.1).
    let client = state
        .oauth_storage
        .get_client(&client_auth.client_id)
        .await
        .map_err(|e| server_error(&e.to_string()))?
        .ok_or_else(|| invalid_client("Unknown client"))?;

    if client.token_endpoint_auth_method == ClientAuthMethod::None {
        return Err(invalid_client(
            "The introspection endpoint requires a confidential client",
        ));
    }

    // Authenticate the client, mirroring the token endpoint checks.
    match &client.token_endpoint_auth_method {
        ClientAuthMethod::ClientSecretBasic | ClientAuthMethod::ClientSecretPost => {
            let provided_secret = client_auth
                .client_secret
                .as_deref()
                .ok_or_else(|| invalid_client("Missing client secret"))?;
            let expected_secret = client
                .client_secret
                .as_deref()
                .ok_or_else(|| invalid_client("Client has no secret configured"))?;
            if provided_secret != expected_secret {
                return Err(invalid_client("Invalid client secret"));
            }
        }
        ClientAuthMethod::PrivateKeyJwt => {
            let assertion = client_auth
                .client_assertion
                .as_deref()
                .ok_or_else(|| invalid_client("Missing client_assertion"))?;
            let introspection_endpoint = format!("{}/oauth/introspect", state.config.external_base);
            match validate_client_assertion(assertion, &client, &introspection_endpoint, None) {
                Ok(validated_client_id) if validated_client_id == client.client_id => {}
                Ok(_) => {
                    return Err(invalid_client(
                        "JWT client_id does not match expected client",
                    ));
                }
                Err(_) => return Err(invalid_client("Invalid client assertion")),
            }
        }
        ClientAuthMethod::None => unreachable!("public clients rejected above"),
    }

    // Look up the token. Missing or expired tokens are inactive
    // (RFC 7662 Section 2.2); storage errors also yield an inactive response
    // rather than leaking internal state.
    let access_token = match state.oauth_storage.get_token(&form.token).await {
        Ok(Some(token)) => token,
        Ok(None) => return Ok(Json(json!({ "active": false }))),
        Err(e) => {
            tracing::error!(
                error = %e,
                token = %form.token,
                "Token lookup failed during introspection"
            );
            return Ok(Json(json!({ "active": false })));
        }
    };

    // Defensive expiry check: storage layers normally filter expired tokens,
    // but an expired token must never be reported active.
    if access_token.expires_at <= chrono::Utc::now() {
        return Ok(Json(json!({ "active": false })));
    }

    let mut response = Map::new();
    response.insert("active".to_string(), json!(true));
    response.insert("iss".to_string(), json!(state.config.external_base));
    // `sub` is the user's atproto DID; client-credentials tokens have no user.
    if let Some(user_id) = &access_token.user_id {
        response.insert("sub".to_string(), json!(user_id));
    }
    response.insert("client_id".to_string(), json!(access_token.client_id));
    // The audience claim key resource servers (e.g. django-lasuite) read.
    response.insert("aud".to_string(), json!(access_token.client_id));
    if let Some(scope) = &access_token.scope {
        response.insert("scope".to_string(), json!(scope));
    }
    response.insert(
        "token_type".to_string(),
        json!(format!("{:?}", access_token.token_type)),
    );
    response.insert("iat".to_string(), json!(access_token.created_at.timestamp()));
    response.insert("exp".to_string(), json!(access_token.expires_at.timestamp()));

    tracing::debug!(
        token = %form.token,
        token_type_hint = ?form.token_type_hint,
        client_id = %access_token.client_id,
        "Token introspection successful"
    );

    Ok(Json(Value::Object(response)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::DPoPNonceGenerator;
    use crate::oauth::types::{AccessToken, ClientType, OAuthClient, TokenType};
    use crate::storage::SimpleKeyProvider;
    use crate::storage::inmemory::MemoryOAuthStorage;
    use atproto_identity::{resolve::HickoryDnsResolver, storage_lru::LruDidDocumentStorage};
    use atproto_oauth::storage_lru::LruOAuthRequestStorage;
    use axum::http::header;
    use base64::{Engine, prelude::*};
    use chrono::{Duration, Utc};
    use std::{num::NonZeroUsize, sync::Arc};

    fn create_test_app_state() -> AppState {
        let oauth_storage = Arc::new(MemoryOAuthStorage::new());

        let http_client = reqwest::Client::new();
        let dns_nameservers = vec![];
        let dns_resolver = Arc::new(HickoryDnsResolver::create_resolver(&dns_nameservers));
        let identity_resolver = atproto_identity::resolve::SharedIdentityResolver(Arc::new(
            atproto_identity::resolve::InnerIdentityResolver {
                http_client: http_client.clone(),
                dns_resolver,
                plc_hostname: "plc.directory".to_string(),
            },
        ));

        let key_provider = Arc::new(SimpleKeyProvider::new());
        let oauth_request_storage =
            Arc::new(LruOAuthRequestStorage::new(NonZeroUsize::new(256).unwrap()));
        let document_storage =
            Arc::new(LruDidDocumentStorage::new(NonZeroUsize::new(100).unwrap()));

        #[cfg(feature = "reload")]
        let template_env = {
            use minijinja_autoreload::AutoReloader;
            axum_template::engine::Engine::new(AutoReloader::new(|_| {
                Ok(minijinja::Environment::new())
            }))
        };

        #[cfg(not(feature = "reload"))]
        let template_env = axum_template::engine::Engine::new(minijinja::Environment::new());

        let config = Arc::new(crate::config::Config {
            version: "test".to_string(),
            http_port: "3000".to_string().try_into().unwrap(),
            http_static_path: "static".to_string(),
            http_templates_path: "templates".to_string(),
            external_base: "https://login.example.com".to_string(),
            certificate_bundles: "".to_string().try_into().unwrap(),
            user_agent: "test-user-agent".to_string(),
            plc_hostname: "plc.directory".to_string(),
            dns_nameservers: "".to_string().try_into().unwrap(),
            http_client_timeout: "10s".to_string().try_into().unwrap(),
            atproto_oauth_signing_keys: Default::default(),
            oauth_signing_keys: Default::default(),
            oauth_supported_scopes: crate::config::OAuthSupportedScopes::try_from(
                "atproto transition:generic transition:email".to_string(),
            )
            .unwrap(),
            dpop_nonce_seed: "seed".to_string(),
            storage_backend: "memory".to_string(),
            database_url: None,
            redis_url: None,
            enable_client_api: false,
            client_default_access_token_expiration: "1d".to_string().try_into().unwrap(),
            client_default_refresh_token_expiration: "14d".to_string().try_into().unwrap(),
            admin_dids: "".to_string().try_into().unwrap(),
            client_default_redirect_exact: "true".to_string().try_into().unwrap(),
            atproto_client_name: "AIP OAuth Server".to_string().try_into().unwrap(),
            atproto_client_logo: None::<String>.try_into().unwrap(),
            atproto_client_tos: None::<String>.try_into().unwrap(),
            atproto_client_policy: None::<String>.try_into().unwrap(),
            internal_device_auth_client_id: "aip-internal-device-auth"
                .to_string()
                .try_into()
                .unwrap(),
            access_policy_endpoint: None,
            access_policy_decisions_endpoint: None,
            access_policy_auth_token: None,
            access_policy_mode: "log".to_string(),
            access_policy_fail_open: true,
        });

        let atp_session_storage = Arc::new(
            crate::oauth::UnifiedAtpOAuthSessionStorageAdapter::new(oauth_storage.clone()),
        );
        let authorization_request_storage = Arc::new(
            crate::oauth::UnifiedAuthorizationRequestStorageAdapter::new(oauth_storage.clone()),
        );
        let client_registration_service = Arc::new(crate::oauth::ClientRegistrationService::new(
            oauth_storage.clone(),
            chrono::Duration::days(1),
            chrono::Duration::days(14),
            true,
        ));

        AppState {
            http_client: http_client.clone(),
            config: config.clone(),
            template_env,
            identity_resolver,
            key_provider,
            oauth_request_storage,
            document_storage,
            oauth_storage,
            client_registration_service,
            atp_session_storage,
            authorization_request_storage,
            atproto_oauth_signing_keys: vec![],
            dpop_nonce_provider: Arc::new(DPoPNonceGenerator::new(
                config.dpop_nonce_seed.clone(),
                1,
            )),
        }
    }

    fn test_client(client_id: &str, secret: Option<&str>) -> OAuthClient {
        let now = Utc::now();
        OAuthClient {
            client_id: client_id.to_string(),
            client_secret: secret.map(|s| s.to_string()),
            client_name: Some("Test Client".to_string()),
            redirect_uris: vec!["https://client.example.com/callback".to_string()],
            grant_types: vec![],
            response_types: vec![],
            scope: None,
            token_endpoint_auth_method: ClientAuthMethod::ClientSecretBasic,
            client_type: ClientType::Confidential,
            application_type: None,
            software_id: None,
            software_version: None,
            created_at: now,
            updated_at: now,
            metadata: serde_json::Value::Null,
            access_token_expiration: Duration::hours(1),
            refresh_token_expiration: Duration::days(14),
            require_redirect_exact: true,
            registration_access_token: None,
            jwks: None,
        }
    }

    fn test_access_token(token: &str, user_id: Option<&str>) -> AccessToken {
        let now = Utc::now();
        AccessToken {
            token: token.to_string(),
            token_type: TokenType::Bearer,
            client_id: "test-client".to_string(),
            user_id: user_id.map(|s| s.to_string()),
            session_id: None,
            session_iteration: None,
            scope: Some("openid profile".to_string()),
            nonce: None,
            created_at: now,
            expires_at: now + Duration::hours(1),
            dpop_jkt: None,
        }
    }

    fn basic_auth_headers(client_id: &str, secret: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let credentials = BASE64_STANDARD.encode(format!("{}:{}", client_id, secret));
        headers.insert(
            header::AUTHORIZATION,
            format!("Basic {}", credentials).parse().unwrap(),
        );
        headers
    }

    #[tokio::test]
    async fn test_introspect_active_token() {
        let state = create_test_app_state();
        state
            .oauth_storage
            .store_client(&test_client("test-client", Some("s3cret")))
            .await
            .unwrap();
        state
            .oauth_storage
            .store_token(&test_access_token("tok-123", Some("did:plc:abc123")))
            .await
            .unwrap();

        let headers = basic_auth_headers("test-client", "s3cret");
        let form = IntrospectForm {
            token: "tok-123".to_string(),
            token_type_hint: Some("access_token".to_string()),
            client_id: None,
            client_secret: None,
            client_assertion: None,
            client_assertion_type: None,
        };

        let response = handle_introspect(State(state), headers, Form(form))
            .await
            .unwrap()
            .0;

        assert_eq!(response["active"], json!(true));
        assert_eq!(response["iss"], json!("https://login.example.com"));
        assert_eq!(response["sub"], json!("did:plc:abc123"));
        assert_eq!(response["client_id"], json!("test-client"));
        assert_eq!(response["aud"], json!("test-client"));
        assert_eq!(response["scope"], json!("openid profile"));
        assert_eq!(response["token_type"], json!("Bearer"));
        assert!(response["iat"].is_i64());
        assert!(response["exp"].is_i64());
    }

    #[tokio::test]
    async fn test_introspect_client_auth_via_form() {
        let state = create_test_app_state();
        state
            .oauth_storage
            .store_client(&test_client("test-client", Some("s3cret")))
            .await
            .unwrap();
        state
            .oauth_storage
            .store_token(&test_access_token("tok-123", Some("did:plc:abc123")))
            .await
            .unwrap();

        // client_secret_post style: credentials in the form body.
        let form = IntrospectForm {
            token: "tok-123".to_string(),
            token_type_hint: None,
            client_id: Some("test-client".to_string()),
            client_secret: Some("s3cret".to_string()),
            client_assertion: None,
            client_assertion_type: None,
        };

        let response = handle_introspect(State(state), HeaderMap::new(), Form(form))
            .await
            .unwrap()
            .0;

        assert_eq!(response["active"], json!(true));
    }

    #[tokio::test]
    async fn test_introspect_unknown_token() {
        let state = create_test_app_state();
        state
            .oauth_storage
            .store_client(&test_client("test-client", Some("s3cret")))
            .await
            .unwrap();

        let headers = basic_auth_headers("test-client", "s3cret");
        let form = IntrospectForm {
            token: "does-not-exist".to_string(),
            token_type_hint: None,
            client_id: None,
            client_secret: None,
            client_assertion: None,
            client_assertion_type: None,
        };

        let response = handle_introspect(State(state), headers, Form(form))
            .await
            .unwrap()
            .0;

        assert_eq!(response, json!({ "active": false }));
    }

    #[tokio::test]
    async fn test_introspect_expired_token() {
        let state = create_test_app_state();
        state
            .oauth_storage
            .store_client(&test_client("test-client", Some("s3cret")))
            .await
            .unwrap();

        // Storage backends treat expired tokens as absent, but the handler also
        // guards against expiry directly.
        let mut access_token = test_access_token("tok-expired", Some("did:plc:abc123"));
        access_token.expires_at = Utc::now() - Duration::seconds(1);
        state
            .oauth_storage
            .store_token(&access_token)
            .await
            .unwrap();

        let headers = basic_auth_headers("test-client", "s3cret");
        let form = IntrospectForm {
            token: "tok-expired".to_string(),
            token_type_hint: None,
            client_id: None,
            client_secret: None,
            client_assertion: None,
            client_assertion_type: None,
        };

        let response = handle_introspect(State(state), headers, Form(form))
            .await
            .unwrap()
            .0;

        assert_eq!(response, json!({ "active": false }));
    }

    #[tokio::test]
    async fn test_introspect_requires_client_auth() {
        let state = create_test_app_state();
        state
            .oauth_storage
            .store_token(&test_access_token("tok-123", Some("did:plc:abc123")))
            .await
            .unwrap();

        let form = IntrospectForm {
            token: "tok-123".to_string(),
            token_type_hint: None,
            client_id: None,
            client_secret: None,
            client_assertion: None,
            client_assertion_type: None,
        };

        let err = handle_introspect(State(state), HeaderMap::new(), Form(form))
            .await
            .unwrap_err();

        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        assert_eq!(err.1 .0["error"], json!("invalid_client"));
    }

    #[tokio::test]
    async fn test_introspect_rejects_public_client() {
        let mut client = test_client("public-client", None);
        client.token_endpoint_auth_method = ClientAuthMethod::None;
        client.client_type = ClientType::Public;

        let state = create_test_app_state();
        state.oauth_storage.store_client(&client).await.unwrap();
        state
            .oauth_storage
            .store_token(&test_access_token("tok-123", Some("did:plc:abc123")))
            .await
            .unwrap();

        let form = IntrospectForm {
            token: "tok-123".to_string(),
            token_type_hint: None,
            client_id: Some("public-client".to_string()),
            client_secret: None,
            client_assertion: None,
            client_assertion_type: None,
        };

        let err = handle_introspect(State(state), HeaderMap::new(), Form(form))
            .await
            .unwrap_err();

        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        assert_eq!(err.1 .0["error"], json!("invalid_client"));
    }

    #[tokio::test]
    async fn test_introspect_rejects_bad_secret() {
        let state = create_test_app_state();
        state
            .oauth_storage
            .store_client(&test_client("test-client", Some("s3cret")))
            .await
            .unwrap();
        state
            .oauth_storage
            .store_token(&test_access_token("tok-123", Some("did:plc:abc123")))
            .await
            .unwrap();

        let headers = basic_auth_headers("test-client", "wrong");
        let form = IntrospectForm {
            token: "tok-123".to_string(),
            token_type_hint: None,
            client_id: None,
            client_secret: None,
            client_assertion: None,
            client_assertion_type: None,
        };

        let err = handle_introspect(State(state), headers, Form(form))
            .await
            .unwrap_err();

        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        assert_eq!(err.1 .0["error"], json!("invalid_client"));
    }

    #[tokio::test]
    async fn test_introspect_client_credentials_token_omits_sub() {
        let state = create_test_app_state();
        state
            .oauth_storage
            .store_client(&test_client("test-client", Some("s3cret")))
            .await
            .unwrap();
        // No user_id: client-credentials grant.
        state
            .oauth_storage
            .store_token(&test_access_token("tok-s2s", None))
            .await
            .unwrap();

        let headers = basic_auth_headers("test-client", "s3cret");
        let form = IntrospectForm {
            token: "tok-s2s".to_string(),
            token_type_hint: None,
            client_id: None,
            client_secret: None,
            client_assertion: None,
            client_assertion_type: None,
        };

        let response = handle_introspect(State(state), headers, Form(form))
            .await
            .unwrap()
            .0;

        assert_eq!(response["active"], json!(true));
        assert!(response.get("sub").is_none());
    }

    #[tokio::test]
    async fn test_introspect_missing_token() {
        let state = create_test_app_state();

        let form = IntrospectForm {
            token: String::new(),
            token_type_hint: None,
            client_id: None,
            client_secret: None,
            client_assertion: None,
            client_assertion_type: None,
        };

        let err = handle_introspect(State(state), HeaderMap::new(), Form(form))
            .await
            .unwrap_err();

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1 .0["error"], json!("invalid_request"));
    }
}
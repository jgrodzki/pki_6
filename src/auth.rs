use crate::{database, AppState, GithubEmail, GoogleProfileInfo};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::get,
    Router,
};
use oauth2::{
    basic::BasicTokenType, reqwest::async_http_client, AuthorizationCode, CsrfToken,
    EmptyExtraTokenFields, PkceCodeVerifier, StandardTokenResponse, TokenResponse,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt::Display, sync::Arc};
use tower_sessions::Session;

#[derive(Deserialize)]
struct AuthCode {
    code: String,
    state: String,
}

#[derive(Debug)]
pub enum AuthError {
    InternalError,
    AuthProviderError,
    ResourceError,
}

impl Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                AuthError::InternalError => "Encountered internal server error!",
                AuthError::AuthProviderError =>
                    "There was an error while contacting the auth provider",
                AuthError::ResourceError =>
                    "There was an error when trying to reach a remote resource",
            }
        )
    }
}

impl Error for AuthError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::INTERNAL_SERVER_ERROR, Html(self.to_string())).into_response()
    }
}

#[derive(Deserialize, Serialize)]
pub struct SecurityTokens {
    pub google_csrf: CsrfToken,
    pub github_csrf: CsrfToken,
    pub google_pkce: PkceCodeVerifier,
}

#[derive(Deserialize, Serialize)]
pub enum AuthProvider {
    Google,
    Github,
}

#[derive(Deserialize, Serialize)]
pub struct AccessToken {
    pub provider: AuthProvider,
    pub access_token: StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
}

pub fn get_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/logout", get(logout_handler))
        .route("/google_auth", get(google_auth_handler))
        .route("/github_auth", get(github_auth_handler))
}

async fn logout_handler(session: Session) -> Result<impl IntoResponse, AuthError> {
    session
        .delete()
        .await
        .map_err(|_| AuthError::ResourceError)?;
    Ok(Redirect::to("/"))
}

async fn google_auth_handler(
    session: Session,
    State(state): State<Arc<AppState>>,
    auth_code: Option<Query<AuthCode>>,
) -> Result<impl IntoResponse, AuthError> {
    let auth_code = auth_code.ok_or(AuthError::AuthProviderError)?;
    let security_tokens = session
        .get::<SecurityTokens>("security_tokens")
        .await
        .map_err(|_| AuthError::InternalError)?
        .ok_or(AuthError::InternalError)?;
    if auth_code.state != *security_tokens.google_csrf.secret() {
        return Err(AuthError::InternalError);
    }
    let access_token = state
        .google_client
        .exchange_code(AuthorizationCode::new(auth_code.code.to_owned()))
        .set_pkce_verifier(security_tokens.google_pkce)
        .request_async(async_http_client)
        .await
        .map_err(|_| AuthError::AuthProviderError)?;
    let access_token = AccessToken {
        provider: AuthProvider::Google,
        access_token,
    };
    let response = Client::new()
        .get("https://www.googleapis.com/oauth2/v3/userinfo")
        .bearer_auth(access_token.access_token.access_token().secret())
        .send()
        .await
        .map_err(|_| AuthError::ResourceError)?
        .json::<GoogleProfileInfo>()
        .await
        .map_err(|_| AuthError::ResourceError)?;
    database::user_login(&state.pool, &response.email).await?;
    session
        .insert("access_token", access_token)
        .await
        .map_err(|_| AuthError::InternalError)?;
    Ok(Redirect::to("/"))
}

async fn github_auth_handler(
    session: Session,
    State(state): State<Arc<AppState>>,
    auth_code: Option<Query<AuthCode>>,
) -> Result<impl IntoResponse, AuthError> {
    let auth_code = auth_code.ok_or(AuthError::AuthProviderError)?;
    let security_tokens = session
        .get::<SecurityTokens>("security_tokens")
        .await
        .map_err(|_| AuthError::InternalError)?
        .ok_or(AuthError::InternalError)?;
    if auth_code.state != *security_tokens.github_csrf.secret() {
        return Err(AuthError::InternalError);
    }
    let access_token = state
        .github_client
        .exchange_code(AuthorizationCode::new(auth_code.code.to_owned()))
        .request_async(async_http_client)
        .await
        .map_err(|_| AuthError::AuthProviderError)?;
    let access_token = AccessToken {
        provider: AuthProvider::Github,
        access_token,
    };
    let response = Client::new()
        .get("https://api.github.com/user/emails")
        .bearer_auth(access_token.access_token.access_token().secret())
        .header("User-Agent", "PKI 7")
        .send()
        .await
        .map_err(|_| AuthError::ResourceError)?
        .json::<Vec<GithubEmail>>()
        .await
        .map_err(|_| AuthError::ResourceError)?;
    let email = response
        .iter()
        .find(|e| e.primary)
        .ok_or(AuthError::ResourceError)?;
    database::user_login(&state.pool, &email.email).await?;
    session
        .insert("access_token", access_token)
        .await
        .map_err(|_| AuthError::InternalError)?;
    Ok(Redirect::to("/").into_response())
}

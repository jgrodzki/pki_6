use ::reqwest::Client;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::get,
    Router,
};
// use dotenvy::dotenv;
use oauth2::{
    basic::{BasicClient, BasicTokenType},
    reqwest::async_http_client,
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, StandardTokenResponse, TokenResponse,
    TokenUrl,
};
use serde::{Deserialize, Serialize};
use std::{env, error::Error, fmt::Display, sync::Arc};
use tokio::net::TcpListener;
use tower_sessions::{MemoryStore, Session, SessionManagerLayer};

#[derive(Deserialize)]
struct GoogleProfileInfo {
    name: String,
    picture: String,
}

#[derive(Deserialize)]
struct GithubProfileInfo {
    login: String,
    avatar_url: String,
}

#[derive(Deserialize)]
struct AuthCode {
    code: String,
    state: String,
}

#[derive(Debug)]
enum AuthError {
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

struct AppState {
    google_client: BasicClient,
    github_client: BasicClient,
}

#[derive(Deserialize, Serialize)]
struct SecurityTokens {
    google_csrf: CsrfToken,
    github_csrf: CsrfToken,
    google_pkce: PkceCodeVerifier,
}

#[derive(Deserialize, Serialize)]
enum AuthProvider {
    Google,
    Github,
}

#[derive(Deserialize, Serialize)]
struct AccessToken {
    provider: AuthProvider,
    access_token: StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
}

async fn logout_handler(session: Session) -> Result<impl IntoResponse, AuthError> {
    session
        .delete()
        .await
        .map_err(|_| AuthError::ResourceError)?;
    Ok(Redirect::to("/"))
}

async fn index_handler(
    session: Session,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AuthError> {
    if let Some(access_token) = session
        .get::<AccessToken>("access_token")
        .await
        .map_err(|_| AuthError::ResourceError)?
    {
        if let AuthProvider::Google = access_token.provider {
            let response = Client::new()
                .get("https://www.googleapis.com/oauth2/v3/userinfo")
                .bearer_auth(access_token.access_token.access_token().secret())
                .send()
                .await
                .map_err(|_| AuthError::ResourceError)?
                .json::<GoogleProfileInfo>()
                .await
                .map_err(|_| AuthError::ResourceError)?;
            Ok(Html(format!(
                r#"<img style="width:5rem" src="{}"><p>Logged in as {}</p><a href="/logout">Logout</a>"#,
                response.picture, response.name
            )))
        } else {
            let response = Client::new()
                .get("https://api.github.com/user")
                .bearer_auth(access_token.access_token.access_token().secret())
                .header("User-Agent", "PKI 7")
                .send()
                .await
                .map_err(|_| AuthError::ResourceError)?
                .json::<GithubProfileInfo>()
                .await
                .map_err(|_| AuthError::ResourceError)?;
            Ok(Html(format!(
                r#"<img style="width:5rem" src="{}"><p>Logged in as {}</p><a href="/logout">Logout</a>"#,
                response.avatar_url, response.login
            )))
        }
    } else {
        let (challange, verifier) = PkceCodeChallenge::new_random_sha256();
        let (google_url, google_csrf_token) = state
            .google_client
            .authorize_url(CsrfToken::new_random)
            .set_pkce_challenge(challange)
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/userinfo.profile".to_owned(),
            ))
            .url();
        let (github_url, github_csrf_token) = state
            .github_client
            .authorize_url(CsrfToken::new_random)
            .url();
        let security_tokens = SecurityTokens {
            google_csrf: google_csrf_token,
            github_csrf: github_csrf_token,
            google_pkce: verifier,
        };
        session
            .insert("security_tokens", security_tokens)
            .await
            .map_err(|_| AuthError::InternalError)?;
        Ok(Html(format!(
            r#"<a href="{google_url}">Google login</a><br><a href="{github_url}">Github login</a>"#
        )))
    }
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
    session
        .insert("access_token", access_token)
        .await
        .map_err(|_| AuthError::InternalError)?;
    Ok(Redirect::to("/").into_response())
}

#[tokio::main]
async fn main() {
    // dotenv().expect("Error while parsing .env file");
    let google_client = BasicClient::new(
        ClientId::new(env::var("GOOGLE_CLIENT_ID").unwrap()),
        Some(ClientSecret::new(env::var("GOOGLE_CLIENT_SECRET").unwrap())),
        AuthUrl::new(env::var("GOOGLE_AUTH_URL").unwrap()).unwrap(),
        Some(TokenUrl::new(env::var("GOOGLE_TOKEN_URL").unwrap()).unwrap()),
    )
    .set_redirect_uri(
        RedirectUrl::new("https://pki-6.onrender.com/google_auth".to_owned()).unwrap(),
    );
    let github_client = BasicClient::new(
        ClientId::new(env::var("GITHUB_CLIENT_ID").unwrap()),
        Some(ClientSecret::new(env::var("GITHUB_CLIENT_SECRET").unwrap())),
        AuthUrl::new(env::var("GITHUB_AUTH_URL").unwrap()).unwrap(),
        Some(TokenUrl::new(env::var("GITHUB_TOKEN_URL").unwrap()).unwrap()),
    )
    .set_redirect_uri(
        RedirectUrl::new("https://pki-6.onrender.com/github_auth".to_owned()).unwrap(),
    );
    let app_state = AppState {
        google_client,
        github_client,
    };
    let app = Router::new()
        .route("/", get(index_handler))
        .route("/logout", get(logout_handler))
        .route("/google_auth", get(google_auth_handler))
        .route("/github_auth", get(github_auth_handler))
        .layer(
            SessionManagerLayer::new(MemoryStore::default())
                .with_same_site(tower_sessions::cookie::SameSite::Lax),
        )
        .with_state(Arc::new(app_state));
    let listener = TcpListener::bind("0.0.0.0:10000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

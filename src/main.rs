use ::reqwest::Client;
use auth::{AccessToken, AuthError, AuthProvider, SecurityTokens};
use axum::{extract::State, response::IntoResponse, routing::get, Router};
use dotenvy::dotenv;
use maud::{html, Markup, DOCTYPE};
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    Scope, TokenResponse, TokenUrl,
};
use serde::Deserialize;
use sqlx::{migrate::MigrateDatabase, PgPool, Postgres};
use std::{env, sync::Arc};
use tokio::net::TcpListener;
use tower_sessions::{cookie::time::format_description, MemoryStore, Session, SessionManagerLayer};

mod auth;
mod database;

#[derive(Deserialize)]
struct GoogleProfileInfo {
    name: String,
    email: String,
    // picture: String,
}

#[derive(Deserialize)]
struct GithubProfileInfo {
    login: String,
    // avatar_url: String,
}

#[derive(Deserialize)]
struct GithubEmail {
    email: String,
    primary: bool,
}

struct AppState {
    pool: PgPool,
    google_client: BasicClient,
    github_client: BasicClient,
}

fn index_markup(bar: Markup, body: Markup, modal: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html {
            head {
                title { "PKI 7" }
                meta name="viewport" content="width=device-width, initial-scale=1.0";
                meta name="author" content="Jakub Grodzki 240675";
                link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous";
                script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous" {}
            }
            body class="bg-dark text-white" data-bs-theme="dark" {
                header {
                    nav class="px-2 navbar navbar-expand-lg navbar-dark bg-primary" {
                        a class="navbar-brand" href="#" {
                            "PKI 7"
                        }
                        button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarContent" {
                            span class="navbar-toggler-icon" {}
                        }
                        div class="collapse navbar-collapse justify-content-end" id="navbarContent" {
                            ul class="navbar-nav"
                            {
                                (bar)
                            }
                        }
                    }
                }
                (body)
                div class="modal fade" tabindex="-1" id="databaseModal" {
                    div class="modal-dialog" {
                        div class="modal-content" {
                            div class="modal-header" {
                                h1 class="modal-title" {
                                    "Database status"
                                }
                                button type="button" class="btn-close" data-bs-dismiss="modal" {}
                            }
                            div class="modal-body" {
                                (modal)
                            }
                            div class="modal-footer" {
                                button type="button" class="btn btn-primary" data-bs-dismiss="modal" {"Ok"}
                            }
                        }
                    }
                }
                script {
                    "var databaseModal = new bootstrap.Modal(document.getElementById('databaseModal'), {}); databaseModal.show()"
                }
            }
        }
    }
}

async fn index_handler(
    session: Session,
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AuthError> {
    let format =
        format_description::parse("[year]-[month]-[day] [hour]:[minute]:[second]").unwrap();
    let Ok(users) = database::get_users(&state.pool).await else {
        return Ok(index_markup(
            html! {},
            html! {},
            html! {"Cannot connect to the database!"},
        ));
    };
    let user_info = html! {
        div style="max-width:48rem" class="mt-4 mx-auto table-responsive" {
            table class="table table-striped table-dark"
            {
                thead {
                    tr {
                        th scope="col" {
                            "Id"
                        }
                        th scope="col" {
                            "Name"
                        }
                        th scope="col" {
                            "Joined"
                        }
                        th scope="col" {
                            "Last visit"
                        }
                        th scope="col" {
                            "Counter"
                        }
                    }
                }
                tbody {
                    @for u in users {
                        tr {
                            th scope="row" {
                                (u.id)
                            }
                            th {
                                (u.name)
                            }
                            th {
                                (u.joined.format(&format).unwrap())
                            }
                            th {
                                (u.lastvisit.format(&format).unwrap())
                            }
                            th {
                                (u.counter)
                            }
                        }
                    }
                }
            }
        }
    };
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
            Ok(index_markup(
                html! {
                    li class="nav-item dropdown" {
                        a class="nav-link dropdown-toggle" data-bs-toggle="dropdown" {
                            "Logged in as " (response.name)
                        }
                        ul class="dropdown-menu" {
                            li {
                                a class="dropdown-item" href="/logout" {
                                    "Logout"
                                }
                            }
                        }
                    }
                },
                user_info,
                html! {"Connected!"},
            ))
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
            Ok(index_markup(
                html! {
                    li class="nav-item dropdown" {
                        a class="nav-link dropdown-toggle" data-bs-toggle="dropdown" {
                            "Logged in as " (response.login)
                        }
                        ul class="dropdown-menu" {
                            li {
                                a class="dropdown-item" href="/logout" {
                                    "Logout"
                                }
                            }
                        }
                    }
                },
                user_info,
                html! {"Connected!"},
            ))
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
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/userinfo.email".to_owned(),
            ))
            .url();
        let (github_url, github_csrf_token) = state
            .github_client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("user:email".to_owned()))
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
        Ok(index_markup(
            html! {
                li class="nav-item dropdown" {
                    a class="nav-link dropdown-toggle" data-bs-toggle="dropdown" {
                        "Login"
                    }
                    ul class="dropdown-menu" {
                        li {
                            a class="dropdown-item" href={(google_url)} {
                                "Google login"
                            }
                        }
                        li {
                            a class="dropdown-item" href={(github_url)} {
                                "Github login"
                            }
                        }
                    }
                }
            },
            user_info,
            html! {"Connected!"},
        ))
    }
}

#[tokio::main]
async fn main() {
    dotenv().unwrap();
    let database_url = env::var("DATABASE_URL").unwrap();
    if !Postgres::database_exists(&database_url)
        .await
        .unwrap_or(false)
    {
        Postgres::create_database(&database_url).await.unwrap();
    }
    let pool = PgPool::connect_lazy(&database_url).unwrap();
    sqlx::migrate!().run(&pool).await.unwrap();
    let google_client = BasicClient::new(
        ClientId::new(env::var("GOOGLE_CLIENT_ID").unwrap()),
        Some(ClientSecret::new(env::var("GOOGLE_CLIENT_SECRET").unwrap())),
        AuthUrl::new(env::var("GOOGLE_AUTH_URL").unwrap()).unwrap(),
        Some(TokenUrl::new(env::var("GOOGLE_TOKEN_URL").unwrap()).unwrap()),
    )
    .set_redirect_uri(
        RedirectUrl::new(env::var("DEPLOYMENT_URL").unwrap() + "/google_auth").unwrap(),
    );
    let github_client = BasicClient::new(
        ClientId::new(env::var("GITHUB_CLIENT_ID").unwrap()),
        Some(ClientSecret::new(env::var("GITHUB_CLIENT_SECRET").unwrap())),
        AuthUrl::new(env::var("GITHUB_AUTH_URL").unwrap()).unwrap(),
        Some(TokenUrl::new(env::var("GITHUB_TOKEN_URL").unwrap()).unwrap()),
    )
    .set_redirect_uri(
        RedirectUrl::new(env::var("DEPLOYMENT_URL").unwrap() + "/github_auth").unwrap(),
    );
    let app_state = AppState {
        pool,
        google_client,
        github_client,
    };
    let app = Router::new()
        .route("/", get(index_handler))
        .merge(auth::get_routes())
        .layer(
            SessionManagerLayer::new(MemoryStore::default())
                .with_same_site(tower_sessions::cookie::SameSite::Lax),
        )
        .with_state(Arc::new(app_state));
    let listener = TcpListener::bind("0.0.0.0:".to_owned() + &env::var("PORT").unwrap())
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}

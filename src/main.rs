use axum::{
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use tokio::net::TcpListener;

async fn hello_handler() -> impl IntoResponse {
    Html("Hello world!")
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/", get(hello_handler));
    let listener = TcpListener::bind("0.0.0.0:10000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

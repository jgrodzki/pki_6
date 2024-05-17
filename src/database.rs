use sqlx::{query, query_as, types::time::PrimitiveDateTime, PgPool};

use crate::auth::AuthError;

pub async fn user_login(pool: &PgPool, name: &str) -> Result<(), AuthError> {
    if let Err(e) = query!("INSERT INTO users (name) VALUES ($1)", name)
        .execute(pool)
        .await
    {
        match e {
            sqlx::Error::Database(e) => {
                if e.is_unique_violation() {
                    query!(
                        "UPDATE users SET counter = counter + 1, lastvisit = NOW() WHERE name=$1",
                        name
                    )
                    .execute(pool)
                    .await
                    .map(|_| ())
                    .map_err(|_| AuthError::InternalError)
                } else {
                    Err(AuthError::InternalError)
                }
            }
            _ => Err(AuthError::InternalError),
        }
    } else {
        Ok(())
    }
}

pub struct UserInfo {
    pub id: i32,
    pub name: String,
    pub joined: PrimitiveDateTime,
    pub lastvisit: PrimitiveDateTime,
    pub counter: i32,
}

pub async fn get_users(pool: &PgPool) -> Result<Vec<UserInfo>, AuthError> {
    query_as!(UserInfo, "SELECT * FROM users")
        .fetch_all(pool)
        .await
        .map_err(|_| AuthError::InternalError)
}

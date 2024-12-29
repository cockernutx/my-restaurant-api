use aide::{
    axum::{routing::post, ApiRouter},
    OperationIo,
};
use axum::{extract::State, http::StatusCode, Json};
use axum_error_handler::AxumErrorResponse;
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Header};
use password_auth::{generate_hash, verify_password, VerifyError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

use crate::{
    auth::{Claims, KEYS}, shared_types::Record, AppState, Pool
};

pub fn routes() -> ApiRouter<AppState> {
    ApiRouter::new()
        .api_route("/create_user", post(create_user))
        .api_route("/authenticate", post(authenticate))
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct CreateUserInput {
    pub username: String,
    pub password: String,
    pub permissions: Vec<String>,
}

#[derive(Debug, Error, AxumErrorResponse, OperationIo)]
enum CreateUserError {
    #[error("Not authorized to use this endpoint")]
    #[status_code("401")]
    Unauthorized,
    #[error("error executing queries on database")]
    #[status_code("500")]
    DatabaseError(#[from] surrealdb::Error),
    #[error("username already taken")]
    #[status_code("409")]
    Conflict,
}


async fn create_user(
    claims: Claims,
    State(pool): State<Pool>,
    Json(user_info): Json<CreateUserInput>,
) -> Result<(StatusCode, String), CreateUserError> {
    if !claims.permissions.contains(&"add_users".to_string()) {
        return Err(CreateUserError::Unauthorized);
    }

    let mut resp = pool
        .query(r#"SELECT id FROM users WHERE username = $username"#)
        .bind(("username", user_info.username.clone()))
        .await?;
    let user: Option<Record> = resp.take(0)?;
    if user.is_some() {
        return Err(CreateUserError::Conflict);
    }

    let password_hash = generate_hash(user_info.password.as_bytes());

    let _: Option<Record> = pool
        .create("users")
        .content(json!({
            "username": user_info.username,
            "password_hash": password_hash,
            "user_permissions": Vec::<String>::new()
        }))
        .await?;

    Ok((
        StatusCode::CREATED,
        format!("/profile/{}", user_info.username),
    ))
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct AuthInfo {
    pub username: String,
    pub password: String,
    pub remember_me: bool,
}

#[derive(Debug, Error, AxumErrorResponse, OperationIo)]
enum AuthenticateError {
    #[error("user not found")]
    #[status_code("401")]
    UserNotFound,
    #[error("wrong password")]
    #[status_code("401")]
    WrongPassword(#[from] VerifyError),
    #[error("error executing queries on database: {0}")]
    #[status_code("500")]
    DatabaseError(#[from] surrealdb::Error),
}

async fn authenticate(
    State(pool): State<Pool>,
    Json(auth_info): Json<AuthInfo>,
) -> Result<String, AuthenticateError> {
    #[derive(Debug, Serialize, Deserialize)]
    struct QueryResp {
        password_hash: String,
        user_permissions: Vec<String>,
    }

    let mut resp = pool
        .query(r#"SELECT password_hash, user_permissions FROM users WHERE username = $username"#)
        .bind(("username", auth_info.username.clone()))
        .await?;
    let resp: Option<QueryResp> = resp.take(0)?;

    if let Some(resp) = resp {
        verify_password(auth_info.password, &resp.password_hash)?;

        let exp = {
            let mut now = Utc::now();
            if auth_info.remember_me {
                now += Duration::weeks(100);
            } else {
                now += Duration::days(1);
            }

            now.timestamp() as usize
        };

        let token = encode(
            &Header::default(),
            &Claims {
                sub: auth_info.username,
                exp,
                permissions: resp.user_permissions,
            },
            &KEYS.encoding,
        )
        .expect("could not generate debug JWT");

        return Ok(token);
    } else {
        return Err(AuthenticateError::UserNotFound);
    }
}

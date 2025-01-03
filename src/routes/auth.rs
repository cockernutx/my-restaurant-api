use aide::{
    axum::{
        routing::{post, post_with},
        ApiRouter,
    },
    OperationIo,
};
use axum::{extract::State, http::StatusCode, Json};
use axum_error_handler::AxumErrorResponse;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Header};
use password_auth::{generate_hash, verify_password, VerifyError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

use crate::{
    auth_operator::{Claims, Refresher, KEYS},
    shared_types::Record,
    AppState, Pool,
};

pub fn routes() -> ApiRouter<AppState> {
    ApiRouter::new()
        .api_route(
            "/create_user",
            post_with(create_user, |t| t.response_with::<201, String, _>(|t| t)),
        )
        .api_route("/authenticate", post(authenticate))
        .api_route("/refresh", post(refresh))
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct CreateUserInput {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Error, AxumErrorResponse, OperationIo)]
enum CreateUserError {
    #[error("error executing queries on database")]
    #[status_code("500")]
    DatabaseError(#[from] surrealdb::Error),
    #[error("username already taken")]
    #[status_code("409")]
    Conflict,
}

async fn create_user(
    State(pool): State<Pool>,
    Json(user_info): Json<CreateUserInput>,
) -> Result<(StatusCode, String), CreateUserError> {
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
            "hash": password_hash
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

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct TokenInfo {
    pub token: String,
    pub refresher: String,
    pub expiration: usize,
    pub refresher_expiration: usize,
}

async fn authenticate(
    State(pool): State<Pool>,
    Json(auth_info): Json<AuthInfo>,
) -> Result<Json<TokenInfo>, AuthenticateError> {
    #[derive(Debug, Serialize, Deserialize)]
    struct QueryResp {
        hash: String
    }

    let mut resp = pool
        .query(r#"SELECT hash FROM users WHERE username = $username"#)
        .bind(("username", auth_info.username.clone()))
        .await?;
    let resp: Option<QueryResp> = resp.take(0)?;

    if let Some(resp) = resp {
        verify_password(auth_info.password, &resp.hash)?;

        let exp: usize = (Utc::now() + Duration::minutes(10)).timestamp() as usize;

        let token = encode(
            &Header::default(),
            &Claims {
                sub: auth_info.username.clone(),
                exp,
                permissions: vec![],
            },
            &KEYS.encoding,
        )
        .expect("could not generate debug JWT");
        let refresher_exp = (Utc::now() + Duration::weeks(10)).timestamp() as usize;

        let refresher = encode(
            &Header::default(),
            &Refresher {
                username: auth_info.username.clone(),
                exp: refresher_exp,
            },
            &KEYS.encoding,
        )
        .expect("could not generate debug JWT");

        return Ok(Json(TokenInfo {
            token,
            refresher,
            expiration: exp,
            refresher_expiration: refresher_exp,
        }));
    } else {
        return Err(AuthenticateError::UserNotFound);
    }
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct RefreshInput {
    pub refresher: String,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct TokenOutput {
    pub token: String,
    pub exp: usize,
}

#[derive(Debug, Error, AxumErrorResponse, OperationIo)]
pub enum RefreshError {
    #[error("invalid token")]
    #[status_code("401")]
    InvalidToken,
    #[error("error executing queries on database: {0}")]
    #[status_code("500")]
    DatabaseError(#[from] surrealdb::Error),
    #[error("user not found")]
    #[status_code("401")]
    UserNotFound,
}

async fn refresh(
    State(pool): State<Pool>,
    Json(refresher_info): Json<RefreshInput>,
) -> Result<Json<TokenOutput>, RefreshError> {

    let token_data = decode::<Refresher>(
        &refresher_info.refresher,
        &KEYS.decoding,
        &jsonwebtoken::Validation::default(),
    )
    .map_err(|_| RefreshError::InvalidToken)?;

    let token_data = token_data.claims;

    let mut resp = pool
        .query(r#"SELECT id FROM users WHERE username = $username"#)
        .bind(("username", token_data.username.clone()))
        .await?;

    let resp: Option<Record> = resp.take(0)?;

    if let Some(_) = resp {
        let exp = (Utc::now() + Duration::minutes(10)).timestamp() as usize;

        let token = encode(
            &Header::default(),
            &Claims {
                sub: token_data.username.clone(),
                exp,
                permissions: vec![],
            },
            &KEYS.encoding,
        )
        .expect("could not generate debug JWT");

        Ok(Json(TokenOutput { token, exp }))
    } else {
        return Err(RefreshError::UserNotFound);
    }
}

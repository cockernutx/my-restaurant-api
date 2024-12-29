use aide::{
    axum::{routing::{post, get}, ApiRouter},
    OperationIo,
};
use axum::{
    extract::{Path, State},
    Json,
};
use axum_error_handler::AxumErrorResponse;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AppState, Pool,
};

mod edit_profile;

pub fn routes() -> ApiRouter<AppState> {
    ApiRouter::new()
        .nest("/edit_profile", edit_profile::routes())
        .api_route("/:username", get(get_profile))
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct UserProfile {
    pub username: String,
    pub bio: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug, Error, AxumErrorResponse, OperationIo)]
enum GetProfileError {
    #[error("database error: {0}")]
    #[status_code("500")]
    DatabaseError(#[from] surrealdb::Error),
    #[error("user not found")]
    #[status_code("404")]
    UserNotFound,
}

async fn get_profile(
    Path(username): Path<String>,
    State(pool): State<Pool>,
) -> Result<Json<UserProfile>, GetProfileError> {
    let mut resp = pool
        .query(r#"SELECT * FROM users WHERE username = $username"#)
        .bind(("username", username))
        .await?;
    let user_profile: Option<UserProfile> = resp.take(0)?;

    if let Some(user_profile) = user_profile {
        return Ok(Json(user_profile));
    } else {
        return Err(GetProfileError::UserNotFound);
    }
}

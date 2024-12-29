use crate::{auth::Claims, shared_types::CommonError, AppState, Pool};
use aide::axum::{routing::post, ApiRouter};
use axum::{extract::State, Json};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub fn routes() -> ApiRouter<AppState> {
    ApiRouter::new().api_route("/edit_bio", post(edit_bio))
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct EditBioInput {
    pub new_bio: String,
}

async fn edit_bio(
    claims: Claims,
    State(pool): State<Pool>,
    Json(bio_edit): Json<EditBioInput>,
) -> Result<(), CommonError> {
    let resp = pool
        .query(r#"UPDATE users SET bio = $new_bio WHERE username = $username"#)
        .bind(("username", claims.sub))
        .bind(("new_bio", bio_edit.new_bio))
        .await?;
    resp.check()?;
    Ok(())
}

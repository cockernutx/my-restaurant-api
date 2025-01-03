use crate::{
    auth_operator::Claims,
    shared_types::{CommonError, Record},
    AppState, Pool,
};
use aide::axum::{routing::{patch, post}, ApiRouter};
use axum::{extract::State, Json};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use surrealdb::{opt::PatchOp, RecordId};

pub fn routes() -> ApiRouter<AppState> {
    ApiRouter::new().api_route("/edit_bio", patch(edit_bio))
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
    let _: Option<Record> = pool
        .update(RecordId::from_table_key("users", claims.sub))
        .patch(PatchOp::replace("/bio", bio_edit.new_bio))
        .await?;
    Ok(())
}

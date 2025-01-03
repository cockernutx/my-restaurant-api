use aide::{
    axum::{
        routing::{get, post},
        ApiRouter,
    },
    OperationIo,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use axum_error_handler::AxumErrorResponse;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use surrealdb::RecordId;
use thiserror::Error;

use crate::{
    auth_operator::Claims,
    shared_types::{CommonError, Record},
    AppState, Pool,
};

pub fn routes() -> ApiRouter<AppState> {
    ApiRouter::new()
        .api_route("/new_recipe", post(new_recipe))
        .api_route("/:recipe_id", get(get_recipe))
        .api_route("/recipe_list", get(get_recipes))
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct NewRecipe {
    pub title: String,
    pub recipe_markdown: String,
    pub recipe_image: Option<String>,
}

#[derive(Debug, Error, AxumErrorResponse, OperationIo)]
enum NewRecipeError {
    #[error("database error: {0}")]
    #[status_code("500")]
    DatabaseError(#[from] surrealdb::Error),
    #[error("recipe not created")]
    #[status_code("500")]
    NotCreated,
}

async fn new_recipe(
    claims: Claims,
    State(pool): State<Pool>,
    Json(new_recipe): Json<NewRecipe>,
) -> Result<(StatusCode, String), NewRecipeError> {
    let mut query = pool
        .query(
            r#"
        BEGIN TRANSACTION;
        LET $user = (SELECT id FROM users WHERE username = $username);

        LET $recipe_content = (SELECT *, $user[0].id AS written_by FROM $content)[0];

        RETURN CREATE recipes CONTENT $recipe_content;
        COMMIT;
        "#,
        )
        .bind(("username", claims.sub))
        .bind(("content", new_recipe))
        .await?;
    let rec: Option<Record> = query.take(0)?;
    if let Some(rec) = rec {
        let code = rec.id.id.to_raw();
        return Ok((StatusCode::CREATED, format!("/recipes/{code}")));
    } else {
        return Err(NewRecipeError::NotCreated);
    }
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct Recipe {
    pub title: String,
    pub recipe_markdown: String,
    pub recipe_image: Option<String>,
    pub written_by: String,
}

#[derive(Debug, Error, AxumErrorResponse, OperationIo)]
enum GetRecipeError {
    #[error("database error: {0}")]
    #[status_code("500")]
    DatabaseError(#[from] surrealdb::Error),
    #[error("recipe not found")]
    #[status_code("404")]
    NotFound,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct GetRecipe {
    recipe_id: String,
}

async fn get_recipe(
    State(pool): State<Pool>,
    Path(get_recipe): Path<GetRecipe>,
) -> Result<Json<Recipe>, GetRecipeError> {
    let mut query = pool
        .query(r#"SELECT *, written_by.username AS written_by FROM $recipe"#)
        .bind((
            "recipe",
            RecordId::from_table_key("recipes", get_recipe.recipe_id),
        ))
        .await?;
    let recipe: Option<Recipe> = query.take(0)?;
    if let Some(recipe) = recipe {
        Ok(Json(recipe))
    } else {
        Err(GetRecipeError::NotFound)
    }
}

async fn get_recipes(State(pool): State<Pool>) -> Result<Json<Vec<Recipe>>, CommonError> {
    let mut query = pool
        .query(r#"SELECT *, written_by.username AS written_by FROM recipes"#)
        .await?;
    let recipes: Vec<Recipe> = query.take(0)?;

    Ok(Json(recipes))
}

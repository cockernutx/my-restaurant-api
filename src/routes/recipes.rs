use aide::{
    axum::{
        routing::{get, post, post_with},
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
use tracing::debug;

use crate::{
    auth_operator::Claims,
    shared_types::{CommonError, Record},
    AppState, Pool,
};

pub fn routes() -> ApiRouter<AppState> {
    ApiRouter::new()
        .api_route("/new_recipe", post_with(new_recipe, |t| t.response_with::<201, String, _>(|t| t)))
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
    #[error("embedding error")]
    #[status_code("500")]
    EmbeddingError(#[from] fastembed::Error)
}

async fn new_recipe(
    claims: Claims,
    State(state): State<AppState>,
    Json(new_recipe): Json<NewRecipe>,
) -> Result<(StatusCode, String), NewRecipeError> {
    let pool = &state.surreal;
    let emb = &state.emb;

    let documents: Vec<String> = {
        let new_text = new_recipe.recipe_markdown.clone();
        let paragraphs = new_text.lines();
        let mut res: Vec<String> = vec![];

        for line in paragraphs {
            if line.len() < 10 {
                if let Some(last) = res.last_mut() {
                    *last += &format!("\n {line}");
                    continue;
                }
            }
            res.push(line.to_string());
        }

        res.insert(0, new_recipe.title.clone());

        res
    };

    let embeddings = emb.embed(documents, None)?;


    let mut query = pool
        .query(
            r#"
        BEGIN TRANSACTION;
        LET $user = (SELECT id FROM users WHERE username = $username);
        LET $recipe_content = (SELECT *, $user[0].id AS written_by, [] AS embeddings FROM $content)[0];
        LET $recipe = CREATE recipes CONTENT $recipe_content;
        LET $recipe_id = $recipe[0].id;
        FOR $emb IN $embeddings {
            LET $id = CREATE recipe_embeddings SET embeddings = $emb, refers_to = $recipe_id;
            UPDATE $recipe_id SET embeddings += $id[0].id;
        };

        RETURN (SELECT * FROM $recipe_id)
        COMMIT;
        "#,
        )
        .bind(("username", claims.sub))
        .bind(("content", new_recipe))
        .bind(("embeddings",embeddings))
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
    pub id: String,
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
        .query(r#"SELECT *, written_by.username AS written_by, id.id() AS id FROM recipes"#)
        .await?;
    let recipes: Vec<Recipe> = query.take(0)?;

    Ok(Json(recipes))
}

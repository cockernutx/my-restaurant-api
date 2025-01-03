use aide::axum::ApiRouter;

use crate::AppState;

mod profile;
mod auth;
mod recipes;

pub fn routes() -> ApiRouter<AppState> {
    ApiRouter::new()
        .nest("/auth", auth::routes())
        .nest("/profile", profile::routes())
        .nest("/recipes", recipes::routes())
}

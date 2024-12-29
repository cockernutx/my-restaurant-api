use aide::axum::ApiRouter;

use crate::AppState;

mod profile;
mod users;
mod recipes;

pub fn routes() -> ApiRouter<AppState> {
    ApiRouter::new()
        .nest("/users", users::routes())
        .nest("/profile", profile::routes())
        .nest("/recipes", recipes::routes())
}

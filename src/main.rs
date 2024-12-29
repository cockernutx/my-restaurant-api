use aide::{
    axum::{routing::get, ApiRouter, IntoApiResponse},
    openapi::{Info, OpenApi},
    scalar::Scalar,
};
use auth::{Claims, KEYS};
use axum::{extract::FromRef, Extension, Json};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Header};
use surrealdb::{
    engine::remote::ws::{Client, Ws},
    opt::auth::Root,
    Surreal,
};
use tracing::{debug, info};

mod routes;
mod auth;
mod shared_types;

pub type Pool = Surreal<Client>;

#[derive(Clone)]
pub struct AppState {
    pub surreal: Pool
}

impl FromRef<AppState> for Pool {
    fn from_ref(input: &AppState) -> Self {
        input.surreal.clone()
    }
}
// Note that this clones the document on each request.
// To be more efficient, we could wrap it into an Arc,
// or even store it as a serialized string.
async fn serve_api(Extension(api): Extension<OpenApi>) -> impl IntoApiResponse {
    Json(api)
}


#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let surreal = Pool::new::<Ws>("surrealdb:8000")
        .await
        .expect("could not connect to database");
    surreal
        .signin(Root {
            username: "root",
            password: "root",
        })
        .await
        .expect("could not login on database");

    surreal
        .use_ns("my-restaurant")
        .use_db("restaurant")
        .await
        .expect("could not switch to database context");


    
    let state = AppState { surreal };

    let app = ApiRouter::new()
        .route("/scalar", Scalar::new("/api.json").axum_route())
        // We'll serve our generated document here.
        .route("/api.json", get(serve_api))
        .nest("/", routes::routes())
        .with_state(state);

    let mut api = OpenApi {
        info: Info {
            description: Some("an example API".to_string()),
            ..Info::default()
        },
        ..OpenApi::default()
    };

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    if cfg!(debug_assertions) {
        let token = encode(&Header::default(), &Claims {
            sub: "debugger".to_string(),
            exp: (Utc::now() + Duration::weeks(1000)).timestamp() as usize,
            permissions: vec!["add_users".to_string()]
        }, &KEYS.encoding).expect("could not generate debug JWT");
        debug!("debugger JWT: {token}");
    }

    info!("starting server at: http://0.0.0.0:3000");
    axum::serve(
        listener,
        app
            // Generate the documentation.
            .finish_api(&mut api)
            // Expose the documentation to the handlers.
            .layer(Extension(api))
            .into_make_service(),
    )
    .await
    .unwrap();
}

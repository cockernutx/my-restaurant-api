use std::sync::Arc;

use aide::{
    axum::{routing::get, ApiRouter, IntoApiResponse},
    openapi::{Info, OpenApi},
    scalar::Scalar,
};
use auth_operator::{Claims, KEYS};
use axum::{extract::FromRef, response::IntoResponse, Extension, Json};
use chrono::{Duration, Utc};
use fastembed::{InitOptions, TextEmbedding};
use jsonwebtoken::{encode, Header};
use surrealdb::{
    engine::remote::ws::{Client, Ws},
    opt::auth::Root,
    Surreal,
};
use tracing::{debug, info};

mod routes;
mod auth_operator;
mod shared_types;

pub type Pool = Surreal<Client>;

#[derive(Clone)]
pub struct AppState {
    pub surreal: Pool,
    pub emb: Arc<TextEmbedding>
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
    Json(api).into_response()
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
    
    let emb = TextEmbedding::try_new(InitOptions::new(fastembed::EmbeddingModel::MxbaiEmbedLargeV1)).expect("could not load embeddings model");
    let emb = Arc::new(emb);
    
    let state = AppState { surreal, emb };

    let app = ApiRouter::new()
        .route("/scalar", Scalar::new("/api.json").axum_route())
        // We'll serve our generated document here.
        .route("/api.json", get(serve_api))
        .nest("/", routes::routes())
        .with_state(state);

    let mut api = OpenApi {
        info: Info {
            title: "My restaurant API".to_string(),
            description: Some("The my-restaurant API".to_string()),
            ..Info::default()
        },
        openapi: "3.1.1".to_string().into(),
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
    .unwrap()
}

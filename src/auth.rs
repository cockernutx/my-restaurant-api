use std::sync::LazyLock;

use aide::{
    openapi::{Parameter, ParameterData, Response, Responses, SchemaObject},
    operation::add_parameters,
    OperationInput,
};
use axum::{async_trait, extract::FromRequestParts, http::request::Parts, RequestPartsExt};
use axum_error_handler::AxumErrorResponse;
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use jsonwebtoken::{decode, DecodingKey, EncodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

const JWT_SECRET: &str = env!("JWT_SECRET");

pub static KEYS: LazyLock<Keys> = LazyLock::new(|| Keys::new(JWT_SECRET.as_bytes()));

pub struct Keys {
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
}

impl Keys {
    fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}

#[derive(Debug, Error, AxumErrorResponse)]
pub enum AuthError {
    #[error("invalid token")]
    #[status_code("401")]
    InvalidToken
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub permissions: Vec<String>
}

#[async_trait]
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::InvalidToken)?;
        // Decode the user data
                
        let token_data = decode::<Claims>(bearer.token(), &KEYS.decoding, &Validation::default())
            .map_err(|_| AuthError::InvalidToken)?;


        Ok(token_data.claims)
    }
}

impl OperationInput for Claims {
    fn operation_input(ctx: &mut aide::gen::GenContext, operation: &mut aide::openapi::Operation) {
        let s = ctx.schema.subschema_for::<String>();
        match &mut operation.responses {
            Some(responses) => {
                responses.responses.insert(
                    aide::openapi::StatusCode::Code(401),
                    aide::openapi::ReferenceOr::Item(Response {
                        description: "unauthorized".to_string(),
                        ..Default::default()
                    }),
                );
            }
            None => {
                let mut responses = Responses::default();
                responses.responses.insert(
                    aide::openapi::StatusCode::Code(401),
                    aide::openapi::ReferenceOr::Item(Response {
                        description: "unauthorized".to_string(),
                        ..Default::default()
                    }),
                );
                operation.responses = Some(responses);
            }
        }
        add_parameters(
            ctx,
            operation,
            [Parameter::Header {
                parameter_data: ParameterData {
                    name: "Authorization".to_string(),
                    description: Some("JWT received when authenticated.".to_string()),
                    required: true,
                    format: aide::openapi::ParameterSchemaOrContent::Schema(SchemaObject {
                        json_schema: s,
                        example: None,
                        external_docs: None,
                    }),
                    extensions: Default::default(),
                    deprecated: None,
                    example: Some(json!("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")),
                    examples: Default::default(),
                    explode: None,
                },
                style: aide::openapi::HeaderStyle::Simple,
            }],
        );
    }
}

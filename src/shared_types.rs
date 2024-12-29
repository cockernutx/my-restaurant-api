use aide::OperationIo;
use axum_error_handler::AxumErrorResponse;
use serde::{Deserialize, Serialize};
use surrealdb::sql::Thing;
use thiserror::Error;

#[derive(Debug, Serialize, Deserialize)]
pub struct Record {
    pub id: Thing,
}

#[derive(Debug, Error, AxumErrorResponse, OperationIo)]
pub enum CommonError {
    #[error("database error: {0}")]
    #[status_code("500")]
    DatabaseError(#[from] surrealdb::Error),
}
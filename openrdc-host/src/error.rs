// SPDX-License-Identifier: Apache-2.0
use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::json;

pub fn err(
    status: StatusCode,
    code: &str,
    message: String,
    retryable: bool,
    request_id: &str,
) -> axum::response::Response {
    let body = Json(json!({"error": {
        "code": code, "message": message,
        "retryable": retryable, "request_id": request_id,
    }}));
    (status, body).into_response()
}

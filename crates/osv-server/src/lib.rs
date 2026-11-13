//! OSV-compatible HTTP routes backed by a local SQLite store.

mod query;

use std::sync::Arc;

use axum::extract::{Path, State, rejection::PathRejection};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use osv_api::RpcStatus;
use osv_store::{Lookup, Store};
use tokio::sync::Semaphore;

const LOOKUP_WORKERS: usize = 8;

#[derive(Clone)]
struct ServerState {
    store: Arc<Store>,
    workers: Arc<Semaphore>,
}

pub fn router(store: Store) -> Router {
    let state = ServerState {
        store: Arc::new(store),
        workers: Arc::new(Semaphore::new(LOOKUP_WORKERS)),
    };
    Router::new()
        .route("/v1/vulns/{id}", get(get_vulnerability))
        .route("/v1/vulns", get(missing_id))
        .route("/v1/vulns/", get(missing_id))
        .route("/v1/query", post(query::single))
        .route("/v1/querybatch", post(query::batch))
        .with_state(state)
}

async fn get_vulnerability(
    State(state): State<ServerState>,
    id: Result<Path<String>, PathRejection>,
) -> Response {
    let Ok(Path(id)) = id else {
        return rpc_error(StatusCode::BAD_REQUEST, 3, "Invalid ID");
    };
    if id.len() > 100 {
        return rpc_error(StatusCode::BAD_REQUEST, 3, "ID is too long");
    }

    let permit = state
        .workers
        .acquire_owned()
        .await
        .expect("worker semaphore stays open");
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        state.store.lookup(&id)
    })
    .await
    {
        Ok(Ok(Lookup::Found(json))) => {
            ([(header::CONTENT_TYPE, "application/json")], json).into_response()
        }
        Ok(Ok(Lookup::Missing)) => rpc_error(StatusCode::NOT_FOUND, 5, "Vulnerability not found"),
        Ok(Ok(Lookup::Aliases(aliases))) => rpc_error(
            StatusCode::NOT_FOUND,
            5,
            format!(
                "Vulnerability not found, but the following aliases were: {}",
                aliases.join(" ")
            ),
        ),
        Ok(Err(error)) => {
            tracing::error!(%error, "error getting vulnerability");
            rpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                13,
                "error getting vulnerability",
            )
        }
        Err(error) => {
            tracing::error!(%error, "vulnerability lookup worker failed");
            rpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                13,
                "error getting vulnerability",
            )
        }
    }
}

async fn missing_id() -> Response {
    rpc_error(StatusCode::BAD_REQUEST, 3, "ID is required")
}

fn rpc_error(status: StatusCode, code: i32, message: impl Into<String>) -> Response {
    (
        status,
        Json(RpcStatus {
            code,
            message: message.into(),
            details: Vec::new(),
        }),
    )
        .into_response()
}

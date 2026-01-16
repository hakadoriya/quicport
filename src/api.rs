//! API サーバー実装
//!
//! ヘルスチェックや Prometheus 形式のメトリクスを提供する HTTP API サーバー

use anyhow::Result;
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

use crate::statistics::ServerStatistics;

/// ヘルスチェックレスポンス
#[derive(Serialize)]
struct HealthCheckResponse {
    status: &'static str,
}

/// GET /healthcheck
async fn healthcheck() -> Json<HealthCheckResponse> {
    Json(HealthCheckResponse { status: "SERVING" })
}

/// GET /metrics
///
/// Prometheus 形式でメトリクスを返す
async fn metrics(State(stats): State<Arc<ServerStatistics>>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        stats.to_prometheus(),
    )
}

/// API サーバーを起動
pub async fn run(listen: SocketAddr, statistics: Arc<ServerStatistics>) -> Result<()> {
    let app = Router::new()
        .route("/healthcheck", get(healthcheck))
        .route("/metrics", get(metrics))
        .with_state(statistics);

    let listener = tokio::net::TcpListener::bind(listen).await?;
    info!("API server listening on {}", listen);

    axum::serve(listener, app).await?;

    Ok(())
}

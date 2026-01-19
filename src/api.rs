//! API サーバー実装
//!
//! Private API（メトリクス、管理操作）と Public API（ヘルスチェック）を提供
//!
//! - Private API: インターネットから見える（QUIC と同じポートの TCP）
//! - Public API: localhost からのみアクセス可能

use anyhow::Result;
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

use crate::control_plane::ControlPlane;
use crate::statistics::ServerStatistics;

/// Private API サーバーの状態
#[derive(Clone)]
pub struct PrivateApiState {
    pub statistics: Arc<ServerStatistics>,
    pub control_plane: Option<Arc<ControlPlane>>,
}

/// ヘルスチェックレスポンス
#[derive(Serialize)]
struct HealthCheckResponse {
    status: &'static str,
}

/// Graceful restart レスポンス
#[derive(Serialize)]
struct GracefulRestartResponse {
    status: &'static str,
    message: String,
}

/// GET /healthcheck
async fn healthcheck() -> Json<HealthCheckResponse> {
    Json(HealthCheckResponse { status: "SERVING" })
}

/// GET /metrics
///
/// Prometheus 形式でメトリクスを返す
async fn metrics(State(state): State<PrivateApiState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state.statistics.to_prometheus(),
    )
}

/// POST /graceful-restart
///
/// グレースフルリスタートを実行
async fn graceful_restart(State(state): State<PrivateApiState>) -> impl IntoResponse {
    match &state.control_plane {
        Some(cp) => match cp.graceful_restart().await {
            Ok(()) => (
                StatusCode::OK,
                Json(GracefulRestartResponse {
                    status: "OK",
                    message: "Graceful restart initiated".to_string(),
                }),
            ),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(GracefulRestartResponse {
                    status: "ERROR",
                    message: format!("Graceful restart failed: {}", e),
                }),
            ),
        },
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(GracefulRestartResponse {
                status: "ERROR",
                message: "Control plane not available".to_string(),
            }),
        ),
    }
}

/// Public API サーバーを起動（/healthcheck のみ）
///
/// インターネットから見えるエンドポイント
pub async fn run_public(listen: SocketAddr) -> Result<()> {
    let app = Router::new().route("/healthcheck", get(healthcheck));

    let listener = tokio::net::TcpListener::bind(listen).await?;
    info!(
        "Public API server listening on {} (healthcheck only)",
        listen
    );

    axum::serve(listener, app).await?;

    Ok(())
}

/// Private API サーバーを起動（/metrics, /graceful-restart）
///
/// localhost からのみアクセス可能なエンドポイント
pub async fn run_private(
    listen: SocketAddr,
    statistics: Arc<ServerStatistics>,
    control_plane: Option<Arc<ControlPlane>>,
) -> Result<()> {
    let state = PrivateApiState {
        statistics,
        control_plane,
    };

    let app = Router::new()
        .route("/healthcheck", get(healthcheck))
        .route("/metrics", get(metrics))
        .route("/api/graceful-restart", post(graceful_restart))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(listen).await?;
    info!("Private API server listening on {}", listen);

    axum::serve(listener, app).await?;

    Ok(())
}

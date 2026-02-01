//! API サーバー実装
//!
//! Private API（メトリクス、管理操作）と Public API（ヘルスチェック）を提供
//!
//! ## HTTP IPC API
//!
//! Control Plane ↔ Data Plane 間の通信は HTTP/JSON API で行います。
//! すべてのエンドポイントは POST メソッドを使用する RPC スタイルです。
//!
//! ### エンドポイント
//!
//! #### IPC 用 API (`/api/v1/ipc/*`)
//!
//! | メソッド | 説明 | 方向 |
//! |----------|------|------|
//! | `POST /api/v1/ipc/SendStatus` | 状態送信（登録・更新・応答すべて統合） | DP → CP |
//! | `POST /api/v1/ipc/ReceiveCommand` | コマンド受信（長ポーリング） | CP → DP |
//!
//! #### 管理用 API (`/api/v1/admin/*`)
//!
//! | メソッド | 説明 |
//! |----------|------|
//! | `POST /api/v1/admin/ListDataPlanes` | 全 DP 一覧 |
//! | `POST /api/v1/admin/GetDataPlaneStatus` | 特定 DP の詳細 |
//! | `POST /api/v1/admin/DrainDataPlane` | ドレイン |
//! | `POST /api/v1/admin/ShutdownDataPlane` | シャットダウン |
//! | `POST /api/v1/admin/GetConnections` | 接続一覧（dp_id 指定必須） |
//! | `POST /api/v1/admin/ListTunnels` | トンネル一覧（全 DP 横断可） |
//! | `POST /api/v1/admin/ListConnections` | 接続一覧（全 DP 横断可） |
//!
//! ## API アクセス
//!
//! - Private API: localhost からのみアクセス可能（/metrics, /api/v1/*）
//! - Public API: インターネットから見える（/healthcheck のみ）

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
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

use crate::control_plane::ControlPlane;
use crate::ipc::state::{HttpDataPlane, HttpIpcState, parse_hex_dp_id};
use crate::ipc::{
    CommandWithId, ConnectionInfoWithDpId, ControlCommand,
    DataPlaneSummary, DrainDataPlaneRequest,
    DrainDataPlaneResponse, ErrorResponse, GetConnectionsRequest, GetConnectionsResponse,
    GetDataPlaneStatusRequest, ListConnectionsRequest,
    ListConnectionsResponse, ListDataPlanesRequest, ListDataPlanesResponse, ListTunnelsRequest,
    ListTunnelsResponse, ReceiveCommandRequest, ReceiveCommandResponse, SendStatusRequest,
    SendStatusResponse, ShutdownDataPlaneRequest, ShutdownDataPlaneResponse,
    TunnelInfoWithDpId,
};
use crate::statistics::ServerStatistics;

// =============================================================================
// API 状態
// =============================================================================

/// Private API サーバーの状態
#[derive(Clone)]
pub struct PrivateApiState {
    pub statistics: Arc<ServerStatistics>,
    pub control_plane: Option<Arc<ControlPlane>>,
    /// HTTP IPC 状態（新規追加）
    pub http_ipc: Arc<HttpIpcState>,
}

/// ヘルスチェックレスポンス
#[derive(Serialize)]
struct HealthCheckResponse {
    status: &'static str,
}

// =============================================================================
// API ハンドラー
// =============================================================================

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

// =============================================================================
// HTTP IPC ハンドラー（DP 用 API）
// =============================================================================

/// POST /api/v1/ipc/SendStatus
///
/// 状態送信（登録・更新・コマンド応答すべて統合）
/// 毎回全状態を冪等に送信することで、CP 再起動後も状態を復旧可能
///
/// - 初回呼び出し: DP 登録（dp_id が割り当てられ、auth_policy と config が返る）
/// - 以降の呼び出し: 状態更新のみ（auth_policy と config は None）
async fn send_status(
    State(state): State<PrivateApiState>,
    Json(req): Json<SendStatusRequest>,
) -> impl IntoResponse {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // 16 進数文字列をパースして u32 に変換（eBPF ルーティング用）
    let dp_id_u32 = match parse_hex_dp_id(&req.dp_id) {
        Ok(id) => id,
        Err(msg) => {
            warn!("SendStatus: invalid dp_id format: {}", req.dp_id);
            return (
                StatusCode::BAD_REQUEST, // 400
                Json(serde_json::json!(ErrorResponse {
                    error: "INVALID_DP_ID".to_string(),
                    message: msg,
                })),
            );
        }
    };

    // dp_id を正規化（常に "0x..." 形式）
    let dp_id = format!("{:#06x}", dp_id_u32);

    debug!(
        "SendStatus: dp_id={}, state={:?}, ack_cmd_id={:?}",
        dp_id, req.state, req.ack_cmd_id
    );

    // 既存の DP かどうかを確認
    let is_new_registration = {
        let data_planes = state.http_ipc.data_planes.read().await;
        !data_planes.contains_key(&dp_id)
    };

    if is_new_registration {
        // ========== 初回登録 ==========

        // dp_id 重複チェック
        {
            let active_ids = state.http_ipc.active_server_ids.read().await;
            if active_ids.contains(&dp_id_u32) {
                warn!("SendStatus: dp_id={} is already in use", dp_id);
                return (
                    StatusCode::CONFLICT, // 409
                    Json(serde_json::json!(ErrorResponse {
                        error: "DP_ID_DUPLICATE".to_string(),
                        message: format!("dp_id {} is already in use", dp_id),
                    })),
                );
            }
        }

        // 認証ポリシーを取得
        let auth_policy = state.http_ipc.auth_policy.read().await;
        let auth_policy = match auth_policy.as_ref() {
            Some(p) => p.clone(),
            None => {
                warn!("No auth policy configured");
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!(ErrorResponse {
                        error: "NO_AUTH_POLICY".to_string(),
                        message: "Authentication policy not configured".to_string(),
                    })),
                );
            }
        };

        // 設定を取得
        let config = state.http_ipc.dp_config.read().await.clone();

        // dp_id を使用中として登録
        state
            .http_ipc
            .active_server_ids
            .write()
            .await
            .insert(dp_id_u32);

        // データプレーンを登録
        {
            let mut data_planes = state.http_ipc.data_planes.write().await;
            let mut dp = HttpDataPlane::new(dp_id.clone(), req.pid, req.listen_addr.clone());
            dp.server_id = Some(dp_id_u32);
            dp.state = req.state;
            dp.active_tunnels = req.active_tunnels;
            dp.bytes_sent = req.bytes_sent;
            dp.bytes_received = req.bytes_received;
            dp.started_at = req.started_at;
            dp.last_active = now;
            data_planes.insert(dp_id.clone(), dp);
        }

        info!("Data plane registered: dp_id={}", dp_id);

        // 最新の ACTIVE をデフォルト ACTIVE として指示
        state.http_ipc.update_default_active_dp().await;

        (
            StatusCode::OK,
            Json(serde_json::json!(SendStatusResponse {
                dp_id,
                auth_policy: Some(auth_policy),
                config: Some(config),
            })),
        )
    } else {
        // ========== 状態更新 ==========

        let mut data_planes = state.http_ipc.data_planes.write().await;
        if let Some(dp) = data_planes.get_mut(&dp_id) {
            // 全状態を更新（冪等）
            dp.server_id = Some(dp_id_u32);
            dp.pid = req.pid;
            dp.state = req.state;
            dp.active_tunnels = req.active_tunnels;
            dp.bytes_sent = req.bytes_sent;
            dp.bytes_received = req.bytes_received;
            dp.listen_addr = req.listen_addr.clone();
            dp.last_active = now;

            // トンネル・接続情報が送信された場合はキャッシュを更新
            if let Some(tunnels) = req.tunnels {
                dp.tunnels = tunnels;
            }
            if let Some(connections) = req.connections {
                dp.connections = connections;
            }

            // dp_id を使用中として登録（CP 再起動後の復旧用）
            {
                let mut active_ids = state.http_ipc.active_server_ids.write().await;
                active_ids.insert(dp_id_u32);
            }

            // コマンド応答がある場合はログ出力
            if let (Some(cmd_id), Some(ack_status)) = (&req.ack_cmd_id, &req.ack_status) {
                debug!(
                    "Command acknowledged: dp_id={}, cmd_id={}, status={}",
                    dp_id, cmd_id, ack_status
                );
            }

            // 最新の ACTIVE をデフォルト ACTIVE として指示
            state.http_ipc.update_default_active_dp().await;

            (
                StatusCode::OK,
                Json(serde_json::json!(SendStatusResponse {
                    dp_id,
                    auth_policy: None,
                    config: None,
                })),
            )
        } else {
            // DP が見つからない（通常は発生しない）
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!(ErrorResponse {
                    error: "NOT_FOUND".to_string(),
                    message: format!("Data plane not found: {}", dp_id),
                })),
            )
        }
    }
}

/// POST /api/v1/ipc/ReceiveCommand
///
/// コマンド受信（長ポーリング）
async fn receive_command(
    State(state): State<PrivateApiState>,
    Json(req): Json<ReceiveCommandRequest>,
) -> impl IntoResponse {
    debug!(
        "ReceiveCommand: dp_id={}, wait_timeout={}s",
        req.dp_id, req.wait_timeout_secs
    );

    const MAX_WAIT_TIMEOUT_SECS: u64 = 60;

    if req.wait_timeout_secs > MAX_WAIT_TIMEOUT_SECS {
        warn!(
            "ReceiveCommand: dp_id={}, wait_timeout_secs={} exceeds max {}, clamping",
            req.dp_id, req.wait_timeout_secs, MAX_WAIT_TIMEOUT_SECS
        );
    }

    let timeout = Duration::from_secs(req.wait_timeout_secs.min(MAX_WAIT_TIMEOUT_SECS));

    // 即座にコマンドがあるか確認
    {
        let mut data_planes = state.http_ipc.data_planes.write().await;
        if let Some(dp) = data_planes.get_mut(&req.dp_id) {
            // 最終アクティブ時刻を更新
            dp.last_active = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            if !dp.pending_commands.is_empty() {
                let commands: Vec<CommandWithId> = dp.pending_commands.drain(..).collect();
                debug!(
                    "Returning {} commands immediately for {}",
                    commands.len(),
                    req.dp_id
                );
                return (
                    StatusCode::OK,
                    Json(serde_json::json!(ReceiveCommandResponse { commands })),
                );
            }
        } else {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!(ErrorResponse {
                    error: "NOT_FOUND".to_string(),
                    message: format!("Data plane not found: {}", req.dp_id),
                })),
            );
        }
    }

    // コマンドがない場合は長ポーリング
    tokio::select! {
        _ = state.http_ipc.command_notify.notified() => {
            // 通知を受けたので再度確認
        }
        _ = tokio::time::sleep(timeout) => {
            // タイムアウト
        }
    }

    // コマンドを取得
    let mut data_planes = state.http_ipc.data_planes.write().await;
    if let Some(dp) = data_planes.get_mut(&req.dp_id) {
        let commands: Vec<CommandWithId> = dp.pending_commands.drain(..).collect();
        debug!(
            "Returning {} commands after poll for {}",
            commands.len(),
            req.dp_id
        );
        (
            StatusCode::OK,
            Json(serde_json::json!(ReceiveCommandResponse { commands })),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!(ErrorResponse {
                error: "NOT_FOUND".to_string(),
                message: format!("Data plane not found: {}", req.dp_id),
            })),
        )
    }
}

/// POST /api/v1/ListDataPlanes
///
/// 全データプレーン一覧を取得
async fn list_data_planes(
    State(state): State<PrivateApiState>,
    Json(_req): Json<ListDataPlanesRequest>,
) -> impl IntoResponse {
    let data_planes = state.http_ipc.data_planes.read().await;
    let list: Vec<DataPlaneSummary> = data_planes.values().map(|dp| dp.to_summary()).collect();

    (
        StatusCode::OK,
        Json(serde_json::json!(ListDataPlanesResponse {
            data_planes: list
        })),
    )
}

/// POST /api/v1/GetDataPlaneStatus
///
/// 特定のデータプレーンの詳細を取得
async fn get_data_plane_status(
    State(state): State<PrivateApiState>,
    Json(req): Json<GetDataPlaneStatusRequest>,
) -> impl IntoResponse {
    let data_planes = state.http_ipc.data_planes.read().await;
    if let Some(dp) = data_planes.get(&req.dp_id) {
        (
            StatusCode::OK,
            Json(serde_json::json!(dp.to_status_response())),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!(ErrorResponse {
                error: "NOT_FOUND".to_string(),
                message: format!("Data plane not found: {}", req.dp_id),
            })),
        )
    }
}

/// POST /api/v1/DrainDataPlane
///
/// データプレーンをドレイン
async fn drain_data_plane(
    State(state): State<PrivateApiState>,
    Json(req): Json<DrainDataPlaneRequest>,
) -> impl IntoResponse {
    info!("DrainDataPlane: dp_id={}", req.dp_id);

    match state
        .http_ipc
        .send_command(&req.dp_id, ControlCommand::Drain)
        .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!(DrainDataPlaneResponse {
                status: "draining".to_string(),
            })),
        ),
        Err(msg) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!(ErrorResponse {
                error: "NOT_FOUND".to_string(),
                message: msg,
            })),
        ),
    }
}

/// POST /api/v1/ShutdownDataPlane
///
/// データプレーンをシャットダウン
async fn shutdown_data_plane(
    State(state): State<PrivateApiState>,
    Json(req): Json<ShutdownDataPlaneRequest>,
) -> impl IntoResponse {
    info!("ShutdownDataPlane: dp_id={}", req.dp_id);

    match state
        .http_ipc
        .send_command(&req.dp_id, ControlCommand::Shutdown)
        .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!(ShutdownDataPlaneResponse {
                status: "shutdown_initiated".to_string(),
            })),
        ),
        Err(msg) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!(ErrorResponse {
                error: "NOT_FOUND".to_string(),
                message: msg,
            })),
        ),
    }
}

/// POST /api/v1/GetConnections
///
/// 特定のデータプレーンの接続一覧を取得
async fn get_connections(
    State(state): State<PrivateApiState>,
    Json(req): Json<GetConnectionsRequest>,
) -> impl IntoResponse {
    let data_planes = state.http_ipc.data_planes.read().await;
    if let Some(dp) = data_planes.get(&req.dp_id) {
        (
            StatusCode::OK,
            Json(serde_json::json!(GetConnectionsResponse {
                connections: dp.connections.clone(),
            })),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!(ErrorResponse {
                error: "NOT_FOUND".to_string(),
                message: format!("Data plane not found: {}", req.dp_id),
            })),
        )
    }
}


/// POST /api/v1/admin/ListTunnels
///
/// トンネル一覧を取得（dp_id 省略時は全 DP 横断）
async fn list_tunnels(
    State(state): State<PrivateApiState>,
    Json(req): Json<ListTunnelsRequest>,
) -> impl IntoResponse {
    let data_planes = state.http_ipc.data_planes.read().await;

    let tunnels: Vec<TunnelInfoWithDpId> = if let Some(ref dp_id) = req.dp_id {
        // 特定 DP のトンネルのみ
        match data_planes.get(dp_id) {
            Some(dp) => dp
                .tunnels
                .iter()
                .map(|t| TunnelInfoWithDpId {
                    dp_id: dp_id.clone(),
                    tunnel: t.clone(),
                })
                .collect(),
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!(ErrorResponse {
                        error: "NOT_FOUND".to_string(),
                        message: format!("Data plane not found: {}", dp_id),
                    })),
                );
            }
        }
    } else {
        // 全 DP 横断
        data_planes
            .iter()
            .flat_map(|(dp_id, dp)| {
                dp.tunnels.iter().map(move |t| TunnelInfoWithDpId {
                    dp_id: dp_id.clone(),
                    tunnel: t.clone(),
                })
            })
            .collect()
    };

    (
        StatusCode::OK,
        Json(serde_json::json!(ListTunnelsResponse { tunnels })),
    )
}

/// POST /api/v1/admin/ListConnections
///
/// 接続一覧を取得（dp_id 省略時は全 DP 横断）
async fn list_connections(
    State(state): State<PrivateApiState>,
    Json(req): Json<ListConnectionsRequest>,
) -> impl IntoResponse {
    let data_planes = state.http_ipc.data_planes.read().await;

    let connections: Vec<ConnectionInfoWithDpId> = if let Some(ref dp_id) = req.dp_id {
        // 特定 DP の接続のみ
        match data_planes.get(dp_id) {
            Some(dp) => dp
                .connections
                .iter()
                .map(|c| ConnectionInfoWithDpId {
                    dp_id: dp_id.clone(),
                    connection: c.clone(),
                })
                .collect(),
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!(ErrorResponse {
                        error: "NOT_FOUND".to_string(),
                        message: format!("Data plane not found: {}", dp_id),
                    })),
                );
            }
        }
    } else {
        // 全 DP 横断
        data_planes
            .iter()
            .flat_map(|(dp_id, dp)| {
                dp.connections.iter().map(move |c| ConnectionInfoWithDpId {
                    dp_id: dp_id.clone(),
                    connection: c.clone(),
                })
            })
            .collect()
    };

    (
        StatusCode::OK,
        Json(serde_json::json!(ListConnectionsResponse { connections })),
    )
}

// =============================================================================
// サーバー起動
// =============================================================================

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

/// Private API サーバーを起動（/metrics, HTTP IPC）
///
/// localhost からのみアクセス可能なエンドポイント
pub async fn run_private(
    listen: SocketAddr,
    statistics: Arc<ServerStatistics>,
    control_plane: Option<Arc<ControlPlane>>,
) -> Result<()> {
    let http_ipc = Arc::new(HttpIpcState::new());
    run_private_with_http_ipc(listen, statistics, control_plane, http_ipc).await
}

/// Private API サーバーを起動（HTTP IPC 状態を外部から渡す）
pub async fn run_private_with_http_ipc(
    listen: SocketAddr,
    statistics: Arc<ServerStatistics>,
    control_plane: Option<Arc<ControlPlane>>,
    http_ipc: Arc<HttpIpcState>,
) -> Result<()> {
    let state = PrivateApiState {
        statistics,
        control_plane,
        http_ipc,
    };

    let app = Router::new()
        // API
        .route("/healthcheck", get(healthcheck))
        .route("/metrics", get(metrics))
        // HTTP IPC API (v1)
        // DP 用 API
        .route(crate::ipc::api_paths::SEND_STATUS, post(send_status))
        .route(crate::ipc::api_paths::RECEIVE_COMMAND, post(receive_command))
        // 管理用 API
        .route(crate::ipc::api_paths::LIST_DATA_PLANES, post(list_data_planes))
        .route(
            crate::ipc::api_paths::GET_DATA_PLANE_STATUS,
            post(get_data_plane_status),
        )
        .route(crate::ipc::api_paths::DRAIN_DATA_PLANE, post(drain_data_plane))
        .route(
            crate::ipc::api_paths::SHUTDOWN_DATA_PLANE,
            post(shutdown_data_plane),
        )
        .route(crate::ipc::api_paths::GET_CONNECTIONS, post(get_connections))
        .route(crate::ipc::api_paths::LIST_TUNNELS, post(list_tunnels))
        .route(crate::ipc::api_paths::LIST_CONNECTIONS, post(list_connections))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(listen).await?;
    info!("Private API server listening on {} (with HTTP IPC)", listen);

    axum::serve(listener, app).await?;

    Ok(())
}

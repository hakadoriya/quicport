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
//! | メソッド | 説明 | 呼び出し元 |
//! |----------|------|-----------|
//! | `POST /api/v1/RegisterDataPlane` | DP 登録 | DP |
//! | `POST /api/v1/PollCommands` | コマンドポーリング | DP |
//! | `POST /api/v1/AckCommand` | コマンド応答 | DP |
//! | `POST /api/v1/ReportEvent` | イベント報告 | DP |
//! | `POST /api/v1/ListDataPlanes` | 全 DP 一覧 | CLI/外部 |
//! | `POST /api/v1/GetDataPlaneStatus` | 特定 DP の詳細 | CLI/外部 |
//! | `POST /api/v1/DrainDataPlane` | ドレイン | CLI/外部 |
//! | `POST /api/v1/ShutdownDataPlane` | シャットダウン | CLI/外部 |
//! | `POST /api/v1/GetConnections` | 接続一覧 | CLI/外部 |
//!
//! ## レガシー API
//!
//! - Private API: localhost からのみアクセス可能
//! - Public API: インターネットから見える（QUIC と同じポートの TCP）

use anyhow::Result;
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Notify, RwLock};
use tracing::{debug, info, warn};

use crate::control_plane::ControlPlane;
use crate::ipc::{
    AckCommandRequest, AckCommandResponse, AuthPolicy, CommandWithId, ControlCommand,
    DataPlaneConfig, DataPlaneEvent, DataPlaneSummary, DataPlaneState,
    DrainDataPlaneRequest, DrainDataPlaneResponse, ErrorResponse, GetConnectionsRequest,
    GetConnectionsResponse, GetDataPlaneStatusRequest, GetDataPlaneStatusResponse,
    ListDataPlanesRequest, ListDataPlanesResponse, PollCommandsRequest, PollCommandsResponse,
    RegisterDataPlaneRequest, RegisterDataPlaneResponse, ReportEventRequest, ReportEventResponse,
    ShutdownDataPlaneRequest, ShutdownDataPlaneResponse, ConnectionInfo,
};
use crate::statistics::ServerStatistics;

// =============================================================================
// HTTP IPC 状態管理
// =============================================================================

/// Data Plane 情報（HTTP IPC 用）
pub struct HttpDataPlane {
    /// Data Plane ID
    pub dp_id: String,
    /// PID
    pub pid: u32,
    /// QUIC リッスンアドレス
    pub listen_addr: String,
    /// 状態
    pub state: DataPlaneState,
    /// アクティブ接続数
    pub active_connections: u32,
    /// 送信バイト数
    pub bytes_sent: u64,
    /// 受信バイト数
    pub bytes_received: u64,
    /// 起動時刻
    pub started_at: u64,
    /// 保留中のコマンドキュー
    pub pending_commands: VecDeque<CommandWithId>,
    /// 接続一覧（DP から報告されたもの）
    pub connections: Vec<ConnectionInfo>,
    /// 最終アクティブ時刻
    pub last_active: u64,
}

impl HttpDataPlane {
    /// 新しい HttpDataPlane を作成
    pub fn new(dp_id: String, pid: u32, listen_addr: String) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            dp_id,
            pid,
            listen_addr,
            state: DataPlaneState::Starting,
            active_connections: 0,
            bytes_sent: 0,
            bytes_received: 0,
            started_at: now,
            pending_commands: VecDeque::new(),
            connections: Vec::new(),
            last_active: now,
        }
    }

    /// 状態をサマリーに変換
    pub fn to_summary(&self) -> DataPlaneSummary {
        DataPlaneSummary {
            dp_id: self.dp_id.clone(),
            pid: self.pid,
            state: self.state,
            active_connections: self.active_connections,
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
        }
    }

    /// 詳細ステータスを取得
    pub fn to_status_response(&self) -> GetDataPlaneStatusResponse {
        GetDataPlaneStatusResponse {
            dp_id: self.dp_id.clone(),
            pid: self.pid,
            state: self.state,
            active_connections: self.active_connections,
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            started_at: self.started_at,
        }
    }
}

/// HTTP IPC 状態
pub struct HttpIpcState {
    /// 登録済みデータプレーン
    pub dataplanes: RwLock<HashMap<String, HttpDataPlane>>,
    /// コマンド ID カウンター
    command_id_counter: AtomicU64,
    /// 新コマンド通知（長ポーリング用）
    pub command_notify: Notify,
    /// 認証ポリシー
    pub auth_policy: RwLock<Option<AuthPolicy>>,
    /// データプレーン設定
    pub dp_config: RwLock<DataPlaneConfig>,
}

impl HttpIpcState {
    /// 新しい HttpIpcState を作成
    pub fn new() -> Self {
        Self {
            dataplanes: RwLock::new(HashMap::new()),
            command_id_counter: AtomicU64::new(1),
            command_notify: Notify::new(),
            auth_policy: RwLock::new(None),
            dp_config: RwLock::new(DataPlaneConfig::default()),
        }
    }

    /// 次のコマンド ID を生成
    pub fn next_command_id(&self) -> String {
        let id = self.command_id_counter.fetch_add(1, Ordering::SeqCst);
        format!("cmd_{}", id)
    }

    /// データプレーンにコマンドを送信
    pub async fn send_command(&self, dp_id: &str, command: ControlCommand) -> Result<String, String> {
        let mut dataplanes = self.dataplanes.write().await;
        if let Some(dp) = dataplanes.get_mut(dp_id) {
            let cmd_id = self.next_command_id();
            dp.pending_commands.push_back(CommandWithId {
                id: cmd_id.clone(),
                command,
            });
            // 長ポーリング中の DP に通知
            self.command_notify.notify_waiters();
            Ok(cmd_id)
        } else {
            Err(format!("Data plane not found: {}", dp_id))
        }
    }

    /// 全 ACTIVE データプレーンにコマンドを送信
    pub async fn broadcast_command(&self, command: ControlCommand) {
        let mut dataplanes = self.dataplanes.write().await;
        for (_, dp) in dataplanes.iter_mut() {
            if dp.state == DataPlaneState::Active {
                let cmd_id = self.next_command_id();
                dp.pending_commands.push_back(CommandWithId {
                    id: cmd_id,
                    command: command.clone(),
                });
            }
        }
        self.command_notify.notify_waiters();
    }
}

impl Default for HttpIpcState {
    fn default() -> Self {
        Self::new()
    }
}

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

/// Graceful restart レスポンス
#[derive(Serialize)]
struct GracefulRestartResponse {
    status: &'static str,
    message: String,
}

/// 接続一覧レスポンス
#[derive(Serialize)]
struct ConnectionsResponse {
    connections: Vec<crate::ipc::ConnectionInfo>,
}

// =============================================================================
// レガシー API ハンドラー
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

/// GET /api/conns
///
/// 接続一覧を取得
async fn get_connections_legacy(State(state): State<PrivateApiState>) -> impl IntoResponse {
    match &state.control_plane {
        Some(cp) => {
            let connections = cp.get_all_connections().await;
            (StatusCode::OK, Json(ConnectionsResponse { connections }))
        }
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ConnectionsResponse {
                connections: Vec::new(),
            }),
        ),
    }
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

// =============================================================================
// HTTP IPC ハンドラー
// =============================================================================

/// POST /api/v1/RegisterDataPlane
///
/// データプレーンを登録し、認証ポリシーを返す
async fn register_data_plane(
    State(state): State<PrivateApiState>,
    Json(req): Json<RegisterDataPlaneRequest>,
) -> impl IntoResponse {
    info!(
        "RegisterDataPlane: pid={}, listen_addr={}",
        req.pid, req.listen_addr
    );

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

    // Data Plane ID を生成
    let dp_id = format!("dp_{}", req.pid);

    // データプレーンを登録
    {
        let mut dataplanes = state.http_ipc.dataplanes.write().await;
        let dp = HttpDataPlane::new(dp_id.clone(), req.pid, req.listen_addr);
        dataplanes.insert(dp_id.clone(), dp);
    }

    info!("Data plane registered: {}", dp_id);

    (
        StatusCode::OK,
        Json(serde_json::json!(RegisterDataPlaneResponse {
            dp_id,
            auth_policy,
            config,
        })),
    )
}

/// POST /api/v1/PollCommands
///
/// 長ポーリングでコマンドを取得
async fn poll_commands(
    State(state): State<PrivateApiState>,
    Json(req): Json<PollCommandsRequest>,
) -> impl IntoResponse {
    debug!(
        "PollCommands: dp_id={}, wait_timeout={}s",
        req.dp_id, req.wait_timeout_secs
    );

    let timeout = Duration::from_secs(req.wait_timeout_secs.min(60)); // 最大 60 秒

    // 即座にコマンドがあるか確認
    {
        let mut dataplanes = state.http_ipc.dataplanes.write().await;
        if let Some(dp) = dataplanes.get_mut(&req.dp_id) {
            // 最終アクティブ時刻を更新
            dp.last_active = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            if !dp.pending_commands.is_empty() {
                let commands: Vec<CommandWithId> = dp.pending_commands.drain(..).collect();
                debug!("Returning {} commands immediately for {}", commands.len(), req.dp_id);
                return (
                    StatusCode::OK,
                    Json(serde_json::json!(PollCommandsResponse { commands })),
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
    let mut dataplanes = state.http_ipc.dataplanes.write().await;
    if let Some(dp) = dataplanes.get_mut(&req.dp_id) {
        let commands: Vec<CommandWithId> = dp.pending_commands.drain(..).collect();
        debug!("Returning {} commands after poll for {}", commands.len(), req.dp_id);
        (
            StatusCode::OK,
            Json(serde_json::json!(PollCommandsResponse { commands })),
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

/// POST /api/v1/AckCommand
///
/// コマンドの実行結果を受信
async fn ack_command(
    State(state): State<PrivateApiState>,
    Json(req): Json<AckCommandRequest>,
) -> impl IntoResponse {
    debug!(
        "AckCommand: dp_id={}, cmd_id={}, status={}",
        req.dp_id, req.cmd_id, req.status
    );

    let mut dataplanes = state.http_ipc.dataplanes.write().await;
    if let Some(dp) = dataplanes.get_mut(&req.dp_id) {
        // ステータスを更新
        if let Some(result) = req.result {
            dp.state = result.state;
            dp.active_connections = result.active_connections;
            dp.bytes_sent = result.bytes_sent;
            dp.bytes_received = result.bytes_received;
        }

        (
            StatusCode::OK,
            Json(serde_json::json!(AckCommandResponse { acknowledged: true })),
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

/// POST /api/v1/ReportEvent
///
/// イベントを受信
async fn report_event(
    State(state): State<PrivateApiState>,
    Json(req): Json<ReportEventRequest>,
) -> impl IntoResponse {
    debug!("ReportEvent: dp_id={}, event={:?}", req.dp_id, req.event);

    let mut dataplanes = state.http_ipc.dataplanes.write().await;
    if let Some(dp) = dataplanes.get_mut(&req.dp_id) {
        // イベントに応じて状態を更新
        match &req.event {
            DataPlaneEvent::Ready { pid, listen_addr } => {
                dp.pid = *pid;
                dp.listen_addr = listen_addr.clone();
                dp.state = DataPlaneState::Active;
                info!("Data plane {} is ready (pid={}, addr={})", req.dp_id, pid, listen_addr);
            }
            DataPlaneEvent::Status(status) => {
                dp.state = status.state;
                dp.active_connections = status.active_connections;
                dp.bytes_sent = status.bytes_sent;
                dp.bytes_received = status.bytes_received;
            }
            DataPlaneEvent::ConnectionOpened { connection_id, remote_addr, protocol } => {
                dp.active_connections += 1;
                dp.connections.push(ConnectionInfo {
                    connection_id: *connection_id,
                    remote_addr: remote_addr.clone(),
                    protocol: protocol.clone(),
                });
            }
            DataPlaneEvent::ConnectionClosed { connection_id, bytes_sent, bytes_received } => {
                if dp.active_connections > 0 {
                    dp.active_connections -= 1;
                }
                dp.bytes_sent += bytes_sent;
                dp.bytes_received += bytes_received;
                dp.connections.retain(|c| c.connection_id != *connection_id);
            }
            DataPlaneEvent::Drained => {
                dp.state = DataPlaneState::Draining;
                info!("Data plane {} has drained", req.dp_id);
            }
            DataPlaneEvent::Connections { connections } => {
                dp.connections = connections.clone();
            }
            DataPlaneEvent::Error { code, message } => {
                warn!("Data plane {} error: {} - {}", req.dp_id, code, message);
            }
        }

        (
            StatusCode::OK,
            Json(serde_json::json!(ReportEventResponse { acknowledged: true })),
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
    let dataplanes = state.http_ipc.dataplanes.read().await;
    let list: Vec<DataPlaneSummary> = dataplanes.values().map(|dp| dp.to_summary()).collect();

    (
        StatusCode::OK,
        Json(serde_json::json!(ListDataPlanesResponse { dataplanes: list })),
    )
}

/// POST /api/v1/GetDataPlaneStatus
///
/// 特定のデータプレーンの詳細を取得
async fn get_data_plane_status(
    State(state): State<PrivateApiState>,
    Json(req): Json<GetDataPlaneStatusRequest>,
) -> impl IntoResponse {
    let dataplanes = state.http_ipc.dataplanes.read().await;
    if let Some(dp) = dataplanes.get(&req.dp_id) {
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

    match state.http_ipc.send_command(&req.dp_id, ControlCommand::Drain).await {
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

    match state.http_ipc.send_command(&req.dp_id, ControlCommand::Shutdown).await {
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
    let dataplanes = state.http_ipc.dataplanes.read().await;
    if let Some(dp) = dataplanes.get(&req.dp_id) {
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

/// Private API サーバーを起動（/metrics, /graceful-restart, HTTP IPC）
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
        // レガシー API
        .route("/healthcheck", get(healthcheck))
        .route("/metrics", get(metrics))
        .route("/api/conns", get(get_connections_legacy))
        .route("/api/graceful-restart", post(graceful_restart))
        // HTTP IPC API (v1)
        .route("/api/v1/RegisterDataPlane", post(register_data_plane))
        .route("/api/v1/PollCommands", post(poll_commands))
        .route("/api/v1/AckCommand", post(ack_command))
        .route("/api/v1/ReportEvent", post(report_event))
        .route("/api/v1/ListDataPlanes", post(list_data_planes))
        .route("/api/v1/GetDataPlaneStatus", post(get_data_plane_status))
        .route("/api/v1/DrainDataPlane", post(drain_data_plane))
        .route("/api/v1/ShutdownDataPlane", post(shutdown_data_plane))
        .route("/api/v1/GetConnections", post(get_connections))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(listen).await?;
    info!("Private API server listening on {} (with HTTP IPC)", listen);

    axum::serve(listener, app).await?;

    Ok(())
}

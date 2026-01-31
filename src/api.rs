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
//! | `POST /api/v1/admin/GetConnections` | 接続一覧 |
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
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Notify, RwLock};
use tracing::{debug, info, warn};

use crate::control_plane::ControlPlane;
use crate::ipc::{
    AuthPolicy, CommandWithId, ConnectionInfo, ControlCommand, DataPlaneConfig, DataPlaneState,
    DataPlaneSummary, DrainDataPlaneRequest, DrainDataPlaneResponse, ErrorResponse,
    GetConnectionsRequest, GetConnectionsResponse, GetDataPlaneStatusRequest,
    GetDataPlaneStatusResponse, ListDataPlanesRequest, ListDataPlanesResponse,
    ReceiveCommandRequest, ReceiveCommandResponse, SendStatusRequest, SendStatusResponse,
    ShutdownDataPlaneRequest, ShutdownDataPlaneResponse,
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
    /// server_id（eBPF ルーティング用）
    pub server_id: Option<u32>,
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
            server_id: None,
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
    /// 使用中の server_id 一覧（eBPF ルーティング用）
    pub active_server_ids: RwLock<HashSet<u32>>,
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
            active_server_ids: RwLock::new(HashSet::new()),
        }
    }

    /// 次のコマンド ID を生成
    pub fn next_command_id(&self) -> String {
        let id = self.command_id_counter.fetch_add(1, Ordering::SeqCst);
        format!("cmd_{}", id)
    }

    /// データプレーンにコマンドを送信
    pub async fn send_command(
        &self,
        dp_id: &str,
        command: ControlCommand,
    ) -> Result<String, String> {
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

    /// 全データプレーンのペンディングコマンドが配信されるまで待機
    ///
    /// 指定されたタイムアウト内にすべてのコマンドが配信されなかった場合でも終了する
    pub async fn wait_for_commands_delivered(&self, timeout: std::time::Duration) {
        let start = std::time::Instant::now();
        let check_interval = std::time::Duration::from_millis(100);

        loop {
            // タイムアウトチェック
            if start.elapsed() >= timeout {
                let dataplanes = self.dataplanes.read().await;
                let pending_count: usize = dataplanes
                    .values()
                    .map(|dp| dp.pending_commands.len())
                    .sum();
                if pending_count > 0 {
                    warn!(
                        "Timeout waiting for commands to be delivered, {} commands still pending",
                        pending_count
                    );
                }
                break;
            }

            // すべてのコマンドが配信されたかチェック
            let all_delivered = {
                let dataplanes = self.dataplanes.read().await;
                dataplanes.values().all(|dp| dp.pending_commands.is_empty())
            };

            if all_delivered {
                info!("All commands delivered to data planes");
                break;
            }

            tokio::time::sleep(check_interval).await;
        }
    }

    /// stale データプレーンを検出（削除はしない）
    ///
    /// `last_active` + `timeout_secs` < 現在時刻 の DP を stale と判定する。
    /// 実際の削除は eBPF map クリーンアップ成功後に `remove_dataplanes()` で行う。
    ///
    /// # Returns
    ///
    /// stale と判定された (dp_id, server_id) のリスト
    pub async fn detect_stale_dataplanes(&self, timeout_secs: u64) -> Vec<(String, u32)> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let dataplanes = self.dataplanes.read().await;
        dataplanes
            .iter()
            .filter_map(|(dp_id, dp)| {
                if dp.last_active + timeout_secs < now {
                    dp.server_id.map(|sid| (dp_id.clone(), sid))
                } else {
                    None
                }
            })
            .collect()
    }

    /// 指定されたデータプレーンを `dataplanes` および `active_server_ids` から削除
    ///
    /// eBPF map エントリの削除が成功した後に呼び出すことを想定。
    pub async fn remove_dataplanes(&self, entries: &[(String, u32)]) {
        let mut dataplanes = self.dataplanes.write().await;
        let mut active_ids = self.active_server_ids.write().await;
        for (dp_id, server_id) in entries {
            dataplanes.remove(dp_id);
            active_ids.remove(server_id);
            warn!(
                "Removed stale data plane: dp_id={}, server_id={}",
                dp_id, server_id
            );
        }
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

/// 16 進数文字列の dp_id を u32 にパース
///
/// "0x3039" → 12345
/// "0X3039" → 12345
/// "3039"   → 12345 (0x プレフィックスは任意)
fn parse_hex_dp_id(s: &str) -> Result<u32, String> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u32::from_str_radix(s, 16).map_err(|e| format!("Invalid dp_id format: {}", e))
}

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
        let dataplanes = state.http_ipc.dataplanes.read().await;
        !dataplanes.contains_key(&dp_id)
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
            let mut dataplanes = state.http_ipc.dataplanes.write().await;
            let mut dp = HttpDataPlane::new(dp_id.clone(), req.pid, req.listen_addr.clone());
            dp.server_id = Some(dp_id_u32);
            dp.state = req.state;
            dp.active_connections = req.active_connections;
            dp.bytes_sent = req.bytes_sent;
            dp.bytes_received = req.bytes_received;
            dp.started_at = req.started_at;
            dp.last_active = now;
            dataplanes.insert(dp_id.clone(), dp);
        }

        info!("Data plane registered: dp_id={}", dp_id);

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

        let mut dataplanes = state.http_ipc.dataplanes.write().await;
        if let Some(dp) = dataplanes.get_mut(&dp_id) {
            // 全状態を更新（冪等）
            dp.server_id = Some(dp_id_u32);
            dp.pid = req.pid;
            dp.state = req.state;
            dp.active_connections = req.active_connections;
            dp.bytes_sent = req.bytes_sent;
            dp.bytes_received = req.bytes_received;
            dp.listen_addr = req.listen_addr.clone();
            dp.last_active = now;

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
        let mut dataplanes = state.http_ipc.dataplanes.write().await;
        if let Some(dp) = dataplanes.get_mut(&req.dp_id) {
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
    let mut dataplanes = state.http_ipc.dataplanes.write().await;
    if let Some(dp) = dataplanes.get_mut(&req.dp_id) {
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
    let dataplanes = state.http_ipc.dataplanes.read().await;
    let list: Vec<DataPlaneSummary> = dataplanes.values().map(|dp| dp.to_summary()).collect();

    (
        StatusCode::OK,
        Json(serde_json::json!(ListDataPlanesResponse {
            dataplanes: list
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
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(listen).await?;
    info!("Private API server listening on {} (with HTTP IPC)", listen);

    axum::serve(listener, app).await?;

    Ok(())
}

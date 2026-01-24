//! データプレーン実装
//!
//! QUIC 接続とバックエンド TCP 接続を維持するデーモンです。
//! コントロールプレーン（quicport control-plane）とは別プロセスとして動作し、
//! コントロールプレーンの再起動・終了後も独立して動作を継続します。
//!
//! ## 責務
//!
//! - QUIC 終端: クライアントからの QUIC 接続を処理
//! - 認証実行: コントロールプレーンから受け取ったポリシーに基づき認証
//! - バックエンド接続: SSH 等への TCP 接続を確立・維持
//! - データ転送: QUIC ↔ TCP 間のデータ中継
//! - 独立動作: コントロールプレーン終了後も継続動作
//! - グレースフル終了: DRAIN モードで既存接続を処理しつつ終了

use anyhow::{Context, Result};
use quinn::{Connection, RecvStream, SendStream};
use socket2::{Domain, Protocol as SockProtocol, Socket, Type};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{broadcast, Mutex, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn, Instrument};

use crate::ipc::{
    AuthPolicy, CommandWithId, ControlCommand, DataPlaneConfig, DataPlaneState, DataPlaneStatus,
    ReceiveCommandRequest, ReceiveCommandResponse, SendStatusRequest, SendStatusResponse,
};
use crate::protocol::{
    CloseReason, ControlMessage, ControlStream, Protocol, ProtocolError, ResponseStatus,
};
use crate::quic::{
    authenticate_client_psk, authenticate_client_x25519, create_server_endpoint_for_ebpf,
    encode_base64_key, parse_base64_key,
};
use crate::statistics::ServerStatistics;

/// 接続 ID カウンター
static CONNECTION_ID_COUNTER: AtomicU32 = AtomicU32::new(1);

/// データプレーンの共有状態
pub struct DataPlane {
    /// プロセス状態
    state: RwLock<DataPlaneState>,
    /// 設定
    config: RwLock<DataPlaneConfig>,
    /// 認証ポリシー
    auth_policy: RwLock<Option<AuthPolicy>>,
    /// 統計情報
    statistics: Arc<ServerStatistics>,
    /// 起動時刻
    started_at: u64,
    /// PID
    pub pid: u32,
    /// シャットダウン通知用
    shutdown_tx: broadcast::Sender<()>,
    /// ドレイン通知用
    drain_tx: broadcast::Sender<()>,
    /// アクティブ接続数
    active_connections: AtomicU32,
    /// 総送信バイト数
    bytes_sent: AtomicU64,
    /// 総受信バイト数
    bytes_received: AtomicU64,
    /// 接続情報（GetConnections 用）
    connection_list: RwLock<HashMap<u32, (Protocol, SocketAddr)>>,
}

impl DataPlane {
    /// 新しいデータプレーンを作成
    pub fn new(config: DataPlaneConfig) -> Arc<Self> {
        let (shutdown_tx, _) = broadcast::channel(1);
        let (drain_tx, _) = broadcast::channel(1);

        let started_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Arc::new(Self {
            state: RwLock::new(DataPlaneState::Starting),
            config: RwLock::new(config),
            auth_policy: RwLock::new(None),
            statistics: Arc::new(ServerStatistics::new()),
            started_at,
            pid: std::process::id(),
            shutdown_tx,
            drain_tx,
            active_connections: AtomicU32::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            connection_list: RwLock::new(HashMap::new()),
        })
    }

    /// 状態を取得
    pub async fn get_state(&self) -> DataPlaneState {
        *self.state.read().await
    }

    /// 状態を設定
    pub async fn set_state(&self, state: DataPlaneState) {
        *self.state.write().await = state;
    }

    /// 認証ポリシーを設定
    pub async fn set_auth_policy(&self, policy: AuthPolicy) {
        *self.auth_policy.write().await = Some(policy);
    }

    /// 認証ポリシーを取得
    pub async fn get_auth_policy(&self) -> Option<AuthPolicy> {
        self.auth_policy.read().await.clone()
    }

    /// 設定を更新
    pub async fn set_config(&self, config: DataPlaneConfig) {
        *self.config.write().await = config;
    }

    /// 設定を取得
    pub async fn get_config(&self) -> DataPlaneConfig {
        self.config.read().await.clone()
    }

    /// 状態レポートを取得
    pub async fn get_status(&self) -> Result<DataPlaneStatus> {
        Ok(DataPlaneStatus {
            state: self.get_state().await,
            pid: self.pid,
            active_connections: self.active_connections.load(Ordering::SeqCst),
            bytes_sent: self.bytes_sent.load(Ordering::SeqCst),
            bytes_received: self.bytes_received.load(Ordering::SeqCst),
            started_at: self.started_at,
        })
    }

    /// シャットダウンを要求
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    /// ドレインを開始
    pub async fn drain(&self) {
        self.set_state(DataPlaneState::Draining).await;
        let _ = self.drain_tx.send(());
    }

    /// シャットダウン通知を購読
    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    /// ドレイン通知を購読
    pub fn subscribe_drain(&self) -> broadcast::Receiver<()> {
        self.drain_tx.subscribe()
    }

    /// 接続数をインクリメント
    pub fn connection_opened(&self) {
        self.active_connections.fetch_add(1, Ordering::SeqCst);
        self.statistics.connection_opened();
    }

    /// 接続数をデクリメント
    pub fn connection_closed(&self) {
        let prev = self.active_connections.fetch_sub(1, Ordering::SeqCst);
        self.statistics.connection_closed();

        // DRAINING 状態で接続が 0 になった場合はログを出力
        // 実際の終了判定はメインループで行う
        if prev == 1 {
            debug!("Active connections reached 0");
        }
    }

    /// バイト統計を更新
    pub fn add_bytes(&self, sent: u64, received: u64) {
        self.bytes_sent.fetch_add(sent, Ordering::SeqCst);
        self.bytes_received.fetch_add(received, Ordering::SeqCst);
        self.statistics.add_bytes_sent(sent);
        self.statistics.add_bytes_received(received);
    }

    /// 接続情報を登録
    pub async fn register_connection(&self, id: u32, protocol: Protocol, remote_addr: SocketAddr) {
        self.connection_list
            .write()
            .await
            .insert(id, (protocol, remote_addr));
    }

    /// 接続情報を削除
    pub async fn unregister_connection(&self, id: u32) {
        self.connection_list.write().await.remove(&id);
    }

    /// 接続一覧を取得
    pub async fn get_connections(&self) -> Vec<crate::ipc::ConnectionInfo> {
        self.connection_list
            .read()
            .await
            .iter()
            .map(|(id, (protocol, addr))| crate::ipc::ConnectionInfo {
                connection_id: *id,
                remote_addr: addr.to_string(),
                protocol: format!("{:?}", protocol),
            })
            .collect()
    }
}

// =============================================================================
// HTTP IPC クライアント
// =============================================================================

/// HTTP IPC クライアント
///
/// Control Plane と HTTP/JSON で通信するクライアント
pub struct HttpIpcClient {
    /// Control Plane の URL
    base_url: String,
    /// HTTP クライアント
    client: reqwest::Client,
    /// Data Plane ID（登録後に設定）
    dp_id: Option<String>,
}

impl HttpIpcClient {
    /// 新しい HTTP IPC クライアントを作成
    pub fn new(base_url: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(35)) // HTTP タイムアウト
            .connect_timeout(Duration::from_secs(5)) // 接続タイムアウト
            .tcp_keepalive(Duration::from_secs(15)) // TCP キープアライブ
            .pool_idle_timeout(Duration::from_secs(90)) // コネクションプール
            .build()
            .expect("Failed to create HTTP client");

        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
            dp_id: None,
        }
    }

    /// 状態を送信（登録・更新・コマンド応答すべて統合）
    ///
    /// - 初回呼び出し: DP 登録（auth_policy と config が返る）
    /// - 以降の呼び出し: 状態更新 + コマンド応答（auth_policy と config は None）
    ///
    /// server_id の重複チェックも同時に行う
    /// 重複時は 409 Conflict エラーが返る
    pub async fn send_status(
        &mut self,
        server_id: u32,
        pid: u32,
        listen_addr: &str,
        status: &DataPlaneStatus,
        ack_cmd_id: Option<&str>,
        ack_status: Option<&str>,
    ) -> anyhow::Result<SendStatusResponse> {
        let url = format!("{}/api/v1/dp/SendStatus", self.base_url);
        // server_id を 16 進数文字列にフォーマット（eBPF デバッグとの一貫性のため）
        let request = SendStatusRequest {
            server_id: format!("{:#06x}", server_id),
            pid,
            listen_addr: listen_addr.to_string(),
            state: status.state,
            active_connections: status.active_connections,
            bytes_sent: status.bytes_sent,
            bytes_received: status.bytes_received,
            started_at: status.started_at,
            ack_cmd_id: ack_cmd_id.map(|s| s.to_string()),
            ack_status: ack_status.map(|s| s.to_string()),
        };

        debug!(
            "SendStatus: url={}, server_id={:#06x}, state={:?}",
            url, server_id, status.state
        );

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .context("Failed to send SendStatus request")?;

        let status_code = response.status();
        if !status_code.is_success() {
            let text = response.text().await.unwrap_or_default();
            // 409 Conflict は server_id 重複を示す
            if status_code == reqwest::StatusCode::CONFLICT {
                return Err(anyhow::anyhow!(
                    "SERVER_ID_DUPLICATE: server_id={:#06x} is already in use",
                    server_id
                ));
            }
            return Err(anyhow::anyhow!(
                "SendStatus failed: status={}, body={}",
                status_code,
                text
            ));
        }

        let resp: SendStatusResponse = response
            .json()
            .await
            .context("Failed to parse SendStatus response")?;

        // dp_id を保存（初回登録時）
        if self.dp_id.is_none() {
            self.dp_id = Some(resp.dp_id.clone());
            info!(
                "Registered with Control Plane as {} (server_id={:#06x})",
                resp.dp_id, server_id
            );
        }

        Ok(resp)
    }

    /// コマンドを受信（長ポーリング）
    pub async fn receive_command(
        &self,
        wait_timeout_secs: u64,
    ) -> anyhow::Result<Vec<CommandWithId>> {
        let dp_id = self
            .dp_id
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Not registered with Control Plane"))?;

        let url = format!("{}/api/v1/dp/ReceiveCommand", self.base_url);
        let request = ReceiveCommandRequest {
            dp_id: dp_id.clone(),
            wait_timeout_secs,
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .context("Failed to send ReceiveCommand request")?;

        let status_code = response.status();
        if !status_code.is_success() {
            let text = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "ReceiveCommand failed: status={}, body={}",
                status_code,
                text
            ));
        }

        let resp: ReceiveCommandResponse = response
            .json()
            .await
            .context("Failed to parse ReceiveCommand response")?;

        Ok(resp.commands)
    }

    /// dp_id が登録済みかどうか
    pub fn is_registered(&self) -> bool {
        self.dp_id.is_some()
    }

    /// dp_id をリセット（再登録用）
    pub fn reset_registration(&mut self) {
        self.dp_id = None;
    }
}

// =============================================================================
// 接続管理
// =============================================================================

/// アクティブな接続を管理
struct ConnectionManager {
    connections: HashMap<u32, ConnectionInfo>,
}

struct ConnectionInfo {
    #[allow(dead_code)]
    protocol: Protocol,
    #[allow(dead_code)]
    remote_addr: SocketAddr,
    cancel_token: CancellationToken,
}

impl ConnectionManager {
    fn new() -> Self {
        Self {
            connections: HashMap::new(),
        }
    }

    fn add_connection(
        &mut self,
        id: u32,
        protocol: Protocol,
        remote_addr: SocketAddr,
        cancel_token: CancellationToken,
    ) {
        self.connections.insert(
            id,
            ConnectionInfo {
                protocol,
                remote_addr,
                cancel_token,
            },
        );
    }

    fn cancel_connection(&mut self, id: u32) -> bool {
        if let Some(info) = self.connections.remove(&id) {
            info.cancel_token.cancel();
            true
        } else {
            false
        }
    }

    fn remove_connection(&mut self, id: u32) {
        self.connections.remove(&id);
    }
}

/// データプレーンを起動
///
/// HTTP IPC アーキテクチャ:
/// 1. STARTING 状態で起動
/// 2. HTTP で CP に登録（リトライ付き）
/// 3. 登録成功後、認証ポリシーを取得
/// 4. ACTIVE 状態に遷移
/// 5. SO_REUSEPORT で QUIC ポートを LISTEN 開始
/// 6. 長ポーリングでコマンドを待機
pub async fn run(config: DataPlaneConfig, cp_url: &str) -> Result<()> {
    let data_plane = DataPlane::new(config.clone());

    let pid = std::process::id();

    // 初期状態を書き込み
    data_plane.set_state(DataPlaneState::Starting).await;
    info!(
        "Data plane starting (connecting to control plane at {})",
        cp_url
    );

    // HTTP IPC クライアントを作成
    let mut http_client = HttpIpcClient::new(cp_url);

    // server_id を 1 から MAX_SOCKETS-1 (65535) の範囲でランダム生成
    // RegisterDataPlane で重複チェックも行い、重複時は 409 → 別の server_id で再試行
    //
    // 【制約】
    // - REUSEPORT_SOCKARRAY マップはキーが 0 から max_entries-1 の範囲でなければならない
    // - platform/linux/bpf/quicport_reuseport.h で MAX_SOCKETS = 65536 と定義
    // - よって server_id は 1 から 65535 の範囲で生成（0 は無効値として避ける）
    const MAX_SOCKETS: u32 = 65536;
    const MAX_SERVER_ID_RETRY: u32 = 10;
    const MAX_CP_CONNECT_RETRY: u32 = 30;

    let mut server_id = (rand::random::<u32>() % (MAX_SOCKETS - 1)) + 1;
    let mut server_id_retries = 0;
    let mut cp_connect_retries = 0;

    // コントロールプレーンに登録（server_id 重複時はリトライ）
    // SendStatus で初回登録を行い、auth_policy と config を取得
    let (auth_policy, dp_config) = loop {
        // 初期状態を作成
        let initial_status = DataPlaneStatus {
            state: DataPlaneState::Starting,
            pid,
            active_connections: 0,
            bytes_sent: 0,
            bytes_received: 0,
            started_at: data_plane.started_at,
        };

        match http_client
            .send_status(
                server_id,
                pid,
                &config.listen_addr.to_string(),
                &initial_status,
                None,
                None,
            )
            .await
        {
            Ok(resp) => {
                // 初回登録時は auth_policy と config が返る
                match (resp.auth_policy, resp.config) {
                    (Some(auth_policy), Some(dp_config)) => {
                        info!(
                            "Registered with control plane (server_id={:#06x})",
                            server_id
                        );
                        break (auth_policy, dp_config);
                    }
                    _ => {
                        return Err(anyhow::anyhow!(
                            "SendStatus response missing auth_policy or config on initial registration"
                        ));
                    }
                }
            }
            Err(e) => {
                let err_str = e.to_string();

                // server_id 重複エラー (409 Conflict)
                if err_str.contains("SERVER_ID_DUPLICATE") {
                    server_id_retries += 1;
                    if server_id_retries >= MAX_SERVER_ID_RETRY {
                        return Err(anyhow::anyhow!(
                            "Failed to find available server_id after {} attempts",
                            MAX_SERVER_ID_RETRY
                        ));
                    }
                    // 別の server_id を生成してリトライ
                    let old_id = server_id;
                    server_id = (rand::random::<u32>() % (MAX_SOCKETS - 1)) + 1;
                    warn!(
                        "server_id={:#06x} is already in use, retrying with {:#06x} (attempt {}/{})",
                        old_id, server_id, server_id_retries, MAX_SERVER_ID_RETRY
                    );
                    // dp_id をリセットして再試行
                    http_client.reset_registration();
                    continue;
                }

                // CP 接続エラー
                cp_connect_retries += 1;
                if cp_connect_retries > MAX_CP_CONNECT_RETRY {
                    return Err(anyhow::anyhow!(
                        "Failed to register with control plane after {} attempts: {}",
                        MAX_CP_CONNECT_RETRY,
                        e
                    ));
                }
                debug!(
                    "Retrying registration to control plane ({}/{}): {}",
                    cp_connect_retries, MAX_CP_CONNECT_RETRY, e
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    };

    info!(
        "Generated random server_id={:#06x} for eBPF routing",
        server_id
    );

    // 認証ポリシーと設定を適用
    data_plane.set_auth_policy(auth_policy).await;
    data_plane.set_config(dp_config).await;

    // QUIC エンドポイントを作成
    // server_id が設定されている場合は eBPF ルーティング対応の CID Generator を使用

    // eBPF ルーターを保持する変数（Linux のみ）
    // run() 関数終了まで保持され、その間 eBPF マップが有効
    #[cfg(target_os = "linux")]
    let _ebpf_router: Option<crate::platform::linux::EbpfRouter>;

    // eBPF ルーティング用に常に server_id を使用
    let endpoint = {
        let sid = server_id;
        info!(
            "Creating QUIC endpoint with server_id={:#06x} for eBPF routing",
            sid
        );

        // eBPF 統合用: ソケットも取得
        let (endpoint, socket_for_ebpf) =
            create_server_endpoint_for_ebpf(config.listen_addr, "quicport-dataplane", sid)?;

        // Linux 時は eBPF ルーターをロードしてアタッチ
        #[cfg(target_os = "linux")]
        {
            use crate::platform::linux::{EbpfRouter, EbpfRouterConfig, is_ebpf_available};

            _ebpf_router = if is_ebpf_available() {
                match EbpfRouter::load(EbpfRouterConfig::default()) {
                    Ok(mut router) => {
                        // ソケットにプログラムをアタッチ
                        if let Err(e) = router.attach_to_socket(&socket_for_ebpf) {
                            warn!(
                                "Failed to attach eBPF SK_REUSEPORT program: {}. \
                                 Falling back to kernel default SO_REUSEPORT behavior. \
                                 This may cause connection resets during graceful restart.",
                                e
                            );
                            None
                        } else {
                            // サーバーを登録
                            if let Err(e) = router.register_server(sid, &socket_for_ebpf) {
                                warn!(
                                    "Failed to register server_id={} in eBPF map: {}",
                                    sid, e
                                );
                                None
                            } else {
                                info!(
                                    "eBPF SK_REUSEPORT routing enabled for server_id={}",
                                    sid
                                );
                                // router を保持して run() 終了まで eBPF マップを維持
                                Some(router)
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Failed to load eBPF router: {}. \
                             Falling back to kernel default SO_REUSEPORT behavior. \
                             This may cause connection resets during graceful restart.",
                            e
                        );
                        None
                    }
                }
            } else {
                info!(
                    "eBPF not available on this system. \
                     Using kernel default SO_REUSEPORT behavior."
                );
                None
            };
        }

        // 非 Linux 時
        #[cfg(not(target_os = "linux"))]
        {
            let _ = socket_for_ebpf; // unused variable warning 抑制
            debug!("eBPF routing not available (non-Linux platform)");
        }

        endpoint
    };
    info!("Data plane QUIC listening on {}", config.listen_addr);

    // ACTIVE 状態に移行
    data_plane.set_state(DataPlaneState::Active).await;
    info!("Data plane is now ACTIVE");

    let mut shutdown_rx = data_plane.subscribe_shutdown();
    let _drain_rx = data_plane.subscribe_drain();
    let drain_timeout = data_plane.get_config().await.drain_timeout;

    // HTTP IPC タスク
    // - 状態送信タスク: 5 秒間隔で SendStatus を呼び出し、状態を同期
    // - コマンド受信タスク: ReceiveCommand で長ポーリング
    let dp_for_ipc = data_plane.clone();
    let http_client = std::sync::Arc::new(tokio::sync::Mutex::new(http_client));
    let http_client_for_status = http_client.clone();
    let http_client_for_cmd = http_client.clone();
    let config_for_status = config.clone();
    let server_id_for_ipc = server_id;

    // 状態送信タスク（5 秒間隔で全状態を送信 + コマンド応答）
    let dp_for_status = dp_for_ipc.clone();
    let config_for_status_task = config_for_status.clone();
    let pending_acks: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let pending_acks_for_status = pending_acks.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;

            // 現在の状態を取得
            let status = match dp_for_status.get_status().await {
                Ok(s) => s,
                Err(e) => {
                    warn!("Failed to get status: {}", e);
                    continue;
                }
            };

            // 保留中のコマンド応答を取得
            let ack = {
                let mut acks = pending_acks_for_status.lock().await;
                acks.pop()
            };

            let (ack_cmd_id, ack_status_str) = match &ack {
                Some((cmd_id, status_str)) => (Some(cmd_id.as_str()), Some(status_str.as_str())),
                None => (None, None),
            };

            let mut client = http_client_for_status.lock().await;
            match client
                .send_status(
                    server_id_for_ipc,
                    dp_for_status.pid,
                    &config_for_status_task.listen_addr.to_string(),
                    &status,
                    ack_cmd_id,
                    ack_status_str,
                )
                .await
            {
                Ok(resp) => {
                    // auth_policy や config が更新された場合は適用
                    if let Some(auth_policy) = resp.auth_policy {
                        dp_for_status.set_auth_policy(auth_policy).await;
                        info!("Authentication policy updated via SendStatus");
                    }
                    if let Some(dp_config) = resp.config {
                        dp_for_status.set_config(dp_config).await;
                        info!("Configuration updated via SendStatus");
                    }
                }
                Err(e) => {
                    let err_str = e.to_string();

                    // NOT_FOUND (404) の場合は再登録を試みる
                    if err_str.contains("NOT_FOUND") || err_str.contains("status=404") {
                        let current_state = dp_for_status.get_state().await;
                        warn!(
                            "Registration lost (state={:?}), attempting re-registration...",
                            current_state
                        );
                        client.reset_registration();
                        match client
                            .send_status(
                                server_id_for_ipc,
                                dp_for_status.pid,
                                &config_for_status_task.listen_addr.to_string(),
                                &status,
                                None,
                                None,
                            )
                            .await
                        {
                            Ok(resp) => {
                                info!(
                                    "Re-registered with control plane (maintaining state={:?})",
                                    current_state
                                );
                                if let Some(auth_policy) = resp.auth_policy {
                                    dp_for_status.set_auth_policy(auth_policy).await;
                                }
                                if let Some(dp_config) = resp.config {
                                    dp_for_status.set_config(dp_config).await;
                                }
                            }
                            Err(re) => {
                                warn!("Re-registration failed: {}", re);
                            }
                        }
                    } else if err_str.contains("connect") || err_str.contains("Connection refused") {
                        debug!("Connection error sending status: {}", e);
                    } else {
                        debug!("SendStatus error: {}", e);
                    }
                }
            }
        }
    }.instrument(tracing::Span::current()));

    // コマンド受信タスク（長ポーリング）
    let dp_for_cmd = dp_for_ipc.clone();
    let pending_acks_for_cmd = pending_acks.clone();
    tokio::spawn(async move {
        loop {
            // 登録されるまで待機
            {
                let client = http_client_for_cmd.lock().await;
                if !client.is_registered() {
                    drop(client);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            }

            let commands = {
                let client = http_client_for_cmd.lock().await;
                match client.receive_command(30).await {
                    Ok(cmds) => cmds,
                    Err(e) => {
                        let err_str = e.to_string();

                        // NOT_FOUND (404) の場合は待機（状態送信タスクが再登録する）
                        if err_str.contains("NOT_FOUND") || err_str.contains("status=404") {
                            debug!("DP not found, waiting for re-registration...");
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        } else if err_str.contains("connect") || err_str.contains("Connection refused") {
                            debug!("Connection error receiving commands: {}", e);
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        } else {
                            debug!("ReceiveCommand error: {}, retrying in 1s", e);
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                        continue;
                    }
                }
            };

            for cmd in commands {
                debug!("Received command: id={}, {:?}", cmd.id, cmd.command);
                process_ipc_command(&dp_for_cmd, cmd.command.clone()).await;

                // コマンド応答を保留リストに追加（次回の SendStatus で送信）
                {
                    let mut acks = pending_acks_for_cmd.lock().await;
                    acks.push((cmd.id.clone(), "completed".to_string()));
                }

                // Shutdown コマンドの場合はループを抜ける
                if matches!(cmd.command, ControlCommand::Shutdown) {
                    info!("Shutdown command received, exiting command receive loop");
                    return;
                }
            }
        }
    }.instrument(tracing::Span::current()));

    // メインループ
    loop {
        tokio::select! {
            // シャットダウン
            _ = shutdown_rx.recv() => {
                info!("Data plane received shutdown signal");
                break;
            }

            // ドレインタイムアウト（drain_timeout == 0 の場合は無限待機）
            _ = async {
                let state = data_plane.get_state().await;
                if state == DataPlaneState::Draining && drain_timeout > 0 {
                    tokio::time::sleep(Duration::from_secs(drain_timeout)).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                warn!("Drain timeout reached ({} seconds), forcing shutdown", drain_timeout);
                break;
            }

            // ドレイン状態で接続数が 0 になった場合
            _ = async {
                loop {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    let state = data_plane.get_state().await;
                    let connections = data_plane.active_connections.load(Ordering::SeqCst);
                    debug!("Drain check: state={:?}, active_connections={}", state, connections);
                    if state == DataPlaneState::Draining && connections == 0 {
                        return;
                    }
                }
            } => {
                info!("All connections drained, shutting down");
                break;
            }

            // QUIC 接続
            result = endpoint.accept() => {
                match result {
                    Some(incoming) => {
                        let state = data_plane.get_state().await;
                        if state == DataPlaneState::Draining {
                            // DRAINING 状態では新規接続を拒否
                            debug!("Rejecting new connection in DRAINING state");
                            continue;
                        }

                        let dp = data_plane.clone();
                        tokio::spawn(async move {
                            match incoming.await {
                                Ok(connection) => {
                                    let remote_addr = connection.remote_address();
                                    info!("New QUIC connection from {}", remote_addr);
                                    dp.connection_opened();

                                    if let Err(e) = handle_quic_connection(dp.clone(), connection).await {
                                        error!("QUIC handler error: {}", e);
                                    }

                                    dp.connection_closed();
                                    info!("QUIC connection closed: {}", remote_addr);
                                }
                                Err(e) => {
                                    error!("Failed to accept QUIC connection: {}", e);
                                }
                            }
                        }.instrument(tracing::Span::current()));
                    }
                    None => {
                        info!("QUIC endpoint closed");
                        break;
                    }
                }
            }
        }
    }

    // 終了処理
    data_plane.set_state(DataPlaneState::Terminated).await;
    info!("Data plane terminated");

    Ok(())
}

/// IPC コマンドを処理
///
/// コマンドを実行し、必要な副作用（状態変更など）を適用する。
/// 結果は次回の SendStatus で送信されるため、戻り値は不要。
async fn process_ipc_command(data_plane: &DataPlane, cmd: ControlCommand) {
    match cmd {
        ControlCommand::SetAuthPolicy(policy) => {
            data_plane.set_auth_policy(policy).await;
            info!("Authentication policy updated");
        }

        ControlCommand::SetConfig(config) => {
            data_plane.set_config(config).await;
            info!("Configuration updated");
        }

        ControlCommand::Drain => {
            data_plane.drain().await;
            info!("Data plane entering DRAINING state");
        }

        ControlCommand::Shutdown => {
            info!("Data plane shutting down");
            data_plane.shutdown();
        }

        ControlCommand::GetStatus => {
            // 状態は次回の SendStatus で自動的に送信される
            debug!("GetStatus command received (status will be sent via SendStatus)");
        }

        ControlCommand::GetConnections => {
            // GetConnections の結果は現状では SendStatus で送信されないため、
            // 将来的に対応が必要な場合は SendStatusRequest に connections フィールドを追加する
            let connections = data_plane.get_connections().await;
            debug!("GetConnections command received: {} connections", connections.len());
        }
    }
}

/// QUIC 接続を処理
async fn handle_quic_connection(data_plane: Arc<DataPlane>, connection: Connection) -> Result<()> {
    let remote_addr = connection.remote_address();

    // 制御用ストリームを受け付け
    let (mut send, mut recv) = connection
        .accept_bi()
        .await
        .context("Failed to accept control stream")?;

    debug!("Control stream established with {}", remote_addr);

    // 認証ポリシーを取得
    let auth_policy = match data_plane.get_auth_policy().await {
        Some(policy) => policy,
        None => {
            warn!("No authentication policy configured, rejecting connection");
            return Ok(());
        }
    };

    // 認証を実行
    match &auth_policy {
        AuthPolicy::X25519 {
            authorized_pubkeys,
            server_private_key,
        } => {
            let pubkeys: Vec<[u8; 32]> = authorized_pubkeys
                .iter()
                .filter_map(|k| parse_base64_key(k).ok())
                .collect();
            let server_key =
                parse_base64_key(server_private_key).context("Invalid server private key")?;

            match authenticate_client_x25519(&mut send, &mut recv, &pubkeys, &server_key).await {
                Ok(client_pubkey) => {
                    data_plane.statistics.auth_x25519_success();
                    let pubkey_b64 = encode_base64_key(&client_pubkey);
                    info!(
                        "Client {} authenticated (pubkey: {}...)",
                        remote_addr,
                        &pubkey_b64[..16]
                    );
                }
                Err(crate::quic::X25519AuthError::PublicKeyNotAuthorized) => {
                    data_plane.statistics.auth_x25519_failed();
                    warn!(
                        "Authentication failed for {}: public key not authorized",
                        remote_addr
                    );
                    return Ok(());
                }
                Err(e) => {
                    data_plane.statistics.auth_x25519_failed();
                    warn!("Authentication failed for {}: {}", remote_addr, e);
                    return Ok(());
                }
            }
        }
        AuthPolicy::Psk { psk } => match authenticate_client_psk(&mut send, &mut recv, psk).await {
            Ok(()) => {
                data_plane.statistics.auth_psk_success();
                info!("Client {} authenticated (PSK)", remote_addr);
            }
            Err(e) => {
                data_plane.statistics.auth_psk_failed();
                warn!("PSK authentication failed for {}: {}", remote_addr, e);
                return Ok(());
            }
        },
    }

    // 制御ストリームをラップ
    let mut control_stream = ControlStream::new(send, recv);
    let conn_manager = Arc::new(Mutex::new(ConnectionManager::new()));

    // リクエストを待機
    let msg = control_stream
        .recv_message()
        .await
        .context("Failed to read initial request")?;

    match msg {
        ControlMessage::RemoteForwardRequest {
            port,
            protocol,
            local_destination,
        } => {
            info!(
                "RemoteForwardRequest from {}: port={}, protocol={}, local_destination={}",
                remote_addr, port, protocol, local_destination
            );

            handle_remote_forward(
                port,
                protocol,
                connection,
                control_stream,
                conn_manager,
                data_plane,
            )
            .await?;
        }
        ControlMessage::LocalForwardRequest {
            remote_destination,
            protocol,
            local_source,
        } => {
            info!(
                "LocalForwardRequest from {}: remote_destination={}, protocol={}, local_source={}",
                remote_addr, remote_destination, protocol, local_source
            );

            handle_local_forward(
                connection,
                control_stream,
                &remote_destination,
                protocol,
                conn_manager,
                data_plane,
            )
            .await?;
        }
        _ => {
            warn!("Unexpected message type from {}", remote_addr);
            let response = ControlMessage::RemoteForwardResponse {
                status: ResponseStatus::InternalError,
                message: "Expected RemoteForwardRequest or LocalForwardRequest".to_string(),
            };
            control_stream.send_message(&response).await?;
        }
    }

    Ok(())
}

// =============================================================================
// Remote Port Forwarding (RPF)
// =============================================================================

/// SO_REUSEADDR + SO_REUSEPORT 付きで TCP リスナーを作成
fn create_tcp_listener_with_reuseport(addr: SocketAddr) -> std::io::Result<std::net::TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::STREAM, Some(SockProtocol::TCP))?;
    socket.set_reuse_address(true)?;

    // SO_REUSEPORT を設定（グレースフルリスタート用）
    // これにより複数プロセスが同じポートで LISTEN 可能
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        unsafe {
            let optval: libc::c_int = 1;
            let ret = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEPORT,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            if ret != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }

    socket.bind(&addr.into())?;
    socket.listen(128)?;
    socket.set_nonblocking(true)?;

    Ok(socket.into())
}

/// Remote Port Forwarding を処理
async fn handle_remote_forward(
    port: u16,
    protocol: Protocol,
    quic_conn: Connection,
    mut control_stream: ControlStream,
    conn_manager: Arc<Mutex<ConnectionManager>>,
    data_plane: Arc<DataPlane>,
) -> Result<()> {
    let bind_addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;

    match protocol {
        Protocol::Tcp => {
            // SO_REUSEPORT を設定して TCP リスナーを作成
            let listener = match create_tcp_listener_with_reuseport(bind_addr) {
                Ok(std_listener) => match TcpListener::from_std(std_listener) {
                    Ok(l) => {
                        info!("TCP listener started on port {} (with SO_REUSEPORT)", port);

                        let response = ControlMessage::RemoteForwardResponse {
                            status: ResponseStatus::Success,
                            message: format!("Listening on port {}", port),
                        };
                        control_stream.send_message(&response).await?;

                        l
                    }
                    Err(e) => {
                        let response = ControlMessage::RemoteForwardResponse {
                            status: ResponseStatus::InternalError,
                            message: e.to_string(),
                        };
                        control_stream.send_message(&response).await?;
                        return Err(e.into());
                    }
                },
                Err(e) => {
                    let status = if e.kind() == std::io::ErrorKind::AddrInUse {
                        ResponseStatus::PortInUse
                    } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                        ResponseStatus::PermissionDenied
                    } else {
                        ResponseStatus::InternalError
                    };

                    let response = ControlMessage::RemoteForwardResponse {
                        status,
                        message: e.to_string(),
                    };
                    control_stream.send_message(&response).await?;
                    return Err(e.into());
                }
            };

            // TCP 接続を受け付けるループ
            // NOTE: DRAINING 状態では新規接続を拒否するが、既存のリレータスクは継続する
            // QUIC 接続ハンドルをドロップすると接続が閉じられるため、リレータスクが完了するまで待機する
            let mut drain_rx = data_plane.subscribe_drain();
            let mut draining = false;
            loop {
                tokio::select! {
                    // DRAINING 状態への移行（既存接続は維持）
                    _ = drain_rx.recv(), if !draining => {
                        info!("Data plane draining, RPF TCP will only process existing connections for port {}", port);
                        draining = true;
                        // break しない: 既存接続のリレータスクを継続処理
                    }

                    // すべてのリレータスクが完了したかチェック（DRAINING 状態のみ）
                    _ = async {
                        loop {
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            let conns = conn_manager.lock().await;
                            if conns.connections.is_empty() {
                                return;
                            }
                        }
                    }, if draining => {
                        info!("All RPF TCP relay tasks completed, releasing port {}", port);
                        break;
                    }

                    // QUIC 接続クローズ
                    reason = quic_conn.closed() => {
                        info!("QUIC connection closed: {:?}, releasing port {}", reason, port);
                        break;
                    }

                    // 新しい TCP 接続
                    result = listener.accept() => {
                        match result {
                            Ok((tcp_stream, tcp_addr)) => {
                                // DRAINING 状態では新しい接続を拒否
                                if draining {
                                    debug!("Rejecting new TCP connection in DRAINING state for port {}", port);
                                    continue;
                                }
                                let conn_id = CONNECTION_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
                                info!("New TCP connection {} from {}", conn_id, tcp_addr);

                                let (mut quic_send, quic_recv) = match quic_conn.open_bi().await {
                                    Ok(s) => s,
                                    Err(e) => {
                                        error!("Failed to open QUIC stream: {}", e);
                                        continue;
                                    }
                                };

                                if let Err(e) = quic_send.write_all(&conn_id.to_be_bytes()).await {
                                    error!("Failed to write conn_id to stream: {}", e);
                                    continue;
                                }

                                let new_conn_msg = ControlMessage::RemoteNewConnection {
                                    connection_id: conn_id,
                                    protocol: Protocol::Tcp,
                                };
                                if let Err(e) = control_stream.send_message(&new_conn_msg).await {
                                    error!("Failed to send RemoteNewConnection: {}", e);
                                    continue;
                                }

                                let cancel_token = CancellationToken::new();
                                conn_manager.lock().await.add_connection(
                                    conn_id,
                                    Protocol::Tcp,
                                    tcp_addr,
                                    cancel_token.clone(),
                                );
                                data_plane.register_connection(conn_id, Protocol::Tcp, tcp_addr).await;

                                let conn_manager_clone = conn_manager.clone();
                                let dp_clone = data_plane.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = relay_tcp_stream(
                                        conn_id,
                                        tcp_stream,
                                        quic_send,
                                        quic_recv,
                                        dp_clone.clone(),
                                        cancel_token,
                                    )
                                    .await
                                    {
                                        debug!("TCP relay ended for {}: {}", conn_id, e);
                                    }
                                    conn_manager_clone.lock().await.remove_connection(conn_id);
                                    dp_clone.unregister_connection(conn_id).await;
                                }.instrument(tracing::Span::current()));
                            }
                            Err(e) => {
                                error!("Failed to accept TCP connection: {}", e);
                            }
                        }
                    }

                    // 制御メッセージ
                    result = control_stream.recv_message() => {
                        match result {
                            Ok(ControlMessage::SessionClose) => {
                                info!("Client requested session close, releasing port {}", port);
                                break;
                            }
                            Ok(ControlMessage::ConnectionClose {
                                connection_id,
                                reason,
                            }) => {
                                info!(
                                    "Client requested connection close for conn_id={}: {:?}",
                                    connection_id, reason
                                );
                                conn_manager.lock().await.cancel_connection(connection_id);
                            }
                            Ok(msg) => {
                                debug!("Received control message: {:?}", msg);
                            }
                            Err(ProtocolError::StreamClosed) => {
                                info!("Control stream closed");
                                break;
                            }
                            Err(e) => {
                                let err_str = e.to_string();
                                if err_str.contains("closed") || err_str.contains("reset") || err_str.contains("lost") {
                                    info!("Client disconnected, releasing port {}: {}", port, e);
                                } else {
                                    error!("Control stream error: {}", e);
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
        Protocol::Udp => {
            // UDP ソケットを作成
            let socket = match UdpSocket::bind(bind_addr).await {
                Ok(s) => {
                    info!("UDP listener started on port {}", port);

                    let response = ControlMessage::RemoteForwardResponse {
                        status: ResponseStatus::Success,
                        message: format!("Listening on UDP port {}", port),
                    };
                    control_stream.send_message(&response).await?;

                    Arc::new(s)
                }
                Err(e) => {
                    let status = if e.kind() == std::io::ErrorKind::AddrInUse {
                        ResponseStatus::PortInUse
                    } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                        ResponseStatus::PermissionDenied
                    } else {
                        ResponseStatus::InternalError
                    };

                    let response = ControlMessage::RemoteForwardResponse {
                        status,
                        message: e.to_string(),
                    };
                    control_stream.send_message(&response).await?;
                    return Err(e.into());
                }
            };

            // UDP "仮想接続" を管理
            // キー: 送信元アドレス (IP:port)
            // 値: (conn_id, QUIC SendStream への送信用チャネル)
            //
            // 【ロック順序】デッドロック防止のため、複数ロック取得時は以下の順序を厳守:
            //   conn_manager → udp_connections
            // また、ロック保持中の await は最小限に抑える（tx.clone() 後に解放してから send）
            let udp_connections: Arc<
                Mutex<HashMap<SocketAddr, (u32, tokio::sync::mpsc::Sender<Vec<u8>>)>>,
            > = Arc::new(Mutex::new(HashMap::new()));

            let mut recv_buf = vec![0u8; 65535]; // UDP 最大パケットサイズ

            // UDP パケットを受け付けるループ
            // NOTE: DRAINING 状態では新規仮想接続の作成を停止するが、既存接続へのパケットは継続処理
            // （UDP はコネクションレスで同じソケットで全パケットを受信するため、ソケットを閉じると既存接続へのパケットも受信できなくなる）
            let mut drain_rx = data_plane.subscribe_drain();
            let mut draining = false;
            loop {
                tokio::select! {
                    // DRAINING 状態への移行（既存接続へのパケットは継続処理）
                    _ = drain_rx.recv(), if !draining => {
                        info!("Data plane draining, UDP port {} will only process existing connections", port);
                        draining = true;
                        // break しない: 既存接続へのパケットを継続処理
                    }

                    // QUIC 接続クローズ
                    reason = quic_conn.closed() => {
                        info!("QUIC connection closed: {:?}, releasing UDP port {}", reason, port);
                        break;
                    }

                    // UDP パケット受信
                    result = socket.recv_from(&mut recv_buf) => {
                        match result {
                            Ok((len, src_addr)) => {
                                let packet = recv_buf[..len].to_vec();
                                debug!("UDP packet from {}: {} bytes", src_addr, len);

                                // 既存の仮想接続を確認（ロックを短く保持）
                                let maybe_existing = {
                                    let conns = udp_connections.lock().await;
                                    conns.get(&src_addr).map(|(id, tx)| (*id, tx.clone()))
                                };

                                if let Some((conn_id, tx)) = maybe_existing {
                                    // 既存の接続にパケットを送信（ロック外で await）
                                    if tx.send(packet).await.is_err() {
                                        // チャネルが閉じている場合は接続を削除
                                        debug!("UDP connection {} channel closed, removing", conn_id);
                                        udp_connections.lock().await.remove(&src_addr);
                                    }
                                } else if draining {
                                    // DRAINING 状態では新規仮想接続を拒否（既存接続へのパケットは上で処理済み）
                                    debug!("Rejecting new UDP connection in DRAINING state for port {}", port);
                                    continue;
                                } else {
                                    // 新しい仮想接続を作成
                                    let conn_id = CONNECTION_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
                                    info!("New UDP connection {} from {}", conn_id, src_addr);

                                    // QUIC ストリームを開く（ロック外で await）
                                    let (mut quic_send, quic_recv) = match quic_conn.open_bi().await {
                                        Ok(s) => s,
                                        Err(e) => {
                                            error!("Failed to open QUIC stream for UDP: {}", e);
                                            continue;
                                        }
                                    };

                                    // conn_id を書き込む
                                    if let Err(e) = quic_send.write_all(&conn_id.to_be_bytes()).await {
                                        error!("Failed to write conn_id to stream: {}", e);
                                        continue;
                                    }

                                    // RemoteNewConnection を送信
                                    let new_conn_msg = ControlMessage::RemoteNewConnection {
                                        connection_id: conn_id,
                                        protocol: Protocol::Udp,
                                    };
                                    if let Err(e) = control_stream.send_message(&new_conn_msg).await {
                                        error!("Failed to send RemoteNewConnection: {}", e);
                                        continue;
                                    }

                                    // パケット送信用チャネルを作成
                                    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
                                    let cancel_token = CancellationToken::new();

                                    // 接続を登録（ロック順序を統一: conn_manager → udp_connections）
                                    {
                                        conn_manager.lock().await.add_connection(
                                            conn_id,
                                            Protocol::Udp,
                                            src_addr,
                                            cancel_token.clone(),
                                        );
                                        udp_connections.lock().await.insert(src_addr, (conn_id, tx.clone()));
                                    }
                                    data_plane.register_connection(conn_id, Protocol::Udp, src_addr).await;

                                    // 最初のパケットを送信（ロック外で await）
                                    let _ = tx.send(packet).await;

                                    // UDP リレータスクを起動
                                    let conn_manager_clone = conn_manager.clone();
                                    let udp_connections_clone = udp_connections.clone();
                                    let dp_clone = data_plane.clone();
                                    let socket_clone = socket.clone();
                                    tokio::spawn(async move {
                                        if let Err(e) = relay_rpf_udp_stream(
                                            conn_id,
                                            src_addr,
                                            socket_clone,
                                            rx,
                                            quic_send,
                                            quic_recv,
                                            dp_clone.clone(),
                                            cancel_token,
                                        )
                                        .await
                                        {
                                            debug!("UDP relay ended for {}: {}", conn_id, e);
                                        }
                                        // ロック順序を統一: conn_manager → udp_connections
                                        conn_manager_clone.lock().await.remove_connection(conn_id);
                                        udp_connections_clone.lock().await.remove(&src_addr);
                                        dp_clone.unregister_connection(conn_id).await;
                                    }.instrument(tracing::Span::current()));
                                }
                            }
                            Err(e) => {
                                error!("Failed to receive UDP packet: {}", e);
                            }
                        }
                    }

                    // 制御メッセージ
                    result = control_stream.recv_message() => {
                        match result {
                            Ok(ControlMessage::SessionClose) => {
                                info!("Client requested session close, releasing UDP port {}", port);
                                break;
                            }
                            Ok(ControlMessage::ConnectionClose {
                                connection_id,
                                reason,
                            }) => {
                                info!(
                                    "Client requested connection close for conn_id={}: {:?}",
                                    connection_id, reason
                                );
                                conn_manager.lock().await.cancel_connection(connection_id);
                            }
                            Ok(msg) => {
                                debug!("Received control message: {:?}", msg);
                            }
                            Err(ProtocolError::StreamClosed) => {
                                info!("Control stream closed");
                                break;
                            }
                            Err(e) => {
                                let err_str = e.to_string();
                                if err_str.contains("closed") || err_str.contains("reset") || err_str.contains("lost") {
                                    info!("Client disconnected, releasing UDP port {}: {}", port, e);
                                } else {
                                    error!("Control stream error: {}", e);
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

// =============================================================================
// Local Port Forwarding (LPF)
// =============================================================================

/// Local Port Forwarding を処理
async fn handle_local_forward(
    quic_conn: Connection,
    mut control_stream: ControlStream,
    remote_destination: &str,
    protocol: Protocol,
    conn_manager: Arc<Mutex<ConnectionManager>>,
    data_plane: Arc<DataPlane>,
) -> Result<()> {
    let response = ControlMessage::LocalForwardResponse {
        status: ResponseStatus::Success,
        message: format!("Ready to forward to {}", remote_destination),
    };
    control_stream.send_message(&response).await?;
    info!(
        "LocalForwardResponse sent: ready to forward to {}",
        remote_destination
    );

    let remote_destination = remote_destination.to_string();

    // NOTE: DRAINING 状態では新規ストリームの受付を停止するが、既存のリレータスクは継続する
    // QUIC 接続ハンドルをドロップすると接続が閉じられるため、リレータスクが完了するまで待機する
    let mut drain_rx = data_plane.subscribe_drain();
    let mut draining = false;
    loop {
        tokio::select! {
            // DRAINING 状態への移行（既存接続へのストリームは継続処理）
            _ = drain_rx.recv(), if !draining => {
                info!("Data plane draining, LPF will only process existing connections");
                draining = true;
                // break しない: 既存接続のストリームを継続処理
            }

            // すべてのリレータスクが完了したかチェック（DRAINING 状態のみ）
            _ = async {
                loop {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    let conns = conn_manager.lock().await;
                    if conns.connections.is_empty() {
                        return;
                    }
                }
            }, if draining => {
                info!("All LPF relay tasks completed, stopping handler");
                break;
            }

            // QUIC 接続クローズ
            reason = quic_conn.closed() => {
                info!("QUIC connection closed: {:?}, stopping LPF handler", reason);
                break;
            }

            // QUIC ストリームを accept
            result = quic_conn.accept_bi() => {
                match result {
                    Ok((send, mut recv)) => {
                        // DRAINING 状態では新しいストリームを拒否
                        if draining {
                            debug!("Rejecting new QUIC stream in DRAINING state (LPF)");
                            continue;
                        }
                        debug!("QUIC stream accepted (LPF)");

                        let mut conn_id_buf = [0u8; 4];
                        match recv.read_exact(&mut conn_id_buf).await {
                            Ok(()) => {
                                let conn_id = u32::from_be_bytes(conn_id_buf);
                                debug!("Read conn_id from stream (LPF): {}", conn_id);

                                let remote_dest = remote_destination.clone();
                                let cancel_token = CancellationToken::new();

                                match protocol {
                                    Protocol::Tcp => {
                                        match TcpStream::connect(&remote_dest).await {
                                            Ok(tcp_stream) => {
                                                info!("Connected to remote TCP service: {} (conn_id={})", remote_dest, conn_id);

                                                let remote_addr = tcp_stream.peer_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
                                                conn_manager.lock().await.add_connection(
                                                    conn_id,
                                                    Protocol::Tcp,
                                                    remote_addr,
                                                    cancel_token.clone(),
                                                );
                                                data_plane.register_connection(conn_id, Protocol::Tcp, remote_addr).await;

                                                let conn_manager_clone = conn_manager.clone();
                                                let dp_clone = data_plane.clone();
                                                tokio::spawn(async move {
                                                    if let Err(e) = relay_tcp_stream(
                                                        conn_id,
                                                        tcp_stream,
                                                        send,
                                                        recv,
                                                        dp_clone.clone(),
                                                        cancel_token,
                                                    )
                                                    .await
                                                    {
                                                        debug!("LPF TCP relay ended for {}: {}", conn_id, e);
                                                    }
                                                    conn_manager_clone.lock().await.remove_connection(conn_id);
                                                    dp_clone.unregister_connection(conn_id).await;
                                                }.instrument(tracing::Span::current()));
                                            }
                                            Err(e) => {
                                                error!("Failed to connect to remote TCP service {}: {}", remote_dest, e);
                                                let close_msg = ControlMessage::ConnectionClose {
                                                    connection_id: conn_id,
                                                    reason: CloseReason::ConnectionRefused,
                                                };
                                                let _ = control_stream.send_message(&close_msg).await;
                                            }
                                        }
                                    }
                                    Protocol::Udp => {
                                        // UDP: リモートサービスに接続
                                        match UdpSocket::bind("0.0.0.0:0").await {
                                            Ok(udp_socket) => {
                                                if let Err(e) = udp_socket.connect(&remote_dest).await {
                                                    error!("Failed to connect UDP socket to remote service {}: {}", remote_dest, e);
                                                    let close_msg = ControlMessage::ConnectionClose {
                                                        connection_id: conn_id,
                                                        reason: CloseReason::ConnectionRefused,
                                                    };
                                                    let _ = control_stream.send_message(&close_msg).await;
                                                    continue;
                                                }

                                                info!("Connected UDP socket to remote service: {} (conn_id={})", remote_dest, conn_id);

                                                let remote_addr: SocketAddr = remote_dest.parse().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
                                                conn_manager.lock().await.add_connection(
                                                    conn_id,
                                                    Protocol::Udp,
                                                    remote_addr,
                                                    cancel_token.clone(),
                                                );
                                                data_plane.register_connection(conn_id, Protocol::Udp, remote_addr).await;

                                                let conn_manager_clone = conn_manager.clone();
                                                let dp_clone = data_plane.clone();
                                                tokio::spawn(async move {
                                                    if let Err(e) = relay_lpf_udp_stream(
                                                        conn_id,
                                                        udp_socket,
                                                        send,
                                                        recv,
                                                        dp_clone.clone(),
                                                        cancel_token,
                                                    )
                                                    .await
                                                    {
                                                        debug!("LPF UDP relay ended for {}: {}", conn_id, e);
                                                    }
                                                    conn_manager_clone.lock().await.remove_connection(conn_id);
                                                    dp_clone.unregister_connection(conn_id).await;
                                                }.instrument(tracing::Span::current()));
                                            }
                                            Err(e) => {
                                                error!("Failed to create UDP socket: {}", e);
                                                let close_msg = ControlMessage::ConnectionClose {
                                                    connection_id: conn_id,
                                                    reason: CloseReason::OtherError,
                                                };
                                                let _ = control_stream.send_message(&close_msg).await;
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to read conn_id from stream: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Failed to accept QUIC stream: {}", e);
                        break;
                    }
                }
            }

            // 制御メッセージ
            result = control_stream.recv_message() => {
                match result {
                    Ok(ControlMessage::SessionClose) => {
                        info!("Client requested session close (LPF)");
                        break;
                    }
                    Ok(ControlMessage::ConnectionClose {
                        connection_id,
                        reason,
                    }) => {
                        info!(
                            "Client requested connection close for conn_id={}: {:?}",
                            connection_id, reason
                        );
                        conn_manager.lock().await.cancel_connection(connection_id);
                    }
                    Ok(msg) => {
                        debug!("Received control message: {:?}", msg);
                    }
                    Err(ProtocolError::StreamClosed) => {
                        info!("Control stream closed");
                        break;
                    }
                    Err(e) => {
                        let err_str = e.to_string();
                        if err_str.contains("closed") || err_str.contains("reset") || err_str.contains("lost") {
                            info!("Client disconnected (LPF): {}", e);
                        } else {
                            error!("Control stream error: {}", e);
                        }
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

// =============================================================================
// データ転送
// =============================================================================

/// TCP ストリームと QUIC ストリーム間でデータを中継
async fn relay_tcp_stream(
    conn_id: u32,
    tcp_stream: TcpStream,
    mut quic_send: SendStream,
    mut quic_recv: RecvStream,
    data_plane: Arc<DataPlane>,
    cancel_token: CancellationToken,
) -> Result<()> {
    debug!("Starting relay for conn_id={}", conn_id);
    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

    // TCP -> QUIC
    let dp_for_send = data_plane.clone();
    let cancel_for_send = cancel_token.clone();
    let tcp_to_quic = tokio::spawn(
        async move {
            let mut buf = vec![0u8; 8192];
            let mut total_sent = 0u64;
            loop {
                tokio::select! {
                    _ = cancel_for_send.cancelled() => {
                        debug!("[{}] TCP->QUIC cancelled", conn_id);
                        break;
                    }
                    result = tcp_read.read(&mut buf) => {
                        let n = result?;
                        if n == 0 {
                            break;
                        }
                        quic_send.write_all(&buf[..n]).await?;
                        total_sent += n as u64;
                    }
                }
            }
            let _ = quic_send.finish();
            dp_for_send.add_bytes(total_sent, 0);
            Ok::<_, anyhow::Error>(())
        }
        .instrument(tracing::Span::current()),
    );

    // QUIC -> TCP
    let dp_for_recv = data_plane.clone();
    let cancel_for_recv = cancel_token.clone();
    let quic_to_tcp = tokio::spawn(
        async move {
            let mut buf = vec![0u8; 8192];
            let mut total_received = 0u64;
            loop {
                tokio::select! {
                    _ = cancel_for_recv.cancelled() => {
                        debug!("[{}] QUIC->TCP cancelled", conn_id);
                        break;
                    }
                    result = quic_recv.read(&mut buf) => {
                        match result? {
                            Some(n) if n > 0 => {
                                tcp_write.write_all(&buf[..n]).await?;
                                total_received += n as u64;
                            }
                            _ => break,
                        }
                    }
                }
            }
            dp_for_recv.add_bytes(0, total_received);
            Ok::<_, anyhow::Error>(())
        }
        .instrument(tracing::Span::current()),
    );

    let (tcp_result, quic_result) = tokio::join!(tcp_to_quic, quic_to_tcp);

    if let Err(e) = tcp_result {
        debug!("TCP->QUIC task error for {}: {}", conn_id, e);
    }
    if let Err(e) = quic_result {
        debug!("QUIC->TCP task error for {}: {}", conn_id, e);
    }

    debug!("[{}] Relay completed", conn_id);
    Ok(())
}

/// RPF: UDP パケットと QUIC ストリーム間でデータを中継
///
/// UDP はパケット境界を保持するため、Length-prefixed framing を使用:
/// - 送信時: [4 bytes length (BE)] + [payload]
/// - 受信時: [4 bytes length (BE)] + [payload]
///
/// cancel_token がキャンセルされると、リレーを中断する
async fn relay_rpf_udp_stream(
    conn_id: u32,
    src_addr: SocketAddr,
    udp_socket: Arc<UdpSocket>,
    mut packet_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    mut quic_send: SendStream,
    mut quic_recv: RecvStream,
    data_plane: Arc<DataPlane>,
    cancel_token: CancellationToken,
) -> Result<()> {
    debug!("[{}] Starting RPF UDP relay for {}", conn_id, src_addr);

    // UDP -> QUIC (受信したパケットをチャネル経由で受け取り、QUIC に送信)
    let dp_for_send = data_plane.clone();
    let cancel_for_send = cancel_token.clone();
    let udp_to_quic = tokio::spawn(
        async move {
            let mut total_sent = 0u64;
            debug!("[{}] UDP->QUIC task started", conn_id);
            loop {
                tokio::select! {
                    _ = cancel_for_send.cancelled() => {
                        debug!("[{}] UDP->QUIC cancelled", conn_id);
                        break;
                    }
                    packet = packet_rx.recv() => {
                        match packet {
                            Some(data) => {
                                // Length-prefixed framing: [4 bytes length] + [payload]
                                let len = data.len() as u32;
                                if let Err(e) = quic_send.write_all(&len.to_be_bytes()).await {
                                    debug!("[{}] Failed to write length: {}", conn_id, e);
                                    break;
                                }
                                if let Err(e) = quic_send.write_all(&data).await {
                                    debug!("[{}] Failed to write UDP data: {}", conn_id, e);
                                    break;
                                }
                                total_sent += 4 + data.len() as u64;
                                debug!("[{}] UDP->QUIC {} bytes", conn_id, data.len());
                            }
                            None => {
                                // チャネルが閉じられた
                                debug!("[{}] UDP packet channel closed", conn_id);
                                break;
                            }
                        }
                    }
                }
            }
            let _ = quic_send.finish();
            dp_for_send.add_bytes(total_sent, 0);
            Ok::<_, anyhow::Error>(())
        }
        .instrument(tracing::Span::current()),
    );

    // QUIC -> UDP (QUIC から受信してオリジナルの送信元に返す)
    let dp_for_recv = data_plane.clone();
    let cancel_for_recv = cancel_token.clone();
    let quic_to_udp = tokio::spawn(
        async move {
            let mut total_received = 0u64;
            debug!("[{}] QUIC->UDP task started", conn_id);
            loop {
                tokio::select! {
                    _ = cancel_for_recv.cancelled() => {
                        debug!("[{}] QUIC->UDP cancelled", conn_id);
                        break;
                    }
                    // Length-prefixed framing で読み取り
                    result = async {
                        // 4 bytes の長さを読み取り
                        let mut len_buf = [0u8; 4];
                        quic_recv.read_exact(&mut len_buf).await?;
                        let len = u32::from_be_bytes(len_buf) as usize;

                        // ペイロードを読み取り
                        let mut payload = vec![0u8; len];
                        quic_recv.read_exact(&mut payload).await?;

                        Ok::<_, quinn::ReadExactError>((len, payload))
                    } => {
                        match result {
                            Ok((len, payload)) => {
                                total_received += 4 + len as u64;
                                // オリジナルの送信元に返す
                                if let Err(e) = udp_socket.send_to(&payload, src_addr).await {
                                    debug!("[{}] Failed to send UDP response: {}", conn_id, e);
                                    break;
                                }
                                debug!("[{}] QUIC->UDP {} bytes to {}", conn_id, len, src_addr);
                            }
                            Err(e) => {
                                debug!("[{}] QUIC read error: {}", conn_id, e);
                                break;
                            }
                        }
                    }
                }
            }
            dp_for_recv.add_bytes(0, total_received);
            Ok::<_, anyhow::Error>(())
        }
        .instrument(tracing::Span::current()),
    );

    // 両方向の完了を待つ
    let (send_result, recv_result) = tokio::join!(udp_to_quic, quic_to_udp);

    if let Err(e) = send_result {
        debug!("UDP->QUIC task error for {}: {}", conn_id, e);
    }
    if let Err(e) = recv_result {
        debug!("QUIC->UDP task error for {}: {}", conn_id, e);
    }

    debug!("[{}] RPF UDP relay completed", conn_id);
    Ok(())
}

/// LPF: UDP パケットと QUIC ストリーム間でデータを中継
async fn relay_lpf_udp_stream(
    conn_id: u32,
    udp_socket: UdpSocket,
    mut quic_send: SendStream,
    mut quic_recv: RecvStream,
    data_plane: Arc<DataPlane>,
    cancel_token: CancellationToken,
) -> Result<()> {
    debug!("[{}] Starting LPF UDP relay", conn_id);

    let udp_socket = Arc::new(udp_socket);

    // QUIC -> UDP (クライアントからのパケットをリモートサービスに送信)
    let socket_for_send = udp_socket.clone();
    let dp_for_recv = data_plane.clone();
    let cancel_for_recv = cancel_token.clone();
    let quic_to_udp = tokio::spawn(
        async move {
            let mut total_received = 0u64;
            debug!("[{}] QUIC->UDP task started", conn_id);
            loop {
                tokio::select! {
                    _ = cancel_for_recv.cancelled() => {
                        debug!("[{}] QUIC->UDP cancelled", conn_id);
                        break;
                    }
                    // Length-prefixed framing で読み取り
                    result = async {
                        let mut len_buf = [0u8; 4];
                        quic_recv.read_exact(&mut len_buf).await?;
                        let len = u32::from_be_bytes(len_buf) as usize;

                        let mut payload = vec![0u8; len];
                        quic_recv.read_exact(&mut payload).await?;

                        Ok::<_, quinn::ReadExactError>((len, payload))
                    } => {
                        match result {
                            Ok((len, payload)) => {
                                total_received += 4 + len as u64;
                                // リモートサービスに送信
                                if let Err(e) = socket_for_send.send(&payload).await {
                                    debug!("[{}] UDP send error: {}", conn_id, e);
                                    break;
                                }
                                debug!("[{}] QUIC->UDP {} bytes", conn_id, len);
                            }
                            Err(e) => {
                                debug!("[{}] QUIC read error: {}", conn_id, e);
                                break;
                            }
                        }
                    }
                }
            }
            dp_for_recv.add_bytes(0, total_received);
            Ok::<_, anyhow::Error>(())
        }
        .instrument(tracing::Span::current()),
    );

    // UDP -> QUIC (リモートサービスからの応答をクライアントに返す)
    let dp_for_send = data_plane.clone();
    let cancel_for_send = cancel_token.clone();
    let udp_to_quic = tokio::spawn(
        async move {
            let mut buf = vec![0u8; 65535];
            let mut total_sent = 0u64;
            debug!("[{}] UDP->QUIC task started", conn_id);
            loop {
                tokio::select! {
                    _ = cancel_for_send.cancelled() => {
                        debug!("[{}] UDP->QUIC cancelled", conn_id);
                        break;
                    }
                    result = udp_socket.recv(&mut buf) => {
                        match result {
                            Ok(len) if len > 0 => {
                                // Length-prefixed framing で送信
                                let len_u32 = len as u32;
                                if let Err(e) = quic_send.write_all(&len_u32.to_be_bytes()).await {
                                    debug!("[{}] QUIC write length error: {}", conn_id, e);
                                    break;
                                }
                                if let Err(e) = quic_send.write_all(&buf[..len]).await {
                                    debug!("[{}] QUIC write payload error: {}", conn_id, e);
                                    break;
                                }
                                total_sent += 4 + len as u64;
                                debug!("[{}] UDP->QUIC {} bytes", conn_id, len);
                            }
                            Ok(_) => {
                                debug!("[{}] UDP recv returned 0", conn_id);
                                break;
                            }
                            Err(e) => {
                                debug!("[{}] UDP recv error: {}", conn_id, e);
                                break;
                            }
                        }
                    }
                }
            }
            let _ = quic_send.finish();
            dp_for_send.add_bytes(total_sent, 0);
            Ok::<_, anyhow::Error>(())
        }
        .instrument(tracing::Span::current()),
    );

    // 両方向の完了を待つ
    let (recv_result, send_result) = tokio::join!(quic_to_udp, udp_to_quic);

    if let Err(e) = recv_result {
        debug!("QUIC->UDP task error for {}: {}", conn_id, e);
    }
    if let Err(e) = send_result {
        debug!("UDP->QUIC task error for {}: {}", conn_id, e);
    }

    debug!("[{}] LPF UDP relay completed", conn_id);
    Ok(())
}

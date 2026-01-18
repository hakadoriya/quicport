//! データプレーン実装
//!
//! QUIC 接続とバックエンド TCP 接続を維持するデーモンです。
//! コントロールプレーン（quicport server）とは別プロセスとして動作し、
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
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, Mutex, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::ipc::{
    cleanup_dataplane_files, ensure_dataplanes_dir, write_dataplane_port, write_dataplane_state,
    AuthPolicy, ControlCommand, DataPlaneConfig, DataPlaneEvent, DataPlaneState, DataPlaneStatus,
    IpcConnection,
};
use crate::protocol::{CloseReason, ControlMessage, ControlStream, Protocol, ProtocolError, ResponseStatus};
use crate::quic::{
    authenticate_client_psk, authenticate_client_x25519, create_server_endpoint, encode_base64_key,
    parse_base64_key,
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
    pid: u32,
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
        })
    }

    /// 状態を取得
    pub async fn get_state(&self) -> DataPlaneState {
        *self.state.read().await
    }

    /// 状態を設定
    pub async fn set_state(&self, state: DataPlaneState) {
        *self.state.write().await = state;
        // 状態ファイルを更新
        if let Ok(status) = self.get_status().await {
            let _ = write_dataplane_state(self.pid, &status);
        }
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
}

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
/// 独立したデーモンとして動作し、以下を行います：
/// 1. IPC ソケットを作成
/// 2. QUIC エンドポイントを起動
/// 3. コントロールプレーンからのコマンドを待機
pub async fn run(config: DataPlaneConfig, auth_policy: Option<AuthPolicy>) -> Result<()> {
    let data_plane = DataPlane::new(config.clone());
    if let Some(policy) = auth_policy {
        data_plane.set_auth_policy(policy).await;
    }

    // ディレクトリを作成
    ensure_dataplanes_dir()?;

    let pid = std::process::id();

    // IPC 用 TCP リスナーを作成（OS が空きポートを自動割り当て）
    let ipc_listener = TcpListener::bind("127.0.0.1:0").await?;
    let ipc_port = ipc_listener.local_addr()?.port();

    // ポート番号をファイルに書き込む
    write_dataplane_port(pid, ipc_port)?;

    info!("Data plane IPC listening on 127.0.0.1:{}", ipc_port);

    // 初期状態を書き込み
    data_plane.set_state(DataPlaneState::Starting).await;

    // QUIC エンドポイントを作成
    let endpoint = create_server_endpoint(config.listen_addr, "quicport-dataplane")?;
    info!("Data plane QUIC listening on {}", config.listen_addr);

    // ACTIVE 状態に移行
    data_plane.set_state(DataPlaneState::Active).await;

    let mut shutdown_rx = data_plane.subscribe_shutdown();
    let mut drain_rx = data_plane.subscribe_drain();
    let drain_timeout = data_plane.get_config().await.drain_timeout;

    // メインループ
    loop {
        tokio::select! {
            // シャットダウン
            _ = shutdown_rx.recv() => {
                info!("Data plane received shutdown signal");
                break;
            }

            // ドレインタイムアウト
            _ = async {
                let state = data_plane.get_state().await;
                if state == DataPlaneState::Draining {
                    tokio::time::sleep(Duration::from_secs(drain_timeout)).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                warn!("Drain timeout reached, forcing shutdown");
                break;
            }

            // ドレイン状態で接続数が 0 になった場合
            _ = async {
                loop {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    let state = data_plane.get_state().await;
                    let connections = data_plane.active_connections.load(Ordering::SeqCst);
                    if state == DataPlaneState::Draining && connections == 0 {
                        return;
                    }
                }
            } => {
                info!("All connections drained, shutting down");
                break;
            }

            // IPC 接続
            result = ipc_listener.accept() => {
                match result {
                    Ok((stream, _)) => {
                        let dp = data_plane.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_ipc_connection(dp, stream).await {
                                error!("IPC handler error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept IPC connection: {}", e);
                    }
                }
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
                        });
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
    cleanup_dataplane_files(pid)?;
    info!("Data plane terminated");

    Ok(())
}

/// IPC 接続を処理
async fn handle_ipc_connection(
    data_plane: Arc<DataPlane>,
    stream: TcpStream,
) -> Result<()> {
    let mut conn = IpcConnection::new(stream);

    // Ready イベントを送信
    let config = data_plane.get_config().await;
    let event = DataPlaneEvent::Ready {
        pid: data_plane.pid,
        listen_addr: config.listen_addr.to_string(),
    };
    conn.send_event(&event).await?;

    // コマンドを処理
    loop {
        match conn.recv_command().await {
            Ok(cmd) => {
                let response = process_ipc_command(&data_plane, cmd).await;
                conn.send_event(&response).await?;
            }
            Err(crate::ipc::IpcError::ConnectionClosed) => {
                debug!("IPC connection closed");
                break;
            }
            Err(e) => {
                error!("IPC recv error: {}", e);
                break;
            }
        }
    }

    Ok(())
}

/// IPC コマンドを処理
async fn process_ipc_command(data_plane: &DataPlane, cmd: ControlCommand) -> DataPlaneEvent {
    match cmd {
        ControlCommand::SetAuthPolicy(policy) => {
            data_plane.set_auth_policy(policy).await;
            info!("Authentication policy updated");
            DataPlaneEvent::Status(data_plane.get_status().await.unwrap_or_else(|_| {
                DataPlaneStatus {
                    state: DataPlaneState::Active,
                    pid: data_plane.pid,
                    active_connections: 0,
                    bytes_sent: 0,
                    bytes_received: 0,
                    started_at: data_plane.started_at,
                }
            }))
        }

        ControlCommand::SetConfig(config) => {
            data_plane.set_config(config).await;
            info!("Configuration updated");
            DataPlaneEvent::Status(data_plane.get_status().await.unwrap_or_else(|_| {
                DataPlaneStatus {
                    state: DataPlaneState::Active,
                    pid: data_plane.pid,
                    active_connections: 0,
                    bytes_sent: 0,
                    bytes_received: 0,
                    started_at: data_plane.started_at,
                }
            }))
        }

        ControlCommand::Drain => {
            data_plane.drain().await;
            info!("Data plane entering DRAINING state");
            DataPlaneEvent::Status(data_plane.get_status().await.unwrap_or_else(|_| {
                DataPlaneStatus {
                    state: DataPlaneState::Draining,
                    pid: data_plane.pid,
                    active_connections: 0,
                    bytes_sent: 0,
                    bytes_received: 0,
                    started_at: data_plane.started_at,
                }
            }))
        }

        ControlCommand::Shutdown => {
            info!("Data plane shutting down");
            data_plane.shutdown();
            DataPlaneEvent::Status(data_plane.get_status().await.unwrap_or_else(|_| {
                DataPlaneStatus {
                    state: DataPlaneState::Terminated,
                    pid: data_plane.pid,
                    active_connections: 0,
                    bytes_sent: 0,
                    bytes_received: 0,
                    started_at: data_plane.started_at,
                }
            }))
        }

        ControlCommand::GetStatus => {
            DataPlaneEvent::Status(data_plane.get_status().await.unwrap_or_else(|_| {
                DataPlaneStatus {
                    state: DataPlaneState::Active,
                    pid: data_plane.pid,
                    active_connections: 0,
                    bytes_sent: 0,
                    bytes_received: 0,
                    started_at: data_plane.started_at,
                }
            }))
        }

        ControlCommand::GetConnections => {
            // TODO: 接続一覧を返す
            DataPlaneEvent::Status(data_plane.get_status().await.unwrap_or_else(|_| {
                DataPlaneStatus {
                    state: DataPlaneState::Active,
                    pid: data_plane.pid,
                    active_connections: 0,
                    bytes_sent: 0,
                    bytes_received: 0,
                    started_at: data_plane.started_at,
                }
            }))
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
            let server_key = parse_base64_key(server_private_key)
                .context("Invalid server private key")?;

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
        AuthPolicy::Psk { psk } => {
            match authenticate_client_psk(&mut send, &mut recv, psk).await {
                Ok(()) => {
                    data_plane.statistics.auth_psk_success();
                    info!("Client {} authenticated (PSK)", remote_addr);
                }
                Err(e) => {
                    data_plane.statistics.auth_psk_failed();
                    warn!("PSK authentication failed for {}: {}", remote_addr, e);
                    return Ok(());
                }
            }
        }
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
    let mut drain_rx = data_plane.subscribe_drain();

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
            loop {
                tokio::select! {
                    // ドレイン
                    _ = drain_rx.recv() => {
                        info!("Data plane draining, stopping accept loop for port {}", port);
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
                                });
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
            // UDP 実装は省略（server.rs と同様の実装）
            let response = ControlMessage::RemoteForwardResponse {
                status: ResponseStatus::InternalError,
                message: "UDP not yet implemented in data plane".to_string(),
            };
            control_stream.send_message(&response).await?;
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
    info!("LocalForwardResponse sent: ready to forward to {}", remote_destination);

    let remote_destination = remote_destination.to_string();
    let mut drain_rx = data_plane.subscribe_drain();

    loop {
        tokio::select! {
            // ドレイン
            _ = drain_rx.recv() => {
                info!("Data plane draining, stopping LPF handler");
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

                                                let conn_manager_clone = conn_manager.clone();
                                                let dp_clone = data_plane.clone();
                                                tokio::spawn(async move {
                                                    if let Err(e) = relay_tcp_stream(
                                                        conn_id,
                                                        tcp_stream,
                                                        send,
                                                        recv,
                                                        dp_clone,
                                                        cancel_token,
                                                    )
                                                    .await
                                                    {
                                                        debug!("LPF TCP relay ended for {}: {}", conn_id, e);
                                                    }
                                                    conn_manager_clone.lock().await.remove_connection(conn_id);
                                                });
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
                                        // UDP 実装は省略
                                        error!("UDP LPF not yet implemented in data plane");
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
    let tcp_to_quic = tokio::spawn(async move {
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
    });

    // QUIC -> TCP
    let dp_for_recv = data_plane.clone();
    let cancel_for_recv = cancel_token.clone();
    let quic_to_tcp = tokio::spawn(async move {
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
    });

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

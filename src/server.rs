//! サーバー実装
//!
//! QUIC コネクションを待ち受け、クライアントからのポート開放リクエストを処理します。

use anyhow::{Context, Result};
use quinn::{Connection, RecvStream, SendStream};
use socket2::{Domain, Protocol as SockProtocol, Socket, Type};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::protocol::{ControlMessage, ControlStream, Protocol, ProtocolError, ResponseStatus};
use crate::quic::{
    authenticate_client_psk, authenticate_client_x25519, create_server_endpoint, encode_base64_key,
};
use crate::statistics::ServerStatistics;

/// 認証設定
pub enum AuthConfig {
    /// X25519 公開鍵認証（相互認証）
    X25519 {
        authorized_pubkeys: Vec<[u8; 32]>,
        /// サーバー秘密鍵（相互認証用、必須）
        server_private_key: [u8; 32],
    },
    /// PSK 認証
    Psk { psk: String },
}

/// 接続 ID カウンター
static CONNECTION_ID_COUNTER: AtomicU32 = AtomicU32::new(1);

/// アクティブな接続を管理
struct ConnectionManager {
    /// Connection ID -> (SendStream, RecvStream) のマッピング
    /// 実際にはストリームは別タスクで管理するため、ここでは接続情報のみ保持
    connections: HashMap<u32, ConnectionInfo>,
}

struct ConnectionInfo {
    /// 将来の拡張用（UDP 対応など）
    #[allow(dead_code)]
    protocol: Protocol,
    /// デバッグ/ロギング用
    #[allow(dead_code)]
    remote_addr: SocketAddr,
    /// リレータスクをキャンセルするためのトークン
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

    /// 指定した接続をキャンセル（TCP ストリームを閉じる）
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

/// サーバーを起動
pub async fn run(
    listen: SocketAddr,
    auth_config: AuthConfig,
    statistics: Arc<ServerStatistics>,
) -> Result<()> {
    info!("Creating QUIC server endpoint on {}", listen);

    // 証明書生成用のダミー文字列（TLS 層では使用しない）
    let endpoint = create_server_endpoint(listen, "quicport-server")?;
    info!("Server listening on {}", listen);

    // 認証設定を Arc で共有
    let auth_config = Arc::new(auth_config);

    // クライアント接続を受け付けるループ
    while let Some(incoming) = endpoint.accept().await {
        let auth_config = auth_config.clone();
        let statistics = statistics.clone();

        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    let remote_addr = connection.remote_address();
                    info!("New connection from {}", remote_addr);

                    // 接続開始を記録
                    statistics.connection_opened();

                    if let Err(e) = handle_client(connection, &auth_config, &statistics).await {
                        error!("Client handler error: {}", e);
                    }

                    // 接続終了を記録
                    statistics.connection_closed();

                    info!("Connection closed: {}", remote_addr);
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        });
    }

    Ok(())
}

/// クライアント接続を処理
async fn handle_client(
    connection: Connection,
    auth_config: &AuthConfig,
    statistics: &Arc<ServerStatistics>,
) -> Result<()> {
    let remote_addr = connection.remote_address();

    // 制御用ストリーム (Stream 0) を開く
    let (mut send, mut recv) = connection
        .accept_bi()
        .await
        .context("Failed to accept control stream")?;

    debug!("Control stream established with {}", remote_addr);

    // 認証方式に応じて処理を分岐
    // 認証は独自のバイナリプロトコルを使用するため、生のストリームを使用
    match auth_config {
        AuthConfig::X25519 {
            authorized_pubkeys,
            server_private_key,
        } => {
            match authenticate_client_x25519(
                &mut send,
                &mut recv,
                authorized_pubkeys,
                server_private_key,
            )
            .await
            {
                Ok(client_pubkey) => {
                    statistics.auth_x25519_success();
                    let pubkey_b64 = encode_base64_key(&client_pubkey);
                    info!(
                        "Client {} authenticated (pubkey: {}...)",
                        remote_addr,
                        &pubkey_b64[..16]
                    );
                }
                Err(crate::quic::X25519AuthError::PublicKeyNotAuthorized) => {
                    statistics.auth_x25519_failed();
                    warn!(
                        "Authentication failed for {}: public key not authorized",
                        remote_addr
                    );
                    return Ok(());
                }
                Err(e) => {
                    statistics.auth_x25519_failed();
                    warn!("Authentication failed for {}: {}", remote_addr, e);
                    return Ok(());
                }
            }
        }
        AuthConfig::Psk { psk } => match authenticate_client_psk(&mut send, &mut recv, psk).await {
            Ok(()) => {
                statistics.auth_psk_success();
                info!("Client {} authenticated (PSK)", remote_addr);
            }
            Err(e) => {
                statistics.auth_psk_failed();
                warn!("PSK authentication failed for {}: {}", remote_addr, e);
                return Ok(());
            }
        },
    }

    // 認証完了後、ControlStream でラップしてメッセージフレーミングを有効化
    let mut control_stream = ControlStream::new(send, recv);

    // 接続マネージャ
    let conn_manager = Arc::new(Mutex::new(ConnectionManager::new()));

    // RemoteForwardRequest または LocalForwardRequest を待機
    let msg = control_stream
        .recv_message()
        .await
        .context("Failed to read initial request")?;

    match msg {
        // Remote Port Forwarding (RPF): サーバー側でリッスン
        ControlMessage::RemoteForwardRequest {
            port,
            protocol,
            local_destination,
        } => {
            info!(
                "RemoteForwardRequest from {}: port={}, protocol={}, local_destination={}",
                remote_addr, port, protocol, local_destination
            );

            // ポートをリッスン
            match start_port_listener(
                port,
                protocol,
                connection.clone(),
                control_stream,
                conn_manager,
                statistics.clone(),
            )
            .await
            {
                Ok(_) => {
                    info!("Port listener closed for port {}", port);
                }
                Err(e) => {
                    error!("Port listener error: {}", e);
                }
            }
        }
        // Local Port Forwarding (LPF): クライアント側でリッスン、サーバーが転送
        ControlMessage::LocalForwardRequest {
            remote_destination,
            protocol,
            local_source,
        } => {
            info!(
                "LocalForwardRequest from {}: remote_destination={}, protocol={}, local_source={}",
                remote_addr, remote_destination, protocol, local_source
            );

            // LPF モードを開始
            match handle_local_port_forwarding(
                connection.clone(),
                control_stream,
                &remote_destination,
                protocol,
                conn_manager,
                statistics.clone(),
            )
            .await
            {
                Ok(_) => {
                    info!("Local port forwarding closed for {}", remote_destination);
                }
                Err(e) => {
                    error!("Local port forwarding error: {}", e);
                }
            }
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

/// SO_REUSEADDR 付きで TCP リスナーを作成
fn create_tcp_listener_with_reuseaddr(addr: SocketAddr) -> std::io::Result<std::net::TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::STREAM, Some(SockProtocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    socket.set_nonblocking(true)?;

    Ok(socket.into())
}

/// ポートリスナーを開始
async fn start_port_listener(
    port: u16,
    protocol: Protocol,
    quic_conn: Connection,
    mut control_stream: ControlStream,
    conn_manager: Arc<Mutex<ConnectionManager>>,
    statistics: Arc<ServerStatistics>,
) -> Result<()> {
    let bind_addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;

    match protocol {
        Protocol::Tcp => {
            // SO_REUSEADDR を設定して TCP リスナーを作成
            // これによりクライアント切断後すぐにポートを再利用可能
            let listener = match create_tcp_listener_with_reuseaddr(bind_addr) {
                Ok(std_listener) => match TcpListener::from_std(std_listener) {
                    Ok(l) => {
                        info!("TCP listener started on port {}", port);

                        // 成功レスポンスを送信
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
                    // QUIC コネクションがクローズされた場合（クライアント切断）
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

                                // 1. QUIC ストリームを開く
                                let (mut quic_send, quic_recv) = match quic_conn.open_bi().await {
                                    Ok(s) => s,
                                    Err(e) => {
                                        error!("Failed to open QUIC stream: {}", e);
                                        continue;
                                    }
                                };

                                // 2. conn_id を 4 bytes (big-endian) でストリームの先頭に書き込む
                                //    クライアントはこれを読んで接続を識別する
                                if let Err(e) = quic_send.write_all(&conn_id.to_be_bytes()).await {
                                    error!("Failed to write conn_id to stream: {}", e);
                                    continue;
                                }

                                // 3. RemoteNewConnection を送信（情報提供のみ、応答は待たない）
                                //    クライアントは QUIC Stream の先頭 4 bytes から conn_id を読み取るため、
                                //    RemoteNewConnection と Stream の到着順序に依存しない設計
                                let new_conn_msg = ControlMessage::RemoteNewConnection {
                                    connection_id: conn_id,
                                    protocol: Protocol::Tcp,
                                };
                                if let Err(e) = control_stream.send_message(&new_conn_msg).await {
                                    error!("Failed to send RemoteNewConnection: {}", e);
                                    continue;
                                }

                                // 4. 接続を登録してデータ転送開始
                                //    クライアントがローカル接続に失敗した場合は Stream が閉じられる
                                //    QUIC フロー制御により、クライアントが読み取らなければ送信も止まる
                                let cancel_token = CancellationToken::new();
                                conn_manager.lock().await.add_connection(
                                    conn_id,
                                    Protocol::Tcp,
                                    tcp_addr,
                                    cancel_token.clone(),
                                );

                                // データ転送タスクを起動
                                let conn_manager_clone = conn_manager.clone();
                                let statistics_clone = statistics.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = relay_tcp_stream(
                                        conn_id,
                                        tcp_stream,
                                        quic_send,
                                        quic_recv,
                                        &statistics_clone,
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

                    // 制御メッセージ（SessionClose, ConnectionClose など）を待機
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
                                // クライアントがローカル接続に失敗した等の理由で接続をクローズ
                                // 対応するリレータスクをキャンセルして TCP を閉じる
                                info!(
                                    "Client requested connection close for conn_id={}: {:?}",
                                    connection_id, reason
                                );
                                let cancelled = conn_manager
                                    .lock()
                                    .await
                                    .cancel_connection(connection_id);
                                if cancelled {
                                    debug!("Connection {} cancelled", connection_id);
                                } else {
                                    debug!(
                                        "Connection {} not found (may have already closed)",
                                        connection_id
                                    );
                                }
                            }
                            Ok(msg) => {
                                debug!("Received control message: {:?}", msg);
                            }
                            Err(ProtocolError::StreamClosed) => {
                                info!("Control stream closed");
                                break;
                            }
                            Err(e) => {
                                // クライアントが正常に切断した場合はエラーではなく INFO レベル
                                let err_str = e.to_string();
                                if err_str.contains("closed") || err_str.contains("reset") {
                                    info!("Client disconnected, releasing port {}", port);
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

                    // 成功レスポンスを送信
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
            let udp_connections: Arc<Mutex<HashMap<SocketAddr, (u32, tokio::sync::mpsc::Sender<Vec<u8>>)>>> =
                Arc::new(Mutex::new(HashMap::new()));

            let mut recv_buf = vec![0u8; 65535]; // UDP 最大パケットサイズ

            // UDP パケットを受け付けるループ
            loop {
                tokio::select! {
                    // QUIC コネクションがクローズされた場合
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

                                    // 最初のパケットを送信（ロック外で await）
                                    let _ = tx.send(packet).await;

                                    // UDP リレータスクを起動
                                    let conn_manager_clone = conn_manager.clone();
                                    let udp_connections_clone = udp_connections.clone();
                                    let statistics_clone = statistics.clone();
                                    let socket_clone = socket.clone();
                                    tokio::spawn(async move {
                                        if let Err(e) = relay_udp_stream(
                                            conn_id,
                                            src_addr,
                                            socket_clone,
                                            rx,
                                            quic_send,
                                            quic_recv,
                                            &statistics_clone,
                                            cancel_token,
                                        )
                                        .await
                                        {
                                            debug!("UDP relay ended for {}: {}", conn_id, e);
                                        }
                                        // ロック順序を統一: conn_manager → udp_connections
                                        conn_manager_clone.lock().await.remove_connection(conn_id);
                                        udp_connections_clone.lock().await.remove(&src_addr);
                                    });
                                }
                            }
                            Err(e) => {
                                error!("Failed to receive UDP packet: {}", e);
                            }
                        }
                    }

                    // 制御メッセージを待機
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
                                let cancelled = conn_manager
                                    .lock()
                                    .await
                                    .cancel_connection(connection_id);
                                if cancelled {
                                    debug!("UDP connection {} cancelled", connection_id);
                                }
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
                                if err_str.contains("closed") || err_str.contains("reset") {
                                    info!("Client disconnected, releasing UDP port {}", port);
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

/// TCP ストリームと QUIC ストリーム間でデータを中継
///
/// 統計情報の bytes_sent / bytes_received はサーバー視点での QUIC 通信を追跡:
/// - bytes_sent: サーバーからクライアントへ送信（QUIC への書き込み）
/// - bytes_received: クライアントからサーバーへ受信（QUIC からの読み取り）
///
/// cancel_token がキャンセルされると、リレーを中断して TCP を閉じる
async fn relay_tcp_stream(
    conn_id: u32,
    tcp_stream: TcpStream,
    mut quic_send: SendStream,
    mut quic_recv: RecvStream,
    statistics: &Arc<ServerStatistics>,
    cancel_token: CancellationToken,
) -> Result<()> {
    debug!("Starting relay for conn_id={}", conn_id);
    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

    // TCP -> QUIC (独立したタスクとして実行)
    // サーバーがクライアントに送信するデータ
    let stats_for_send = statistics.clone();
    let cancel_for_send = cancel_token.clone();
    let tcp_to_quic = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        debug!("[{}] TCP->QUIC task started", conn_id);
        loop {
            tokio::select! {
                // キャンセル要求を監視
                _ = cancel_for_send.cancelled() => {
                    debug!("[{}] TCP->QUIC cancelled", conn_id);
                    break;
                }
                // TCP から読み取り
                result = tcp_read.read(&mut buf) => {
                    let n = result?;
                    debug!("[{}] TCP read {} bytes", conn_id, n);
                    if n == 0 {
                        debug!("[{}] TCP read EOF", conn_id);
                        break;
                    }
                    quic_send.write_all(&buf[..n]).await?;
                    // 送信バイト数を記録
                    stats_for_send.add_bytes_sent(n as u64);
                    debug!("[{}] QUIC write {} bytes", conn_id, n);
                }
            }
        }
        debug!("[{}] TCP->QUIC finishing stream", conn_id);
        let _ = quic_send.finish();
        Ok::<_, anyhow::Error>(())
    });

    // QUIC -> TCP (独立したタスクとして実行)
    // クライアントからサーバーが受信するデータ
    let stats_for_recv = statistics.clone();
    let cancel_for_recv = cancel_token.clone();
    let quic_to_tcp = tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        debug!("[{}] QUIC->TCP task started", conn_id);
        loop {
            tokio::select! {
                // キャンセル要求を監視
                _ = cancel_for_recv.cancelled() => {
                    debug!("[{}] QUIC->TCP cancelled", conn_id);
                    break;
                }
                // QUIC から読み取り
                result = quic_recv.read(&mut buf) => {
                    match result? {
                        Some(n) if n > 0 => {
                            debug!("[{}] QUIC read {} bytes", conn_id, n);
                            // 受信バイト数を記録
                            stats_for_recv.add_bytes_received(n as u64);
                            tcp_write.write_all(&buf[..n]).await?;
                            debug!("[{}] TCP write {} bytes", conn_id, n);
                        }
                        _ => {
                            debug!("[{}] QUIC read EOF", conn_id);
                            break;
                        }
                    }
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    });

    // 両方向の完了を待つ（エコーパターンに対応）
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

/// UDP パケットと QUIC ストリーム間でデータを中継
///
/// UDP はパケット境界を保持するため、Length-prefixed framing を使用:
/// - 送信時: [4 bytes length (BE)] + [payload]
/// - 受信時: [4 bytes length (BE)] + [payload]
///
/// cancel_token がキャンセルされると、リレーを中断する
async fn relay_udp_stream(
    conn_id: u32,
    src_addr: SocketAddr,
    udp_socket: Arc<UdpSocket>,
    mut packet_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    mut quic_send: SendStream,
    mut quic_recv: RecvStream,
    statistics: &Arc<ServerStatistics>,
    cancel_token: CancellationToken,
) -> Result<()> {
    debug!("[{}] Starting UDP relay for {}", conn_id, src_addr);

    // UDP -> QUIC (受信したパケットをチャネル経由で受け取り、QUIC に送信)
    let stats_for_send = statistics.clone();
    let cancel_for_send = cancel_token.clone();
    let udp_to_quic = tokio::spawn(async move {
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
                            stats_for_send.add_bytes_sent(4 + data.len() as u64);
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
        Ok::<_, anyhow::Error>(())
    });

    // QUIC -> UDP (QUIC から受信してオリジナルの送信元に返す)
    let stats_for_recv = statistics.clone();
    let cancel_for_recv = cancel_token.clone();
    let quic_to_udp = tokio::spawn(async move {
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
                            stats_for_recv.add_bytes_received(4 + len as u64);
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
        Ok::<_, anyhow::Error>(())
    });

    // 両方向の完了を待つ
    let (send_result, recv_result) = tokio::join!(udp_to_quic, quic_to_udp);

    if let Err(e) = send_result {
        debug!("UDP->QUIC task error for {}: {}", conn_id, e);
    }
    if let Err(e) = recv_result {
        debug!("QUIC->UDP task error for {}: {}", conn_id, e);
    }

    debug!("[{}] UDP relay completed", conn_id);
    Ok(())
}

// =============================================================================
// Local Port Forwarding (LPF) 実装
// クライアント側でリッスンし、サーバー側のリモートサービスに転送
// =============================================================================

/// LPF モードを処理
///
/// クライアントからの LocalForwardRequest を受け付け、
/// クライアントが開いた QUIC ストリームを accept してリモートサービスに転送
async fn handle_local_port_forwarding(
    quic_conn: Connection,
    mut control_stream: ControlStream,
    remote_destination: &str,
    protocol: Protocol,
    conn_manager: Arc<Mutex<ConnectionManager>>,
    statistics: Arc<ServerStatistics>,
) -> Result<()> {
    // LocalForwardResponse を送信
    let response = ControlMessage::LocalForwardResponse {
        status: ResponseStatus::Success,
        message: format!("Ready to forward to {}", remote_destination),
    };
    control_stream.send_message(&response).await?;
    info!("LocalForwardResponse sent: ready to forward to {}", remote_destination);

    let remote_destination = remote_destination.to_string();

    // クライアントからの QUIC ストリームを受け付けるループ
    loop {
        tokio::select! {
            // QUIC コネクションがクローズされた場合
            reason = quic_conn.closed() => {
                info!("QUIC connection closed: {:?}, stopping LPF handler", reason);
                break;
            }

            // クライアントからの QUIC ストリームを accept
            result = quic_conn.accept_bi() => {
                match result {
                    Ok((send, mut recv)) => {
                        debug!("QUIC stream accepted (LPF)");

                        // ストリームの先頭 4 bytes から conn_id を読み取る
                        let mut conn_id_buf = [0u8; 4];
                        match recv.read_exact(&mut conn_id_buf).await {
                            Ok(()) => {
                                let conn_id = u32::from_be_bytes(conn_id_buf);
                                debug!("Read conn_id from stream (LPF): {}", conn_id);

                                // リモートサービスに接続してデータ転送を開始
                                let remote_dest = remote_destination.clone();
                                let cancel_token = CancellationToken::new();

                                match protocol {
                                    Protocol::Tcp => {
                                        // TCP: リモートサービスに接続
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
                                                let statistics_clone = statistics.clone();
                                                tokio::spawn(async move {
                                                    if let Err(e) = relay_tcp_stream(
                                                        conn_id,
                                                        tcp_stream,
                                                        send,
                                                        recv,
                                                        &statistics_clone,
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
                                                // ConnectionClose を送信
                                                let close_msg = ControlMessage::ConnectionClose {
                                                    connection_id: conn_id,
                                                    reason: crate::protocol::CloseReason::ConnectionRefused,
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
                                                        reason: crate::protocol::CloseReason::ConnectionRefused,
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

                                                let conn_manager_clone = conn_manager.clone();
                                                let statistics_clone = statistics.clone();
                                                tokio::spawn(async move {
                                                    if let Err(e) = relay_lpf_udp_stream(
                                                        conn_id,
                                                        udp_socket,
                                                        send,
                                                        recv,
                                                        &statistics_clone,
                                                        cancel_token,
                                                    )
                                                    .await
                                                    {
                                                        debug!("LPF UDP relay ended for {}: {}", conn_id, e);
                                                    }
                                                    conn_manager_clone.lock().await.remove_connection(conn_id);
                                                });
                                            }
                                            Err(e) => {
                                                error!("Failed to create UDP socket: {}", e);
                                                let close_msg = ControlMessage::ConnectionClose {
                                                    connection_id: conn_id,
                                                    reason: crate::protocol::CloseReason::OtherError,
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

            // 制御メッセージを待機
            result = control_stream.recv_message() => {
                match result {
                    Ok(ControlMessage::SessionClose) => {
                        info!("Client requested session close (LPF)");
                        break;
                    }
                    Ok(ControlMessage::LocalNewConnection {
                        connection_id,
                        protocol: conn_protocol,
                    }) => {
                        // LocalNewConnection は情報提供のみ（conn_id はストリームから取得済み）
                        debug!(
                            "LocalNewConnection notification: conn_id={}, protocol={}",
                            connection_id, conn_protocol
                        );
                    }
                    Ok(ControlMessage::ConnectionClose {
                        connection_id,
                        reason,
                    }) => {
                        info!(
                            "Client requested connection close for conn_id={}: {:?}",
                            connection_id, reason
                        );
                        let cancelled = conn_manager.lock().await.cancel_connection(connection_id);
                        if cancelled {
                            debug!("Connection {} cancelled", connection_id);
                        }
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
                        if err_str.contains("closed") || err_str.contains("reset") {
                            info!("Client disconnected (LPF)");
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

/// LPF: UDP パケットと QUIC ストリーム間でデータを中継
async fn relay_lpf_udp_stream(
    conn_id: u32,
    udp_socket: UdpSocket,
    mut quic_send: SendStream,
    mut quic_recv: RecvStream,
    statistics: &Arc<ServerStatistics>,
    cancel_token: CancellationToken,
) -> Result<()> {
    debug!("[{}] Starting LPF UDP relay", conn_id);

    let udp_socket = Arc::new(udp_socket);

    // QUIC -> UDP (クライアントからのパケットをリモートサービスに送信)
    let socket_for_send = udp_socket.clone();
    let stats_for_recv = statistics.clone();
    let cancel_for_recv = cancel_token.clone();
    let quic_to_udp = tokio::spawn(async move {
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
                            stats_for_recv.add_bytes_received(4 + len as u64);
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
        Ok::<_, anyhow::Error>(())
    });

    // UDP -> QUIC (リモートサービスからの応答をクライアントに返す)
    let stats_for_send = statistics.clone();
    let cancel_for_send = cancel_token.clone();
    let udp_to_quic = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
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
                            stats_for_send.add_bytes_sent(4 + len as u64);
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
        Ok::<_, anyhow::Error>(())
    });

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

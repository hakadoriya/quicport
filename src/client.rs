//! クライアント実装
//!
//! サーバーに接続し、ポートフォワーディングを設定します。

use anyhow::{Context, Result};
use quinn::{Connection, RecvStream, SendStream};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn, Instrument};

// LPF で使用する追加 imports はファイル末尾の LPF 実装セクションに配置

#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};

use crate::protocol::{
    parse_destination_spec, parse_port_spec, ControlMessage, ControlStream, Protocol,
    ProtocolError, ResponseStatus,
};
use crate::quic::{
    authenticate_with_server_psk, authenticate_with_server_x25519, create_client_endpoint,
    create_client_endpoint_with_tofu, KnownHosts, TofuStatus,
};

/// クライアント認証設定
#[derive(Clone)]
pub enum ClientAuthConfig {
    /// X25519 秘密鍵認証（相互認証）
    X25519 {
        private_key: [u8; 32],
        /// 期待するサーバー公開鍵（相互認証用、必須）
        expected_server_pubkey: [u8; 32],
    },
    /// PSK 認証
    Psk { psk: String },
}

/// 再接続設定
#[derive(Clone, Debug)]
pub struct ReconnectConfig {
    /// 自動再接続を有効にするかどうか
    pub enabled: bool,
    /// 最大再試行回数（0 = 無制限）
    pub max_attempts: u32,
    /// 初期再試行間隔（秒）
    pub initial_delay_secs: u64,
    /// 最大再試行間隔（秒）
    pub max_delay_secs: u64,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_attempts: 0,
            initial_delay_secs: 1,
            max_delay_secs: 60,
        }
    }
}

impl ReconnectConfig {
    /// 再接続設定を作成
    pub fn new(enabled: bool, max_attempts: u32, initial_delay_secs: u64) -> Self {
        Self {
            enabled,
            max_attempts,
            initial_delay_secs,
            max_delay_secs: 60,
        }
    }
}

/// アクティブな接続を管理
struct ConnectionManager {
    connections: HashMap<u32, ConnectionInfo>,
}

struct ConnectionInfo {
    #[allow(dead_code)]
    protocol: Protocol,
}

impl ConnectionManager {
    fn new() -> Self {
        Self {
            connections: HashMap::new(),
        }
    }

    fn add_connection(&mut self, conn_id: u32, protocol: Protocol) {
        self.connections
            .insert(conn_id, ConnectionInfo { protocol });
    }

    fn remove_connection(&mut self, conn_id: u32) {
        self.connections.remove(&conn_id);
    }
}

/// ユーザーに yes/no を確認（非同期版）
///
/// 標準入力から y/yes または n/no を読み取る
/// ブロッキング I/O は spawn_blocking で実行し、Tokio ランタイムをブロックしない
async fn prompt_yes_no(prompt: &str) -> Result<bool> {
    use std::io::{self, Write};

    print!("{} [y/N]: ", prompt);
    io::stdout().flush()?;

    // ブロッキング I/O を専用スレッドで実行
    let result = tokio::task::spawn_blocking(|| {
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        Ok::<_, anyhow::Error>(input)
    })
    .await??;

    let input = result.trim().to_lowercase();
    Ok(input == "y" || input == "yes")
}

/// ホストとポートをソケットアドレス文字列に整形
///
/// IPv6 アドレスは `[addr]:port` 形式に、IPv4 アドレスは `addr:port` 形式にする
fn format_socket_addr(host: &str, port: u16) -> String {
    if host.contains(':') {
        // IPv6 アドレス
        format!("[{}]:{}", host, port)
    } else {
        // IPv4 アドレスまたはホスト名
        format!("{}:{}", host, port)
    }
}

/// TOFU 検証結果を処理（非同期版）
///
/// 未知のホストや証明書が変更されたホストに対して、ユーザーに確認を求める
async fn handle_tofu_status(status: &TofuStatus, known_hosts: &KnownHosts) -> Result<()> {
    match status {
        TofuStatus::Known => {
            // 既知のホスト、何もしない
            debug!("Server certificate verified (known host)");
            Ok(())
        }
        TofuStatus::Unknown {
            host,
            fingerprint,
            cert_info,
        } => {
            // 未知のホスト - SSH 風の警告を表示
            eprintln!();
            eprintln!("The authenticity of host '{}' can't be established.", host);
            eprintln!("Certificate details:");
            eprintln!("{}", cert_info);
            eprintln!();

            if prompt_yes_no("Are you sure you want to continue connecting?").await? {
                // known_hosts に追加
                let line_number = known_hosts.add_host(host, fingerprint)?;
                let file_path = known_hosts.path().display();
                eprintln!(
                    "Warning: Permanently added '{}' to the list of known hosts ({}:{}).",
                    host, file_path, line_number
                );
                eprintln!();
                Ok(())
            } else {
                anyhow::bail!("Host key verification failed.")
            }
        }
        TofuStatus::Changed {
            host,
            old_fingerprint,
            new_fingerprint,
            cert_info,
        } => {
            // 証明書が変更された - 強い警告を表示
            eprintln!();
            eprintln!("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
            eprintln!("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @");
            eprintln!("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
            eprintln!("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!");
            eprintln!(
                "Someone could be eavesdropping on you right now (man-in-the-middle attack)!"
            );
            eprintln!("It is also possible that a host key has just been changed.");
            eprintln!();
            eprintln!("Host: {}", host);
            eprintln!("Old fingerprint: {}", old_fingerprint);
            eprintln!("New fingerprint: {}", new_fingerprint);
            eprintln!();
            eprintln!("New certificate details:");
            eprintln!("{}", cert_info);
            eprintln!();

            if prompt_yes_no(
                "Are you sure you want to continue connecting (and update the known host)?",
            )
            .await?
            {
                // known_hosts を更新
                let line_number = known_hosts.add_host(host, new_fingerprint)?;
                let file_path = known_hosts.path().display();
                eprintln!(
                    "Warning: Updated '{}' in the list of known hosts ({}:{}).",
                    host, file_path, line_number
                );
                eprintln!();
                Ok(())
            } else {
                anyhow::bail!("Host key verification failed.")
            }
        }
    }
}

/// クライアントを起動
///
/// # Arguments
/// * `destination` - 接続先サーバーのアドレス
/// * `remote_source` - リモートソースポート（サーバー側でリッスン、例: "9022/tcp" or "9022"）
/// * `local_destination` - ローカル転送先（例: "22/tcp", "22", "192.168.1.100:22"）
/// * `auth_config` - 認証設定
/// * `insecure` - true の場合、証明書検証をスキップ（テスト用）
async fn run_remote_forward(
    destination: &str,
    remote_source: &str,
    local_destination: &str,
    auth_config: ClientAuthConfig,
    insecure: bool,
    keep_alive_secs: u64,
    idle_timeout_secs: u64,
) -> Result<()> {
    // 引数をパース
    // remote_source は port/protocol 形式（アドレスなし）
    let (remote_port_num, remote_protocol) = parse_port_spec(remote_source)
        .context("Invalid remote-source format (expected: port/protocol, e.g., 9022/tcp)")?;

    // local_destination は addr:port/protocol 形式（addr と protocol は省略可）
    let (local_host, local_port_num, local_protocol) = parse_destination_spec(local_destination)
        .context("Invalid local-destination format (expected: [addr:]port[/protocol], e.g., 22, 22/tcp, 192.168.1.100:22)")?;

    if remote_protocol != local_protocol {
        anyhow::bail!(
            "Protocol mismatch: remote={}, local={}",
            remote_protocol,
            local_protocol
        );
    }

    // 接続先アドレスをパース
    let server_addr: SocketAddr = destination
        .parse()
        .or_else(|_| {
            // ホスト名の場合は DNS 解決
            use std::net::ToSocketAddrs;
            destination
                .to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next())
                .ok_or_else(|| anyhow::anyhow!("Failed to resolve address: {}", destination))
        })
        .context("Invalid destination address")?;

    info!("Connecting to {} ...", server_addr);

    // insecure モードまたは TOFU モードで接続
    let tunnel = if insecure {
        // 証明書検証をスキップ（テスト用）
        warn!("Insecure mode: skipping server certificate verification");
        let endpoint =
            create_client_endpoint(&server_addr, keep_alive_secs, idle_timeout_secs)?;
        endpoint
            .connect(server_addr, "quicport")
            .context("Failed to initiate tunnel")?
            .await
            .context("Failed to establish QUIC tunnel")?
    } else {
        // TOFU 検証を行う
        let known_hosts_path = KnownHosts::default_path()?;
        let known_hosts = Arc::new(KnownHosts::new(known_hosts_path)?);

        let (endpoint, tofu_verifier) = create_client_endpoint_with_tofu(
            &server_addr,
            destination,
            known_hosts.clone(),
            keep_alive_secs,
            idle_timeout_secs,
        )?;

        let tunnel = endpoint
            .connect(server_addr, "quicport")
            .context("Failed to initiate tunnel")?
            .await
            .context("Failed to establish QUIC tunnel")?;

        // TOFU 検証結果を確認
        if let Some(status) = tofu_verifier.get_status() {
            handle_tofu_status(&status, &known_hosts).await?;
        }

        tunnel
    };

    info!("Connected to {}", server_addr);

    // 制御ストリームを開く
    let (mut control_send, mut control_recv) = tunnel
        .open_bi()
        .await
        .context("Failed to open control stream")?;

    debug!("Control stream opened");

    // 認証方式に応じて処理を分岐
    // 認証は独自のバイナリプロトコルを使用するため、生のストリームを使用
    match &auth_config {
        ClientAuthConfig::X25519 {
            private_key,
            expected_server_pubkey,
        } => {
            authenticate_with_server_x25519(
                &mut control_send,
                &mut control_recv,
                private_key,
                expected_server_pubkey,
            )
            .await
            .context("X25519 authentication failed")?;
            info!("Authenticated with server (X25519)");
        }
        ClientAuthConfig::Psk { psk } => {
            authenticate_with_server_psk(&mut control_send, &mut control_recv, psk)
                .await
                .context("PSK authentication failed")?;
            info!("Authenticated with server (PSK)");
        }
    }

    // 認証完了後、ControlStream でラップしてメッセージフレーミングを有効化
    let mut control_stream = ControlStream::new(control_send, control_recv);

    // RemoteForwardRequest を送信
    let port_request = ControlMessage::RemoteForwardRequest {
        port: remote_port_num,
        protocol: remote_protocol,
        local_destination: local_destination.to_string(),
    };
    control_stream
        .send_message(&port_request)
        .await
        .context("Failed to send RemoteForwardRequest")?;

    debug!(
        "RemoteForwardRequest sent: port={}, protocol={}",
        remote_port_num, remote_protocol
    );

    // RemoteForwardResponse を待機（正しいフレーミングで読み取り）
    let response = control_stream
        .recv_message()
        .await
        .context("Failed to read RemoteForwardResponse")?;

    match response {
        ControlMessage::RemoteForwardResponse { status, message } => {
            if status != ResponseStatus::Success {
                anyhow::bail!(
                    "Server rejected RemoteForwardRequest: {:?} - {}",
                    status,
                    message
                );
            }
            info!("Server accepted RemoteForwardRequest: {}", message);
        }
        _ => {
            anyhow::bail!("Unexpected response from server");
        }
    }

    // 接続マネージャ
    let conn_manager = Arc::new(Mutex::new(ConnectionManager::new()));
    let local_addr = format_socket_addr(&local_host, local_port_num);

    info!(
        "Tunnel established: server:{}:{} -> {}",
        remote_port_num, remote_protocol, local_addr
    );

    // RemoteNewConnection を待機してデータ転送を処理
    handle_incoming_tunnel(
        tunnel,
        control_stream,
        &local_addr,
        remote_protocol,
        conn_manager,
    )
    .await?;

    Ok(())
}

/// 再接続機能付きでクライアントを起動（RPF モード）
///
/// 接続が切断された場合、指定された設定に従って自動的に再接続を試みる。
/// エクスポネンシャルバックオフで再試行間隔を増加させる。
pub async fn run_remote_forward_with_reconnect(
    destination: &str,
    remote_source: &str,
    local_destination: &str,
    auth_config: ClientAuthConfig,
    insecure: bool,
    reconnect_config: ReconnectConfig,
    keep_alive_secs: u64,
    idle_timeout_secs: u64,
) -> Result<()> {
    if !reconnect_config.enabled {
        // 再接続が無効の場合は通常の run_remote_forward を呼び出す
        return run_remote_forward(
            destination,
            remote_source,
            local_destination,
            auth_config,
            insecure,
            keep_alive_secs,
            idle_timeout_secs,
        )
        .await;
    }

    let mut attempt = 0u32;
    let mut delay_secs = reconnect_config.initial_delay_secs;

    loop {
        attempt += 1;
        let attempt_str = if reconnect_config.max_attempts == 0 {
            format!("#{}", attempt)
        } else {
            format!("#{}/{}", attempt, reconnect_config.max_attempts)
        };

        info!("Connection attempt {}", attempt_str);

        match run_remote_forward(
            destination,
            remote_source,
            local_destination,
            auth_config.clone(),
            insecure,
            keep_alive_secs,
            idle_timeout_secs,
        )
        .await
        {
            Ok(()) => {
                // 正常終了（シャットダウンシグナルなど）
                info!("Connection closed normally");
                return Ok(());
            }
            Err(e) => {
                // エラーで終了
                warn!("Connection failed: {}", e);

                // 最大試行回数をチェック（0 = 無制限）
                if reconnect_config.max_attempts > 0 && attempt >= reconnect_config.max_attempts {
                    error!(
                        "Maximum reconnection attempts ({}) reached",
                        reconnect_config.max_attempts
                    );
                    return Err(e);
                }

                info!("Reconnecting in {} seconds...", delay_secs);
                tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;

                // エクスポネンシャルバックオフ（最大まで増加）
                delay_secs = std::cmp::min(delay_secs * 2, reconnect_config.max_delay_secs);
            }
        }
    }
}

/// シャットダウンシグナル Future を作成
///
/// ループ外で一度だけ呼び出し、tokio::pin! でピン留めして使い回す。
/// Unix では SIGINT と SIGTERM の両方を、Windows では Ctrl+C のみを待機。
/// 受信したシグナル名を返す。
async fn create_shutdown_signal() -> &'static str {
    #[cfg(unix)]
    {
        let mut sigint = signal(SignalKind::interrupt()).expect("Failed to install SIGINT handler");
        let mut sigterm =
            signal(SignalKind::terminate()).expect("Failed to install SIGTERM handler");

        tokio::select! {
            _ = sigint.recv() => "SIGINT",
            _ = sigterm.recv() => "SIGTERM",
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
        "Ctrl+C"
    }
}

/// SSH ProxyCommand 用シャットダウンシグナル Future を作成
///
/// SSH がセッション終了時に ProxyCommand へ送るシグナル (SIGTERM, SIGHUP) と、
/// 直接の Ctrl+C (SIGINT) を待機する。
/// 受信したシグナル名を返す。
async fn create_shutdown_signal_for_ssh_proxy() -> &'static str {
    #[cfg(unix)]
    {
        let mut sigint = signal(SignalKind::interrupt()).expect("Failed to install SIGINT handler");
        let mut sigterm =
            signal(SignalKind::terminate()).expect("Failed to install SIGTERM handler");
        let mut sighup = signal(SignalKind::hangup()).expect("Failed to install SIGHUP handler");

        tokio::select! {
            _ = sigint.recv() => "SIGINT",
            _ = sigterm.recv() => "SIGTERM",
            _ = sighup.recv() => "SIGHUP",
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
        "Ctrl+C"
    }
}

/// 受信した RemoteNewConnection を処理
///
/// QUIC ストリームの先頭 4 bytes に conn_id が書き込まれているため、
/// それを読み取って接続を識別する。RemoteNewConnection メッセージは情報提供のみ。
async fn handle_incoming_tunnel(
    tunnel: Connection,
    mut control_stream: ControlStream,
    local_addr: &str,
    protocol: Protocol,
    conn_manager: Arc<Mutex<ConnectionManager>>,
) -> Result<()> {
    let local_addr = local_addr.to_string();

    // シグナルハンドラをループ外で一度だけ作成
    let shutdown_signal = create_shutdown_signal();
    tokio::pin!(shutdown_signal);

    loop {
        debug!("Waiting for events...");

        tokio::select! {
            // SIGINT または SIGTERM を受信
            // ピン留めした Future を参照で使用
            signal_name = &mut shutdown_signal => {
                info!("Received {}, sending SessionClose to server...", signal_name);

                // SessionClose メッセージを送信
                let close_msg = ControlMessage::SessionClose;
                if let Err(e) = control_stream.send_message(&close_msg).await {
                    warn!("Failed to send SessionClose: {}", e);
                }

                // ストリームを正常に終了
                if let Err(e) = control_stream.finish() {
                    debug!("Failed to finish control stream: {}", e);
                }

                // メッセージが送信されるまで少し待機
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;

                // QUIC コネクションを閉じる
                tunnel.close(0u32.into(), b"client shutdown");

                info!("Connection closed gracefully");
                break;
            }

            // QUIC ストリームを受け付け（サーバーが開く）
            // ストリームの先頭 4 bytes から conn_id を読み取る
            result = tunnel.accept_bi() => {
                match result {
                    Ok((send, mut recv)) => {
                        debug!("QUIC stream accepted");

                        // ストリームの先頭 4 bytes から conn_id を読み取る
                        let mut conn_id_buf = [0u8; 4];
                        match recv.read_exact(&mut conn_id_buf).await {
                            Ok(()) => {
                                let conn_id = u32::from_be_bytes(conn_id_buf);
                                debug!("Read conn_id from stream: {}", conn_id);

                                // 接続を処理
                                process_remote_new_connection(
                                    conn_id,
                                    protocol,
                                    send,
                                    recv,
                                    &local_addr,
                                    &mut control_stream,
                                    &conn_manager,
                                )
                                .await;
                            }
                            Err(e) => {
                                error!("Failed to read conn_id from stream: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        // コネクションが閉じられた場合
                        debug!("Failed to accept QUIC stream: {}", e);
                        break;
                    }
                }
            }

            // サーバーからのメッセージを待機（正しいフレーミング）
            // RemoteNewConnection は情報提供のみ（conn_id はストリームから取得済み）
            result = control_stream.recv_message() => {
                match result {
                    Ok(ControlMessage::RemoteNewConnection {
                        connection_id,
                        protocol: conn_protocol,
                    }) => {
                        // RemoteNewConnection は情報提供のみ（実際の conn_id はストリームから取得済み）
                        debug!(
                            "RemoteNewConnection notification: conn_id={}, protocol={}",
                            connection_id, conn_protocol
                        );
                    }
                    Ok(ControlMessage::SessionClose) => {
                        info!("Server requested session close");
                        break;
                    }
                    Ok(msg) => {
                        debug!("Received control message: {:?}", msg);
                    }
                    Err(ProtocolError::StreamClosed) => {
                        info!("Control stream closed by server");
                        break;
                    }
                    Err(e) => {
                        error!("Control stream error: {}", e);
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

/// RemoteNewConnection を処理してデータ転送を開始
///
/// conn_id はストリームから読み取り済み。
/// ローカルサービスへの接続を確立してからデータ転送を開始する。
/// 接続失敗時は ConnectionClose を送信して Stream を閉じる。
async fn process_remote_new_connection(
    connection_id: u32,
    conn_protocol: Protocol,
    quic_send: SendStream,
    quic_recv: RecvStream,
    local_addr: &str,
    control_stream: &mut ControlStream,
    conn_manager: &Arc<Mutex<ConnectionManager>>,
) {
    match conn_protocol {
        Protocol::Tcp => {
            // TCP: ローカルサービスに接続
            let local_stream = match TcpStream::connect(local_addr).await {
                Ok(s) => s,
                Err(e) => {
                    error!(
                        "Failed to connect to local TCP service {}: {}",
                        local_addr, e
                    );
                    let close_msg = ControlMessage::ConnectionClose {
                        connection_id,
                        reason: crate::protocol::CloseReason::ConnectionRefused,
                    };
                    let _ = control_stream.send_message(&close_msg).await;
                    return;
                }
            };

            debug!("Connected to local TCP service: {}", local_addr);

            conn_manager
                .lock()
                .await
                .add_connection(connection_id, conn_protocol);

            let conn_manager_clone = conn_manager.clone();
            tokio::spawn(
                async move {
                    if let Err(e) =
                        relay_tcp_stream(connection_id, local_stream, quic_send, quic_recv).await
                    {
                        debug!("TCP relay ended for {}: {}", connection_id, e);
                    }
                    conn_manager_clone
                        .lock()
                        .await
                        .remove_connection(connection_id);
                }
                .instrument(tracing::Span::current()),
            );
        }
        Protocol::Udp => {
            // UDP: ローカルソケットを作成してローカルサービスに接続
            // 0.0.0.0:0 にバインドして、ローカルサービスに connect する
            let local_socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to create local UDP socket: {}", e);
                    let close_msg = ControlMessage::ConnectionClose {
                        connection_id,
                        reason: crate::protocol::CloseReason::OtherError,
                    };
                    let _ = control_stream.send_message(&close_msg).await;
                    return;
                }
            };

            // connect でローカルサービスに接続（送信先を固定）
            if let Err(e) = local_socket.connect(local_addr).await {
                error!(
                    "Failed to connect UDP socket to local service {}: {}",
                    local_addr, e
                );
                let close_msg = ControlMessage::ConnectionClose {
                    connection_id,
                    reason: crate::protocol::CloseReason::ConnectionRefused,
                };
                let _ = control_stream.send_message(&close_msg).await;
                return;
            }

            debug!("Connected UDP socket to local service: {}", local_addr);

            conn_manager
                .lock()
                .await
                .add_connection(connection_id, conn_protocol);

            let conn_manager_clone = conn_manager.clone();
            tokio::spawn(
                async move {
                    if let Err(e) =
                        relay_udp_stream(connection_id, local_socket, quic_send, quic_recv).await
                    {
                        debug!("UDP relay ended for {}: {}", connection_id, e);
                    }
                    conn_manager_clone
                        .lock()
                        .await
                        .remove_connection(connection_id);
                }
                .instrument(tracing::Span::current()),
            );
        }
    }
}

/// TCP ストリームと QUIC ストリーム間でデータを中継
async fn relay_tcp_stream(
    conn_id: u32,
    tcp_stream: TcpStream,
    mut quic_send: SendStream,
    mut quic_recv: RecvStream,
) -> Result<()> {
    debug!("[{}] Starting relay", conn_id);
    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

    // TCP -> QUIC (独立したタスクとして実行)
    let tcp_to_quic = tokio::spawn(
        async move {
            let mut buf = vec![0u8; 8192];
            debug!("[{}] TCP->QUIC task started", conn_id);
            loop {
                let n = tcp_read.read(&mut buf).await?;
                debug!("[{}] TCP read {} bytes", conn_id, n);
                if n == 0 {
                    debug!("[{}] TCP read EOF", conn_id);
                    break;
                }
                quic_send.write_all(&buf[..n]).await?;
                debug!("[{}] QUIC write {} bytes", conn_id, n);
            }
            debug!("[{}] TCP->QUIC finishing stream", conn_id);
            quic_send.finish()?;
            Ok::<_, anyhow::Error>(())
        }
        .instrument(tracing::Span::current()),
    );

    // QUIC -> TCP (独立したタスクとして実行)
    let quic_to_tcp = tokio::spawn(
        async move {
            let mut buf = vec![0u8; 8192];
            debug!("[{}] QUIC->TCP task started", conn_id);
            loop {
                match quic_recv.read(&mut buf).await? {
                    Some(n) if n > 0 => {
                        debug!("[{}] QUIC read {} bytes", conn_id, n);
                        tcp_write.write_all(&buf[..n]).await?;
                        debug!("[{}] TCP write {} bytes", conn_id, n);
                    }
                    _ => {
                        debug!("[{}] QUIC read EOF", conn_id);
                        break;
                    }
                }
            }
            Ok::<_, anyhow::Error>(())
        }
        .instrument(tracing::Span::current()),
    );

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

/// UDP ソケットと QUIC ストリーム間でデータを中継
///
/// UDP はパケット境界を保持するため、Length-prefixed framing を使用:
/// - 送信時: [4 bytes length (BE)] + [payload]
/// - 受信時: [4 bytes length (BE)] + [payload]
async fn relay_udp_stream(
    conn_id: u32,
    local_socket: UdpSocket,
    mut quic_send: SendStream,
    mut quic_recv: RecvStream,
) -> Result<()> {
    debug!("[{}] Starting UDP relay", conn_id);

    let local_socket = Arc::new(local_socket);

    // QUIC -> UDP (サーバーからのパケットをローカルに転送)
    let socket_for_recv = local_socket.clone();
    let quic_to_udp = tokio::spawn(
        async move {
            debug!("[{}] QUIC->UDP task started", conn_id);
            loop {
                // Length-prefixed framing で読み取り
                let mut len_buf = [0u8; 4];
                if let Err(e) = quic_recv.read_exact(&mut len_buf).await {
                    debug!("[{}] QUIC read length error: {}", conn_id, e);
                    break;
                }
                let len = u32::from_be_bytes(len_buf) as usize;

                let mut payload = vec![0u8; len];
                if let Err(e) = quic_recv.read_exact(&mut payload).await {
                    debug!("[{}] QUIC read payload error: {}", conn_id, e);
                    break;
                }

                debug!("[{}] QUIC read {} bytes", conn_id, len);

                // ローカルサービスに送信
                if let Err(e) = socket_for_recv.send(&payload).await {
                    debug!("[{}] UDP send error: {}", conn_id, e);
                    break;
                }
                debug!("[{}] UDP sent {} bytes", conn_id, len);
            }
            Ok::<_, anyhow::Error>(())
        }
        .instrument(tracing::Span::current()),
    );

    // UDP -> QUIC (ローカルからの応答をサーバーに転送)
    let udp_to_quic = tokio::spawn(
        async move {
            let mut buf = vec![0u8; 65535];
            debug!("[{}] UDP->QUIC task started", conn_id);
            loop {
                let n = match local_socket.recv(&mut buf).await {
                    Ok(n) if n > 0 => n,
                    Ok(_) => {
                        debug!("[{}] UDP recv returned 0", conn_id);
                        break;
                    }
                    Err(e) => {
                        debug!("[{}] UDP recv error: {}", conn_id, e);
                        break;
                    }
                };

                debug!("[{}] UDP recv {} bytes", conn_id, n);

                // Length-prefixed framing で送信
                let len = n as u32;
                if let Err(e) = quic_send.write_all(&len.to_be_bytes()).await {
                    debug!("[{}] QUIC write length error: {}", conn_id, e);
                    break;
                }
                if let Err(e) = quic_send.write_all(&buf[..n]).await {
                    debug!("[{}] QUIC write payload error: {}", conn_id, e);
                    break;
                }
                debug!("[{}] QUIC sent {} bytes", conn_id, n);
            }
            let _ = quic_send.finish();
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

    debug!("[{}] UDP relay completed", conn_id);
    Ok(())
}

// =============================================================================
// Local Port Forwarding (LPF) 実装
// クライアント側でポートをリッスンし、サーバー側のリモートサービスに転送
// =============================================================================

use socket2::{Domain, Protocol as SockProtocol, Socket, Type};
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::net::TcpListener;

/// LPF 用の接続 ID カウンター
static LPF_CONNECTION_ID_COUNTER: AtomicU32 = AtomicU32::new(1);

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

/// LPF クライアントを起動
///
/// ローカルポートでリッスンし、接続をサーバー経由でリモートサービスに転送
///
/// # Arguments
/// * `destination` - 接続先サーバーのアドレス
/// * `local_source` - ローカルソースポート（クライアント側でリッスン、例: "9022/tcp" or "9022"）
/// * `remote_destination` - リモート転送先（例: "22/tcp", "22", "192.168.1.100:22"）
/// * `auth_config` - 認証設定
/// * `insecure` - true の場合、証明書検証をスキップ（テスト用）
async fn run_local_forward(
    destination: &str,
    local_source: &str,
    remote_destination: &str,
    auth_config: ClientAuthConfig,
    insecure: bool,
    keep_alive_secs: u64,
    idle_timeout_secs: u64,
) -> Result<()> {
    // 引数をパース
    // local_source は port/protocol 形式（アドレスなし）
    let (local_port_num, local_protocol) = parse_port_spec(local_source)
        .context("Invalid local-source format (expected: port/protocol, e.g., 9022/tcp)")?;

    // remote_destination は addr:port/protocol 形式（addr と protocol は省略可）
    let (remote_host, remote_port_num, remote_protocol) = parse_destination_spec(remote_destination)
        .context("Invalid remote-destination format (expected: [addr:]port[/protocol], e.g., 22, 22/tcp, 192.168.1.100:22)")?;

    if local_protocol != remote_protocol {
        anyhow::bail!(
            "Protocol mismatch: local={}, remote={}",
            local_protocol,
            remote_protocol
        );
    }

    // 接続先アドレスをパース
    let server_addr: SocketAddr = destination
        .parse()
        .or_else(|_| {
            // ホスト名の場合は DNS 解決
            use std::net::ToSocketAddrs;
            destination
                .to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next())
                .ok_or_else(|| anyhow::anyhow!("Failed to resolve address: {}", destination))
        })
        .context("Invalid destination address")?;

    info!("Connecting to {} ...", server_addr);

    // insecure モードまたは TOFU モードで接続
    let tunnel = if insecure {
        // 証明書検証をスキップ（テスト用）
        warn!("Insecure mode: skipping server certificate verification");
        let endpoint =
            create_client_endpoint(&server_addr, keep_alive_secs, idle_timeout_secs)?;
        endpoint
            .connect(server_addr, "quicport")
            .context("Failed to initiate tunnel")?
            .await
            .context("Failed to establish QUIC tunnel")?
    } else {
        // TOFU 検証を行う
        let known_hosts_path = KnownHosts::default_path()?;
        let known_hosts = Arc::new(KnownHosts::new(known_hosts_path)?);

        let (endpoint, tofu_verifier) = create_client_endpoint_with_tofu(
            &server_addr,
            destination,
            known_hosts.clone(),
            keep_alive_secs,
            idle_timeout_secs,
        )?;

        let tunnel = endpoint
            .connect(server_addr, "quicport")
            .context("Failed to initiate tunnel")?
            .await
            .context("Failed to establish QUIC tunnel")?;

        // TOFU 検証結果を確認
        if let Some(status) = tofu_verifier.get_status() {
            handle_tofu_status(&status, &known_hosts).await?;
        }

        tunnel
    };

    info!("Connected to {}", server_addr);

    // 制御ストリームを開く
    let (mut control_send, mut control_recv) = tunnel
        .open_bi()
        .await
        .context("Failed to open control stream")?;

    debug!("Control stream opened");

    // 認証方式に応じて処理を分岐
    match &auth_config {
        ClientAuthConfig::X25519 {
            private_key,
            expected_server_pubkey,
        } => {
            authenticate_with_server_x25519(
                &mut control_send,
                &mut control_recv,
                private_key,
                expected_server_pubkey,
            )
            .await
            .context("X25519 authentication failed")?;
            info!("Authenticated with server (X25519)");
        }
        ClientAuthConfig::Psk { psk } => {
            authenticate_with_server_psk(&mut control_send, &mut control_recv, psk)
                .await
                .context("PSK authentication failed")?;
            info!("Authenticated with server (PSK)");
        }
    }

    // 認証完了後、ControlStream でラップしてメッセージフレーミングを有効化
    let mut control_stream = ControlStream::new(control_send, control_recv);

    // リモート転送先のアドレス文字列を構築
    let remote_addr_str = format_socket_addr(&remote_host, remote_port_num);

    // LocalForwardRequest を送信
    let forward_request = ControlMessage::LocalForwardRequest {
        remote_destination: remote_addr_str.clone(),
        protocol: local_protocol,
        local_source: local_source.to_string(),
    };
    control_stream
        .send_message(&forward_request)
        .await
        .context("Failed to send LocalForwardRequest")?;

    debug!(
        "LocalForwardRequest sent: remote_destination={}, protocol={}",
        remote_addr_str, local_protocol
    );

    // LocalForwardResponse を待機
    let response = control_stream
        .recv_message()
        .await
        .context("Failed to read LocalForwardResponse")?;

    match response {
        ControlMessage::LocalForwardResponse { status, message } => {
            if status != ResponseStatus::Success {
                anyhow::bail!(
                    "Server rejected LocalForwardRequest: {:?} - {}",
                    status,
                    message
                );
            }
            info!("Server accepted LocalForwardRequest: {}", message);
        }
        _ => {
            anyhow::bail!("Unexpected response from server");
        }
    }

    // 接続マネージャ
    let conn_manager = Arc::new(Mutex::new(ConnectionManager::new()));

    info!(
        "Tunnel established: localhost:{}:{} -> server -> {}",
        local_port_num, local_protocol, remote_addr_str
    );

    // ローカルポートでリッスンして接続をサーバーに転送
    handle_local_tunnel(
        tunnel,
        control_stream,
        local_port_num,
        local_protocol,
        conn_manager,
    )
    .await?;

    Ok(())
}

/// LPF 切断理由
enum LpfCloseReason {
    /// ユーザーによる正常終了（SIGINT/SIGTERM）
    GracefulShutdown,
    /// サーバーからの正常終了要求
    ServerSessionClose,
    /// QUIC 接続が予期せずクローズされた（再接続が必要）
    ConnectionLost(String),
    /// 制御ストリームエラー（再接続が必要）
    ControlStreamError(String),
}

/// LPF: ローカルポートでリッスンして接続を処理
async fn handle_local_tunnel(
    tunnel: Connection,
    mut control_stream: ControlStream,
    local_port: u16,
    protocol: Protocol,
    conn_manager: Arc<Mutex<ConnectionManager>>,
) -> Result<()> {
    let bind_addr: SocketAddr = format!("0.0.0.0:{}", local_port).parse()?;

    match protocol {
        Protocol::Tcp => {
            // SO_REUSEADDR を設定して TCP リスナーを作成
            let listener = match create_tcp_listener_with_reuseaddr(bind_addr) {
                Ok(std_listener) => match TcpListener::from_std(std_listener) {
                    Ok(l) => {
                        info!("TCP listener started on port {} (LPF)", local_port);
                        l
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                },
                Err(e) => {
                    return Err(e.into());
                }
            };

            // シグナルハンドラをループ外で一度だけ作成
            let shutdown_signal = create_shutdown_signal();
            tokio::pin!(shutdown_signal);

            // TCP 用切断理由
            let close_reason: LpfCloseReason;

            // TCP 接続を受け付けるループ
            loop {
                tokio::select! {
                    // SIGINT または SIGTERM を受信
                    // ピン留めした Future を参照で使用
                    signal_name = &mut shutdown_signal => {
                        info!("Received {}, sending SessionClose to server...", signal_name);

                        let close_msg = ControlMessage::SessionClose;
                        if let Err(e) = control_stream.send_message(&close_msg).await {
                            warn!("Failed to send SessionClose: {}", e);
                        }

                        if let Err(e) = control_stream.finish() {
                            debug!("Failed to finish control stream: {}", e);
                        }

                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        tunnel.close(0u32.into(), b"client shutdown");

                        info!("Connection closed gracefully");
                        close_reason = LpfCloseReason::GracefulShutdown;
                        break;
                    }

                    // QUIC コネクションがクローズされた場合
                    reason = tunnel.closed() => {
                        info!("QUIC tunnel closed: {:?}, stopping LPF listener", reason);
                        close_reason = LpfCloseReason::ConnectionLost(format!("{:?}", reason));
                        break;
                    }

                    // 新しい TCP 接続
                    result = listener.accept() => {
                        match result {
                            Ok((tcp_stream, tcp_addr)) => {
                                let conn_id = LPF_CONNECTION_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
                                info!("New local TCP connection {} from {}", conn_id, tcp_addr);

                                // 1. QUIC ストリームを開く（LPF ではクライアントが開く）
                                let (mut quic_send, quic_recv) = match tunnel.open_bi().await {
                                    Ok(s) => s,
                                    Err(e) => {
                                        error!("Failed to open QUIC stream: {}", e);
                                        continue;
                                    }
                                };

                                // 2. conn_id を 4 bytes (big-endian) でストリームの先頭に書き込む
                                if let Err(e) = quic_send.write_all(&conn_id.to_be_bytes()).await {
                                    error!("Failed to write conn_id to stream: {}", e);
                                    continue;
                                }

                                // 3. LocalNewConnection を送信
                                let new_conn_msg = ControlMessage::LocalNewConnection {
                                    connection_id: conn_id,
                                    protocol: Protocol::Tcp,
                                };
                                if let Err(e) = control_stream.send_message(&new_conn_msg).await {
                                    error!("Failed to send LocalNewConnection: {}", e);
                                    continue;
                                }

                                // 4. 接続を登録してデータ転送開始
                                conn_manager.lock().await.add_connection(conn_id, Protocol::Tcp);

                                let conn_manager_clone = conn_manager.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = relay_tcp_stream(conn_id, tcp_stream, quic_send, quic_recv).await {
                                        debug!("TCP relay ended for {}: {}", conn_id, e);
                                    }
                                    conn_manager_clone.lock().await.remove_connection(conn_id);
                                }.instrument(tracing::Span::current()));
                            }
                            Err(e) => {
                                error!("Failed to accept TCP connection: {}", e);
                            }
                        }
                    }

                    // サーバーからの制御メッセージを待機
                    result = control_stream.recv_message() => {
                        match result {
                            Ok(ControlMessage::SessionClose) => {
                                info!("Server requested session close");
                                close_reason = LpfCloseReason::ServerSessionClose;
                                break;
                            }
                            Ok(ControlMessage::ConnectionClose {
                                connection_id,
                                reason,
                            }) => {
                                info!(
                                    "Server notified connection close for conn_id={}: {:?}",
                                    connection_id, reason
                                );
                                conn_manager.lock().await.remove_connection(connection_id);
                            }
                            Ok(msg) => {
                                debug!("Received control message: {:?}", msg);
                            }
                            Err(ProtocolError::StreamClosed) => {
                                info!("Control stream closed by server");
                                // 予期しないストリーム切断は再接続対象
                                close_reason = LpfCloseReason::ConnectionLost("Control stream closed unexpectedly".to_string());
                                break;
                            }
                            Err(e) => {
                                error!("Control stream error: {}", e);
                                close_reason = LpfCloseReason::ControlStreamError(format!("{}", e));
                                break;
                            }
                        }
                    }
                }
            }

            // TCP セクションの切断理由を返す
            return match close_reason {
                LpfCloseReason::GracefulShutdown | LpfCloseReason::ServerSessionClose => Ok(()),
                LpfCloseReason::ConnectionLost(reason) => {
                    Err(anyhow::anyhow!("Connection lost: {}", reason))
                }
                LpfCloseReason::ControlStreamError(reason) => {
                    Err(anyhow::anyhow!("Control stream error: {}", reason))
                }
            };
        }
        Protocol::Udp => {
            // UDP ソケットを作成してリッスン
            let socket = match UdpSocket::bind(bind_addr).await {
                Ok(s) => {
                    info!("UDP listener started on port {} (LPF)", local_port);
                    Arc::new(s)
                }
                Err(e) => {
                    return Err(e.into());
                }
            };

            // UDP "仮想接続" を管理
            let udp_connections: Arc<
                Mutex<HashMap<SocketAddr, (u32, tokio::sync::mpsc::Sender<Vec<u8>>)>>,
            > = Arc::new(Mutex::new(HashMap::new()));

            let mut recv_buf = vec![0u8; 65535];

            // シグナルハンドラをループ外で一度だけ作成
            let shutdown_signal = create_shutdown_signal();
            tokio::pin!(shutdown_signal);

            // UDP 用切断理由
            let udp_close_reason: LpfCloseReason;

            loop {
                tokio::select! {
                    // シャットダウンシグナル
                    // ピン留めした Future を参照で使用
                    signal_name = &mut shutdown_signal => {
                        info!("Received {}, sending SessionClose to server...", signal_name);

                        let close_msg = ControlMessage::SessionClose;
                        if let Err(e) = control_stream.send_message(&close_msg).await {
                            warn!("Failed to send SessionClose: {}", e);
                        }

                        if let Err(e) = control_stream.finish() {
                            debug!("Failed to finish control stream: {}", e);
                        }

                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        tunnel.close(0u32.into(), b"client shutdown");

                        info!("Connection closed gracefully");
                        udp_close_reason = LpfCloseReason::GracefulShutdown;
                        break;
                    }

                    // QUIC コネクションがクローズされた場合
                    reason = tunnel.closed() => {
                        info!("QUIC tunnel closed: {:?}, stopping UDP LPF listener", reason);
                        udp_close_reason = LpfCloseReason::ConnectionLost(format!("{:?}", reason));
                        break;
                    }

                    // UDP パケット受信
                    result = socket.recv_from(&mut recv_buf) => {
                        match result {
                            Ok((len, src_addr)) => {
                                let packet = recv_buf[..len].to_vec();
                                debug!("UDP packet from {}: {} bytes", src_addr, len);

                                // 既存の仮想接続を確認
                                let maybe_existing = {
                                    let conns = udp_connections.lock().await;
                                    conns.get(&src_addr).map(|(id, tx)| (*id, tx.clone()))
                                };

                                if let Some((conn_id, tx)) = maybe_existing {
                                    // 既存の接続にパケットを送信
                                    if tx.send(packet).await.is_err() {
                                        debug!("UDP connection {} channel closed, removing", conn_id);
                                        udp_connections.lock().await.remove(&src_addr);
                                    }
                                } else {
                                    // 新しい仮想接続を作成
                                    let conn_id = LPF_CONNECTION_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
                                    info!("New local UDP connection {} from {}", conn_id, src_addr);

                                    // QUIC ストリームを開く
                                    let (mut quic_send, quic_recv) = match tunnel.open_bi().await {
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

                                    // LocalNewConnection を送信
                                    let new_conn_msg = ControlMessage::LocalNewConnection {
                                        connection_id: conn_id,
                                        protocol: Protocol::Udp,
                                    };
                                    if let Err(e) = control_stream.send_message(&new_conn_msg).await {
                                        error!("Failed to send LocalNewConnection: {}", e);
                                        continue;
                                    }

                                    // パケット送信用チャネルを作成
                                    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

                                    // 接続を登録
                                    {
                                        conn_manager.lock().await.add_connection(conn_id, Protocol::Udp);
                                        udp_connections.lock().await.insert(src_addr, (conn_id, tx.clone()));
                                    }

                                    // 最初のパケットを送信
                                    let _ = tx.send(packet).await;

                                    // UDP リレータスクを起動
                                    let conn_manager_clone = conn_manager.clone();
                                    let udp_connections_clone = udp_connections.clone();
                                    let socket_clone = socket.clone();
                                    tokio::spawn(async move {
                                        if let Err(e) = relay_lpf_udp_stream(
                                            conn_id,
                                            src_addr,
                                            socket_clone,
                                            rx,
                                            quic_send,
                                            quic_recv,
                                        )
                                        .await
                                        {
                                            debug!("UDP relay ended for {}: {}", conn_id, e);
                                        }
                                        conn_manager_clone.lock().await.remove_connection(conn_id);
                                        udp_connections_clone.lock().await.remove(&src_addr);
                                    }.instrument(tracing::Span::current()));
                                }
                            }
                            Err(e) => {
                                error!("Failed to receive UDP packet: {}", e);
                            }
                        }
                    }

                    // サーバーからの制御メッセージを待機
                    result = control_stream.recv_message() => {
                        match result {
                            Ok(ControlMessage::SessionClose) => {
                                info!("Server requested session close");
                                udp_close_reason = LpfCloseReason::ServerSessionClose;
                                break;
                            }
                            Ok(ControlMessage::ConnectionClose {
                                connection_id,
                                reason,
                            }) => {
                                info!(
                                    "Server notified connection close for conn_id={}: {:?}",
                                    connection_id, reason
                                );
                                conn_manager.lock().await.remove_connection(connection_id);
                            }
                            Ok(msg) => {
                                debug!("Received control message: {:?}", msg);
                            }
                            Err(ProtocolError::StreamClosed) => {
                                info!("Control stream closed by server");
                                // 予期しないストリーム切断は再接続対象
                                udp_close_reason = LpfCloseReason::ConnectionLost("Control stream closed unexpectedly".to_string());
                                break;
                            }
                            Err(e) => {
                                error!("Control stream error: {}", e);
                                udp_close_reason = LpfCloseReason::ControlStreamError(format!("{}", e));
                                break;
                            }
                        }
                    }
                }
            }

            // UDP セクションの切断理由を返す
            return match udp_close_reason {
                LpfCloseReason::GracefulShutdown | LpfCloseReason::ServerSessionClose => Ok(()),
                LpfCloseReason::ConnectionLost(reason) => {
                    Err(anyhow::anyhow!("Connection lost: {}", reason))
                }
                LpfCloseReason::ControlStreamError(reason) => {
                    Err(anyhow::anyhow!("Control stream error: {}", reason))
                }
            };
        }
    }
}

/// LPF: UDP パケットと QUIC ストリーム間でデータを中継
async fn relay_lpf_udp_stream(
    conn_id: u32,
    src_addr: SocketAddr,
    udp_socket: Arc<UdpSocket>,
    mut packet_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    mut quic_send: SendStream,
    mut quic_recv: RecvStream,
) -> Result<()> {
    debug!("[{}] Starting LPF UDP relay for {}", conn_id, src_addr);

    // UDP -> QUIC (ローカルクライアントからのパケットをサーバーに送信)
    let udp_to_quic = tokio::spawn(
        async move {
            debug!("[{}] UDP->QUIC task started", conn_id);
            loop {
                match packet_rx.recv().await {
                    Some(data) => {
                        // Length-prefixed framing
                        let len = data.len() as u32;
                        if let Err(e) = quic_send.write_all(&len.to_be_bytes()).await {
                            debug!("[{}] Failed to write length: {}", conn_id, e);
                            break;
                        }
                        if let Err(e) = quic_send.write_all(&data).await {
                            debug!("[{}] Failed to write UDP data: {}", conn_id, e);
                            break;
                        }
                        debug!("[{}] UDP->QUIC {} bytes", conn_id, data.len());
                    }
                    None => {
                        debug!("[{}] UDP packet channel closed", conn_id);
                        break;
                    }
                }
            }
            let _ = quic_send.finish();
            Ok::<_, anyhow::Error>(())
        }
        .instrument(tracing::Span::current()),
    );

    // QUIC -> UDP (サーバーからの応答をローカルクライアントに返す)
    let quic_to_udp = tokio::spawn(
        async move {
            debug!("[{}] QUIC->UDP task started", conn_id);
            loop {
                // Length-prefixed framing で読み取り
                let mut len_buf = [0u8; 4];
                if let Err(e) = quic_recv.read_exact(&mut len_buf).await {
                    debug!("[{}] QUIC read length error: {}", conn_id, e);
                    break;
                }
                let len = u32::from_be_bytes(len_buf) as usize;

                let mut payload = vec![0u8; len];
                if let Err(e) = quic_recv.read_exact(&mut payload).await {
                    debug!("[{}] QUIC read payload error: {}", conn_id, e);
                    break;
                }

                debug!("[{}] QUIC read {} bytes", conn_id, len);

                // ローカルクライアントに返す
                if let Err(e) = udp_socket.send_to(&payload, src_addr).await {
                    debug!("[{}] UDP send error: {}", conn_id, e);
                    break;
                }
                debug!("[{}] UDP sent {} bytes to {}", conn_id, len, src_addr);
            }
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

    debug!("[{}] LPF UDP relay completed", conn_id);
    Ok(())
}

// =============================================================================
// SSH ProxyCommand モード実装
// stdin/stdout を使用してデータを転送
// =============================================================================

/// SSH ProxyCommand モードを実行
///
/// stdin/stdout を使用して QUIC トンネル経由でリモートサービスに接続。
/// SSH の ProxyCommand として使用することを想定。
///
/// # Arguments
/// * `destination` - 接続先サーバーのアドレス
/// * `remote_destination` - リモート転送先（例: "22", "192.168.1.100:22"）
/// * `auth_config` - 認証設定
/// * `insecure` - true の場合、証明書検証をスキップ（テスト用）
async fn run_ssh_proxy(
    destination: &str,
    remote_destination: &str,
    auth_config: ClientAuthConfig,
    insecure: bool,
    keep_alive_secs: u64,
    idle_timeout_secs: u64,
) -> Result<()> {
    // remote_destination は addr:port/protocol 形式（addr と protocol は省略可）
    // SSH 用なので protocol は TCP 固定
    let (remote_host, remote_port_num, _remote_protocol) = parse_destination_spec(remote_destination)
        .context("Invalid remote-destination format (expected: [addr:]port[/protocol], e.g., 22, 192.168.1.100:22)")?;

    // 接続先アドレスをパース
    let server_addr: SocketAddr = destination
        .parse()
        .or_else(|_| {
            // ホスト名の場合は DNS 解決
            use std::net::ToSocketAddrs;
            destination
                .to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next())
                .ok_or_else(|| anyhow::anyhow!("Failed to resolve address: {}", destination))
        })
        .context("Invalid destination address")?;

    info!("SSH proxy connecting to {} ...", server_addr);

    // insecure モードまたは TOFU モードで接続
    // 注意: ssh-proxy は対話的でないため、TOFU の未知ホスト確認はできない
    // insecure=false の場合も TOFU は無効化し、既知ホストのみ接続可能とする
    let tunnel = if insecure {
        warn!("Insecure mode: skipping server certificate verification");
        let endpoint =
            create_client_endpoint(&server_addr, keep_alive_secs, idle_timeout_secs)?;
        endpoint
            .connect(server_addr, "quicport")
            .context("Failed to initiate tunnel")?
            .await
            .context("Failed to establish QUIC tunnel")?
    } else {
        // TOFU 検証を行う（ただし非対話なので未知ホストは拒否）
        let known_hosts_path = KnownHosts::default_path()?;
        let known_hosts = Arc::new(KnownHosts::new(known_hosts_path)?);

        let (endpoint, tofu_verifier) = create_client_endpoint_with_tofu(
            &server_addr,
            destination,
            known_hosts.clone(),
            keep_alive_secs,
            idle_timeout_secs,
        )?;

        let tunnel = endpoint
            .connect(server_addr, "quicport")
            .context("Failed to initiate tunnel")?
            .await
            .context("Failed to establish QUIC tunnel")?;

        // TOFU 検証結果を確認（非対話モードなので未知/変更は拒否）
        if let Some(status) = tofu_verifier.get_status() {
            match &status {
                TofuStatus::Known => {
                    debug!("Server certificate verified (known host)");
                }
                TofuStatus::Unknown {
                    host, fingerprint, ..
                } => {
                    anyhow::bail!(
                        "Unknown host '{}' with fingerprint '{}'. \
                         Run quicport client first to add it to known_hosts, or use --insecure.",
                        host,
                        fingerprint
                    );
                }
                TofuStatus::Changed {
                    host,
                    old_fingerprint,
                    new_fingerprint,
                    ..
                } => {
                    anyhow::bail!(
                        "Host '{}' certificate changed! Old: {}, New: {}. \
                         This could be a man-in-the-middle attack. \
                         Update known_hosts manually if this is expected.",
                        host,
                        old_fingerprint,
                        new_fingerprint
                    );
                }
            }
        }

        tunnel
    };

    info!("Connected to {}", server_addr);

    // 制御ストリームを開く
    let (mut control_send, mut control_recv) = tunnel
        .open_bi()
        .await
        .context("Failed to open control stream")?;

    debug!("Control stream opened");

    // 認証方式に応じて処理を分岐
    match &auth_config {
        ClientAuthConfig::X25519 {
            private_key,
            expected_server_pubkey,
        } => {
            authenticate_with_server_x25519(
                &mut control_send,
                &mut control_recv,
                private_key,
                expected_server_pubkey,
            )
            .await
            .context("X25519 authentication failed")?;
            info!("Authenticated with server (X25519)");
        }
        ClientAuthConfig::Psk { psk } => {
            authenticate_with_server_psk(&mut control_send, &mut control_recv, psk)
                .await
                .context("PSK authentication failed")?;
            info!("Authenticated with server (PSK)");
        }
    }

    // 認証完了後、ControlStream でラップしてメッセージフレーミングを有効化
    let mut control_stream = ControlStream::new(control_send, control_recv);

    // リモート転送先のアドレス文字列を構築
    let remote_addr_str = format_socket_addr(&remote_host, remote_port_num);

    // LocalForwardRequest を送信（LPF と同じプロトコル）
    let forward_request = ControlMessage::LocalForwardRequest {
        remote_destination: remote_addr_str.clone(),
        protocol: Protocol::Tcp,
        local_source: "ssh-proxy".to_string(), // 識別用
    };
    control_stream
        .send_message(&forward_request)
        .await
        .context("Failed to send LocalForwardRequest")?;

    debug!(
        "LocalForwardRequest sent: remote_destination={}",
        remote_addr_str
    );

    // LocalForwardResponse を待機
    let response = control_stream
        .recv_message()
        .await
        .context("Failed to read LocalForwardResponse")?;

    match response {
        ControlMessage::LocalForwardResponse { status, message } => {
            if status != ResponseStatus::Success {
                anyhow::bail!(
                    "Server rejected LocalForwardRequest: {:?} - {}",
                    status,
                    message
                );
            }
            info!("Server accepted LocalForwardRequest: {}", message);
        }
        _ => {
            anyhow::bail!("Unexpected response from server");
        }
    }

    // QUIC ストリームを開いてデータ転送
    let conn_id = LPF_CONNECTION_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
    info!("Opening data stream for SSH proxy (conn_id={})", conn_id);

    let (mut quic_send, quic_recv) = tunnel
        .open_bi()
        .await
        .context("Failed to open data stream")?;

    // conn_id を 4 bytes (big-endian) でストリームの先頭に書き込む
    quic_send
        .write_all(&conn_id.to_be_bytes())
        .await
        .context("Failed to write conn_id to stream")?;

    // LocalNewConnection を送信
    let new_conn_msg = ControlMessage::LocalNewConnection {
        connection_id: conn_id,
        protocol: Protocol::Tcp,
    };
    control_stream
        .send_message(&new_conn_msg)
        .await
        .context("Failed to send LocalNewConnection")?;

    info!(
        "SSH proxy tunnel established: stdin/stdout -> {} -> {}",
        server_addr, remote_addr_str
    );

    // stdin/stdout と QUIC ストリーム間でデータを中継
    relay_stdio_to_quic(conn_id, quic_send, quic_recv).await?;

    // グレースフルシャットダウン
    info!("Sending SessionClose to server...");
    let close_msg = ControlMessage::SessionClose;
    if let Err(e) = control_stream.send_message(&close_msg).await {
        debug!("Failed to send SessionClose: {}", e);
    }
    if let Err(e) = control_stream.finish() {
        debug!("Failed to finish control stream: {}", e);
    }

    // 少し待ってから接続を閉じる
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    tunnel.close(0u32.into(), b"ssh-proxy done");

    info!("SSH proxy tunnel closed");
    Ok(())
}

/// stdin/stdout と QUIC ストリーム間でデータを中継
///
/// SSH ProxyCommand モード専用。stdin EOF で終了。
async fn relay_stdio_to_quic(
    conn_id: u32,
    mut quic_send: SendStream,
    mut quic_recv: RecvStream,
) -> Result<()> {
    debug!("[{}] Starting stdin/stdout <-> QUIC relay", conn_id);

    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    // stdin -> QUIC (独立したタスクとして実行)
    let stdin_to_quic = tokio::spawn(
        async move {
            let mut buf = vec![0u8; 8192];
            debug!("[{}] stdin->QUIC task started", conn_id);
            loop {
                let n = stdin.read(&mut buf).await?;
                debug!("[{}] stdin read {} bytes", conn_id, n);
                if n == 0 {
                    debug!("[{}] stdin EOF", conn_id);
                    break;
                }
                quic_send.write_all(&buf[..n]).await?;
                debug!("[{}] QUIC write {} bytes", conn_id, n);
            }
            debug!("[{}] stdin->QUIC finishing stream", conn_id);
            quic_send.finish()?;
            Ok::<_, anyhow::Error>(())
        }
        .instrument(tracing::Span::current()),
    );

    // QUIC -> stdout (独立したタスクとして実行)
    let quic_to_stdout = tokio::spawn(
        async move {
            let mut buf = vec![0u8; 8192];
            debug!("[{}] QUIC->stdout task started", conn_id);
            loop {
                match quic_recv.read(&mut buf).await? {
                    Some(n) if n > 0 => {
                        debug!("[{}] QUIC read {} bytes", conn_id, n);
                        stdout.write_all(&buf[..n]).await?;
                        stdout.flush().await?;
                        debug!("[{}] stdout write {} bytes", conn_id, n);
                    }
                    _ => {
                        debug!("[{}] QUIC read EOF", conn_id);
                        break;
                    }
                }
            }
            Ok::<_, anyhow::Error>(())
        }
        .instrument(tracing::Span::current()),
    );

    // シグナルハンドラを作成（SIGINT, SIGTERM, SIGHUP）
    let shutdown_signal = create_shutdown_signal_for_ssh_proxy();
    tokio::pin!(shutdown_signal);

    // どちらかが終了 or シグナル受信で完了
    tokio::select! {
        result = stdin_to_quic => {
            if let Err(e) = result {
                debug!("[{}] stdin->QUIC task error: {}", conn_id, e);
            }
        }
        result = quic_to_stdout => {
            if let Err(e) = result {
                debug!("[{}] QUIC->stdout task error: {}", conn_id, e);
            }
        }
        signal_name = &mut shutdown_signal => {
            info!("[{}] Received {}, stopping relay", conn_id, signal_name);
        }
    }

    debug!("[{}] stdin/stdout relay completed", conn_id);
    Ok(())
}

/// 再接続機能付きでクライアントを起動（LPF モード）
///
/// 接続が切断された場合、指定された設定に従って自動的に再接続を試みる。
pub async fn run_local_forward_with_reconnect(
    destination: &str,
    local_source: &str,
    remote_destination: &str,
    auth_config: ClientAuthConfig,
    insecure: bool,
    reconnect_config: ReconnectConfig,
    keep_alive_secs: u64,
    idle_timeout_secs: u64,
) -> Result<()> {
    if !reconnect_config.enabled {
        return run_local_forward(
            destination,
            local_source,
            remote_destination,
            auth_config,
            insecure,
            keep_alive_secs,
            idle_timeout_secs,
        )
        .await;
    }

    let mut attempt = 0u32;
    let mut delay_secs = reconnect_config.initial_delay_secs;

    loop {
        attempt += 1;
        let attempt_str = if reconnect_config.max_attempts == 0 {
            format!("#{}", attempt)
        } else {
            format!("#{}/{}", attempt, reconnect_config.max_attempts)
        };

        info!("Connection attempt {}", attempt_str);

        match run_local_forward(
            destination,
            local_source,
            remote_destination,
            auth_config.clone(),
            insecure,
            keep_alive_secs,
            idle_timeout_secs,
        )
        .await
        {
            Ok(()) => {
                info!("Connection closed normally");
                return Ok(());
            }
            Err(e) => {
                warn!("Connection failed: {}", e);

                if reconnect_config.max_attempts > 0 && attempt >= reconnect_config.max_attempts {
                    error!(
                        "Maximum reconnection attempts ({}) reached",
                        reconnect_config.max_attempts
                    );
                    return Err(e);
                }

                info!("Reconnecting in {} seconds...", delay_secs);
                tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;
                delay_secs = std::cmp::min(delay_secs * 2, reconnect_config.max_delay_secs);
            }
        }
    }
}

/// 再接続機能付きでクライアントを起動（SSH Proxy モード）
///
/// 接続が切断された場合、指定された設定に従って自動的に再接続を試みる。
/// 注意: SSH プロセスは stdin/stdout が閉じると終了するため、再接続には制限がある。
pub async fn run_ssh_proxy_with_reconnect(
    destination: &str,
    remote_destination: &str,
    auth_config: ClientAuthConfig,
    insecure: bool,
    reconnect_config: ReconnectConfig,
    keep_alive_secs: u64,
    idle_timeout_secs: u64,
) -> Result<()> {
    if !reconnect_config.enabled {
        return run_ssh_proxy(
            destination,
            remote_destination,
            auth_config,
            insecure,
            keep_alive_secs,
            idle_timeout_secs,
        )
        .await;
    }

    let mut attempt = 0u32;
    let mut delay_secs = reconnect_config.initial_delay_secs;

    loop {
        attempt += 1;
        let attempt_str = if reconnect_config.max_attempts == 0 {
            format!("#{}", attempt)
        } else {
            format!("#{}/{}", attempt, reconnect_config.max_attempts)
        };

        info!("Connection attempt {}", attempt_str);

        match run_ssh_proxy(
            destination,
            remote_destination,
            auth_config.clone(),
            insecure,
            keep_alive_secs,
            idle_timeout_secs,
        )
        .await
        {
            Ok(()) => {
                info!("Connection closed normally");
                return Ok(());
            }
            Err(e) => {
                warn!("Connection failed: {}", e);

                if reconnect_config.max_attempts > 0 && attempt >= reconnect_config.max_attempts {
                    error!(
                        "Maximum reconnection attempts ({}) reached",
                        reconnect_config.max_attempts
                    );
                    return Err(e);
                }

                info!("Reconnecting in {} seconds...", delay_secs);
                tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;
                delay_secs = std::cmp::min(delay_secs * 2, reconnect_config.max_delay_secs);
            }
        }
    }
}

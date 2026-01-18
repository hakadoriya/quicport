//! quicport CLI エントリーポイント

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;

use quicport::control_plane;
use quicport::data_plane;
use quicport::ipc::{AuthPolicy, DataPlaneConfig};
use quicport::quic::{
    encode_base64_key, generate_psk, load_privkey_from_file, load_pubkeys_from_file,
    parse_base64_key, psk_file_path,
};
use quicport::statistics::ServerStatistics;
use quicport::{api, client, server};

/// ログ出力形式
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
enum LogFormat {
    /// 人間が読みやすい形式
    #[default]
    Console,
    /// JSON 形式（構造化ログ）
    Json,
}

/// QUIC-based port forwarding / tunneling tool
#[derive(Parser, Debug)]
#[command(name = "quicport")]
#[command(version, about, long_about = None)]
struct Cli {
    /// Log output format
    #[arg(long, default_value = "console", env = "QUICPORT_LOG_FORMAT")]
    log_format: LogFormat,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run as data plane (QUIC connection handler)
    ///
    /// This command is typically invoked by the control plane (quicport server).
    /// The data plane handles QUIC connections and maintains backend TCP connections.
    /// It operates independently of the control plane after startup.
    DataPlane {
        /// Address and port to listen on for QUIC
        #[arg(short, long, default_value = "0.0.0.0:39000")]
        listen: SocketAddr,

        /// Drain timeout in seconds (force shutdown after this time in DRAINING state)
        #[arg(long, default_value = "300")]
        drain_timeout: u64,
    },

    /// Control commands for managing data planes
    #[command(subcommand)]
    Ctl(CtlCommands),

    /// SSH ProxyCommand mode (for use with ssh -o ProxyCommand)
    ///
    /// Connects stdin/stdout to a remote destination via QUIC tunnel.
    /// Example: ssh -o ProxyCommand='quicport ssh-proxy --server %h:39000 --psk SECRET --remote-destination 22' user@host
    SshProxy {
        /// Server address (host:port)
        #[arg(short = 's', long)]
        server: String,

        /// Remote destination (host:port or just port, e.g., "22" or "192.168.1.100:22")
        #[arg(short = 'R', long)]
        remote_destination: String,

        /// Private key in Base64 format
        #[arg(long, env = "QUICPORT_PRIVKEY")]
        privkey: Option<String>,

        /// Path to file containing the private key
        #[arg(long, env = "QUICPORT_PRIVKEY_FILE")]
        privkey_file: Option<PathBuf>,

        /// Expected server's public key in Base64 format (for mutual authentication)
        #[arg(long, env = "QUICPORT_SERVER_PUBKEY")]
        server_pubkey: Option<String>,

        /// Path to file containing the expected server's public key
        #[arg(long, env = "QUICPORT_SERVER_PUBKEY_FILE")]
        server_pubkey_file: Option<PathBuf>,

        /// Pre-shared key for authentication
        #[arg(long, env = "QUICPORT_PSK")]
        psk: Option<String>,

        /// Skip server certificate verification (insecure, for testing only)
        #[arg(long, default_value = "false")]
        insecure: bool,

        /// Auto-reconnect on connection loss (for ssh-proxy mode)
        #[arg(long, default_value = "true")]
        reconnect: bool,

        /// Maximum reconnection attempts (0 = unlimited)
        #[arg(long, default_value = "0")]
        reconnect_max_attempts: u32,

        /// Initial delay between reconnection attempts in seconds
        #[arg(long, default_value = "1")]
        reconnect_delay: u64,
    },

    /// Run as server (listen for QUIC connections)
    Server {
        /// Address and port to listen on for QUIC
        #[arg(short, long, default_value = "0.0.0.0:39000")]
        listen: SocketAddr,

        /// Address and port to listen on for API server (health checks, metrics)
        #[arg(long, default_value = "0.0.0.0:39001")]
        api_listen: SocketAddr,

        /// Disable API server
        #[arg(long, default_value = "false")]
        no_api: bool,

        /// Server's private key in Base64 format (for mutual authentication)
        #[arg(long, env = "QUICPORT_PRIVKEY")]
        privkey: Option<String>,

        /// Path to file containing the server's private key
        #[arg(long, env = "QUICPORT_PRIVKEY_FILE")]
        privkey_file: Option<PathBuf>,

        /// Authorized client public key(s) in Base64 format (comma-separated for multiple)
        #[arg(long, env = "QUICPORT_CLIENT_PUBKEYS", value_delimiter = ',')]
        client_pubkeys: Option<Vec<String>>,

        /// Path to file containing authorized client public keys (one per line)
        #[arg(long, env = "QUICPORT_CLIENT_PUBKEYS_FILE")]
        client_pubkeys_file: Option<PathBuf>,

        /// Pre-shared key for authentication
        #[arg(long, env = "QUICPORT_PSK")]
        psk: Option<String>,
    },

    /// Run as client (connect to server and forward ports)
    ///
    /// Supports two modes:
    /// - Remote Port Forwarding (RPF): --remote-source + --local-destination
    ///   Server listens on remote-source, forwards to client's local-destination
    /// - Local Port Forwarding (LPF): --local-source + --remote-destination
    ///   Client listens on local-source, forwards to server's remote-destination
    Client {
        /// Server address to connect to
        #[arg(short = 's', long)]
        server: String,

        // =========================================================================
        // Remote Port Forwarding (RPF) オプション
        // サーバー側でポートをリッスンし、クライアント側のローカルサービスに転送
        // =========================================================================

        /// [RPF] Remote source port to open on server (e.g., "9022/tcp")
        /// Mutually exclusive with --local-source
        #[arg(short = 'r', long, conflicts_with = "local_source")]
        remote_source: Option<String>,

        /// [RPF] Local destination to forward to (e.g., "22/tcp" or "192.168.1.100:22/tcp")
        /// Mutually exclusive with --remote-destination
        #[arg(short = 'l', long, conflicts_with = "remote_destination")]
        local_destination: Option<String>,

        // =========================================================================
        // Local Port Forwarding (LPF) オプション
        // クライアント側でポートをリッスンし、サーバー側のリモートサービスに転送
        // =========================================================================

        /// [LPF] Local source port to listen on client (e.g., "9022/tcp")
        /// Mutually exclusive with --remote-source
        #[arg(short = 'L', long, conflicts_with = "remote_source")]
        local_source: Option<String>,

        /// [LPF] Remote destination to forward to via server (e.g., "22/tcp" or "192.168.1.100:22/tcp")
        /// Mutually exclusive with --local-destination
        #[arg(short = 'R', long, conflicts_with = "local_destination")]
        remote_destination: Option<String>,

        // =========================================================================
        // 認証オプション
        // =========================================================================

        /// Private key in Base64 format
        #[arg(long, env = "QUICPORT_PRIVKEY")]
        privkey: Option<String>,

        /// Path to file containing the private key
        #[arg(long, env = "QUICPORT_PRIVKEY_FILE")]
        privkey_file: Option<PathBuf>,

        /// Expected server's public key in Base64 format (for mutual authentication)
        #[arg(long, env = "QUICPORT_SERVER_PUBKEY")]
        server_pubkey: Option<String>,

        /// Path to file containing the expected server's public key
        #[arg(long, env = "QUICPORT_SERVER_PUBKEY_FILE")]
        server_pubkey_file: Option<PathBuf>,

        /// Pre-shared key for authentication
        #[arg(long, env = "QUICPORT_PSK")]
        psk: Option<String>,

        /// Skip server certificate verification (insecure, for testing only)
        #[arg(long, default_value = "false")]
        insecure: bool,

        /// Auto-reconnect on connection loss
        #[arg(long, default_value = "true")]
        reconnect: bool,

        /// Maximum reconnection attempts (0 = unlimited)
        #[arg(long, default_value = "0")]
        reconnect_max_attempts: u32,

        /// Initial delay between reconnection attempts in seconds
        #[arg(long, default_value = "1")]
        reconnect_delay: u64,
    },
}

/// Control subcommands
#[derive(Subcommand, Debug)]
enum CtlCommands {
    /// Trigger graceful restart of data planes
    ///
    /// This will:
    /// 1. Send DRAIN to all currently ACTIVE data planes
    /// 2. New data planes should be started separately
    GracefulRestart,

    /// Show status of all data planes
    Status,

    /// Drain a specific data plane
    Drain {
        /// PID of the data plane to drain
        #[arg(short, long)]
        pid: u32,
    },
}

/// サーバー用の認証設定を構築
fn build_server_auth_config(
    privkey: Option<String>,
    privkey_file: Option<PathBuf>,
    client_pubkeys: Option<Vec<String>>,
    client_pubkeys_file: Option<PathBuf>,
    psk: Option<String>,
) -> Result<server::AuthConfig> {
    let mut authorized_pubkeys = Vec::new();

    // サーバー秘密鍵を取得（相互認証用）
    let server_private_key = if let Some(key_str) = privkey {
        Some(parse_base64_key(&key_str).context("Invalid server private key format")?)
    } else if let Some(path) = privkey_file {
        Some(
            load_privkey_from_file(&path)
                .with_context(|| format!("Failed to load server private key from {:?}", path))?,
        )
    } else {
        None
    };

    // コマンドライン/環境変数からクライアント公開鍵を取得
    if let Some(keys) = client_pubkeys {
        for key_str in keys {
            let key = parse_base64_key(&key_str).context("Invalid client public key format")?;
            authorized_pubkeys.push(key);
        }
    }

    // ファイルからクライアント公開鍵を読み込み
    if let Some(path) = client_pubkeys_file {
        let file_keys = load_pubkeys_from_file(&path)
            .with_context(|| format!("Failed to load client pubkeys from {:?}", path))?;
        authorized_pubkeys.extend(file_keys);
    }

    // X25519 認証が設定されている場合はそちらを使用
    if !authorized_pubkeys.is_empty() {
        let server_private_key = server_private_key.ok_or_else(|| {
            anyhow::anyhow!(
                "X25519 authentication requires server private key. \
                 Provide --privkey or --privkey-file"
            )
        })?;
        info!(
            "Using X25519 mutual authentication with {} authorized public key(s)",
            authorized_pubkeys.len()
        );
        return Ok(server::AuthConfig::X25519 {
            authorized_pubkeys,
            server_private_key,
        });
    }

    // PSK 認証にフォールバック
    if let Some(psk) = psk {
        info!("Using PSK authentication");
        return Ok(server::AuthConfig::Psk { psk });
    }

    // 認証オプションが何も指定されていない場合、PSK を自動生成
    let psk_path = psk_file_path()?;
    if psk_path.exists() {
        // 既存の PSK を読み込む
        let psk = std::fs::read_to_string(&psk_path)
            .with_context(|| format!("Failed to read PSK from {:?}", psk_path))?;
        info!("Using existing PSK from {}", psk_path.display());
        return Ok(server::AuthConfig::Psk {
            psk: psk.trim().to_string(),
        });
    } else {
        // 新規 PSK を生成して保存
        let psk = generate_psk();
        std::fs::write(&psk_path, &psk)
            .with_context(|| format!("Failed to write PSK to {:?}", psk_path))?;
        info!("Generated new PSK and saved to {}", psk_path.display());
        return Ok(server::AuthConfig::Psk { psk });
    }
}

/// クライアント用の認証設定を構築
fn build_client_auth_config(
    privkey: Option<String>,
    privkey_file: Option<PathBuf>,
    server_pubkey: Option<String>,
    server_pubkey_file: Option<PathBuf>,
    psk: Option<String>,
) -> Result<client::ClientAuthConfig> {
    // サーバー公開鍵を取得（相互認証用）
    let expected_server_pubkey = if let Some(key_str) = server_pubkey {
        Some(parse_base64_key(&key_str).context("Invalid server public key format")?)
    } else if let Some(path) = server_pubkey_file {
        Some(
            load_privkey_from_file(&path)
                .with_context(|| format!("Failed to load server public key from {:?}", path))?,
        )
    } else {
        None
    };

    // X25519 認証が優先
    if let Some(key_str) = privkey {
        let private_key = parse_base64_key(&key_str).context("Invalid private key format")?;
        let expected_server_pubkey = expected_server_pubkey.ok_or_else(|| {
            anyhow::anyhow!(
                "X25519 authentication requires server public key. \
                 Provide --server-pubkey or --server-pubkey-file"
            )
        })?;
        info!("Using X25519 mutual authentication");
        return Ok(client::ClientAuthConfig::X25519 {
            private_key,
            expected_server_pubkey,
        });
    }

    if let Some(path) = privkey_file {
        let private_key = load_privkey_from_file(&path)
            .with_context(|| format!("Failed to load private key from {:?}", path))?;
        let expected_server_pubkey = expected_server_pubkey.ok_or_else(|| {
            anyhow::anyhow!(
                "X25519 authentication requires server public key. \
                 Provide --server-pubkey or --server-pubkey-file"
            )
        })?;
        info!("Using X25519 mutual authentication");
        return Ok(client::ClientAuthConfig::X25519 {
            private_key,
            expected_server_pubkey,
        });
    }

    // PSK 認証にフォールバック
    if let Some(psk) = psk {
        info!("Using PSK authentication");
        return Ok(client::ClientAuthConfig::Psk { psk });
    }

    anyhow::bail!("No authentication configured. Provide --privkey, --privkey-file, or --psk")
}

/// データプレーン用の認証ポリシーを構築（環境変数から）
fn build_dataplane_auth_policy() -> Result<AuthPolicy> {
    let auth_type = std::env::var("QUICPORT_DP_AUTH_TYPE")
        .unwrap_or_else(|_| "psk".to_string());

    match auth_type.as_str() {
        "x25519" => {
            let server_privkey = std::env::var("QUICPORT_DP_SERVER_PRIVKEY")
                .context("QUICPORT_DP_SERVER_PRIVKEY is required for X25519 authentication")?;

            let client_pubkeys_str = std::env::var("QUICPORT_DP_CLIENT_PUBKEYS")
                .unwrap_or_default();
            let authorized_pubkeys: Vec<String> = client_pubkeys_str
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect();

            if authorized_pubkeys.is_empty() {
                anyhow::bail!("QUICPORT_DP_CLIENT_PUBKEYS is required for X25519 authentication");
            }

            Ok(AuthPolicy::X25519 {
                authorized_pubkeys,
                server_private_key: server_privkey,
            })
        }
        "psk" => {
            let psk = std::env::var("QUICPORT_DP_PSK")
                .or_else(|_| std::env::var("QUICPORT_PSK"))
                .context("QUICPORT_DP_PSK or QUICPORT_PSK is required for PSK authentication")?;

            Ok(AuthPolicy::Psk { psk })
        }
        _ => {
            anyhow::bail!("Invalid auth type: {}. Expected 'psk' or 'x25519'", auth_type)
        }
    }
}

/// サーバー用の認証ポリシーを構築（IPC 用）
#[allow(dead_code)]
fn build_server_auth_policy(
    privkey: Option<String>,
    privkey_file: Option<PathBuf>,
    client_pubkeys: Option<Vec<String>>,
    client_pubkeys_file: Option<PathBuf>,
    psk: Option<String>,
) -> Result<AuthPolicy> {
    let mut authorized_pubkeys_b64 = Vec::new();

    // サーバー秘密鍵を取得
    let server_private_key_b64 = if let Some(key_str) = privkey.clone() {
        let _ = parse_base64_key(&key_str).context("Invalid server private key format")?;
        Some(key_str)
    } else if let Some(ref path) = privkey_file {
        let key = load_privkey_from_file(path)
            .with_context(|| format!("Failed to load server private key from {:?}", path))?;
        Some(encode_base64_key(&key))
    } else {
        None
    };

    // クライアント公開鍵を取得
    if let Some(keys) = client_pubkeys {
        for key_str in keys {
            let _ = parse_base64_key(&key_str).context("Invalid client public key format")?;
            authorized_pubkeys_b64.push(key_str);
        }
    }

    if let Some(ref path) = client_pubkeys_file {
        let file_keys = load_pubkeys_from_file(path)
            .with_context(|| format!("Failed to load client pubkeys from {:?}", path))?;
        for key in file_keys {
            authorized_pubkeys_b64.push(encode_base64_key(&key));
        }
    }

    // X25519 認証が設定されている場合
    if !authorized_pubkeys_b64.is_empty() {
        let server_private_key = server_private_key_b64.ok_or_else(|| {
            anyhow::anyhow!(
                "X25519 authentication requires server private key. \
                 Provide --privkey or --privkey-file"
            )
        })?;

        return Ok(AuthPolicy::X25519 {
            authorized_pubkeys: authorized_pubkeys_b64,
            server_private_key,
        });
    }

    // PSK 認証にフォールバック
    if let Some(psk) = psk {
        return Ok(AuthPolicy::Psk { psk });
    }

    // 認証オプションが何も指定されていない場合、PSK を自動生成
    let psk_path = psk_file_path()?;
    if psk_path.exists() {
        let psk = std::fs::read_to_string(&psk_path)
            .with_context(|| format!("Failed to read PSK from {:?}", psk_path))?;
        return Ok(AuthPolicy::Psk {
            psk: psk.trim().to_string(),
        });
    } else {
        let psk = generate_psk();
        std::fs::write(&psk_path, &psk)
            .with_context(|| format!("Failed to write PSK to {:?}", psk_path))?;
        info!("Generated new PSK and saved to {}", psk_path.display());
        return Ok(AuthPolicy::Psk { psk });
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // ssh-proxy コマンドの場合はログを stderr に出力（stdout は SSH データ専用）
    let use_stderr = matches!(cli.command, Commands::SshProxy { .. });

    // Initialize logging
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if use_stderr {
        // ssh-proxy: ログを stderr に出力
        match cli.log_format {
            LogFormat::Console => {
                tracing_subscriber::fmt()
                    .with_writer(std::io::stderr)
                    .with_env_filter(env_filter)
                    .init();
            }
            LogFormat::Json => {
                tracing_subscriber::fmt()
                    .with_writer(std::io::stderr)
                    .with_env_filter(env_filter)
                    .json()
                    .init();
            }
        }
    } else {
        // 通常モード: ログを stdout に出力
        match cli.log_format {
            LogFormat::Console => {
                tracing_subscriber::fmt()
                    .with_writer(std::io::stdout)
                    .with_env_filter(env_filter)
                    .init();
            }
            LogFormat::Json => {
                tracing_subscriber::fmt()
                    .with_writer(std::io::stdout)
                    .with_env_filter(env_filter)
                    .json()
                    .init();
            }
        }
    }

    match cli.command {
        Commands::DataPlane {
            listen,
            drain_timeout,
        } => {
            // データプレーン用の認証設定を環境変数から取得
            let auth_policy = build_dataplane_auth_policy()?;

            let config = DataPlaneConfig {
                listen_addr: listen,
                drain_timeout,
                ..Default::default()
            };

            info!("Starting data plane on {}", listen);
            data_plane::run(config, Some(auth_policy)).await?;
        }

        Commands::Ctl(ctl_cmd) => {
            match ctl_cmd {
                CtlCommands::GracefulRestart => {
                    control_plane::graceful_restart().await?;
                }
                CtlCommands::Status => {
                    control_plane::show_status().await?;
                }
                CtlCommands::Drain { pid } => {
                    use quicport::ipc::{read_dataplane_port, ControlCommand, IpcConnection};

                    let port = read_dataplane_port(pid)
                        .with_context(|| format!("Failed to read port for data plane PID {}", pid))?;
                    let mut conn = IpcConnection::connect(port).await
                        .with_context(|| format!("Failed to connect to data plane PID {} on port {}", pid, port))?;

                    // Ready イベントをスキップ
                    let _ = conn.recv_event().await;

                    // DRAIN を送信
                    conn.send_command(&ControlCommand::Drain).await?;
                    info!("Sent DRAIN to data plane PID {}", pid);
                }
            }
        }

        Commands::SshProxy {
            server,
            remote_destination,
            privkey,
            privkey_file,
            server_pubkey,
            server_pubkey_file,
            psk,
            insecure,
            reconnect,
            reconnect_max_attempts,
            reconnect_delay,
        } => {
            let auth_config = build_client_auth_config(
                privkey,
                privkey_file,
                server_pubkey,
                server_pubkey_file,
                psk,
            )?;

            let reconnect_config = client::ReconnectConfig::new(
                reconnect,
                reconnect_max_attempts,
                reconnect_delay,
            );

            info!(
                "SSH proxy connecting to {} (remote={})",
                server, remote_destination
            );
            client::run_ssh_proxy_with_reconnect(
                &server,
                &remote_destination,
                auth_config,
                insecure,
                reconnect_config,
            )
            .await?;
        }

        Commands::Server {
            listen,
            api_listen,
            no_api,
            privkey,
            privkey_file,
            client_pubkeys,
            client_pubkeys_file,
            psk,
        } => {
            let auth_config = build_server_auth_config(
                privkey,
                privkey_file,
                client_pubkeys,
                client_pubkeys_file,
                psk,
            )?;

            // 統計情報を初期化
            let statistics = Arc::new(ServerStatistics::new());

            if no_api {
                // API サーバーなしで QUIC サーバーのみ起動
                info!("Starting QUIC server on {}", listen);
                server::run(listen, auth_config, statistics).await?;
            } else {
                // QUIC サーバーと API サーバーを並列起動
                info!("Starting QUIC server on {}", listen);
                info!("Starting API server on {}", api_listen);

                let quic_server = server::run(listen, auth_config, statistics.clone());
                let api_server = api::run(api_listen, statistics);

                // どちらかが終了したら両方終了
                tokio::select! {
                    result = quic_server => {
                        if let Err(e) = result {
                            return Err(e);
                        }
                    }
                    result = api_server => {
                        if let Err(e) = result {
                            return Err(e);
                        }
                    }
                }
            }
        }
        Commands::Client {
            server,
            remote_source,
            local_destination,
            local_source,
            remote_destination,
            privkey,
            privkey_file,
            server_pubkey,
            server_pubkey_file,
            psk,
            insecure,
            reconnect,
            reconnect_max_attempts,
            reconnect_delay,
        } => {
            let auth_config = build_client_auth_config(
                privkey,
                privkey_file,
                server_pubkey,
                server_pubkey_file,
                psk,
            )?;

            let reconnect_config = client::ReconnectConfig::new(
                reconnect,
                reconnect_max_attempts,
                reconnect_delay,
            );

            // フォワーディングモードを判定
            match (remote_source, local_destination, local_source, remote_destination) {
                // Remote Port Forwarding (RPF): --remote-source + --local-destination
                (Some(rs), Some(ld), None, None) => {
                    info!(
                        "Connecting to {} (RPF: remote={}, local={})",
                        server, rs, ld
                    );
                    client::run_with_reconnect(
                        &server,
                        &rs,
                        &ld,
                        auth_config,
                        insecure,
                        reconnect_config,
                    )
                    .await?;
                }
                // Local Port Forwarding (LPF): --local-source + --remote-destination
                (None, None, Some(ls), Some(rd)) => {
                    info!(
                        "Connecting to {} (LPF: local={}, remote={})",
                        server, ls, rd
                    );
                    client::run_local_forward_with_reconnect(
                        &server,
                        &ls,
                        &rd,
                        auth_config,
                        insecure,
                        reconnect_config,
                    )
                    .await?;
                }
                // 不正な組み合わせ
                _ => {
                    anyhow::bail!(
                        "Invalid port forwarding options. Use one of:\n\
                         - Remote Port Forwarding: --remote-source <port> --local-destination <addr:port>\n\
                         - Local Port Forwarding: --local-source <port> --remote-destination <addr:port>"
                    );
                }
            }
        }
    }

    Ok(())
}

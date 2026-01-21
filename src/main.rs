//! quicport CLI エントリーポイント

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;

use quicport::client;
use quicport::control_plane;
use quicport::data_plane;
use quicport::ipc::{AuthPolicy, DataPlaneConfig};
use quicport::quic::{
    encode_base64_key, generate_psk, load_privkey_from_file, load_pubkeys_from_file,
    parse_base64_key, psk_file_path,
};
use quicport::statistics::ServerStatistics;

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

    /// Log output file (default: stdout, or stderr for ssh-proxy mode)
    #[arg(long, env = "QUICPORT_LOG_OUTPUT")]
    log_output: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run as data plane (QUIC connection handler)
    ///
    /// This command is typically invoked by the control plane (quicport control-plane) or
    /// by quicport.sh script for cgroup separation.
    /// The data plane handles QUIC connections and maintains backend TCP connections.
    /// It operates independently of the control plane after startup.
    DataPlane {
        /// Address and port to listen on for QUIC
        #[arg(short, long, default_value = "0.0.0.0:39000")]
        listen: SocketAddr,

        /// Control plane HTTP URL to connect to for receiving auth policy (HTTP IPC).
        /// Example: http://127.0.0.1:39000
        #[arg(long)]
        control_plane_url: String,

        /// Drain timeout in seconds (force shutdown after this time in DRAINING state, 0 means infinite)
        #[arg(long, default_value = "0")]
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

    /// Run as control plane (manages data planes)
    ///
    /// The control plane spawns and manages data plane processes via HTTP IPC.
    /// Data planes handle actual QUIC connections.
    #[command(name = "control-plane")]
    ControlPlane {
        /// Address and port to listen on for QUIC (data planes bind to this)
        #[arg(short, long, default_value = "0.0.0.0:39000")]
        listen: SocketAddr,

        /// Disable public API server (/healthcheck)
        #[arg(long, default_value = "false")]
        no_public_api: bool,

        /// Address and port for private API server (/metrics, /graceful-restart)
        /// Only accessible from localhost. Default: 127.0.0.1:<listen_port>
        #[arg(long)]
        private_api_listen: Option<SocketAddr>,

        /// Disable private API server
        #[arg(long, default_value = "false")]
        no_private_api: bool,

        /// Do not automatically start a data-plane process.
        /// Use this when data-plane is started separately (e.g., via systemd-run)
        #[arg(long, default_value = "false")]
        no_auto_dataplane: bool,

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
    /// Show status of all data planes
    Status {
        /// Private API server address to connect to
        #[arg(long, default_value = "127.0.0.1:39000")]
        api_addr: SocketAddr,
    },

    /// Drain a specific data plane
    Drain {
        /// Data plane ID to drain (e.g., "dp_12345")
        #[arg(short = 'd', long)]
        dp_id: String,

        /// Private API server address to connect to
        #[arg(long, default_value = "127.0.0.1:39000")]
        api_addr: SocketAddr,
    },
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

/// サーバー用の認証ポリシーを構築
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

/// ログ出力先の MakeWriter 実装
struct FileWriter(Arc<std::sync::Mutex<std::fs::File>>);

impl Write for FileWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.lock().unwrap().flush()
    }
}

impl Clone for FileWriter {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for FileWriter {
    type Writer = FileWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // ssh-proxy コマンドの場合はログを stderr に出力（stdout は SSH データ専用）
    let use_stderr = matches!(cli.command, Commands::SshProxy { .. });

    // Initialize logging
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    // ログ出力先を決定
    if let Some(ref log_path) = cli.log_output {
        // ファイルに出力（append モード）
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .with_context(|| format!("Failed to open log file: {:?}", log_path))?;
        let writer = FileWriter(Arc::new(std::sync::Mutex::new(file)));

        match cli.log_format {
            LogFormat::Console => {
                tracing_subscriber::fmt()
                    .with_writer(writer)
                    .with_env_filter(env_filter)
                    .init();
            }
            LogFormat::Json => {
                tracing_subscriber::fmt()
                    .with_writer(writer)
                    .with_env_filter(env_filter)
                    .json()
                    .flatten_event(true)
                    .with_current_span(false)
                    .with_span_list(true)
                    .init();
            }
        }
    } else if use_stderr {
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
                    .flatten_event(true)
                    .with_current_span(false)
                    .with_span_list(true)
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
                    .flatten_event(true)
                    .with_current_span(false)
                    .with_span_list(true)
                    .init();
            }
        }
    }

    // PID を含むルートスパンを作成（全ログに PID が含まれる）
    let pid = std::process::id();
    let _root_span = tracing::info_span!("quicport", pid).entered();

    match cli.command {
        Commands::DataPlane {
            listen,
            control_plane_url,
            drain_timeout,
        } => {
            let config = DataPlaneConfig {
                listen_addr: listen,
                drain_timeout,
                ..Default::default()
            };

            // HTTP IPC: control-plane に HTTP で接続して認証ポリシーを取得
            info!(
                "Starting data plane on {} (HTTP IPC to control plane at {})",
                listen, control_plane_url
            );
            data_plane::run(config, &control_plane_url).await?;
        }

        Commands::Ctl(ctl_cmd) => {
            match ctl_cmd {
                CtlCommands::Status { api_addr } => {
                    control_plane::show_status(api_addr).await?;
                }
                CtlCommands::Drain { dp_id, api_addr } => {
                    use quicport::ipc::DrainDataPlaneRequest;

                    let url = format!("http://{}/api/v1/DrainDataPlane", api_addr);
                    let client = reqwest::Client::new();

                    let response = client
                        .post(&url)
                        .json(&DrainDataPlaneRequest {
                            dp_id: dp_id.clone(),
                        })
                        .send()
                        .await
                        .with_context(|| {
                            format!("Failed to connect to API server at {}", api_addr)
                        })?;

                    let status = response.status();
                    if status.is_success() {
                        info!("Sent DRAIN to data plane {}", dp_id);
                    } else {
                        let body: serde_json::Value = response
                            .json()
                            .await
                            .context("Failed to parse API response")?;
                        let message = body
                            .get("message")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Unknown error");
                        anyhow::bail!("Failed to drain data plane {}: {}", dp_id, message);
                    }
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

            let reconnect_config =
                client::ReconnectConfig::new(reconnect, reconnect_max_attempts, reconnect_delay);

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

        Commands::ControlPlane {
            listen,
            no_public_api,
            private_api_listen,
            no_private_api,
            no_auto_dataplane,
            privkey,
            privkey_file,
            client_pubkeys,
            client_pubkeys_file,
            psk,
        } => {
            // 認証ポリシーを構築（コントロールプレーン → データプレーン間で使用）
            let auth_policy = build_server_auth_policy(
                privkey,
                privkey_file,
                client_pubkeys,
                client_pubkeys_file,
                psk,
            )?;

            // 統計情報を初期化
            let statistics = Arc::new(ServerStatistics::new());

            // API サーバー設定を構築
            let api_config = {
                // Private API: QUIC と同じポートの TCP、localhost のみ（/metrics, /graceful-restart）
                let private_addr = if no_private_api {
                    None
                } else {
                    Some(private_api_listen.unwrap_or_else(|| {
                        // デフォルト: 127.0.0.1:<listen_port>
                        SocketAddr::new(
                            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                            listen.port(),
                        )
                    }))
                };

                // Public API: QUIC ポート + 1（/healthcheck のみ）
                let public_addr = if no_public_api {
                    None
                } else {
                    // 0.0.0.0:<listen_port + 1>
                    Some(SocketAddr::new(listen.ip(), listen.port() + 1))
                };

                if public_addr.is_some() || private_addr.is_some() {
                    Some(control_plane::ApiConfig {
                        public_addr,
                        private_addr,
                    })
                } else {
                    None
                }
            };

            // コントロールプレーンを起動（API サーバーも統合）
            info!("Starting control plane (QUIC on {})", listen);
            if let Some(ref config) = api_config {
                if let Some(addr) = config.public_addr {
                    info!("Starting public API server on {} (TCP, /healthcheck)", addr);
                }
                if let Some(addr) = config.private_addr {
                    info!(
                        "Starting private API server on {} (/metrics, /graceful-restart)",
                        addr
                    );
                }
            }

            control_plane::run_with_api(
                listen,
                auth_policy,
                statistics,
                api_config,
                no_auto_dataplane,
            )
            .await?;
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

            let reconnect_config =
                client::ReconnectConfig::new(reconnect, reconnect_max_attempts, reconnect_delay);

            // フォワーディングモードを判定
            match (
                remote_source,
                local_destination,
                local_source,
                remote_destination,
            ) {
                // Remote Port Forwarding (RPF): --remote-source + --local-destination
                (Some(rs), Some(ld), None, None) => {
                    info!(
                        "Connecting to {} (RPF: remote={}, local={})",
                        server, rs, ld
                    );
                    client::run_remote_forward_with_reconnect(
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

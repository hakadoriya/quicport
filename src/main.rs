//! quicport CLI エントリーポイント

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;

use quicport::quic::{load_privkey_from_file, load_pubkeys_from_file, parse_base64_key};
use quicport::statistics::ServerStatistics;
use quicport::{api, client, server};

/// QUIC-based port forwarding / tunneling tool
#[derive(Parser, Debug)]
#[command(name = "quicport")]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
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
    Client {
        /// Server address to connect to
        #[arg(short = 's', long)]
        server: String,

        /// Remote source port to open on server (e.g., "9022/tcp")
        #[arg(short = 'r', long)]
        remote_source: String,

        /// Local destination to forward to (e.g., "22/tcp" or "192.168.1.100:22/tcp")
        #[arg(short = 'l', long)]
        local_destination: String,

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

    anyhow::bail!(
        "No authentication configured. Provide --client-pubkeys, --client-pubkeys-file, or --psk"
    )
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

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
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
            privkey,
            privkey_file,
            server_pubkey,
            server_pubkey_file,
            psk,
            insecure,
        } => {
            let auth_config = build_client_auth_config(
                privkey,
                privkey_file,
                server_pubkey,
                server_pubkey_file,
                psk,
            )?;
            info!(
                "Connecting to {} (remote: {}, local: {})",
                server, remote_source, local_destination
            );
            client::run(
                &server,
                &remote_source,
                &local_destination,
                auth_config,
                insecure,
            )
            .await?;
        }
    }

    Ok(())
}

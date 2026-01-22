//! QUIC 設定モジュール
//!
//! サーバー・クライアント共通の QUIC 設定を提供します。

use anyhow::{Context, Result};
use base64::Engine;
use hmac::{Hmac, Mac};
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream, ServerConfig};
use rand::rngs::OsRng;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use socket2::{Domain, Protocol as SockProtocol, Socket, Type};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use subtle::ConstantTimeEq;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

type HmacSha256 = Hmac<Sha256>;

/// ALPN プロトコル識別子
pub const ALPN_QUICPORT: &[u8] = b"quicport/1";

// =============================================================================
// TOFU (Trust On First Use) 証明書検証
// =============================================================================

/// TOFU 検証エラー
#[derive(Debug, Clone)]
pub enum TofuStatus {
    /// 既知のホストと一致（検証成功）
    Known,
    /// 未知のホスト（初回接続）
    Unknown {
        host: String,
        fingerprint: String,
        cert_info: CertificateInfo,
    },
    /// ホストは既知だがフィンガープリントが異なる（潜在的な MITM 攻撃）
    Changed {
        host: String,
        old_fingerprint: String,
        new_fingerprint: String,
        cert_info: CertificateInfo,
    },
}

/// 証明書情報（ユーザーに表示用）
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    /// SHA-256 フィンガープリント（コロン区切り 16 進数）
    pub fingerprint: String,
    /// Subject（発行先）
    pub subject: String,
    /// Issuer（発行者）
    pub issuer: String,
    /// 有効期間（開始）
    pub not_before: String,
    /// 有効期間（終了）
    pub not_after: String,
}

impl std::fmt::Display for CertificateInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "  SHA256 Fingerprint: {}", self.fingerprint)?;
        writeln!(f, "  Subject: {}", self.subject)?;
        writeln!(f, "  Issuer: {}", self.issuer)?;
        writeln!(f, "  Valid from: {}", self.not_before)?;
        write!(f, "  Valid until: {}", self.not_after)
    }
}

/// 証明書から SHA-256 フィンガープリントを計算
pub fn compute_cert_fingerprint(cert_der: &[u8]) -> String {
    let hash = Sha256::digest(cert_der);
    hash.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// DER 証明書から情報を抽出
fn extract_cert_info(cert_der: &[u8]) -> CertificateInfo {
    let fingerprint = compute_cert_fingerprint(cert_der);

    // x509-parser を使って証明書をパース
    match x509_parser::parse_x509_certificate(cert_der) {
        Ok((_, cert)) => {
            let subject = cert.subject().to_string();
            let issuer = cert.issuer().to_string();
            let not_before = cert.validity().not_before.to_string();
            let not_after = cert.validity().not_after.to_string();

            CertificateInfo {
                fingerprint,
                subject,
                issuer,
                not_before,
                not_after,
            }
        }
        Err(_) => {
            // パースに失敗した場合はフィンガープリントのみ
            CertificateInfo {
                fingerprint,
                subject: "(parse error)".to_string(),
                issuer: "(parse error)".to_string(),
                not_before: "(parse error)".to_string(),
                not_after: "(parse error)".to_string(),
            }
        }
    }
}

/// known_hosts ファイルを管理
///
/// ファイル形式（SSH 互換に近い形式）:
/// ```text
/// # コメント
/// host:port SHA256:XX:XX:XX:...
/// ```
#[derive(Debug)]
pub struct KnownHosts {
    /// ファイルパス
    path: PathBuf,
    /// ホスト -> フィンガープリント のマップ
    hosts: RwLock<HashMap<String, String>>,
}

impl KnownHosts {
    /// 新しい KnownHosts を作成
    ///
    /// ファイルが存在しない場合は空の状態で開始
    pub fn new(path: PathBuf) -> Result<Self> {
        let hosts = if path.exists() {
            Self::load_from_file(&path)?
        } else {
            HashMap::new()
        };

        Ok(Self {
            path,
            hosts: RwLock::new(hosts),
        })
    }

    /// デフォルトのパスで KnownHosts を作成
    ///
    /// ~/.local/share/quicport/known_hosts を使用
    /// (XDG Base Directory Specification に準拠)
    pub fn default_path() -> Result<PathBuf> {
        let home = dirs::home_dir().context("Failed to get home directory")?;
        let share_dir = home.join(".local").join("share").join("quicport");

        // ディレクトリが存在しない場合は作成
        if !share_dir.exists() {
            fs::create_dir_all(&share_dir)
                .context("Failed to create ~/.local/share/quicport directory")?;
        }

        Ok(share_dir.join("known_hosts"))
    }

    /// known_hosts ファイルのパスを取得
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// ファイルから読み込み
    fn load_from_file(path: &Path) -> Result<HashMap<String, String>> {
        let file = fs::File::open(path).context("Failed to open known_hosts file")?;
        let reader = BufReader::new(file);
        let mut hosts = HashMap::new();

        for line in reader.lines() {
            let line = line.context("Failed to read line from known_hosts")?;
            let line = line.trim();

            // 空行とコメントをスキップ
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // "host:port fingerprint" 形式でパース
            let parts: Vec<&str> = line.splitn(2, ' ').collect();
            if parts.len() == 2 {
                let host = parts[0].to_string();
                let fingerprint = parts[1].to_string();
                hosts.insert(host, fingerprint);
            }
        }

        Ok(hosts)
    }

    /// ホストのフィンガープリントを検証
    ///
    /// - Known: 既知で一致
    /// - Unknown: 未知のホスト
    /// - Changed: 既知だがフィンガープリントが異なる
    pub fn verify(&self, host: &str, cert_der: &[u8]) -> TofuStatus {
        let fingerprint = compute_cert_fingerprint(cert_der);
        let cert_info = extract_cert_info(cert_der);

        let hosts = self.hosts.read().unwrap();

        match hosts.get(host) {
            Some(known_fingerprint) if known_fingerprint == &fingerprint => TofuStatus::Known,
            Some(known_fingerprint) => TofuStatus::Changed {
                host: host.to_string(),
                old_fingerprint: known_fingerprint.clone(),
                new_fingerprint: fingerprint,
                cert_info,
            },
            None => TofuStatus::Unknown {
                host: host.to_string(),
                fingerprint,
                cert_info,
            },
        }
    }

    /// ホストのフィンガープリントを追加・更新
    ///
    /// 戻り値: 追加された行番号（1-indexed）
    pub fn add_host(&self, host: &str, fingerprint: &str) -> Result<usize> {
        // メモリ上のマップを更新
        {
            let mut hosts = self.hosts.write().unwrap();
            hosts.insert(host.to_string(), fingerprint.to_string());
        }

        // ファイルに書き込み、行番号を返す
        self.save_to_file(host)
    }

    /// ファイルに保存
    ///
    /// 戻り値: 指定されたホストが書き込まれた行番号（1-indexed）
    fn save_to_file(&self, target_host: &str) -> Result<usize> {
        let hosts = self.hosts.read().unwrap();

        // 親ディレクトリが存在することを確認
        if let Some(parent) = self.path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).context("Failed to create parent directory")?;
            }
        }

        let mut file = fs::File::create(&self.path).context("Failed to create known_hosts file")?;

        // ヘッダー行（3行）
        writeln!(file, "# quicport known_hosts file").ok();
        writeln!(file, "# Format: host:port fingerprint").ok();
        writeln!(file).ok();

        let mut line_number = 3; // ヘッダー行数
        let mut target_line = 0;

        for (host, fingerprint) in hosts.iter() {
            line_number += 1;
            if host == target_host {
                target_line = line_number;
            }
            writeln!(file, "{} {}", host, fingerprint)
                .context("Failed to write to known_hosts file")?;
        }

        Ok(target_line)
    }
}

/// TOFU 証明書検証器
///
/// ServerCertVerifier を実装し、known_hosts に基づいて証明書を検証
/// 検証結果は内部に保存され、接続後に取得可能
#[derive(Debug)]
pub struct TofuVerifier {
    /// 接続先ホスト（host:port 形式）
    host: String,
    /// 検証結果を保存
    status: RwLock<Option<TofuStatus>>,
    /// known_hosts 参照
    known_hosts: Arc<KnownHosts>,
}

impl TofuVerifier {
    /// 新しい TofuVerifier を作成
    pub fn new(host: String, known_hosts: Arc<KnownHosts>) -> Self {
        Self {
            host,
            status: RwLock::new(None),
            known_hosts,
        }
    }

    /// 検証結果を取得
    pub fn get_status(&self) -> Option<TofuStatus> {
        self.status.read().unwrap().clone()
    }
}

impl rustls::client::danger::ServerCertVerifier for TofuVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // 証明書を検証
        let status = self.known_hosts.verify(&self.host, end_entity.as_ref());

        // 結果を保存
        *self.status.write().unwrap() = Some(status.clone());

        // TOFU では常に接続を許可（ユーザーが後で確認）
        // ただし、Unknown/Changed の場合は後でユーザー確認が必要
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// サーバー証明書の設定ディレクトリパスを取得
///
/// ~/.config/quicport/ を使用
pub fn server_config_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Failed to get home directory")?;
    let config_dir = home.join(".config").join("quicport");

    // ディレクトリが存在しない場合は作成
    if !config_dir.exists() {
        fs::create_dir_all(&config_dir).context("Failed to create ~/.config/quicport directory")?;
    }

    Ok(config_dir)
}

/// PSK ファイルのパスを取得（~/.config/quicport/psk）
pub fn psk_file_path() -> Result<PathBuf> {
    Ok(server_config_dir()?.join("psk"))
}

/// ランダムな PSK を生成（32 バイト → Base64 エンコード）
pub fn generate_psk() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// 証明書ファイルのパス
fn server_cert_path() -> Result<PathBuf> {
    Ok(server_config_dir()?.join("server.crt"))
}

/// 秘密鍵ファイルのパス
fn server_key_path() -> Result<PathBuf> {
    Ok(server_config_dir()?.join("server.key"))
}

/// 証明書ファイルのロックファイルパス
fn server_cert_lock_path() -> Result<PathBuf> {
    Ok(server_config_dir()?.join("server.lock"))
}

/// 証明書と秘密鍵をファイルに保存（アトミック操作）
fn save_server_cert(cert_der: &[u8], key_der: &[u8]) -> Result<()> {
    let cert_path = server_cert_path()?;
    let key_path = server_key_path()?;
    let config_dir = server_config_dir()?;

    // 一時ファイルに書き込んでからリネーム（アトミック操作）
    let cert_tmp = config_dir.join("server.crt.tmp");
    let key_tmp = config_dir.join("server.key.tmp");

    fs::write(&cert_tmp, cert_der)
        .with_context(|| format!("Failed to write certificate to {:?}", cert_tmp))?;
    fs::write(&key_tmp, key_der)
        .with_context(|| format!("Failed to write private key to {:?}", key_tmp))?;

    // 秘密鍵ファイルのパーミッションを 0600 に設定 (Unix のみ)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&key_tmp)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&key_tmp, perms)?;
    }

    // アトミックにリネーム
    fs::rename(&key_tmp, &key_path)
        .with_context(|| format!("Failed to rename {:?} to {:?}", key_tmp, key_path))?;
    fs::rename(&cert_tmp, &cert_path)
        .with_context(|| format!("Failed to rename {:?} to {:?}", cert_tmp, cert_path))?;

    tracing::info!("Server certificate saved to {:?}", cert_path);

    Ok(())
}

/// 証明書と秘密鍵をファイルから読み込み
fn load_server_cert() -> Result<Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>> {
    let cert_path = server_cert_path()?;
    let key_path = server_key_path()?;

    // 両方のファイルが存在する場合のみ読み込み
    if !cert_path.exists() || !key_path.exists() {
        return Ok(None);
    }

    let cert_der = fs::read(&cert_path)
        .with_context(|| format!("Failed to read certificate from {:?}", cert_path))?;
    let key_der = fs::read(&key_path)
        .with_context(|| format!("Failed to read private key from {:?}", key_path))?;

    let cert = CertificateDer::from(cert_der);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

    tracing::info!("Server certificate loaded from {:?}", cert_path);

    Ok(Some((vec![cert], key)))
}

/// サーバー証明書を取得（ファイルから読み込むか、なければ生成して保存）
///
/// 証明書は ~/.config/quicport/server.crt と server.key に保存される
/// ファイルロックを使用して複数プロセスからの同時アクセスを防止
fn get_or_create_server_cert() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let lock_path = server_cert_lock_path()?;

    // ロックファイルを作成・オープン
    // _lock_file は関数終了までロックを保持するために保持（drop されるとロック解放）
    let _lock_file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("Failed to open lock file {:?}", lock_path))?;

    // 排他ロックを取得
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = _lock_file.as_raw_fd();
        unsafe {
            if libc::flock(fd, libc::LOCK_EX) != 0 {
                anyhow::bail!("Failed to acquire file lock");
            }
        }
    }

    // ロック取得後に既存の証明書を確認
    if let Some(certs) = load_server_cert()? {
        return Ok(certs);
    }

    // 新規生成
    tracing::info!("Generating new server certificate...");
    let subject_alt_names = vec!["localhost".to_string(), "quicport".to_string()];

    let certified_key = rcgen::generate_simple_self_signed(subject_alt_names)
        .context("Failed to generate self-signed certificate")?;

    let cert_der_bytes = certified_key.cert.der().to_vec();
    let key_der_bytes = certified_key.key_pair.serialize_der();

    // ファイルに保存
    save_server_cert(&cert_der_bytes, &key_der_bytes)?;

    let cert_der = CertificateDer::from(cert_der_bytes);
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der_bytes));

    // ロックは lock_file が drop されると自動的に解放される
    Ok((vec![cert_der], key_der))
}

/// SO_REUSEADDR + SO_REUSEPORT 付きで UDP ソケットを作成（グレースフルリスタート用）
///
/// これにより複数の data-plane プロセスが同じポートで LISTEN 可能
fn create_udp_socket_with_reuseport(addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(SockProtocol::UDP))?;
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
    socket.set_nonblocking(true)?;

    Ok(socket.into())
}

/// サーバー用の QUIC エンドポイントを作成
///
/// 証明書は ~/.config/quicport/ に永続化される
/// SO_REUSEPORT を設定して複数プロセスが同じポートで LISTEN 可能にする
pub fn create_server_endpoint(bind_addr: SocketAddr, _psk: &str) -> Result<Endpoint> {
    let (certs, key) = get_or_create_server_cert()?;

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to create server TLS config")?;

    server_crypto.alpn_protocols = vec![ALPN_QUICPORT.to_vec()];

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .context("Failed to create QUIC server config")?,
    ));

    // トランスポート設定
    // Keep-alive: 5 秒ごとに ping を送信
    // Idle timeout: 10 秒間応答がなければ接続をクローズ
    // これによりクライアントが強制終了された場合も 10 秒以内に検出可能
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    transport_config.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(10)).unwrap(),
    ));
    server_config.transport_config(Arc::new(transport_config));

    // SO_REUSEPORT を設定した UDP ソケットを作成（グレースフルリスタート用）
    let udp_socket = create_udp_socket_with_reuseport(bind_addr)
        .context("Failed to create UDP socket with SO_REUSEPORT")?;

    // カスタムソケットから Endpoint を作成
    let runtime =
        quinn::default_runtime().ok_or_else(|| anyhow::anyhow!("No async runtime found"))?;

    let endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        udp_socket,
        runtime,
    )
    .context("Failed to create server endpoint")?;

    Ok(endpoint)
}

/// サーバー用の QUIC エンドポイントを作成（カスタム Connection ID Generator 付き）
///
/// # Arguments
///
/// * `bind_addr` - バインドするアドレス
/// * `_psk` - 認証用 PSK（将来のために保持）
/// * `server_id` - eBPF ルーティング用の server_id
///
/// # CID フォーマット
///
/// ```text
/// +------------------+------------------+
/// | server_id (4B)   | counter (4B)     |
/// | Big Endian       | Big Endian       |
/// +------------------+------------------+
///  0                4                  8
/// ```
///
/// 証明書は ~/.config/quicport/ に永続化される
/// SO_REUSEPORT を設定して複数プロセスが同じポートで LISTEN 可能にする
pub fn create_server_endpoint_with_cid(
    bind_addr: SocketAddr,
    _psk: &str,
    server_id: u32,
) -> Result<Endpoint> {
    use crate::cid_generator::RoutableCidGenerator;

    let (certs, key) = get_or_create_server_cert()?;

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to create server TLS config")?;

    server_crypto.alpn_protocols = vec![ALPN_QUICPORT.to_vec()];

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .context("Failed to create QUIC server config")?,
    ));

    // トランスポート設定
    // Keep-alive: 5 秒ごとに ping を送信
    // Idle timeout: 10 秒間応答がなければ接続をクローズ
    // これによりクライアントが強制終了された場合も 10 秒以内に検出可能
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    transport_config.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(10)).unwrap(),
    ));
    server_config.transport_config(Arc::new(transport_config));

    // SO_REUSEPORT を設定した UDP ソケットを作成（グレースフルリスタート用）
    let udp_socket = create_udp_socket_with_reuseport(bind_addr)
        .context("Failed to create UDP socket with SO_REUSEPORT")?;

    // カスタムソケットから Endpoint を作成
    let runtime =
        quinn::default_runtime().ok_or_else(|| anyhow::anyhow!("No async runtime found"))?;

    // カスタム CID Generator を使用した EndpointConfig
    let mut endpoint_config = quinn::EndpointConfig::default();
    endpoint_config.cid_generator(move || Box::new(RoutableCidGenerator::new(server_id)));

    let endpoint = Endpoint::new(endpoint_config, Some(server_config), udp_socket, runtime)
        .context("Failed to create server endpoint with custom CID generator")?;

    tracing::info!(
        "Server endpoint created with server_id={} (CID format: [server_id:4B][counter:4B])",
        server_id
    );

    Ok(endpoint)
}

/// サーバー用の QUIC エンドポイントを作成（eBPF 統合用）
///
/// この関数は eBPF ルーターの統合に必要な UDP ソケットへの参照も返します。
/// eBPF SK_REUSEPORT プログラムをアタッチするために使用します。
///
/// # Arguments
///
/// * `bind_addr` - バインドするアドレス
/// * `_psk` - 認証用 PSK（将来のために保持）
/// * `server_id` - eBPF ルーティング用の server_id
///
/// # Returns
///
/// (Endpoint, UdpSocket) - QUIC エンドポイントと eBPF アタッチ用のソケットクローン
///
/// # eBPF 統合の流れ
///
/// ```ignore
/// let (endpoint, socket) = create_server_endpoint_for_ebpf(addr, psk, server_id)?;
///
/// #[cfg(target_os = "linux")]
/// {
///     let router = EbpfRouter::load(EbpfRouterConfig::default())?;
///     router.attach_to_socket(&socket)?;
///     router.register_server(server_id, &socket)?;
/// }
/// ```
pub fn create_server_endpoint_for_ebpf(
    bind_addr: SocketAddr,
    _psk: &str,
    server_id: u32,
) -> Result<(Endpoint, std::net::UdpSocket)> {
    use crate::cid_generator::RoutableCidGenerator;

    let (certs, key) = get_or_create_server_cert()?;

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to create server TLS config")?;

    server_crypto.alpn_protocols = vec![ALPN_QUICPORT.to_vec()];

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .context("Failed to create QUIC server config")?,
    ));

    // トランスポート設定
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    transport_config.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(10)).unwrap(),
    ));
    server_config.transport_config(Arc::new(transport_config));

    // SO_REUSEPORT を設定した UDP ソケットを作成
    let udp_socket = create_udp_socket_with_reuseport(bind_addr)
        .context("Failed to create UDP socket with SO_REUSEPORT")?;

    // eBPF アタッチ用にソケットをクローン
    // try_clone() は新しい fd を作成するが、同じ reuseport グループに属する
    let socket_for_ebpf = udp_socket
        .try_clone()
        .context("Failed to clone UDP socket for eBPF")?;

    // カスタムソケットから Endpoint を作成
    let runtime =
        quinn::default_runtime().ok_or_else(|| anyhow::anyhow!("No async runtime found"))?;

    // カスタム CID Generator を使用した EndpointConfig
    let mut endpoint_config = quinn::EndpointConfig::default();
    endpoint_config.cid_generator(move || Box::new(RoutableCidGenerator::new(server_id)));

    let endpoint = Endpoint::new(endpoint_config, Some(server_config), udp_socket, runtime)
        .context("Failed to create server endpoint with custom CID generator")?;

    tracing::info!(
        "Server endpoint created with server_id={} (eBPF-ready)",
        server_id
    );

    Ok((endpoint, socket_for_ebpf))
}

/// クライアント用の QUIC エンドポイントを作成
///
/// server_addr の IP バージョンに応じて適切なバインドアドレスを選択:
/// - IPv4 サーバー: 0.0.0.0:0 にバインド
/// - IPv6 サーバー: [::]:0 にバインド
pub fn create_client_endpoint(server_addr: &std::net::SocketAddr) -> Result<Endpoint> {
    // 接続先の IP バージョンに応じてバインドアドレスを選択
    let bind_addr: std::net::SocketAddr = if server_addr.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };

    let mut endpoint = Endpoint::client(bind_addr).context("Failed to create client endpoint")?;

    // 自己署名証明書を許可するカスタム証明書検証
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    // ALPN プロトコルを設定
    crypto.alpn_protocols = vec![ALPN_QUICPORT.to_vec()];

    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .context("Failed to create QUIC client config")?,
    ));

    // トランスポート設定
    // Keep-alive: 5 秒ごとに ping を送信
    // Idle timeout: 10 秒間応答がなければ接続をクローズ
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    transport_config.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(10)).unwrap(),
    ));
    client_config.transport_config(Arc::new(transport_config));

    endpoint.set_default_client_config(client_config);

    Ok(endpoint)
}

/// TOFU 対応のクライアント QUIC エンドポイントを作成
///
/// 戻り値: (Endpoint, Arc<TofuVerifier>)
/// - Endpoint: QUIC 接続に使用
/// - TofuVerifier: 接続後に `get_status()` で検証結果を取得
///
/// server_addr の IP バージョンに応じて適切なバインドアドレスを選択
pub fn create_client_endpoint_with_tofu(
    server_addr: &std::net::SocketAddr,
    server_host: &str,
    known_hosts: Arc<KnownHosts>,
) -> Result<(Endpoint, Arc<TofuVerifier>)> {
    // 接続先の IP バージョンに応じてバインドアドレスを選択
    let bind_addr: std::net::SocketAddr = if server_addr.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };

    let mut endpoint = Endpoint::client(bind_addr).context("Failed to create client endpoint")?;

    // TOFU 証明書検証器を作成
    let verifier = Arc::new(TofuVerifier::new(server_host.to_string(), known_hosts));

    // TofuVerifier を使用するカスタム証明書検証
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();

    // ALPN プロトコルを設定
    crypto.alpn_protocols = vec![ALPN_QUICPORT.to_vec()];

    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .context("Failed to create QUIC client config")?,
    ));

    // トランスポート設定
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
    transport_config.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(10)).unwrap(),
    ));
    client_config.transport_config(Arc::new(transport_config));

    endpoint.set_default_client_config(client_config);

    Ok((endpoint, verifier))
}

/// 自己署名証明書を許可する証明書検証（開発用）
///
/// 注意: 本番環境では適切な証明書検証を実装すべきです。
/// PSK による認証はアプリケーション層で別途行います。
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // 自己署名証明書を許可
        // 実際の認証は PSK を使ってアプリケーション層で行う
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// ランダムなチャレンジを生成
pub fn generate_auth_challenge() -> [u8; 32] {
    rand::random::<[u8; 32]>()
}

// =============================================================================
// PSK 認証（強化版: HMAC-SHA256 + タイムスタンプ + エフェメラル DH）
// =============================================================================

/// PSK 認証エラー
#[derive(Debug, thiserror::Error)]
pub enum PskAuthError {
    #[error("Invalid magic bytes")]
    InvalidMagicBytes,

    #[error("Timestamp out of range (clock skew > 30 seconds)")]
    TimestampOutOfRange,

    #[error("Client HMAC verification failed")]
    ClientHmacVerificationFailed,

    #[error("Server HMAC verification failed")]
    ServerHmacVerificationFailed,

    #[error("DH response verification failed")]
    DhResponseVerificationFailed,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("QUIC read error: {0}")]
    QuicReadError(#[from] quinn::ReadExactError),

    #[error("QUIC write error: {0}")]
    QuicWriteError(#[from] quinn::WriteError),
}

/// PSK 認証マジックバイト
const PSK_AUTH_MAGIC: &[u8; 12] = b"QUICPORT_PSK";

/// タイムスタンプ許容範囲（秒）
const TIMESTAMP_TOLERANCE_SECS: u64 = 30;

/// 現在のタイムスタンプを取得（Unix 秒）
fn get_current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// タイムスタンプが許容範囲内か検証
fn is_timestamp_valid(timestamp: u64) -> bool {
    let now = get_current_timestamp();
    let diff = if now > timestamp {
        now - timestamp
    } else {
        timestamp - now
    };
    diff <= TIMESTAMP_TOLERANCE_SECS
}

/// HMAC-SHA256 を計算
fn compute_hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    let result = mac.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result.into_bytes()[..32]);
    output
}

/// サーバー側: PSK 認証を実施（強化版）
///
/// プロトコル:
/// 1. クライアントから: "QUICPORT_PSK" (12 bytes)
/// 2. クライアントから: タイムスタンプ (8 bytes, BE)
/// 3. クライアントから: クライアントエフェメラル公開鍵 (32 bytes)
/// 4. クライアントから: クライアント認証 HMAC (32 bytes) = HMAC(PSK, timestamp || client_eph_pub)
/// 5. サーバーがタイムスタンプと HMAC を検証
/// 6. サーバーから: サーバーエフェメラル公開鍵 (32 bytes)
/// 7. サーバーから: サーバーチャレンジ (32 bytes)
/// 8. サーバーから: サーバー認証 HMAC (32 bytes) = HMAC(PSK, challenge || server_eph_pub)
/// 9. クライアントから: クライアント DH レスポンス (32 bytes) = HMAC(shared_secret, server_challenge)
/// 10. サーバーが DH レスポンスを検証
pub async fn authenticate_client_psk(
    send: &mut SendStream,
    recv: &mut RecvStream,
    psk: &str,
) -> Result<(), PskAuthError> {
    // 1. マジックバイトを受信
    let mut magic = [0u8; 12];
    recv.read_exact(&mut magic).await?;
    if &magic != PSK_AUTH_MAGIC {
        return Err(PskAuthError::InvalidMagicBytes);
    }

    // 2. タイムスタンプを受信・検証
    let mut timestamp_bytes = [0u8; 8];
    recv.read_exact(&mut timestamp_bytes).await?;
    let timestamp = u64::from_be_bytes(timestamp_bytes);

    if !is_timestamp_valid(timestamp) {
        return Err(PskAuthError::TimestampOutOfRange);
    }

    // 3. クライアントエフェメラル公開鍵を受信
    let mut client_eph_pub = [0u8; 32];
    recv.read_exact(&mut client_eph_pub).await?;

    // 4. クライアント認証 HMAC を受信・検証
    let mut client_auth_hmac = [0u8; 32];
    recv.read_exact(&mut client_auth_hmac).await?;

    // 期待される HMAC を計算: HMAC(PSK, timestamp || client_eph_pub)
    let mut auth_data = Vec::with_capacity(8 + 32);
    auth_data.extend_from_slice(&timestamp_bytes);
    auth_data.extend_from_slice(&client_eph_pub);
    let expected_client_hmac = compute_hmac(psk.as_bytes(), &auth_data);

    if !bool::from(expected_client_hmac.ct_eq(&client_auth_hmac)) {
        return Err(PskAuthError::ClientHmacVerificationFailed);
    }

    // 5. サーバーエフェメラル鍵ペアを生成
    let server_eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let server_eph_public = PublicKey::from(&server_eph_secret);

    // 6. サーバーエフェメラル公開鍵を送信
    send.write_all(server_eph_public.as_bytes()).await?;

    // 7. サーバーチャレンジを生成・送信
    let server_challenge = generate_auth_challenge();
    send.write_all(&server_challenge).await?;

    // 8. サーバー認証 HMAC を計算・送信: HMAC(PSK, challenge || server_eph_pub)
    let mut server_auth_data = Vec::with_capacity(32 + 32);
    server_auth_data.extend_from_slice(&server_challenge);
    server_auth_data.extend_from_slice(server_eph_public.as_bytes());
    let server_auth_hmac = compute_hmac(psk.as_bytes(), &server_auth_data);
    send.write_all(&server_auth_hmac).await?;

    // 9. 共有シークレットを計算
    let client_eph_pubkey = PublicKey::from(client_eph_pub);
    let shared_secret = server_eph_secret.diffie_hellman(&client_eph_pubkey);

    // 10. クライアント DH レスポンスを受信・検証
    let mut client_dh_response = [0u8; 32];
    recv.read_exact(&mut client_dh_response).await?;

    let expected_dh_response = compute_hmac(shared_secret.as_bytes(), &server_challenge);
    if !bool::from(expected_dh_response.ct_eq(&client_dh_response)) {
        return Err(PskAuthError::DhResponseVerificationFailed);
    }

    Ok(())
}

/// クライアント側: PSK 認証を実施（強化版）
pub async fn authenticate_with_server_psk(
    send: &mut SendStream,
    recv: &mut RecvStream,
    psk: &str,
) -> Result<(), PskAuthError> {
    // 1. マジックバイトを送信
    send.write_all(PSK_AUTH_MAGIC).await?;

    // 2. タイムスタンプを送信
    let timestamp = get_current_timestamp();
    send.write_all(&timestamp.to_be_bytes()).await?;

    // 3. クライアントエフェメラル鍵ペアを生成・送信
    let client_eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let client_eph_public = PublicKey::from(&client_eph_secret);
    send.write_all(client_eph_public.as_bytes()).await?;

    // 4. クライアント認証 HMAC を計算・送信: HMAC(PSK, timestamp || client_eph_pub)
    let mut auth_data = Vec::with_capacity(8 + 32);
    auth_data.extend_from_slice(&timestamp.to_be_bytes());
    auth_data.extend_from_slice(client_eph_public.as_bytes());
    let client_auth_hmac = compute_hmac(psk.as_bytes(), &auth_data);
    send.write_all(&client_auth_hmac).await?;

    // 5. サーバーエフェメラル公開鍵を受信
    let mut server_eph_pub = [0u8; 32];
    recv.read_exact(&mut server_eph_pub).await?;

    // 6. サーバーチャレンジを受信
    let mut server_challenge = [0u8; 32];
    recv.read_exact(&mut server_challenge).await?;

    // 7. サーバー認証 HMAC を受信・検証
    let mut server_auth_hmac = [0u8; 32];
    recv.read_exact(&mut server_auth_hmac).await?;

    // 期待される HMAC を計算: HMAC(PSK, challenge || server_eph_pub)
    let mut server_auth_data = Vec::with_capacity(32 + 32);
    server_auth_data.extend_from_slice(&server_challenge);
    server_auth_data.extend_from_slice(&server_eph_pub);
    let expected_server_hmac = compute_hmac(psk.as_bytes(), &server_auth_data);

    if !bool::from(expected_server_hmac.ct_eq(&server_auth_hmac)) {
        return Err(PskAuthError::ServerHmacVerificationFailed);
    }

    // 8. 共有シークレットを計算
    let server_eph_pubkey = PublicKey::from(server_eph_pub);
    let shared_secret = client_eph_secret.diffie_hellman(&server_eph_pubkey);

    // 9. クライアント DH レスポンスを計算・送信: HMAC(shared_secret, server_challenge)
    let client_dh_response = compute_hmac(shared_secret.as_bytes(), &server_challenge);
    send.write_all(&client_dh_response).await?;

    Ok(())
}

// =============================================================================
// X25519 公開鍵認証
// =============================================================================

/// X25519 認証エラー
#[derive(Debug, thiserror::Error)]
pub enum X25519AuthError {
    #[error("Invalid key length: expected 32 bytes, got {0}")]
    InvalidKeyLength(usize),

    #[error("Invalid base64 encoding: {0}")]
    InvalidBase64(String),

    #[error("Public key not authorized")]
    PublicKeyNotAuthorized,

    #[error("HMAC verification failed")]
    HmacVerificationFailed,

    #[error("Server public key mismatch")]
    ServerPublicKeyMismatch,

    #[error("Server HMAC verification failed")]
    ServerHmacVerificationFailed,

    #[error("Invalid auth magic bytes")]
    InvalidMagicBytes,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("QUIC read error: {0}")]
    QuicReadError(#[from] quinn::ReadExactError),

    #[error("QUIC write error: {0}")]
    QuicWriteError(#[from] quinn::WriteError),
}

/// Base64 形式の WireGuard 鍵をパース
///
/// WireGuard の鍵形式:
/// - 32 バイトの生データを標準 Base64 でエンコード
/// - 末尾に "=" パディングあり
/// - 結果は 44 文字
pub fn parse_base64_key(key_str: &str) -> Result<[u8; 32], X25519AuthError> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(key_str.trim())
        .map_err(|e| X25519AuthError::InvalidBase64(e.to_string()))?;

    if decoded.len() != 32 {
        return Err(X25519AuthError::InvalidKeyLength(decoded.len()));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

/// 公開鍵を Base64 文字列に変換
pub fn encode_base64_key(key: &[u8; 32]) -> String {
    base64::engine::general_purpose::STANDARD.encode(key)
}

/// 公開鍵ファイルを読み込み
///
/// ファイル形式:
/// - 1 行に 1 つの Base64 エンコード公開鍵
/// - '#' で始まる行はコメントとして無視
/// - 空行は無視
pub fn load_pubkeys_from_file(path: &Path) -> Result<Vec<[u8; 32]>, X25519AuthError> {
    let content = std::fs::read_to_string(path)?;
    let mut pubkeys = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        pubkeys.push(parse_base64_key(line)?);
    }

    Ok(pubkeys)
}

/// 秘密鍵ファイルを読み込み
pub fn load_privkey_from_file(path: &Path) -> Result<[u8; 32], X25519AuthError> {
    let content = std::fs::read_to_string(path)?;
    for line in content.lines() {
        let line = line.trim();
        if !line.is_empty() && !line.starts_with('#') {
            return parse_base64_key(line);
        }
    }
    Err(X25519AuthError::InvalidKeyLength(0))
}

/// HMAC-SHA256 でレスポンスを計算
///
/// 共有シークレットを鍵、チャレンジをメッセージとして HMAC を計算
fn compute_hmac_response(shared_secret: &[u8; 32], challenge: &[u8; 32]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(shared_secret).expect("HMAC can take key of any size");
    mac.update(challenge);
    let result = mac.finalize();

    let mut response = [0u8; 32];
    response.copy_from_slice(&result.into_bytes()[..32]);
    response
}

/// サーバー側: X25519 相互認証を実施
///
/// プロトコル（相互認証）:
/// 1. クライアントから: "QUICPORT_AUTH" (13 bytes)
/// 2. クライアントから: クライアント公開鍵 (32 bytes)
/// 3. クライアントから: クライアントチャレンジ (32 bytes)  <- NEW
/// 4. サーバーが公開鍵を認可リストと照合
/// 5. サーバーから: サーバー公開鍵 (32 bytes)  <- NEW
/// 6. サーバーから: エフェメラル公開鍵 (32 bytes)
/// 7. サーバーから: サーバーチャレンジ (32 bytes)
/// 8. サーバーから: サーバー HMAC レスポンス (32 bytes)  <- NEW
/// 9. クライアントから: クライアント HMAC レスポンス (32 bytes)
/// 10. サーバーがクライアント HMAC を検証
///
/// 戻り値: 認証成功時はクライアントの公開鍵を返す
pub async fn authenticate_client_x25519(
    send: &mut SendStream,
    recv: &mut RecvStream,
    authorized_pubkeys: &[[u8; 32]],
    server_private_key: &[u8; 32],
) -> Result<[u8; 32], X25519AuthError> {
    // 1. マジックバイトを受信
    let mut magic = [0u8; 13];
    recv.read_exact(&mut magic).await?;
    if &magic != b"QUICPORT_AUTH" {
        return Err(X25519AuthError::InvalidMagicBytes);
    }

    // 2. クライアント公開鍵を受信
    let mut client_pubkey_bytes = [0u8; 32];
    recv.read_exact(&mut client_pubkey_bytes).await?;

    // 3. クライアントチャレンジを受信（相互認証用）
    let mut client_challenge = [0u8; 32];
    recv.read_exact(&mut client_challenge).await?;

    // 4. 公開鍵が認可リストにあるか確認（定数時間比較）
    let is_authorized = authorized_pubkeys
        .iter()
        .any(|authorized| bool::from(authorized.ct_eq(&client_pubkey_bytes)));

    if !is_authorized {
        return Err(X25519AuthError::PublicKeyNotAuthorized);
    }

    // 5. サーバー公開鍵を送信（相互認証）
    let server_secret = StaticSecret::from(*server_private_key);
    let server_public = PublicKey::from(&server_secret);
    send.write_all(server_public.as_bytes()).await?;

    // 6. エフェメラル鍵ペアを生成（Forward Secrecy のため）
    let server_ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let server_ephemeral_public = PublicKey::from(&server_ephemeral_secret);

    // エフェメラル公開鍵を送信
    send.write_all(server_ephemeral_public.as_bytes()).await?;

    // 7. サーバーチャレンジを生成・送信
    let server_challenge = generate_auth_challenge();
    send.write_all(&server_challenge).await?;

    // 8. サーバー HMAC レスポンスを計算・送信（相互認証）
    // shared_static = X25519(server_private, client_public)
    let client_pubkey = PublicKey::from(client_pubkey_bytes);
    let shared_static = server_secret.diffie_hellman(&client_pubkey);
    // server_response = HMAC(shared_static, client_challenge)
    let server_response = compute_hmac_response(shared_static.as_bytes(), &client_challenge);
    send.write_all(&server_response).await?;

    // 9. 共有シークレットを計算（クライアント認証用）
    // shared = X25519(server_ephemeral_private, client_public)
    let client_pubkey = PublicKey::from(client_pubkey_bytes);
    let shared_secret = server_ephemeral_secret.diffie_hellman(&client_pubkey);

    // 10. 期待されるクライアントレスポンスを計算
    // response = HMAC-SHA256(shared_secret, server_challenge)
    let expected_response = compute_hmac_response(shared_secret.as_bytes(), &server_challenge);

    // 11. クライアントからのレスポンスを受信
    let mut response = [0u8; 32];
    recv.read_exact(&mut response).await?;

    // 12. 定数時間比較で検証
    if !bool::from(expected_response.ct_eq(&response)) {
        return Err(X25519AuthError::HmacVerificationFailed);
    }

    // 認証成功: クライアントの公開鍵を返す
    Ok(client_pubkey_bytes)
}

/// クライアント側: X25519 相互認証を実施
///
/// プロトコル（相互認証）:
/// 1. "QUICPORT_AUTH" を送信
/// 2. クライアント公開鍵を送信
/// 3. クライアントチャレンジを送信  <- NEW
/// 4. サーバー公開鍵を受信・検証  <- NEW
/// 5. サーバーのエフェメラル公開鍵を受信
/// 6. サーバーチャレンジを受信
/// 7. サーバー HMAC レスポンスを受信・検証  <- NEW
/// 8. 共有シークレットを計算
/// 9. クライアント HMAC レスポンスを計算・送信
pub async fn authenticate_with_server_x25519(
    send: &mut SendStream,
    recv: &mut RecvStream,
    client_private_key: &[u8; 32],
    expected_server_pubkey: &[u8; 32],
) -> Result<(), X25519AuthError> {
    // クライアント鍵ペア
    let client_secret = StaticSecret::from(*client_private_key);
    let client_public = PublicKey::from(&client_secret);

    // 1. マジックバイトを送信
    send.write_all(b"QUICPORT_AUTH").await?;

    // 2. クライアント公開鍵を送信
    send.write_all(client_public.as_bytes()).await?;

    // 3. クライアントチャレンジを生成・送信（相互認証用）
    let client_challenge = generate_auth_challenge();
    send.write_all(&client_challenge).await?;

    // 4. サーバー公開鍵を受信
    let mut server_pubkey_bytes = [0u8; 32];
    recv.read_exact(&mut server_pubkey_bytes).await?;

    // サーバー公開鍵を検証（常に必須）
    if !bool::from(server_pubkey_bytes.ct_eq(expected_server_pubkey)) {
        return Err(X25519AuthError::ServerPublicKeyMismatch);
    }

    // 5. サーバーのエフェメラル公開鍵を受信
    let mut server_ephemeral_bytes = [0u8; 32];
    recv.read_exact(&mut server_ephemeral_bytes).await?;
    let server_ephemeral_public = PublicKey::from(server_ephemeral_bytes);

    // 6. サーバーチャレンジを受信
    let mut server_challenge = [0u8; 32];
    recv.read_exact(&mut server_challenge).await?;

    // 7. サーバー HMAC レスポンスを受信・検証（常に必須）
    let mut server_response = [0u8; 32];
    recv.read_exact(&mut server_response).await?;

    // サーバーレスポンスを検証
    // shared_static = X25519(client_private, server_public)
    let server_pubkey = PublicKey::from(server_pubkey_bytes);
    let shared_static = client_secret.diffie_hellman(&server_pubkey);
    // expected_server_response = HMAC(shared_static, client_challenge)
    let expected_server_response =
        compute_hmac_response(shared_static.as_bytes(), &client_challenge);

    if !bool::from(expected_server_response.ct_eq(&server_response)) {
        return Err(X25519AuthError::ServerHmacVerificationFailed);
    }

    // 8. 共有シークレットを計算（クライアント認証用）
    // shared = X25519(client_private, server_ephemeral_public)
    let shared_secret = client_secret.diffie_hellman(&server_ephemeral_public);

    // 9. クライアントレスポンスを計算・送信
    // response = HMAC-SHA256(shared_secret, server_challenge)
    let response = compute_hmac_response(shared_secret.as_bytes(), &server_challenge);
    send.write_all(&response).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_computation() {
        let key = b"test-secret-key";
        let data = b"test-data-to-sign";

        // 同じ入力で同じ出力が得られることを確認
        let hmac1 = compute_hmac(key, data);
        let hmac2 = compute_hmac(key, data);
        assert_eq!(hmac1, hmac2);

        // 異なるキーで異なる出力が得られることを確認
        let hmac_different_key = compute_hmac(b"different-key", data);
        assert_ne!(hmac1, hmac_different_key);

        // 異なるデータで異なる出力が得られることを確認
        let hmac_different_data = compute_hmac(key, b"different-data");
        assert_ne!(hmac1, hmac_different_data);
    }

    #[test]
    fn test_auth_challenge_generation() {
        // チャレンジが 32 バイトであることを確認
        let challenge = generate_auth_challenge();
        assert_eq!(challenge.len(), 32);

        // 連続生成で異なる値が得られることを確認（ランダム性）
        let challenge2 = generate_auth_challenge();
        assert_ne!(challenge, challenge2);
    }

    #[test]
    fn test_timestamp_validation() {
        let now = get_current_timestamp();

        // 現在のタイムスタンプは有効
        assert!(is_timestamp_valid(now));

        // 少し前のタイムスタンプも有効（許容範囲内）
        assert!(is_timestamp_valid(now - 30));

        // 許容範囲外のタイムスタンプは無効
        assert!(!is_timestamp_valid(now - 120)); // 2分前
        assert!(!is_timestamp_valid(now + 120)); // 2分後
    }

    #[test]
    fn test_parse_base64_key() {
        // テスト用の WireGuard 鍵
        let privkey_b64 = "mBJ3XsDyuJxqU2bk0XEa+rUH+XD1lYwMlx9xH8ZTMUg=";
        let pubkey_b64 = "IexqQqW8ngM33aoJWqheXfW+11hL6A3h6kpO8uNl9Ws=";

        // 秘密鍵をパース
        let privkey = parse_base64_key(privkey_b64).expect("Failed to parse private key");
        assert_eq!(privkey.len(), 32);

        // 公開鍵をパース
        let pubkey = parse_base64_key(pubkey_b64).expect("Failed to parse public key");
        assert_eq!(pubkey.len(), 32);

        // 秘密鍵から公開鍵を導出して検証
        let secret = StaticSecret::from(privkey);
        let derived_public = PublicKey::from(&secret);
        assert_eq!(derived_public.as_bytes(), &pubkey);
    }

    #[test]
    fn test_encode_base64_key() {
        let pubkey_b64 = "IexqQqW8ngM33aoJWqheXfW+11hL6A3h6kpO8uNl9Ws=";
        let pubkey = parse_base64_key(pubkey_b64).unwrap();
        let encoded = encode_base64_key(&pubkey);
        assert_eq!(encoded, pubkey_b64);
    }

    #[test]
    fn test_invalid_base64_key() {
        // 無効な Base64
        assert!(parse_base64_key("not-valid-base64!!!").is_err());

        // 長さが不正（短すぎる）
        assert!(parse_base64_key("AAAA").is_err());
    }

    #[test]
    fn test_hmac_response() {
        let shared_secret = [0u8; 32];
        let challenge = [1u8; 32];

        let response1 = compute_hmac_response(&shared_secret, &challenge);
        let response2 = compute_hmac_response(&shared_secret, &challenge);

        // 同じ入力なら同じ出力
        assert_eq!(response1, response2);

        // 異なるチャレンジなら異なる出力
        let different_challenge = [2u8; 32];
        let response3 = compute_hmac_response(&shared_secret, &different_challenge);
        assert_ne!(response1, response3);
    }
}

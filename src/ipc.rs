//! IPC (Inter-Process Communication) プロトコル定義
//!
//! コントロールプレーンとデータプレーン間の通信を定義します。
//!
//! ## メッセージフレーミング
//!
//! ```text
//! +----------------+----------------+------------------+
//! | Length (4byte) | Type (1byte)   | Payload (JSON)   |
//! | big-endian     |                | (Length - 1)     |
//! +----------------+----------------+------------------+
//! ```
//!
//! ## 通信方式
//!
//! - TCP localhost (127.0.0.1)
//! - ポート番号ファイル: `~/.local/state/quicport/dataplanes/dp-<pid>.port`

use serde::{Deserialize, Serialize};
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// IPC エラー
#[derive(Error, Debug)]
pub enum IpcError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Invalid message type: {0}")]
    InvalidMessageType(u8),

    #[error("Message too large: {0} bytes (max: {1})")]
    MessageTooLarge(usize, usize),
}

/// 最大メッセージサイズ (1MB)
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

// =============================================================================
// メッセージタイプ定義
// =============================================================================

/// コントロールプレーン → データプレーン コマンド
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ControlCommand {
    /// 認証ポリシーを設定
    SetAuthPolicy(AuthPolicy),

    /// 設定を更新
    SetConfig(DataPlaneConfig),

    /// DRAIN モードに移行（新規接続拒否）
    Drain,

    /// 即座にシャットダウン
    Shutdown,

    /// 状態を取得
    GetStatus,

    /// アクティブ接続の一覧を取得
    GetConnections,
}

/// データプレーン → コントロールプレーン イベント/レスポンス
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DataPlaneEvent {
    /// 初期化完了、接続受付可能
    Ready {
        /// データプレーンの PID
        pid: u32,
        /// リッスンアドレス
        listen_addr: String,
    },

    /// 状態レポート
    Status(DataPlaneStatus),

    /// 新規接続確立
    ConnectionOpened {
        /// 接続 ID
        connection_id: u32,
        /// リモートアドレス
        remote_addr: String,
        /// プロトコル (TCP/UDP)
        protocol: String,
    },

    /// 接続終了
    ConnectionClosed {
        /// 接続 ID
        connection_id: u32,
        /// 送信バイト数
        bytes_sent: u64,
        /// 受信バイト数
        bytes_received: u64,
    },

    /// 認証判断の問い合わせ（将来の拡張用）
    AuthRequest {
        /// 接続 ID
        connection_id: u32,
        /// 認証タイプ
        auth_type: String,
        /// 認証データ
        auth_data: Vec<u8>,
    },

    /// 全接続終了、終了準備完了
    Drained,

    /// エラー応答
    Error {
        /// エラーコード
        code: String,
        /// エラーメッセージ
        message: String,
    },
}

// =============================================================================
// 認証ポリシー
// =============================================================================

/// 認証ポリシー
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "auth_type")]
pub enum AuthPolicy {
    /// X25519 公開鍵認証
    X25519 {
        /// 許可されたクライアント公開鍵（Base64）
        authorized_pubkeys: Vec<String>,
        /// サーバー秘密鍵（Base64）
        server_private_key: String,
    },
    /// PSK 認証
    Psk {
        /// Pre-shared key
        psk: String,
    },
}

// =============================================================================
// データプレーン設定
// =============================================================================

/// データプレーン設定
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPlaneConfig {
    /// QUIC リッスンアドレス
    pub listen_addr: SocketAddr,

    /// DRAIN 状態のタイムアウト（秒）
    #[serde(default = "default_drain_timeout")]
    pub drain_timeout: u64,

    /// アイドル接続のタイムアウト（秒）
    #[serde(default = "default_idle_connection_timeout")]
    pub idle_connection_timeout: u64,
}

fn default_drain_timeout() -> u64 {
    300 // 5 minutes
}

fn default_idle_connection_timeout() -> u64 {
    3600 // 1 hour
}

impl Default for DataPlaneConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:39000".parse().unwrap(),
            drain_timeout: default_drain_timeout(),
            idle_connection_timeout: default_idle_connection_timeout(),
        }
    }
}

// =============================================================================
// データプレーン状態
// =============================================================================

/// データプレーンの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataPlaneState {
    /// 起動中、初期化処理
    Starting,
    /// 通常稼働中、新規接続受付可能
    Active,
    /// ドレイン中、新規接続拒否、既存接続のみ処理
    Draining,
    /// 終了済み
    Terminated,
}

impl std::fmt::Display for DataPlaneState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataPlaneState::Starting => write!(f, "STARTING"),
            DataPlaneState::Active => write!(f, "ACTIVE"),
            DataPlaneState::Draining => write!(f, "DRAINING"),
            DataPlaneState::Terminated => write!(f, "TERMINATED"),
        }
    }
}

/// データプレーン状態レポート
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPlaneStatus {
    /// プロセス状態
    pub state: DataPlaneState,
    /// PID
    pub pid: u32,
    /// アクティブ接続数
    pub active_connections: u32,
    /// 総送信バイト数
    pub bytes_sent: u64,
    /// 総受信バイト数
    pub bytes_received: u64,
    /// 起動時刻（UNIX タイムスタンプ）
    pub started_at: u64,
}

/// 接続情報
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    /// 接続 ID
    pub connection_id: u32,
    /// リモートアドレス
    pub remote_addr: String,
    /// プロトコル (TCP/UDP)
    pub protocol: String,
    /// 送信バイト数
    pub bytes_sent: u64,
    /// 受信バイト数
    pub bytes_received: u64,
    /// 接続開始時刻（UNIX タイムスタンプ）
    pub created_at: u64,
    /// 最終アクティビティ時刻（UNIX タイムスタンプ）
    pub last_activity: u64,
}

// =============================================================================
// IPC 通信
// =============================================================================

/// IPC 接続
pub struct IpcConnection {
    stream: TcpStream,
}

impl IpcConnection {
    /// 新しい IPC 接続を作成
    pub fn new(stream: TcpStream) -> Self {
        Self { stream }
    }

    /// TCP localhost に接続
    pub async fn connect(port: u16) -> Result<Self, IpcError> {
        let addr = format!("127.0.0.1:{}", port);
        let stream = TcpStream::connect(&addr).await?;
        Ok(Self { stream })
    }

    /// コマンドを送信
    pub async fn send_command(&mut self, cmd: &ControlCommand) -> Result<(), IpcError> {
        let payload = serde_json::to_vec(cmd)?;
        self.send_raw(0x01, &payload).await
    }

    /// イベントを送信
    pub async fn send_event(&mut self, event: &DataPlaneEvent) -> Result<(), IpcError> {
        let payload = serde_json::to_vec(event)?;
        self.send_raw(0x02, &payload).await
    }

    /// コマンドを受信
    pub async fn recv_command(&mut self) -> Result<ControlCommand, IpcError> {
        let (msg_type, payload) = self.recv_raw().await?;
        if msg_type != 0x01 {
            return Err(IpcError::InvalidMessageType(msg_type));
        }
        Ok(serde_json::from_slice(&payload)?)
    }

    /// イベントを受信
    pub async fn recv_event(&mut self) -> Result<DataPlaneEvent, IpcError> {
        let (msg_type, payload) = self.recv_raw().await?;
        if msg_type != 0x02 {
            return Err(IpcError::InvalidMessageType(msg_type));
        }
        Ok(serde_json::from_slice(&payload)?)
    }

    /// 生のメッセージを送信
    async fn send_raw(&mut self, msg_type: u8, payload: &[u8]) -> Result<(), IpcError> {
        let length = (payload.len() + 1) as u32;
        if length as usize > MAX_MESSAGE_SIZE {
            return Err(IpcError::MessageTooLarge(
                length as usize,
                MAX_MESSAGE_SIZE,
            ));
        }

        // Length (4 bytes, big-endian)
        self.stream.write_all(&length.to_be_bytes()).await?;
        // Type (1 byte)
        self.stream.write_all(&[msg_type]).await?;
        // Payload
        self.stream.write_all(payload).await?;
        self.stream.flush().await?;

        Ok(())
    }

    /// 生のメッセージを受信
    async fn recv_raw(&mut self) -> Result<(u8, Vec<u8>), IpcError> {
        // Length (4 bytes, big-endian)
        let mut length_buf = [0u8; 4];
        match self.stream.read_exact(&mut length_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(IpcError::ConnectionClosed);
            }
            Err(e) => return Err(e.into()),
        }

        let length = u32::from_be_bytes(length_buf) as usize;
        if length > MAX_MESSAGE_SIZE {
            return Err(IpcError::MessageTooLarge(length, MAX_MESSAGE_SIZE));
        }
        if length < 1 {
            return Err(IpcError::InvalidMessageType(0));
        }

        // Type (1 byte)
        let mut type_buf = [0u8; 1];
        self.stream.read_exact(&mut type_buf).await?;
        let msg_type = type_buf[0];

        // Payload
        let payload_len = length - 1;
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            self.stream.read_exact(&mut payload).await?;
        }

        Ok((msg_type, payload))
    }
}

// =============================================================================
// ユーティリティ関数
// =============================================================================

/// データプレーンディレクトリのパスを取得
///
/// `~/.local/state/quicport/dataplanes/`
pub fn dataplanes_dir() -> Result<PathBuf, io::Error> {
    let state_dir = dirs::state_dir()
        .or_else(|| dirs::data_local_dir())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Cannot determine state directory"))?;

    Ok(state_dir.join("quicport").join("dataplanes"))
}

/// データプレーンのポートファイルパスを取得
pub fn dataplane_port_path(pid: u32) -> Result<PathBuf, io::Error> {
    Ok(dataplanes_dir()?.join(format!("dp-{}.port", pid)))
}

/// データプレーンのポート番号をファイルに書き込む
pub fn write_dataplane_port(pid: u32, port: u16) -> Result<(), io::Error> {
    let path = dataplane_port_path(pid)?;
    std::fs::write(&path, port.to_string())
}

/// データプレーンのポート番号をファイルから読み取る
pub fn read_dataplane_port(pid: u32) -> Result<u16, io::Error> {
    let path = dataplane_port_path(pid)?;
    let content = std::fs::read_to_string(&path)?;
    content
        .trim()
        .parse::<u16>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

/// データプレーンの状態ファイルパスを取得
pub fn dataplane_state_path(pid: u32) -> Result<PathBuf, io::Error> {
    Ok(dataplanes_dir()?.join(format!("dp-{}.state", pid)))
}

/// データプレーンディレクトリを作成
pub fn ensure_dataplanes_dir() -> Result<PathBuf, io::Error> {
    let dir = dataplanes_dir()?;
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// 実行中のデータプレーンを検出
///
/// `~/.local/state/quicport/dataplanes/` をスキャンして、
/// 存在するポートファイルの PID リストを返す
pub fn discover_dataplanes() -> Result<Vec<u32>, io::Error> {
    let dir = dataplanes_dir()?;
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut pids = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            // dp-<pid>.port のパターンにマッチ
            if name.starts_with("dp-") && name.ends_with(".port") {
                if let Ok(pid) = name[3..name.len() - 5].parse::<u32>() {
                    pids.push(pid);
                }
            }
        }
    }

    Ok(pids)
}

/// データプレーンの状態を読み取る
pub fn read_dataplane_state(pid: u32) -> Result<DataPlaneStatus, io::Error> {
    let path = dataplane_state_path(pid)?;
    let content = std::fs::read_to_string(&path)?;
    serde_json::from_str(&content)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

/// データプレーンの状態を書き込む
pub fn write_dataplane_state(pid: u32, status: &DataPlaneStatus) -> Result<(), io::Error> {
    let path = dataplane_state_path(pid)?;
    let content = serde_json::to_string_pretty(status)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    std::fs::write(&path, content)
}

/// データプレーンのファイルをクリーンアップ
pub fn cleanup_dataplane_files(pid: u32) -> Result<(), io::Error> {
    let port_path = dataplane_port_path(pid)?;
    let state_path = dataplane_state_path(pid)?;

    if port_path.exists() {
        std::fs::remove_file(&port_path)?;
    }
    if state_path.exists() {
        std::fs::remove_file(&state_path)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_control_command() {
        let cmd = ControlCommand::Drain;
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("Drain"));

        let cmd = ControlCommand::SetAuthPolicy(AuthPolicy::Psk {
            psk: "secret".to_string(),
        });
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("Psk"));
        assert!(json.contains("secret"));
    }

    #[test]
    fn test_serialize_dataplane_event() {
        let event = DataPlaneEvent::Ready {
            pid: 12345,
            listen_addr: "0.0.0.0:39000".to_string(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("Ready"));
        assert!(json.contains("12345"));
    }

    #[test]
    fn test_dataplane_state_display() {
        assert_eq!(DataPlaneState::Starting.to_string(), "STARTING");
        assert_eq!(DataPlaneState::Active.to_string(), "ACTIVE");
        assert_eq!(DataPlaneState::Draining.to_string(), "DRAINING");
        assert_eq!(DataPlaneState::Terminated.to_string(), "TERMINATED");
    }
}

//! IPC (Inter-Process Communication) プロトコル定義
//!
//! コントロールプレーンとデータプレーン間の通信を定義します。
//!
//! ## HTTP IPC API
//!
//! Control Plane ↔ Data Plane 間の通信は HTTP/JSON API で行います。
//! すべてのエンドポイントは POST メソッドを使用する RPC スタイルです。
//!
//! ### エンドポイント
//!
//! | メソッド | 説明 | 呼び出し元 |
//! |----------|------|-----------|
//! | `POST /api/v1/RegisterDataPlane` | DP 登録、認証ポリシー取得 | DP |
//! | `POST /api/v1/PollCommands` | コマンドポーリング（長ポーリング） | DP |
//! | `POST /api/v1/AckCommand` | コマンド応答 | DP |
//! | `POST /api/v1/ReportEvent` | イベント報告 | DP |
//! | `POST /api/v1/ListDataPlanes` | 全 DP 一覧 | CLI/外部 |
//! | `POST /api/v1/GetDataPlaneStatus` | 特定 DP の詳細 | CLI/外部 |
//! | `POST /api/v1/DrainDataPlane` | ドレイン | CLI/外部 |
//! | `POST /api/v1/ShutdownDataPlane` | シャットダウン | CLI/外部 |
//! | `POST /api/v1/GetConnections` | 接続一覧 | CLI/外部 |

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use thiserror::Error;

/// IPC エラー
#[derive(Error, Debug)]
pub enum IpcError {
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

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

    /// 全接続終了、終了準備完了
    Drained,

    /// 接続一覧の応答
    Connections {
        /// 接続一覧
        connections: Vec<ConnectionInfo>,
    },

    /// エラー応答
    Error {
        /// エラーコード
        code: String,
        /// エラーメッセージ
        message: String,
    },
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
}

// =============================================================================
// HTTP IPC リクエスト/レスポンス型
// =============================================================================

/// RegisterDataPlane リクエスト (DP → CP)
///
/// データプレーンが起動時にコントロールプレーンに登録
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterDataPlaneRequest {
    /// データプレーンの PID
    pub pid: u32,
    /// QUIC リッスンアドレス
    pub listen_addr: String,
}

/// RegisterDataPlane レスポンス (CP → DP)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterDataPlaneResponse {
    /// 割り当てられた Data Plane ID
    pub dp_id: String,
    /// 認証ポリシー
    pub auth_policy: AuthPolicy,
    /// データプレーン設定
    pub config: DataPlaneConfig,
}

/// PollCommands リクエスト (DP → CP)
///
/// 長ポーリングでコマンドを取得
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollCommandsRequest {
    /// Data Plane ID
    pub dp_id: String,
    /// 待機タイムアウト（秒）
    #[serde(default = "default_poll_timeout")]
    pub wait_timeout_secs: u64,
}

fn default_poll_timeout() -> u64 {
    30
}

/// コマンド（ID 付き）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandWithId {
    /// コマンド ID
    pub id: String,
    /// コマンド内容
    #[serde(flatten)]
    pub command: ControlCommand,
}

/// PollCommands レスポンス (CP → DP)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollCommandsResponse {
    /// 保留中のコマンド
    pub commands: Vec<CommandWithId>,
}

/// AckCommand リクエスト (DP → CP)
///
/// コマンドの実行結果を報告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckCommandRequest {
    /// Data Plane ID
    pub dp_id: String,
    /// コマンド ID
    pub cmd_id: String,
    /// 実行ステータス
    pub status: String,
    /// 実行結果（オプション）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<DataPlaneStatus>,
}

/// AckCommand レスポンス (CP → DP)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AckCommandResponse {
    /// 確認済みフラグ
    pub acknowledged: bool,
}

/// ReportEvent リクエスト (DP → CP)
///
/// イベントを報告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportEventRequest {
    /// Data Plane ID
    pub dp_id: String,
    /// イベント
    pub event: DataPlaneEvent,
}

/// ReportEvent レスポンス (CP → DP)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportEventResponse {
    /// 確認済みフラグ
    pub acknowledged: bool,
}

/// ListDataPlanes リクエスト (CLI/外部 → CP)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDataPlanesRequest {}

/// データプレーンサマリー
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPlaneSummary {
    /// Data Plane ID
    pub dp_id: String,
    /// PID
    pub pid: u32,
    /// 状態
    pub state: DataPlaneState,
    /// アクティブ接続数
    pub active_connections: u32,
    /// 送信バイト数
    pub bytes_sent: u64,
    /// 受信バイト数
    pub bytes_received: u64,
}

/// ListDataPlanes レスポンス (CP → CLI/外部)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDataPlanesResponse {
    /// データプレーン一覧
    pub dataplanes: Vec<DataPlaneSummary>,
}

/// GetDataPlaneStatus リクエスト (CLI/外部 → CP)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetDataPlaneStatusRequest {
    /// Data Plane ID
    pub dp_id: String,
}

/// GetDataPlaneStatus レスポンス (CP → CLI/外部)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetDataPlaneStatusResponse {
    /// Data Plane ID
    pub dp_id: String,
    /// PID
    pub pid: u32,
    /// 状態
    pub state: DataPlaneState,
    /// アクティブ接続数
    pub active_connections: u32,
    /// 送信バイト数
    pub bytes_sent: u64,
    /// 受信バイト数
    pub bytes_received: u64,
    /// 起動時刻（UNIX タイムスタンプ）
    pub started_at: u64,
}

/// DrainDataPlane リクエスト (CLI/外部 → CP)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrainDataPlaneRequest {
    /// Data Plane ID
    pub dp_id: String,
}

/// DrainDataPlane レスポンス (CP → CLI/外部)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrainDataPlaneResponse {
    /// ステータス
    pub status: String,
}

/// ShutdownDataPlane リクエスト (CLI/外部 → CP)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownDataPlaneRequest {
    /// Data Plane ID
    pub dp_id: String,
}

/// ShutdownDataPlane レスポンス (CP → CLI/外部)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownDataPlaneResponse {
    /// ステータス
    pub status: String,
}

/// GetConnections リクエスト (CLI/外部 → CP)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetConnectionsRequest {
    /// Data Plane ID
    pub dp_id: String,
}

/// GetConnections レスポンス (CP → CLI/外部)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetConnectionsResponse {
    /// 接続一覧
    pub connections: Vec<ConnectionInfo>,
}

/// HTTP IPC エラーレスポンス
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// エラーコード
    pub error: String,
    /// エラーメッセージ
    pub message: String,
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
    0 // 0 means infinite (no timeout)
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

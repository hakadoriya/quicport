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
//! #### DP 用 API (`/api/v1/dp/*`)
//!
//! | メソッド | 説明 | 方向 |
//! |----------|------|------|
//! | `POST /api/v1/dp/SendStatus` | 状態送信（登録・更新・応答すべて統合） | DP → CP |
//! | `POST /api/v1/dp/ReceiveCommand` | コマンド受信（長ポーリング） | CP → DP |
//!
//! #### 管理用 API (`/api/v1/admin/*`)
//!
//! | メソッド | 説明 |
//! |----------|------|
//! | `POST /api/v1/admin/ListDataPlanes` | 全 DP 一覧 |
//! | `POST /api/v1/admin/GetDataPlaneStatus` | 特定 DP の詳細 |
//! | `POST /api/v1/admin/DrainDataPlane` | ドレイン |
//! | `POST /api/v1/admin/ShutdownDataPlane` | シャットダウン |
//! | `POST /api/v1/admin/GetConnections` | 接続一覧 |

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use thiserror::Error;

// =============================================================================
// API パス定数
// =============================================================================

/// DP 用 API パス
pub mod api_paths {
    // DP → CP（データプレーン用）
    pub const SEND_STATUS: &str = "/api/v1/dp/SendStatus";
    pub const RECEIVE_COMMAND: &str = "/api/v1/dp/ReceiveCommand";

    // CLI/外部 → CP（管理用）
    pub const LIST_DATA_PLANES: &str = "/api/v1/admin/ListDataPlanes";
    pub const GET_DATA_PLANE_STATUS: &str = "/api/v1/admin/GetDataPlaneStatus";
    pub const DRAIN_DATA_PLANE: &str = "/api/v1/admin/DrainDataPlane";
    pub const SHUTDOWN_DATA_PLANE: &str = "/api/v1/admin/ShutdownDataPlane";
    pub const GET_CONNECTIONS: &str = "/api/v1/admin/GetConnections";
}

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
}

// =============================================================================
// HTTP IPC リクエスト/レスポンス型（DP 用 API）
// =============================================================================

/// SendStatus リクエスト (DP → CP)
///
/// 状態送信（登録・更新・コマンド応答すべて統合）
/// 毎回全状態を冪等に送信することで、CP 再起動後も状態を復旧可能
///
/// - 初回呼び出し: DP 登録
/// - 以降の呼び出し: 状態更新 + コマンド応答
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendStatusRequest {
    // ========== DP 識別情報 ==========
    /// Data Plane ID（eBPF ルーティング用、16 進数文字列 "0x0001" 形式）
    /// 重複時は 409 Conflict エラーが返る
    pub dp_id: String,
    /// データプレーンの PID
    pub pid: u32,
    /// QUIC リッスンアドレス
    pub listen_addr: String,

    // ========== 状態情報 ==========
    /// 現在の状態
    pub state: DataPlaneState,
    /// アクティブ接続数
    pub active_connections: u32,
    /// 総送信バイト数
    pub bytes_sent: u64,
    /// 総受信バイト数
    pub bytes_received: u64,
    /// 起動時刻（UNIX タイムスタンプ）
    pub started_at: u64,

    // ========== コマンド応答（オプション） ==========
    /// 応答するコマンド ID（None の場合は状態更新のみ）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ack_cmd_id: Option<String>,
    /// コマンド実行ステータス（"completed", "failed" など）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ack_status: Option<String>,
}

/// SendStatus レスポンス (CP → DP)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendStatusResponse {
    /// Data Plane ID（server_id から生成、初回登録時に割り当て）
    pub dp_id: String,
    /// 認証ポリシー（初回登録時または更新時のみ Some）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_policy: Option<AuthPolicy>,
    /// データプレーン設定（初回登録時または更新時のみ Some）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<DataPlaneConfig>,
}

/// ReceiveCommand リクエスト (DP → CP)
///
/// コマンド受信（長ポーリング）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiveCommandRequest {
    /// Data Plane ID
    pub dp_id: String,
    /// 待機タイムアウト（秒）
    #[serde(default = "default_receive_timeout")]
    pub wait_timeout_secs: u64,
}

fn default_receive_timeout() -> u64 {
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

/// ReceiveCommand レスポンス (CP → DP)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiveCommandResponse {
    /// 保留中のコマンド
    pub commands: Vec<CommandWithId>,
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

    /// サーバー ID（eBPF ルーティング用）
    ///
    /// この値は QUIC Connection ID の先頭 4 バイトに埋め込まれ、
    /// eBPF プログラムがパケットを正しい Data Plane プロセスに
    /// ルーティングするために使用されます。
    ///
    /// None の場合、従来の接続 ID カウンターが使用されます。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<u32>,

    /// eBPF ルーティングを有効にするか
    ///
    /// true の場合、eBPF プログラムを使用して QUIC パケットを
    /// Connection ID に基づいてルーティングします。
    /// Linux + ebpf feature が必要です。
    #[serde(default)]
    pub enable_ebpf_routing: bool,

    /// stale データプレーンの検出タイムアウト（秒）
    ///
    /// CP のバックグラウンドタスクが DP の `last_active` をチェックし、
    /// この値を超過した DP を stale と判定して eBPF map エントリを削除する。
    /// SendStatus の送信間隔（デフォルト 5 秒）より十分大きくする必要がある。
    #[serde(default = "default_stale_dp_timeout")]
    pub stale_dp_timeout: u64,

    /// QUIC keep-alive interval（秒）
    /// NAT テーブル維持のために定期的に ping を送信する間隔
    #[serde(default = "default_quic_keep_alive_secs")]
    pub quic_keep_alive_secs: u64,

    /// QUIC max idle timeout（秒）
    /// この時間応答がなければ接続をクローズする
    #[serde(default = "default_quic_idle_timeout_secs")]
    pub quic_idle_timeout_secs: u64,
}

fn default_drain_timeout() -> u64 {
    0 // 0 means infinite (no timeout)
}

fn default_idle_connection_timeout() -> u64 {
    3600 // 1 hour
}

fn default_stale_dp_timeout() -> u64 {
    300 // 5 minutes
}

fn default_quic_keep_alive_secs() -> u64 {
    crate::quic::DEFAULT_QUIC_KEEP_ALIVE_SECS
}

fn default_quic_idle_timeout_secs() -> u64 {
    crate::quic::DEFAULT_QUIC_IDLE_TIMEOUT_SECS
}

impl Default for DataPlaneConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:39000".parse().unwrap(),
            drain_timeout: default_drain_timeout(),
            idle_connection_timeout: default_idle_connection_timeout(),
            server_id: None,
            enable_ebpf_routing: false,
            stale_dp_timeout: default_stale_dp_timeout(),
            quic_keep_alive_secs: default_quic_keep_alive_secs(),
            quic_idle_timeout_secs: default_quic_idle_timeout_secs(),
        }
    }
}

// =============================================================================
// データプレーン状態
// =============================================================================

/// データプレーンの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
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
    fn test_serialize_send_status_request() {
        let req = SendStatusRequest {
            dp_id: "0x1234".to_string(),
            pid: 12345,
            listen_addr: "0.0.0.0:39000".to_string(),
            state: DataPlaneState::Active,
            active_connections: 10,
            bytes_sent: 1000,
            bytes_received: 2000,
            started_at: 1700000000,
            ack_cmd_id: None,
            ack_status: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("0x1234"));
        assert!(json.contains("12345")); // pid
        assert!(json.contains("ACTIVE"));
    }

    #[test]
    fn test_dataplane_state_display() {
        assert_eq!(DataPlaneState::Starting.to_string(), "STARTING");
        assert_eq!(DataPlaneState::Active.to_string(), "ACTIVE");
        assert_eq!(DataPlaneState::Draining.to_string(), "DRAINING");
        assert_eq!(DataPlaneState::Terminated.to_string(), "TERMINATED");
    }
}

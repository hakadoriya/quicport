//! IPC ランタイム状態管理
//!
//! コントロールプレーンにおける HTTP IPC のランタイム状態を管理します。
//! データプレーンの登録・状態追跡・コマンド配信などを担当します。

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Notify, RwLock};
use tracing::{info, warn};

use crate::ipc::{
    AuthPolicy, CommandWithId, ConnectionInfo, ControlCommand, DataPlaneConfig, DataPlaneState,
    DataPlaneSummary, GetDataPlaneStatusResponse, TunnelInfo,
};

// =============================================================================
// HTTP IPC 状態管理
// =============================================================================

/// Data Plane 情報（HTTP IPC 用）
pub struct HttpDataPlane {
    /// Data Plane ID
    pub dp_id: String,
    /// PID
    pub pid: u32,
    /// QUIC リッスンアドレス
    pub listen_addr: String,
    /// 状態
    pub state: DataPlaneState,
    /// アクティブトンネル数
    pub active_tunnels: u32,
    /// 送信バイト数
    pub bytes_sent: u64,
    /// 受信バイト数
    pub bytes_received: u64,
    /// 起動時刻
    pub started_at: u64,
    /// 保留中のコマンドキュー
    pub pending_commands: VecDeque<CommandWithId>,
    /// 接続一覧（DP から報告されたもの）
    pub connections: Vec<ConnectionInfo>,
    /// トンネル一覧（DP から報告されたもの）
    pub tunnels: Vec<TunnelInfo>,
    /// 最終アクティブ時刻
    pub last_active: u64,
    /// server_id（eBPF ルーティング用）
    pub server_id: Option<u32>,
}

impl HttpDataPlane {
    /// 新しい HttpDataPlane を作成
    pub fn new(dp_id: String, pid: u32, listen_addr: String) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            dp_id,
            pid,
            listen_addr,
            state: DataPlaneState::Starting,
            active_tunnels: 0,
            bytes_sent: 0,
            bytes_received: 0,
            started_at: now,
            pending_commands: VecDeque::new(),
            connections: Vec::new(),
            tunnels: Vec::new(),
            last_active: now,
            server_id: None,
        }
    }

    /// 状態をサマリーに変換
    pub fn to_summary(&self) -> DataPlaneSummary {
        DataPlaneSummary {
            dp_id: self.dp_id.clone(),
            pid: self.pid,
            state: self.state,
            active_tunnels: self.active_tunnels,
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
        }
    }

    /// 詳細ステータスを取得
    pub fn to_status_response(&self) -> GetDataPlaneStatusResponse {
        GetDataPlaneStatusResponse {
            dp_id: self.dp_id.clone(),
            pid: self.pid,
            state: self.state,
            active_tunnels: self.active_tunnels,
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            started_at: self.started_at,
        }
    }
}

/// HTTP IPC 状態
pub struct HttpIpcState {
    /// 登録済みデータプレーン
    pub data_planes: RwLock<HashMap<String, HttpDataPlane>>,
    /// コマンド ID カウンター
    command_id_counter: AtomicU64,
    /// 新コマンド通知（長ポーリング用）
    pub command_notify: Notify,
    /// 認証ポリシー
    pub auth_policy: RwLock<Option<AuthPolicy>>,
    /// データプレーン設定
    pub dp_config: RwLock<DataPlaneConfig>,
    /// 使用中の server_id 一覧（eBPF ルーティング用）
    pub active_server_ids: RwLock<HashSet<u32>>,
    /// デフォルト ACTIVE として指定された dp_id
    pub default_active_dp_id: RwLock<Option<String>>,
}

impl HttpIpcState {
    /// 新しい HttpIpcState を作成
    pub fn new() -> Self {
        Self {
            data_planes: RwLock::new(HashMap::new()),
            command_id_counter: AtomicU64::new(1),
            command_notify: Notify::new(),
            auth_policy: RwLock::new(None),
            dp_config: RwLock::new(DataPlaneConfig::default()),
            active_server_ids: RwLock::new(HashSet::new()),
            default_active_dp_id: RwLock::new(None),
        }
    }

    /// 次のコマンド ID を生成
    pub fn next_command_id(&self) -> String {
        let id = self.command_id_counter.fetch_add(1, Ordering::SeqCst);
        format!("cmd_{}", id)
    }

    /// データプレーンにコマンドを送信
    pub async fn send_command(
        &self,
        dp_id: &str,
        command: ControlCommand,
    ) -> Result<String, String> {
        let mut data_planes = self.data_planes.write().await;
        if let Some(dp) = data_planes.get_mut(dp_id) {
            let cmd_id = self.next_command_id();
            dp.pending_commands.push_back(CommandWithId {
                id: cmd_id.clone(),
                command,
            });
            // 長ポーリング中の DP に通知
            self.command_notify.notify_waiters();
            Ok(cmd_id)
        } else {
            Err(format!("Data plane not found: {}", dp_id))
        }
    }

    /// 全 ACTIVE データプレーンにコマンドを送信
    pub async fn broadcast_command(&self, command: ControlCommand) {
        let mut data_planes = self.data_planes.write().await;
        for (_, dp) in data_planes.iter_mut() {
            if dp.state == DataPlaneState::Active {
                let cmd_id = self.next_command_id();
                dp.pending_commands.push_back(CommandWithId {
                    id: cmd_id,
                    command: command.clone(),
                });
            }
        }
        self.command_notify.notify_waiters();
    }

    /// ACTIVE DP の中から最新のものをデフォルト ACTIVE として指示
    pub async fn update_default_active_dp(&self) {
        let candidate_dp_id = {
            let data_planes = self.data_planes.read().await;
            data_planes
                .values()
                .filter(|dp| dp.state == DataPlaneState::Active)
                .max_by_key(|dp| dp.last_active)
                .map(|dp| dp.dp_id.clone())
        };

        let current_dp_id = self.default_active_dp_id.read().await.clone();
        if candidate_dp_id == current_dp_id {
            return;
        }

        if let Some(dp_id) = candidate_dp_id.clone() {
            match self.send_command(&dp_id, ControlCommand::SetDefaultActive).await {
                Ok(_) => {
                    let mut current = self.default_active_dp_id.write().await;
                    *current = candidate_dp_id;
                    info!("Assigned default active DP: {}", dp_id);
                }
                Err(e) => {
                    warn!(
                        "Failed to assign default active DP (dp_id={}): {}",
                        dp_id, e
                    );
                }
            }
        } else {
            let mut current = self.default_active_dp_id.write().await;
            *current = None;
            info!("Cleared default active DP (no ACTIVE data planes)");
        }
    }

    /// 全データプレーンのペンディングコマンドが配信されるまで待機
    ///
    /// 指定されたタイムアウト内にすべてのコマンドが配信されなかった場合でも終了する
    pub async fn wait_for_commands_delivered(&self, timeout: Duration) {
        let start = std::time::Instant::now();
        let check_interval = Duration::from_millis(100);

        loop {
            // タイムアウトチェック
            if start.elapsed() >= timeout {
                let data_planes = self.data_planes.read().await;
                let pending_count: usize = data_planes
                    .values()
                    .map(|dp| dp.pending_commands.len())
                    .sum();
                if pending_count > 0 {
                    warn!(
                        "Timeout waiting for commands to be delivered, {} commands still pending",
                        pending_count
                    );
                }
                break;
            }

            // すべてのコマンドが配信されたかチェック
            let all_delivered = {
                let data_planes = self.data_planes.read().await;
                data_planes.values().all(|dp| dp.pending_commands.is_empty())
            };

            if all_delivered {
                info!("All commands delivered to data planes");
                break;
            }

            tokio::time::sleep(check_interval).await;
        }
    }

    /// 応答不能データプレーンを検出（削除はしない）
    ///
    /// `last_active` + `timeout_secs` < 現在時刻 の DP を応答不能と判定する。
    /// 実際の削除は eBPF map クリーンアップ成功後に `remove_data_planes()` で行う。
    ///
    /// # Returns
    ///
    /// 応答不能と判定された (dp_id, server_id) のリスト
    pub async fn detect_unresponsive_data_planes(
        &self,
        timeout_secs: u64,
    ) -> Vec<(String, u32)> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let data_planes = self.data_planes.read().await;
        data_planes
            .iter()
            .filter_map(|(dp_id, dp)| {
                if dp.last_active + timeout_secs < now {
                    dp.server_id.map(|sid| (dp_id.clone(), sid))
                } else {
                    None
                }
            })
            .collect()
    }

    /// 指定されたデータプレーンを `data_planes` および `active_server_ids` から削除
    ///
    /// eBPF map エントリの削除が成功した後に呼び出すことを想定。
    pub async fn remove_data_planes(&self, entries: &[(String, u32)]) {
        let mut data_planes = self.data_planes.write().await;
        let mut active_ids = self.active_server_ids.write().await;
        for (dp_id, server_id) in entries {
            data_planes.remove(dp_id);
            active_ids.remove(server_id);
            warn!(
                "Removed unresponsive data plane: dp_id={}, server_id={}",
                dp_id, server_id
            );
        }
    }
}

impl Default for HttpIpcState {
    fn default() -> Self {
        Self::new()
    }
}

/// 16 進数文字列の dp_id を u32 にパース
///
/// "0x3039" → 12345
/// "0X3039" → 12345
/// "3039"   → 12345 (0x プレフィックスは任意)
pub fn parse_hex_dp_id(s: &str) -> Result<u32, String> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u32::from_str_radix(s, 16).map_err(|e| format!("Invalid dp_id format: {}", e))
}

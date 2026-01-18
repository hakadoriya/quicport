//! コントロールプレーン実装
//!
//! データプレーンの管理、認証ポリシーの配布、グレースフルリスタートなどを担当します。
//!
//! ## 責務
//!
//! - プロセス管理: データプレーンの起動・グレースフルリスタート
//! - 認証ポリシー: PSK/X25519 認証情報の管理と配布
//! - 設定管理: 設定ファイルの読み込みと配布
//! - API サーバー: 管理用 REST API の提供
//! - モニタリング: 接続状態、メトリクスの収集

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::ipc::{
    discover_dataplanes, read_dataplane_port, read_dataplane_state, AuthPolicy, ControlCommand,
    DataPlaneConfig, DataPlaneEvent, DataPlaneState, DataPlaneStatus, IpcConnection,
};
use crate::statistics::ServerStatistics;

/// データプレーンの接続情報
struct DataPlaneConnection {
    /// PID
    #[allow(dead_code)]
    pid: u32,
    /// IPC 接続
    conn: Option<IpcConnection>,
    /// 最新の状態
    status: Option<DataPlaneStatus>,
}

/// コントロールプレーン
pub struct ControlPlane {
    /// QUIC リッスンアドレス
    listen_addr: SocketAddr,
    /// 認証ポリシー
    auth_policy: AuthPolicy,
    /// データプレーン設定
    #[allow(dead_code)]
    dp_config: DataPlaneConfig,
    /// 管理中のデータプレーン
    dataplanes: RwLock<HashMap<u32, DataPlaneConnection>>,
    /// 統計情報
    #[allow(dead_code)]
    statistics: Arc<ServerStatistics>,
    /// 実行ファイルパス
    executable_path: PathBuf,
}

impl ControlPlane {
    /// 新しいコントロールプレーンを作成
    pub fn new(
        listen_addr: SocketAddr,
        auth_policy: AuthPolicy,
        statistics: Arc<ServerStatistics>,
    ) -> Result<Arc<Self>> {
        let executable_path = std::env::current_exe()
            .context("Failed to get current executable path")?;

        let dp_config = DataPlaneConfig {
            listen_addr,
            ..Default::default()
        };

        Ok(Arc::new(Self {
            listen_addr,
            auth_policy,
            dp_config,
            dataplanes: RwLock::new(HashMap::new()),
            statistics,
            executable_path,
        }))
    }

    /// コントロールプレーンを起動
    ///
    /// 1. 既存のデータプレーンを検出して接続
    /// 2. ACTIVE なデータプレーンがなければ新規起動
    /// 3. 認証ポリシーを配布
    pub async fn start(self: Arc<Self>) -> Result<()> {
        info!("Control plane starting");

        // 既存のデータプレーンを検出
        let existing_pids = discover_dataplanes()?;
        info!("Discovered {} existing data plane(s)", existing_pids.len());

        let mut has_active = false;

        for pid in existing_pids {
            match self.connect_to_dataplane(pid).await {
                Ok(status) => {
                    info!(
                        "Connected to data plane PID {} (state: {})",
                        pid, status.state
                    );
                    if status.state == DataPlaneState::Active {
                        has_active = true;
                    }
                }
                Err(e) => {
                    warn!("Failed to connect to data plane PID {}: {}", pid, e);
                    // 接続できないデータプレーンはクリーンアップ
                    let _ = crate::ipc::cleanup_dataplane_files(pid);
                }
            }
        }

        // ACTIVE なデータプレーンがなければ新規起動
        if !has_active {
            info!("No active data plane found, starting new one");
            self.start_dataplane().await?;
        }

        // 全データプレーンに認証ポリシーを配布
        self.distribute_auth_policy().await?;

        info!("Control plane started successfully");
        Ok(())
    }

    /// データプレーンに接続
    async fn connect_to_dataplane(&self, pid: u32) -> Result<DataPlaneStatus> {
        let port = read_dataplane_port(pid)
            .with_context(|| format!("Failed to read port for data plane PID {}", pid))?;

        let mut conn = IpcConnection::connect(port)
            .await
            .with_context(|| format!("Failed to connect to data plane PID {} on port {}", pid, port))?;

        // Ready イベントを受信
        let event = conn.recv_event().await?;
        let status = match event {
            DataPlaneEvent::Ready { pid: dp_pid, listen_addr } => {
                debug!("Data plane PID {} is ready on {}", dp_pid, listen_addr);
                // 状態を取得
                conn.send_command(&ControlCommand::GetStatus).await?;
                match conn.recv_event().await? {
                    DataPlaneEvent::Status(s) => s,
                    _ => {
                        return Err(anyhow::anyhow!("Unexpected response from data plane"));
                    }
                }
            }
            DataPlaneEvent::Status(s) => s,
            _ => {
                return Err(anyhow::anyhow!("Unexpected event from data plane: {:?}", event));
            }
        };

        // 接続を保存
        let mut dataplanes = self.dataplanes.write().await;
        dataplanes.insert(
            pid,
            DataPlaneConnection {
                pid,
                conn: Some(conn),
                status: Some(status.clone()),
            },
        );

        Ok(status)
    }

    /// 新しいデータプレーンを起動
    ///
    /// setsid() で独立したセッションとして起動し、
    /// 親プロセス（コントロールプレーン）の終了に影響されないようにします。
    pub async fn start_dataplane(&self) -> Result<u32> {
        info!("Starting new data plane process");

        #[cfg(unix)]
        {
            // CommandExt provides pre_exec method for tokio::process::Command
            #[allow(unused_imports)]
            use std::os::unix::process::CommandExt;

            // 認証ポリシーを環境変数経由で渡す
            let mut cmd = Command::new(&self.executable_path);
            cmd.arg("data-plane")
                .arg("--listen")
                .arg(self.listen_addr.to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit());

            match &self.auth_policy {
                AuthPolicy::Psk { psk } => {
                    cmd.env("QUICPORT_DP_AUTH_TYPE", "psk");
                    cmd.env("QUICPORT_DP_PSK", psk);
                }
                AuthPolicy::X25519 {
                    authorized_pubkeys,
                    server_private_key,
                } => {
                    cmd.env("QUICPORT_DP_AUTH_TYPE", "x25519");
                    cmd.env("QUICPORT_DP_SERVER_PRIVKEY", server_private_key);
                    cmd.env("QUICPORT_DP_CLIENT_PUBKEYS", authorized_pubkeys.join(","));
                }
            }

            // setsid() を使用して独立したプロセスグループを作成
            // これにより親プロセス終了後もデータプレーンは動作し続ける
            unsafe {
                cmd.pre_exec(|| {
                    libc::setsid();
                    Ok(())
                });
            }

            let child = cmd.spawn().context("Failed to spawn data plane process")?;
            let pid = child.id().ok_or_else(|| anyhow::anyhow!("Failed to get child PID"))?;

            info!("Data plane process started with PID {}", pid);

            // プロセスが起動するまで少し待つ
            tokio::time::sleep(Duration::from_millis(500)).await;

            // 接続を試みる
            let mut retries = 0;
            let max_retries = 10;
            loop {
                match self.connect_to_dataplane(pid).await {
                    Ok(status) => {
                        info!("Connected to new data plane PID {} (state: {})", pid, status.state);
                        return Ok(pid);
                    }
                    Err(e) => {
                        retries += 1;
                        if retries >= max_retries {
                            return Err(anyhow::anyhow!(
                                "Failed to connect to data plane after {} retries: {}",
                                max_retries,
                                e
                            ));
                        }
                        debug!("Waiting for data plane to start (attempt {}/{})", retries, max_retries);
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            }
        }

        #[cfg(not(unix))]
        {
            Err(anyhow::anyhow!("Data plane process management is only supported on Unix"))
        }
    }

    /// 認証ポリシーを全データプレーンに配布
    pub async fn distribute_auth_policy(&self) -> Result<()> {
        let cmd = ControlCommand::SetAuthPolicy(self.auth_policy.clone());

        let mut dataplanes = self.dataplanes.write().await;
        for (pid, dp) in dataplanes.iter_mut() {
            if let Some(conn) = &mut dp.conn {
                match conn.send_command(&cmd).await {
                    Ok(_) => {
                        debug!("Auth policy sent to data plane PID {}", pid);
                        // 応答を受信
                        match conn.recv_event().await {
                            Ok(DataPlaneEvent::Status(status)) => {
                                dp.status = Some(status);
                            }
                            Ok(_) => {}
                            Err(e) => {
                                warn!("Failed to receive response from data plane {}: {}", pid, e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to send auth policy to data plane {}: {}", pid, e);
                    }
                }
            }
        }

        Ok(())
    }

    /// グレースフルリスタートを実行
    ///
    /// 1. 新しいデータプレーンを起動
    /// 2. 旧データプレーンに DRAIN を送信
    pub async fn graceful_restart(&self) -> Result<()> {
        info!("Starting graceful restart");

        // 現在の ACTIVE なデータプレーンを取得
        let old_pids: Vec<u32> = {
            let dataplanes = self.dataplanes.read().await;
            dataplanes
                .iter()
                .filter_map(|(pid, dp)| {
                    if dp.status.as_ref().map(|s| s.state) == Some(DataPlaneState::Active) {
                        Some(*pid)
                    } else {
                        None
                    }
                })
                .collect()
        };

        // 新しいデータプレーンを起動
        let new_pid = self.start_dataplane().await?;
        info!("New data plane started with PID {}", new_pid);

        // 認証ポリシーを配布
        self.distribute_auth_policy().await?;

        // 旧データプレーンに DRAIN を送信
        for old_pid in old_pids {
            if let Err(e) = self.drain_dataplane(old_pid).await {
                warn!("Failed to drain data plane PID {}: {}", old_pid, e);
            }
        }

        info!("Graceful restart completed");
        Ok(())
    }

    /// データプレーンをドレイン
    pub async fn drain_dataplane(&self, pid: u32) -> Result<()> {
        info!("Draining data plane PID {}", pid);

        let mut dataplanes = self.dataplanes.write().await;
        if let Some(dp) = dataplanes.get_mut(&pid) {
            if let Some(conn) = &mut dp.conn {
                conn.send_command(&ControlCommand::Drain).await?;
                // 応答を受信
                match conn.recv_event().await {
                    Ok(DataPlaneEvent::Status(status)) => {
                        info!("Data plane PID {} is now {}", pid, status.state);
                        dp.status = Some(status);
                    }
                    Ok(_) => {}
                    Err(e) => {
                        warn!("Failed to receive response from data plane {}: {}", pid, e);
                    }
                }
            }
        }

        Ok(())
    }

    /// データプレーンをシャットダウン
    #[allow(dead_code)]
    pub async fn shutdown_dataplane(&self, pid: u32) -> Result<()> {
        info!("Shutting down data plane PID {}", pid);

        let mut dataplanes = self.dataplanes.write().await;
        if let Some(dp) = dataplanes.get_mut(&pid) {
            if let Some(conn) = &mut dp.conn {
                conn.send_command(&ControlCommand::Shutdown).await?;
            }
            dataplanes.remove(&pid);
        }

        Ok(())
    }

    /// 全データプレーンをドレインして終了を待機
    pub async fn shutdown_all(&self) -> Result<()> {
        info!("Shutting down all data planes");

        // 全データプレーンに DRAIN を送信
        let pids: Vec<u32> = {
            let dataplanes = self.dataplanes.read().await;
            dataplanes.keys().copied().collect()
        };

        for pid in pids {
            if let Err(e) = self.drain_dataplane(pid).await {
                warn!("Failed to drain data plane PID {}: {}", pid, e);
            }
        }

        Ok(())
    }

    /// 全データプレーンの状態を取得
    #[allow(dead_code)]
    pub async fn get_all_status(&self) -> Vec<DataPlaneStatus> {
        let mut statuses = Vec::new();

        // まず、接続済みのデータプレーンから状態を取得
        {
            let mut dataplanes = self.dataplanes.write().await;
            for (pid, dp) in dataplanes.iter_mut() {
                if let Some(conn) = &mut dp.conn {
                    if conn.send_command(&ControlCommand::GetStatus).await.is_ok() {
                        if let Ok(DataPlaneEvent::Status(status)) = conn.recv_event().await {
                            dp.status = Some(status.clone());
                            statuses.push(status);
                            continue;
                        }
                    }
                }
                // IPC 接続に失敗した場合は状態ファイルから読み取る
                if let Ok(status) = read_dataplane_state(*pid) {
                    statuses.push(status);
                }
            }
        }

        statuses
    }
}

/// コントロールプレーンを起動（ユーティリティ関数）
pub async fn run(
    listen_addr: SocketAddr,
    auth_policy: AuthPolicy,
    statistics: Arc<ServerStatistics>,
) -> Result<()> {
    let control_plane = ControlPlane::new(listen_addr, auth_policy, statistics)?;
    let cp_for_shutdown = control_plane.clone();
    control_plane.start().await?;

    // 終了シグナルを待機
    tokio::signal::ctrl_c().await?;

    info!("Received shutdown signal");
    cp_for_shutdown.shutdown_all().await?;

    Ok(())
}

/// グレースフルリスタートを実行（CLI コマンド用）
pub async fn graceful_restart() -> Result<()> {
    info!("Executing graceful restart command");

    // 既存のデータプレーンを検出
    let pids = discover_dataplanes()?;
    if pids.is_empty() {
        return Err(anyhow::anyhow!("No running data planes found"));
    }

    // 全ての ACTIVE なデータプレーンに DRAIN を送信
    for pid in pids {
        let port = match read_dataplane_port(pid) {
            Ok(p) => p,
            Err(e) => {
                warn!("Failed to read port for data plane PID {}: {}", pid, e);
                continue;
            }
        };
        match IpcConnection::connect(port).await {
            Ok(mut conn) => {
                // Ready イベントをスキップ
                let _ = conn.recv_event().await;

                // DRAIN を送信
                if let Err(e) = conn.send_command(&ControlCommand::Drain).await {
                    warn!("Failed to send DRAIN to data plane PID {}: {}", pid, e);
                } else {
                    info!("Sent DRAIN to data plane PID {}", pid);
                }
            }
            Err(e) => {
                warn!("Failed to connect to data plane PID {}: {}", pid, e);
            }
        }
    }

    info!("Graceful restart command completed");
    Ok(())
}

/// データプレーンの状態を表示（CLI コマンド用）
pub async fn show_status() -> Result<()> {
    let pids = discover_dataplanes()?;
    if pids.is_empty() {
        println!("No running data planes found");
        return Ok(());
    }

    println!("Data Planes:");
    println!("{:<10} {:<12} {:<12} {:<15} {:<15}", "PID", "State", "Connections", "Bytes Sent", "Bytes Received");
    println!("{}", "-".repeat(64));

    for pid in pids {
        match read_dataplane_state(pid) {
            Ok(status) => {
                println!(
                    "{:<10} {:<12} {:<12} {:<15} {:<15}",
                    status.pid,
                    status.state.to_string(),
                    status.active_connections,
                    status.bytes_sent,
                    status.bytes_received
                );
            }
            Err(e) => {
                println!("{:<10} (error: {})", pid, e);
            }
        }
    }

    Ok(())
}

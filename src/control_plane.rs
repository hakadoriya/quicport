//! コントロールプレーン実装
//!
//! データプレーンの管理、認証ポリシーの配布などを担当します。
//!
//! ## 責務
//!
//! - プロセス管理: データプレーンの起動・管理
//! - 認証ポリシー: PSK/X25519 認証情報の管理と配布
//! - 設定管理: コマンドライン引数からの設定構築と配布（設定ファイルは未対応）
//! - API サーバー: 管理用 REST API + HTTP IPC API の提供
//! - モニタリング: 接続状態、メトリクスの収集

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use tracing::{debug, info, warn, Instrument};

use crate::api::{run_private_with_http_ipc, HttpIpcState};
use crate::ipc::{AuthPolicy, ControlCommand, DataPlaneConfig, DataPlaneStatus};
use crate::statistics::ServerStatistics;

/// コントロールプレーン
pub struct ControlPlane {
    /// コントロールプレーン HTTP IPC アドレス
    cp_addr: SocketAddr,
    /// データプレーン QUIC リッスンアドレス
    dp_listen_addr: SocketAddr,
    /// 認証ポリシー
    auth_policy: AuthPolicy,
    /// データプレーン設定
    #[allow(dead_code)]
    dp_config: DataPlaneConfig,
    /// 統計情報
    #[allow(dead_code)]
    statistics: Arc<ServerStatistics>,
    /// 実行ファイルパス
    executable_path: PathBuf,
    /// HTTP IPC 状態
    http_ipc: Arc<HttpIpcState>,
    /// ログ出力形式（data-plane に継承させる）
    log_format: String,
    /// ログ出力先（data-plane に継承させる）
    log_output: Option<PathBuf>,
}

impl ControlPlane {
    /// 新しいコントロールプレーンを作成
    pub fn new(
        cp_addr: SocketAddr,
        dp_listen_addr: SocketAddr,
        auth_policy: AuthPolicy,
        statistics: Arc<ServerStatistics>,
        http_ipc: Arc<HttpIpcState>,
        log_format: String,
        log_output: Option<PathBuf>,
    ) -> Result<Arc<Self>> {
        let executable_path =
            std::env::current_exe().context("Failed to get current executable path")?;

        let dp_config = DataPlaneConfig {
            listen_addr: dp_listen_addr,
            ..Default::default()
        };

        Ok(Arc::new(Self {
            cp_addr,
            dp_listen_addr,
            auth_policy,
            dp_config,
            statistics,
            executable_path,
            http_ipc,
            log_format,
            log_output,
        }))
    }

    /// HTTP IPC 状態を取得
    pub fn http_ipc(&self) -> Arc<HttpIpcState> {
        self.http_ipc.clone()
    }

    /// コントロールプレーンを起動
    ///
    /// 認証ポリシーを HttpIpcState に設定
    pub async fn start(self: Arc<Self>) -> Result<()> {
        info!("Control plane starting");

        // 認証ポリシーを HttpIpcState に設定
        *self.http_ipc.auth_policy.write().await = Some(self.auth_policy.clone());
        *self.http_ipc.dp_config.write().await = self.dp_config.clone();

        info!("Control plane started successfully");
        Ok(())
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

            let mut cmd = Command::new(&self.executable_path);
            cmd.arg("--log-format")
                .arg(&self.log_format);
            // CP に --log-output が指定されている場合、DP にも継承する
            if let Some(ref log_output) = self.log_output {
                cmd.arg("--log-output").arg(log_output);
            }
            cmd.arg("data-plane")
                .arg("--data-plane-addr")
                .arg(self.dp_listen_addr.to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());

            // HTTP IPC: --control-plane-url を使用
            let cp_url = format!("http://127.0.0.1:{}", self.cp_addr.port());
            cmd.arg("--control-plane-url").arg(&cp_url);
            info!("Data plane will connect to control plane at {}", cp_url);

            // setsid() を使用して独立したプロセスグループを作成
            // これにより親プロセス終了後もデータプレーンは動作し続ける
            unsafe {
                cmd.pre_exec(|| {
                    libc::setsid();
                    Ok(())
                });
            }

            let child = cmd.spawn().context("Failed to spawn data plane process")?;
            let pid = child
                .id()
                .ok_or_else(|| anyhow::anyhow!("Failed to get child PID"))?;

            info!("Data plane process started with PID {}", pid);

            // プロセスが起動するまで少し待つ
            tokio::time::sleep(Duration::from_millis(500)).await;

            // データプレーンの登録を待つ（PID で検索）
            // DP は自ら dp_id を採番し hex 形式（例: "0x3039"）で CP に登録するため、
            // PID をキーにして dataplanes マップから登録済みの DP を検索する
            let mut retries = 0;
            let max_retries = 20; // 10秒
            loop {
                {
                    let dataplanes = self.http_ipc.dataplanes.read().await;
                    if let Some((dp_id, _)) =
                        dataplanes.iter().find(|(_, dp)| dp.pid == pid)
                    {
                        info!(
                            "Data plane {} (PID={}) registered via HTTP IPC",
                            dp_id, pid
                        );
                        return Ok(pid);
                    }
                }
                retries += 1;
                if retries >= max_retries {
                    return Err(anyhow::anyhow!(
                        "Data plane (PID={}) did not register within {} retries",
                        pid,
                        max_retries
                    ));
                }
                debug!(
                    "Waiting for data plane (PID={}) to register (attempt {}/{})",
                    pid, retries, max_retries
                );
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }

        #[cfg(not(unix))]
        {
            Err(anyhow::anyhow!(
                "Data plane process management is only supported on Unix"
            ))
        }
    }

    /// 認証ポリシーを全データプレーンに配布
    #[allow(dead_code)]
    pub async fn distribute_auth_policy(&self) -> Result<()> {
        // HTTP IPC モード: 認証ポリシーは HttpIpcState に既に設定されている
        // データプレーンは RegisterDataPlane 時に取得する
        self.http_ipc
            .broadcast_command(ControlCommand::SetAuthPolicy(self.auth_policy.clone()))
            .await;
        Ok(())
    }

    /// データプレーンをドレイン
    pub async fn drain_dataplane(&self, pid: u32) -> Result<()> {
        info!("Draining data plane PID {}", pid);

        let dp_id = format!("dp_{}", pid);
        self.http_ipc
            .send_command(&dp_id, ControlCommand::Drain)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        Ok(())
    }

    /// 全データプレーンの接続情報を取得
    pub async fn get_all_connections(&self) -> Vec<crate::ipc::ConnectionInfo> {
        let mut all_connections = Vec::new();

        let dataplanes = self.http_ipc.dataplanes.read().await;
        for dp in dataplanes.values() {
            all_connections.extend(dp.connections.clone());
        }

        all_connections
    }

    /// データプレーンをシャットダウン
    #[allow(dead_code)]
    pub async fn shutdown_dataplane(&self, pid: u32) -> Result<()> {
        info!("Shutting down data plane PID {}", pid);

        let dp_id = format!("dp_{}", pid);
        self.http_ipc
            .send_command(&dp_id, ControlCommand::Shutdown)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        Ok(())
    }

    /// 全データプレーンをドレインして終了を待機
    pub async fn shutdown_all(&self) -> Result<()> {
        info!("Shutting down all data planes");

        self.http_ipc.broadcast_command(ControlCommand::Drain).await;
        // data-plane がコマンドを受け取るまで待機
        // 長ポーリングは notify_waiters() で即座に起こされるが、
        // HTTP レスポンスが完了するまで少し待機する
        self.http_ipc
            .wait_for_commands_delivered(std::time::Duration::from_secs(5))
            .await;
        Ok(())
    }

    /// 全データプレーンの状態を取得
    #[allow(dead_code)]
    pub async fn get_all_status(&self) -> Vec<DataPlaneStatus> {
        let mut statuses = Vec::new();

        let dataplanes = self.http_ipc.dataplanes.read().await;
        for dp in dataplanes.values() {
            statuses.push(DataPlaneStatus {
                state: dp.state,
                pid: dp.pid,
                active_connections: dp.active_connections,
                bytes_sent: dp.bytes_sent,
                bytes_received: dp.bytes_received,
                started_at: dp.started_at,
            });
        }

        statuses
    }

    /// stale データプレーンのクリーンアップタスクを起動
    ///
    /// バックグラウンドで 60 秒ごとに stale DP を検出する。
    /// Linux 環境では eBPF map エントリの削除を先に行い、成功した場合のみ
    /// `dataplanes` / `active_server_ids` から削除する。
    /// 非 Linux 環境では eBPF map 操作なしで直接 dataplanes から削除する。
    pub fn start_stale_cleanup_task(self: Arc<Self>) {
        let check_interval = Duration::from_secs(10);

        tokio::spawn(async move {
            info!("Stale data plane cleanup task started (interval=10s)");
            loop {
                tokio::time::sleep(check_interval).await;

                // stale DP のタイムアウト値を設定から取得
                let timeout_secs = {
                    let config = self.http_ipc.dp_config.read().await;
                    config.stale_dp_timeout
                };

                let stale_entries = self.http_ipc.detect_stale_dataplanes(timeout_secs).await;

                if stale_entries.is_empty() {
                    debug!("No stale data planes detected");
                    continue;
                }

                info!(
                    "Detected {} stale data plane(s), cleaning up",
                    stale_entries.len()
                );

                // eBPF map 削除成功後に dataplanes から削除するエントリを収集
                let mut entries_to_remove: Vec<(String, u32)> = Vec::new();

                // Linux 環境では eBPF map からエントリを削除し、成功したもののみ
                // dataplanes から削除する
                #[cfg(target_os = "linux")]
                {
                    use std::path::Path;
                    let ebpf_pin_path = Path::new("/sys/fs/bpf/quicport");
                    for (dp_id, server_id) in &stale_entries {
                        match crate::platform::linux::ebpf_router::cleanup_stale_entry(
                            ebpf_pin_path,
                            *server_id,
                        ) {
                            Ok(()) => {
                                info!(
                                    "Cleaned up eBPF map entry for stale DP: dp_id={}, server_id={}",
                                    dp_id, server_id
                                );
                                entries_to_remove.push((dp_id.clone(), *server_id));
                            }
                            Err(e) => {
                                warn!(
                                    "Failed to cleanup eBPF map entry for stale DP: dp_id={}, server_id={}, error={}. \
                                     Will retry on next cycle.",
                                    dp_id, server_id, e
                                );
                                // eBPF map 削除に失敗した場合は dataplanes から削除しない
                                // 次のサイクルでリトライされる
                            }
                        }
                    }
                }

                // 非 Linux 環境では eBPF map がないため、そのまま全て削除対象
                #[cfg(not(target_os = "linux"))]
                {
                    for (dp_id, server_id) in &stale_entries {
                        warn!(
                            "Stale DP detected (non-Linux, no eBPF cleanup): dp_id={}, server_id={}",
                            dp_id, server_id
                        );
                        entries_to_remove.push((dp_id.clone(), *server_id));
                    }
                }

                // eBPF map 削除が成功したエントリのみ dataplanes から削除
                if !entries_to_remove.is_empty() {
                    self.http_ipc.remove_dataplanes(&entries_to_remove).await;
                }

                // ACTIVE な DP が 1 つも存在しない場合、key=0（デフォルト ACTIVE DP）も削除
                // key=0 が stale なソケットを指し続けることを防ぐ
                #[cfg(target_os = "linux")]
                {
                    use crate::ipc::DataPlaneState;
                    use std::path::Path;

                    let dataplanes = self.http_ipc.dataplanes.read().await;
                    let has_active_dp = dataplanes
                        .values()
                        .any(|dp| dp.state == DataPlaneState::Active);

                    if !has_active_dp {
                        let ebpf_pin_path = Path::new("/sys/fs/bpf/quicport");
                        match crate::platform::linux::ebpf_router::cleanup_stale_entry(
                            ebpf_pin_path,
                            0, // key=0: デフォルト ACTIVE DP
                        ) {
                            Ok(()) => {
                                info!(
                                    "Cleaned up default active DP (key=0) from eBPF map (no ACTIVE DP exists)"
                                );
                            }
                            Err(e) => {
                                debug!(
                                    "Failed to cleanup default active DP (key=0): {} (may already be removed)",
                                    e
                                );
                            }
                        }
                    }
                }
            }
        });
    }
}

/// API サーバー設定
pub struct ApiConfig {
    /// Public API アドレス（/healthcheck のみ、インターネットから見える）
    pub public_addr: Option<SocketAddr>,
    /// Private API アドレス（/metrics, HTTP IPC、localhost のみ）
    pub private_addr: SocketAddr,
}

/// コントロールプレーンを起動（API サーバー付き、HTTP IPC モード）
pub async fn run_with_api(
    cp_addr: SocketAddr,
    dp_listen_addr: SocketAddr,
    auth_policy: AuthPolicy,
    statistics: Arc<ServerStatistics>,
    api_config: Option<ApiConfig>,
    skip_dataplane_start: bool,
    log_format: String,
    log_output: Option<PathBuf>,
    quic_keep_alive_secs: u64,
    quic_idle_timeout_secs: u64,
) -> Result<()> {
    // HTTP IPC 状態を作成（API サーバーと ControlPlane で共有）
    let http_ipc = Arc::new(HttpIpcState::new());

    // 認証ポリシーと設定を HttpIpcState に設定
    *http_ipc.auth_policy.write().await = Some(auth_policy.clone());
    {
        let mut config = http_ipc.dp_config.write().await;
        config.listen_addr = dp_listen_addr;
        config.quic_keep_alive_secs = quic_keep_alive_secs;
        config.quic_idle_timeout_secs = quic_idle_timeout_secs;
    }

    let control_plane = ControlPlane::new(
        cp_addr,
        dp_listen_addr,
        auth_policy,
        statistics.clone(),
        http_ipc.clone(),
        log_format,
        log_output,
    )?;
    let cp_for_shutdown = control_plane.clone();
    let cp_for_api = control_plane.clone();

    // API サーバーを起動
    let mut api_handles = Vec::new();

    if let Some(config) = api_config {
        // Public API サーバー（/healthcheck のみ）
        if let Some(public_addr) = config.public_addr {
            api_handles.push(tokio::spawn(
                async move { crate::api::run_public(public_addr).await }
                    .instrument(tracing::Span::current()),
            ));
        }

        // Private API サーバー（/metrics, HTTP IPC）
        let private_addr = config.private_addr;
        let stats_for_api = statistics.clone();
        let http_ipc_for_api = http_ipc.clone();
        api_handles.push(tokio::spawn(
            async move {
                run_private_with_http_ipc(
                    private_addr,
                    stats_for_api,
                    Some(cp_for_api),
                    http_ipc_for_api,
                )
                .await
            }
            .instrument(tracing::Span::current()),
        ));
    }

    // Control Plane を起動
    let cp_for_dataplane = control_plane.clone();
    let cp_for_cleanup = control_plane.clone();
    control_plane.start().await?;

    // stale DP クリーンアップタスクを起動
    cp_for_cleanup.start_stale_cleanup_task();

    // API サーバーが起動するのを待つ
    tokio::time::sleep(Duration::from_millis(100)).await;

    // データプレーンを起動（skip_dataplane_start が false の場合のみ）
    if !skip_dataplane_start {
        cp_for_dataplane.start_dataplane().await?;
    } else {
        info!("Skipping automatic data plane startup (--no-auto-dataplane)");
    }

    // 終了シグナルを待機
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm =
            signal(SignalKind::terminate()).context("Failed to create SIGTERM handler")?;

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Received SIGINT");
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM");
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        info!("Received SIGINT");
    }

    info!("Shutting down control plane");

    // API サーバーを停止
    for handle in api_handles {
        handle.abort();
    }

    cp_for_shutdown.shutdown_all().await?;

    Ok(())
}

/// データプレーンの状態を表示（CLI コマンド用）
///
/// HTTP API 経由でデータプレーン一覧を取得して表示します。
pub async fn show_status(api_addr: SocketAddr) -> Result<()> {
    let url = format!("http://{}{}", api_addr, crate::ipc::api_paths::LIST_DATA_PLANES);
    let client = reqwest::Client::new();

    let response = client
        .post(&url)
        .json(&crate::ipc::ListDataPlanesRequest {})
        .send()
        .await
        .with_context(|| format!("Failed to connect to API server at {}", api_addr))?;

    let status = response.status();
    if !status.is_success() {
        return Err(anyhow::anyhow!(
            "API request failed with status: {}",
            status
        ));
    }

    let body: crate::ipc::ListDataPlanesResponse = response
        .json()
        .await
        .context("Failed to parse API response")?;

    if body.dataplanes.is_empty() {
        println!("No running data planes found");
        return Ok(());
    }

    println!("Data Planes:");
    println!(
        "{:<15} {:<10} {:<12} {:<12} {:<15} {:<15}",
        "ID", "PID", "State", "Connections", "Bytes Sent", "Bytes Received"
    );
    println!("{}", "-".repeat(79));

    for dp in body.dataplanes {
        println!(
            "{:<15} {:<10} {:<12} {:<12} {:<15} {:<15}",
            dp.dp_id,
            dp.pid,
            dp.state.to_string(),
            dp.active_connections,
            dp.bytes_sent,
            dp.bytes_received
        );
    }

    Ok(())
}

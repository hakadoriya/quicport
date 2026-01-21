//! コントロールプレーン実装
//!
//! データプレーンの管理、認証ポリシーの配布、グレースフルリスタートなどを担当します。
//!
//! ## 責務
//!
//! - プロセス管理: データプレーンの起動・グレースフルリスタート
//! - 認証ポリシー: PSK/X25519 認証情報の管理と配布
//! - 設定管理: 設定ファイルの読み込みと配布
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
use crate::ipc::{AuthPolicy, ControlCommand, DataPlaneConfig, DataPlaneState, DataPlaneStatus};
use crate::statistics::ServerStatistics;

/// コントロールプレーン
pub struct ControlPlane {
    /// QUIC リッスンアドレス
    listen_addr: SocketAddr,
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
}

impl ControlPlane {
    /// 新しいコントロールプレーンを作成
    pub fn new(
        listen_addr: SocketAddr,
        auth_policy: AuthPolicy,
        statistics: Arc<ServerStatistics>,
        http_ipc: Arc<HttpIpcState>,
    ) -> Result<Arc<Self>> {
        let executable_path =
            std::env::current_exe().context("Failed to get current executable path")?;

        let dp_config = DataPlaneConfig {
            listen_addr,
            ..Default::default()
        };

        Ok(Arc::new(Self {
            listen_addr,
            auth_policy,
            dp_config,
            statistics,
            executable_path,
            http_ipc,
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
            cmd.arg("data-plane")
                .arg("--listen")
                .arg(self.listen_addr.to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit());

            // HTTP IPC: --control-plane-url を使用
            let cp_url = format!("http://127.0.0.1:{}", self.listen_addr.port());
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

            // データプレーンの登録を待つ
            let mut retries = 0;
            let max_retries = 20; // 10秒
            let dp_id = format!("dp_{}", pid);
            loop {
                {
                    let dataplanes = self.http_ipc.dataplanes.read().await;
                    if dataplanes.contains_key(&dp_id) {
                        info!("Data plane {} registered via HTTP IPC", dp_id);
                        return Ok(pid);
                    }
                }
                retries += 1;
                if retries >= max_retries {
                    return Err(anyhow::anyhow!(
                        "Data plane {} did not register within {} retries",
                        dp_id,
                        max_retries
                    ));
                }
                debug!(
                    "Waiting for data plane {} to register (attempt {}/{})",
                    dp_id, retries, max_retries
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
    pub async fn distribute_auth_policy(&self) -> Result<()> {
        // HTTP IPC モード: 認証ポリシーは HttpIpcState に既に設定されている
        // データプレーンは RegisterDataPlane 時に取得する
        self.http_ipc
            .broadcast_command(ControlCommand::SetAuthPolicy(self.auth_policy.clone()))
            .await;
        Ok(())
    }

    /// グレースフルリスタートを実行
    ///
    /// 1. 新しいデータプレーンを起動
    /// 2. 旧データプレーンに DRAIN を送信
    pub async fn graceful_restart(&self) -> Result<()> {
        info!("Starting graceful restart");

        // 現在の ACTIVE な DP を取得
        let old_dp_ids: Vec<String> = {
            let dataplanes = self.http_ipc.dataplanes.read().await;
            dataplanes
                .iter()
                .filter_map(|(dp_id, dp)| {
                    if dp.state == DataPlaneState::Active {
                        Some(dp_id.clone())
                    } else {
                        None
                    }
                })
                .collect()
        };

        // 新しいデータプレーンを起動
        let new_pid = self.start_dataplane().await?;
        info!("New data plane started with PID {}", new_pid);

        // 旧データプレーンに DRAIN を送信
        for dp_id in old_dp_ids {
            if let Err(e) = self
                .http_ipc
                .send_command(&dp_id, ControlCommand::Drain)
                .await
            {
                warn!("Failed to drain data plane {}: {}", dp_id, e);
            }
        }

        info!("Graceful restart completed");
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
}

/// API サーバー設定
pub struct ApiConfig {
    /// Public API アドレス（/healthcheck のみ、インターネットから見える）
    pub public_addr: Option<SocketAddr>,
    /// Private API アドレス（/metrics, /graceful-restart、localhost のみ）
    pub private_addr: Option<SocketAddr>,
}

/// コントロールプレーンを起動（API サーバー付き、HTTP IPC モード）
pub async fn run_with_api(
    listen_addr: SocketAddr,
    auth_policy: AuthPolicy,
    statistics: Arc<ServerStatistics>,
    api_config: Option<ApiConfig>,
    skip_dataplane_start: bool,
) -> Result<()> {
    // HTTP IPC 状態を作成（API サーバーと ControlPlane で共有）
    let http_ipc = Arc::new(HttpIpcState::new());

    // 認証ポリシーと設定を HttpIpcState に設定
    *http_ipc.auth_policy.write().await = Some(auth_policy.clone());
    {
        let mut config = http_ipc.dp_config.write().await;
        config.listen_addr = listen_addr;
    }

    // Private API がない場合は HTTP IPC を使用できないため、
    // 内部的に HTTP IPC サーバーを起動する
    let has_private_api = api_config
        .as_ref()
        .map_or(false, |c| c.private_addr.is_some());

    // HTTP IPC 用の内部 API アドレスを決定
    // Private API が有効な場合はそれを使用、そうでなければ localhost でリッスン
    let internal_http_ipc_addr = if has_private_api {
        None // Private API が HTTP IPC を提供
    } else {
        // Private API がない場合は内部的に HTTP IPC サーバーを起動
        Some(SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            listen_addr.port(),
        ))
    };

    let control_plane = ControlPlane::new(
        listen_addr,
        auth_policy,
        statistics.clone(),
        http_ipc.clone(),
    )?;
    let cp_for_shutdown = control_plane.clone();
    let cp_for_api = control_plane.clone();

    // API サーバーを起動
    let mut api_handles = Vec::new();

    // 内部 HTTP IPC サーバーを起動（Private API がない場合）
    if let Some(internal_addr) = internal_http_ipc_addr {
        let stats_for_internal = statistics.clone();
        let http_ipc_for_internal = http_ipc.clone();
        let cp_for_internal = control_plane.clone();
        api_handles.push(tokio::spawn(
            async move {
                run_private_with_http_ipc(
                    internal_addr,
                    stats_for_internal,
                    Some(cp_for_internal),
                    http_ipc_for_internal,
                )
                .await
            }
            .instrument(tracing::Span::current()),
        ));
        info!("Internal HTTP IPC server started on {}", internal_addr);
    }

    if let Some(config) = api_config {
        // Public API サーバー（/healthcheck のみ）
        if let Some(public_addr) = config.public_addr {
            api_handles.push(tokio::spawn(
                async move { crate::api::run_public(public_addr).await }
                    .instrument(tracing::Span::current()),
            ));
        }

        // Private API サーバー（/metrics, /graceful-restart, HTTP IPC）
        if let Some(private_addr) = config.private_addr {
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
    }

    // Control Plane を起動
    let cp_for_dataplane = control_plane.clone();
    control_plane.start().await?;

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

/// グレースフルリスタートを実行（CLI コマンド用）
///
/// API サーバーの /api/graceful-restart エンドポイントを呼び出して、
/// control-plane に graceful restart を実行させます。
pub async fn graceful_restart(api_addr: SocketAddr) -> Result<()> {
    info!("Executing graceful restart command via API");

    let url = format!("http://{}/api/graceful-restart", api_addr);
    let client = reqwest::Client::new();

    let response = client
        .post(&url)
        .send()
        .await
        .with_context(|| format!("Failed to connect to API server at {}", api_addr))?;

    let status = response.status();
    let body: serde_json::Value = response
        .json()
        .await
        .context("Failed to parse API response")?;

    if status.is_success() {
        info!(
            "Graceful restart initiated: {}",
            body.get("message").and_then(|v| v.as_str()).unwrap_or("")
        );
        Ok(())
    } else {
        let message = body
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error");
        Err(anyhow::anyhow!("Graceful restart failed: {}", message))
    }
}

/// データプレーンの状態を表示（CLI コマンド用）
///
/// HTTP API 経由でデータプレーン一覧を取得して表示します。
pub async fn show_status(api_addr: SocketAddr) -> Result<()> {
    let url = format!("http://{}/api/v1/ListDataPlanes", api_addr);
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

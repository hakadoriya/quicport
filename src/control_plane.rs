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
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::api::{HttpIpcState, run_private_with_http_ipc};
use crate::ipc::{
    discover_dataplanes, read_dataplane_port, read_dataplane_state, AuthPolicy, ControlCommand,
    DataPlaneConfig, DataPlaneEvent, DataPlaneState, DataPlaneStatus, IpcConnection,
};
use crate::statistics::ServerStatistics;

/// データプレーンの接続情報（レガシー IPC 用）
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
    /// 管理中のデータプレーン（レガシー IPC 用）
    dataplanes: RwLock<HashMap<u32, DataPlaneConnection>>,
    /// 統計情報
    #[allow(dead_code)]
    statistics: Arc<ServerStatistics>,
    /// 実行ファイルパス
    executable_path: PathBuf,
    /// HTTP IPC 状態（新規追加）
    http_ipc: Arc<HttpIpcState>,
    /// HTTP IPC モードフラグ（新規追加）
    use_http_ipc: bool,
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

        let http_ipc = Arc::new(HttpIpcState::new());

        Ok(Arc::new(Self {
            listen_addr,
            auth_policy,
            dp_config,
            dataplanes: RwLock::new(HashMap::new()),
            statistics,
            executable_path,
            http_ipc,
            use_http_ipc: false,
        }))
    }

    /// HTTP IPC モードでコントロールプレーンを作成
    pub fn new_with_http_ipc(
        listen_addr: SocketAddr,
        auth_policy: AuthPolicy,
        statistics: Arc<ServerStatistics>,
        http_ipc: Arc<HttpIpcState>,
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
            http_ipc,
            use_http_ipc: true,
        }))
    }

    /// HTTP IPC 状態を取得
    pub fn http_ipc(&self) -> Arc<HttpIpcState> {
        self.http_ipc.clone()
    }

    /// コントロールプレーンを起動
    ///
    /// 1. 既存のデータプレーンを検出して接続
    /// 2. ACTIVE なデータプレーンがなければ新規起動
    /// 3. 認証ポリシーを配布
    pub async fn start(self: Arc<Self>) -> Result<()> {
        info!("Control plane starting (http_ipc={})", self.use_http_ipc);

        // HTTP IPC の場合は認証ポリシーを HttpIpcState に設定
        if self.use_http_ipc {
            *self.http_ipc.auth_policy.write().await = Some(self.auth_policy.clone());
            *self.http_ipc.dp_config.write().await = self.dp_config.clone();
        }

        // 既存のデータプレーンを検出（レガシー IPC のみ）
        if !self.use_http_ipc {
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
        }

        info!("Control plane started successfully");
        Ok(())
    }

    /// データプレーンに接続（レガシー IPC）
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
        info!("Starting new data plane process (http_ipc={})", self.use_http_ipc);

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

            if self.use_http_ipc {
                // HTTP IPC モード: --control-plane-url を使用
                let cp_url = format!("http://127.0.0.1:{}", self.listen_addr.port());
                cmd.arg("--control-plane-url").arg(&cp_url);
                info!("Data plane will connect to control plane at {}", cp_url);
            } else {
                // レガシー IPC モード: 環境変数経由で認証ポリシーを渡す
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

            if self.use_http_ipc {
                // HTTP IPC モード: データプレーンの登録を待つ
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
                    debug!("Waiting for data plane {} to register (attempt {}/{})", dp_id, retries, max_retries);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            } else {
                // レガシー IPC モード: 接続を試みる
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
        }

        #[cfg(not(unix))]
        {
            Err(anyhow::anyhow!("Data plane process management is only supported on Unix"))
        }
    }

    /// 認証ポリシーを全データプレーンに配布（レガシー IPC）
    pub async fn distribute_auth_policy(&self) -> Result<()> {
        if self.use_http_ipc {
            // HTTP IPC モード: 認証ポリシーは HttpIpcState に既に設定されている
            // データプレーンは RegisterDataPlane 時に取得する
            self.http_ipc.broadcast_command(
                ControlCommand::SetAuthPolicy(self.auth_policy.clone())
            ).await;
            return Ok(());
        }

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
        info!("Starting graceful restart (http_ipc={})", self.use_http_ipc);

        if self.use_http_ipc {
            // HTTP IPC モード: 現在の ACTIVE な DP を取得
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
                if let Err(e) = self.http_ipc.send_command(&dp_id, ControlCommand::Drain).await {
                    warn!("Failed to drain data plane {}: {}", dp_id, e);
                }
            }
        } else {
            // レガシー IPC モード
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
        }

        info!("Graceful restart completed");
        Ok(())
    }

    /// データプレーンをドレイン
    pub async fn drain_dataplane(&self, pid: u32) -> Result<()> {
        info!("Draining data plane PID {}", pid);

        if self.use_http_ipc {
            let dp_id = format!("dp_{}", pid);
            self.http_ipc.send_command(&dp_id, ControlCommand::Drain).await
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            return Ok(());
        }

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

    /// 全データプレーンの接続情報を取得
    pub async fn get_all_connections(&self) -> Vec<crate::ipc::ConnectionInfo> {
        let mut all_connections = Vec::new();

        if self.use_http_ipc {
            let dataplanes = self.http_ipc.dataplanes.read().await;
            for dp in dataplanes.values() {
                all_connections.extend(dp.connections.clone());
            }
            return all_connections;
        }

        let pids: Vec<u32> = {
            let dataplanes = self.dataplanes.read().await;
            dataplanes.keys().copied().collect()
        };

        for pid in pids {
            let mut dataplanes = self.dataplanes.write().await;
            if let Some(dp) = dataplanes.get_mut(&pid) {
                if let Some(conn) = &mut dp.conn {
                    if conn.send_command(&ControlCommand::GetConnections).await.is_ok() {
                        match conn.recv_event().await {
                            Ok(DataPlaneEvent::Connections { connections }) => {
                                all_connections.extend(connections);
                            }
                            Ok(_) => {}
                            Err(e) => {
                                warn!("Failed to get connections from data plane {}: {}", pid, e);
                            }
                        }
                    }
                }
            }
        }

        all_connections
    }

    /// データプレーンをシャットダウン
    #[allow(dead_code)]
    pub async fn shutdown_dataplane(&self, pid: u32) -> Result<()> {
        info!("Shutting down data plane PID {}", pid);

        if self.use_http_ipc {
            let dp_id = format!("dp_{}", pid);
            self.http_ipc.send_command(&dp_id, ControlCommand::Shutdown).await
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            return Ok(());
        }

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

        if self.use_http_ipc {
            self.http_ipc.broadcast_command(ControlCommand::Drain).await;
            return Ok(());
        }

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

        if self.use_http_ipc {
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
            return statuses;
        }

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
    let has_private_api = api_config.as_ref().map_or(false, |c| c.private_addr.is_some());

    // HTTP IPC 用の内部 API アドレスを決定
    // Private API が有効な場合はそれを使用、そうでなければ localhost でリッスン
    let internal_http_ipc_addr = if has_private_api {
        None // Private API が HTTP IPC を提供
    } else {
        // Private API がない場合は内部的に HTTP IPC サーバーを起動
        Some(SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), listen_addr.port()))
    };

    let control_plane = ControlPlane::new_with_http_ipc(
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
        api_handles.push(tokio::spawn(async move {
            run_private_with_http_ipc(
                internal_addr,
                stats_for_internal,
                Some(cp_for_internal),
                http_ipc_for_internal,
            ).await
        }));
        info!("Internal HTTP IPC server started on {}", internal_addr);
    }

    if let Some(config) = api_config {
        // Public API サーバー（/healthcheck のみ）
        if let Some(public_addr) = config.public_addr {
            api_handles.push(tokio::spawn(async move {
                crate::api::run_public(public_addr).await
            }));
        }

        // Private API サーバー（/metrics, /graceful-restart, HTTP IPC）
        if let Some(private_addr) = config.private_addr {
            let stats_for_api = statistics.clone();
            let http_ipc_for_api = http_ipc.clone();
            api_handles.push(tokio::spawn(async move {
                run_private_with_http_ipc(
                    private_addr,
                    stats_for_api,
                    Some(cp_for_api),
                    http_ipc_for_api,
                ).await
            }));
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

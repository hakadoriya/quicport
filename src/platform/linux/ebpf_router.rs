//! eBPF ベースの QUIC パケットルーター (libbpf-rs 版)
//!
//! このモジュールは BPF_PROG_TYPE_SK_REUSEPORT プログラムをロードし、
//! QUIC Connection ID に基づいてパケットを正しいソケットにルーティングします。
//!
//! # アーキテクチャ
//!
//! ```text
//!                     ┌─────────────────────────────────────────┐
//!                     │              Linux Kernel               │
//!   UDP Packet        │  ┌───────────────────────────────────┐  │
//!   ──────────────────┼─▶│    SO_REUSEPORT Socket Group      │  │
//!                     │  │  ┌─────────────────────────────┐  │  │
//!                     │  │  │  SK_REUSEPORT BPF Program   │  │  │
//!                     │  │  │  (quicport_select_socket)   │  │  │
//!                     │  │  │                             │  │  │
//!                     │  │  │  1. Extract CID from QUIC   │  │  │
//!                     │  │  │  2. Get server_id (4 bytes) │  │  │
//!                     │  │  │  3. Lookup in socket_map    │  │  │
//!                     │  │  │  4. Select target socket    │  │  │
//!                     │  │  └─────────────────────────────┘  │  │
//!                     │  │              │                    │  │
//!                     │  │              ▼                    │  │
//!                     │  │  ┌─────────────────────────────┐  │  │
//!                     │  │  │   REUSEPORT_SOCKARRAY       │  │  │
//!                     │  │  │                             │  │  │
//!                     │  │  │  key=1 → Socket (Old DP)    │  │  │
//!                     │  │  │  key=2 → Socket (New DP)    │  │  │
//!                     │  │  └─────────────────────────────┘  │  │
//!                     │  └───────────────────────────────────┘  │
//!                     └─────────────────────────────────────────┘
//!                                        │
//!                     ┌──────────────────┴──────────────────┐
//!                     ▼                                     ▼
//!             ┌─────────────┐                       ┌─────────────┐
//!             │  Old DP     │                       │  New DP     │
//!             │ server_id=1 │                       │ server_id=2 │
//!             │ (draining)  │                       │ (accepting) │
//!             └─────────────┘                       └─────────────┘
//! ```
//!
//! # 必要な権限
//!
//! - `CAP_BPF`: eBPF プログラムのロード
//! - `CAP_NET_ADMIN`: ソケットへのアタッチ
//!
//! # 使用方法
//!
//! ```ignore
//! use quicport::platform::linux::EbpfRouter;
//!
//! // ルーターをロード
//! let mut router = EbpfRouter::load(EbpfRouterConfig::default())?;
//!
//! // ソケットにアタッチ
//! router.attach_to_socket(&udp_socket)?;
//!
//! // サーバーを登録
//! router.register_server(server_id, &udp_socket)?;
//! ```

use std::net::UdpSocket;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::path::PathBuf;

use anyhow::{Context, Result};
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::{MapCore, MapFlags};
use tracing::{debug, info, warn};

// libbpf-cargo が生成するスケルトン
// build.rs で OUT_DIR に quicport_reuseport.skel.rs として生成される
mod skel {
    include!(concat!(env!("OUT_DIR"), "/quicport_reuseport.skel.rs"));
}

use skel::*;

/// eBPF ルーター設定
#[derive(Debug, Clone)]
pub struct EbpfRouterConfig {
    /// BPF マップのピン留めディレクトリ (将来の拡張用)
    pub pin_path: Option<PathBuf>,
}

impl Default for EbpfRouterConfig {
    fn default() -> Self {
        Self { pin_path: None }
    }
}

/// eBPF ベースのパケットルーター
///
/// QUIC Connection ID に基づいてパケットを正しいソケットにルーティングします。
///
/// # ライフサイクル
///
/// 1. `load()`: eBPF プログラムをカーネルにロード
/// 2. `attach_to_socket()`: SO_REUSEPORT ソケットグループにアタッチ
/// 3. `register_server()`: Data Plane のソケットを登録
/// 4. (Drop 時): プログラムとマップが自動的にクリーンアップ
pub struct EbpfRouter {
    /// ロード済み BPF オブジェクト (スケルトン)
    skel: QuicportReuseportSkel<'static>,
    /// 設定
    #[allow(dead_code)]
    config: EbpfRouterConfig,
}

impl EbpfRouter {
    /// eBPF ルーターをロード
    ///
    /// # Errors
    ///
    /// - 権限不足（CAP_BPF, CAP_NET_ADMIN が必要）
    /// - eBPF プログラムのロードに失敗
    /// - カーネルバージョンが古い（Linux 4.19+ 推奨）
    pub fn load(config: EbpfRouterConfig) -> Result<Self> {
        info!("Loading eBPF SK_REUSEPORT router");

        // スケルトンをオープン
        let skel_builder = QuicportReuseportSkelBuilder::default();
        let open_skel = skel_builder
            .open()
            .context("Failed to open eBPF skeleton")?;

        // eBPF プログラムをカーネルにロード
        let skel = open_skel
            .load()
            .context("Failed to load eBPF program into kernel")?;

        info!("eBPF SK_REUSEPORT router loaded successfully");

        Ok(Self { skel, config })
    }

    /// eBPF プログラムをソケットにアタッチ
    ///
    /// SO_ATTACH_REUSEPORT_EBPF を使用して、SK_REUSEPORT プログラムを
    /// ソケットグループにアタッチします。
    ///
    /// # 重要
    ///
    /// このメソッドは SO_REUSEPORT が有効なソケットに対して呼び出す必要があります。
    /// 同じ reuseport グループ内のすべてのソケットが、アタッチ後にこのプログラムで
    /// ルーティングされるようになります。
    ///
    /// # Arguments
    ///
    /// * `socket` - SO_REUSEPORT が有効な UDP ソケット
    pub fn attach_to_socket(&self, socket: &UdpSocket) -> Result<()> {
        let sock_fd = socket.as_raw_fd();
        let prog = &self.skel.progs.quicport_select_socket;
        let prog_fd = prog.as_fd().as_raw_fd();

        debug!(
            "Attaching SK_REUSEPORT program (fd={}) to socket (fd={})",
            prog_fd, sock_fd
        );

        // SO_ATTACH_REUSEPORT_EBPF でソケットにアタッチ
        //
        // このソケットオプションは、BPF プログラムの fd を設定することで
        // reuseport グループ全体にプログラムをアタッチします。
        let ret = unsafe {
            libc::setsockopt(
                sock_fd,
                libc::SOL_SOCKET,
                libc::SO_ATTACH_REUSEPORT_EBPF,
                &prog_fd as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            return Err(anyhow::anyhow!(
                "Failed to attach eBPF program to socket: {}",
                err
            ));
        }

        info!("SK_REUSEPORT program attached to socket");
        Ok(())
    }

    /// サーバーを登録
    ///
    /// Data Plane のソケットを REUSEPORT_SOCKARRAY マップに登録します。
    /// 登録後、その server_id を持つ CID のパケットはこのソケットにルーティングされます。
    ///
    /// # Arguments
    ///
    /// * `server_id` - Data Plane の server_id (CID の先頭 4 バイト)
    /// * `socket` - UDP ソケット
    ///
    /// # 注意
    ///
    /// REUSEPORT_SOCKARRAY は特殊なマップで、ソケット fd を直接値として
    /// 格納するのではなく、カーネルがソケット参照を管理します。
    /// libbpf-rs の update() は内部でこれを適切に処理します。
    pub fn register_server(&mut self, server_id: u32, socket: &UdpSocket) -> Result<()> {
        let sock_fd = socket.as_raw_fd();

        debug!(
            "Registering server_id={} with socket fd={}",
            server_id, sock_fd
        );

        // REUSEPORT_SOCKARRAY マップにソケットを登録
        //
        // マップの型は:
        //   key: u32 (server_id)
        //   value: socket (カーネルが fd から参照を取得)
        //
        // libbpf-rs では、update() に fd をバイト配列として渡すと、
        // カーネルが適切にソケット参照を設定します。
        let key = server_id.to_ne_bytes();
        let value = (sock_fd as u64).to_ne_bytes();

        self.skel
            .maps
            .socket_map
            .update(&key, &value, MapFlags::ANY)
            .with_context(|| {
                format!("Failed to register server_id={} in socket_map", server_id)
            })?;

        info!(
            "Registered server_id={} in REUSEPORT_SOCKARRAY",
            server_id
        );
        Ok(())
    }

    /// サーバーの登録を解除
    ///
    /// Data Plane が終了する際に呼び出し、マップからエントリを削除します。
    ///
    /// # Arguments
    ///
    /// * `server_id` - 削除する Data Plane の server_id
    pub fn unregister_server(&mut self, server_id: u32) -> Result<()> {
        let key = server_id.to_ne_bytes();

        self.skel
            .maps
            .socket_map
            .delete(&key)
            .with_context(|| {
                format!("Failed to unregister server_id={} from socket_map", server_id)
            })?;

        debug!("Unregistered server_id={}", server_id);
        Ok(())
    }

    /// 登録されているサーバー数を取得
    ///
    /// デバッグ・監視用。
    pub fn registered_count(&self) -> usize {
        // REUSEPORT_SOCKARRAY のイテレーションは制限があるため、
        // 現在はサポートされていません。
        // 将来的には別の補助マップで追跡することも可能。
        0
    }
}

impl Drop for EbpfRouter {
    fn drop(&mut self) {
        info!("Dropping eBPF SK_REUSEPORT router");
        // QuicportReuseportSkel の Drop でプログラムとマップが
        // 自動的にクリーンアップされます。
    }
}

/// eBPF がこのシステムで利用可能かチェック
///
/// # チェック項目
///
/// 1. Linux カーネルであること
/// 2. CAP_BPF または CAP_SYS_ADMIN 権限があること
/// 3. bpf() システムコールが利用可能であること
pub fn is_ebpf_available() -> bool {
    // 簡易チェック: /sys/fs/bpf が存在するか
    std::path::Path::new("/sys/fs/bpf").exists()
}

/// eBPF が利用できない理由を取得
///
/// デバッグ・ユーザーへのフィードバック用。
pub fn ebpf_unavailable_reason() -> Option<String> {
    if !std::path::Path::new("/sys/fs/bpf").exists() {
        return Some("BPF filesystem not mounted at /sys/fs/bpf".to_string());
    }

    // TODO: より詳細なチェック
    // - カーネルバージョン
    // - Capabilities
    // - BPF JIT 有効化状態

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = EbpfRouterConfig::default();
        assert!(config.pin_path.is_none());
    }

    #[test]
    fn test_is_ebpf_available() {
        // このテストは環境依存
        // Linux 以外では false を返すはず
        let _ = is_ebpf_available();
    }
}

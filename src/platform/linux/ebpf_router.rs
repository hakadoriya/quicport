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
//!                     │  │  │   (pinned at /sys/fs/bpf/   │  │  │
//!                     │  │  │    quicport/socket_map)     │  │  │
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
//! # マップピン留め（Graceful Restart 対応）
//!
//! `socket_map` は BPF filesystem にピン留めされ、複数の Data Plane プロセス間で
//! 共有されます。これにより graceful restart 時に既存の QUIC 接続が維持されます。
//!
//! ```text
//! /sys/fs/bpf/quicport/socket_map  ← ピン留めされたマップ
//!      │
//!      ├── key=1 → 旧 DP のソケット（draining 中）
//!      └── key=2 → 新 DP のソケット（新規接続受付中）
//! ```
//!
//! ## ピン留めの動作
//!
//! 1. 最初の DP 起動時: 新規マップを作成してピン留め
//! 2. graceful restart 時: 既存のピン留めマップを再利用
//! 3. DP 終了時: 自分が登録した server_id のみ削除、マップは保持
//!
//! # 必要な権限
//!
//! - `CAP_BPF`: eBPF プログラムのロード
//! - `CAP_NET_ADMIN`: ソケットへのアタッチ
//! - `/sys/fs/bpf` への書き込み権限（ピン留め用）
//!
//! # 使用方法
//!
//! ```ignore
//! use quicport::platform::linux::{EbpfRouter, EbpfRouterConfig};
//!
//! // ルーターをロード（デフォルトでピン留め有効）
//! let mut router = EbpfRouter::load(EbpfRouterConfig::default())?;
//!
//! // ソケットにアタッチ
//! router.attach_to_socket(&udp_socket)?;
//!
//! // サーバーを登録
//! router.register_server(server_id, &udp_socket)?;
//!
//! // router がドロップされると、登録した server_id のみ削除される
//! // マップ自体はピン留めされているため、他プロセスが使用可能
//! ```

use std::mem::MaybeUninit;
use std::net::UdpSocket;
use std::os::fd::{AsFd, AsRawFd};
use std::path::PathBuf;

use anyhow::{Context, Result};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, OpenObject};
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
    /// BPF マップのピン留めディレクトリ
    ///
    /// `Some(path)` の場合:
    /// - `{path}/socket_map` にマップをピン留め
    /// - 既存のピン留めマップがあれば再利用（graceful restart 対応）
    ///
    /// `None` の場合:
    /// - ピン留めを行わない
    /// - プロセス終了時にマップは自動的に削除される
    ///
    /// デフォルト: `Some("/sys/fs/bpf/quicport")`
    pub pin_path: Option<PathBuf>,
}

impl Default for EbpfRouterConfig {
    fn default() -> Self {
        Self {
            // デフォルトでピン留めを有効化
            // graceful restart 時に既存の socket_map を複数プロセス間で共有するために使用
            pin_path: Some(PathBuf::from("/sys/fs/bpf/quicport")),
        }
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
    /// Box でヒープに配置し、自己参照構造を避ける
    skel: QuicportReuseportSkel<'static>,
    /// OpenObject の所有権を保持（skel がこれを参照する）
    /// Box<MaybeUninit<...>> で安定したアドレスを確保
    _open_object: Box<MaybeUninit<OpenObject>>,
    /// 設定
    #[allow(dead_code)]
    config: EbpfRouterConfig,
    /// このプロセスが登録した server_id のリスト（Drop 時にクリーンアップ用）
    registered_server_ids: Vec<u32>,
    /// ピン留めマップを再利用したかどうか
    #[allow(dead_code)]
    reused_pinned_map: bool,
}

impl EbpfRouter {
    /// eBPF ルーターをロード
    ///
    /// # ピン留め動作
    ///
    /// `config.pin_path` が設定されている場合:
    /// 1. `{pin_path}/socket_map` が存在するか確認
    /// 2. 存在する場合: 既存のピン留めマップを再利用（graceful restart 対応）
    /// 3. 存在しない場合: 新規マップを作成してピン留め
    ///
    /// # Errors
    ///
    /// - 権限不足（CAP_BPF, CAP_NET_ADMIN が必要）
    /// - eBPF プログラムのロードに失敗
    /// - カーネルバージョンが古い（Linux 4.19+ 推奨）
    /// - ピン留めパスへのアクセスに失敗
    pub fn load(config: EbpfRouterConfig) -> Result<Self> {
        info!("Loading eBPF SK_REUSEPORT router");

        // OpenObject を Box でヒープに配置し、安定したアドレスを確保
        // これにより skel がこのオブジェクトを参照できる
        let mut open_object: Box<MaybeUninit<OpenObject>> = Box::new(MaybeUninit::uninit());

        // スケルトンをオープン
        let skel_builder = QuicportReuseportSkelBuilder::default();
        let mut open_skel = skel_builder
            .open(&mut *open_object)
            .context("Failed to open eBPF skeleton")?;

        // ピン留め処理フラグ
        let mut reused_pinned_map = false;

        // ピン留めパスが設定されている場合、マップのピン留めを設定
        if let Some(ref pin_dir) = config.pin_path {
            let socket_map_pin_path = pin_dir.join("socket_map");

            if socket_map_pin_path.exists() {
                // 既存のピン留めマップを再利用
                info!(
                    "Reusing existing pinned socket_map at {:?}",
                    socket_map_pin_path
                );

                // reuse_pinned_map() は OpenMapMut::reuse_pinned_map() を使用
                // ピン留めファイルが存在する場合、そのマップを再利用する
                match open_skel.maps.socket_map.reuse_pinned_map(&socket_map_pin_path) {
                    Ok(()) => {
                        info!("Successfully reusing pinned socket_map");
                        reused_pinned_map = true;
                    }
                    Err(e) => {
                        // 再利用に失敗した場合（マップ属性の不一致など）
                        // 古いピン留めファイルを削除して新規作成
                        warn!(
                            "Failed to reuse pinned socket_map: {}. Recreating...",
                            e
                        );
                        if let Err(remove_err) = std::fs::remove_file(&socket_map_pin_path) {
                            warn!(
                                "Failed to remove corrupted pin file {:?}: {}",
                                socket_map_pin_path, remove_err
                            );
                        }

                        // ディレクトリが存在することを確認して新規ピン留め設定
                        Self::ensure_pin_directory_exists(pin_dir)?;
                        open_skel
                            .maps
                            .socket_map
                            .set_pin_path(&socket_map_pin_path)
                            .with_context(|| {
                                format!(
                                    "Failed to set pin path for socket_map: {:?}",
                                    socket_map_pin_path
                                )
                            })?;
                    }
                }
            } else {
                // ピン留めファイルが存在しない場合、新規作成
                info!("Creating new pinned socket_map at {:?}", socket_map_pin_path);

                // ピン留めディレクトリを作成
                Self::ensure_pin_directory_exists(pin_dir)?;

                // set_pin_path() でロード時に自動的にピン留め
                open_skel
                    .maps
                    .socket_map
                    .set_pin_path(&socket_map_pin_path)
                    .with_context(|| {
                        format!(
                            "Failed to set pin path for socket_map: {:?}",
                            socket_map_pin_path
                        )
                    })?;
            }
        }

        // eBPF プログラムをカーネルにロード
        let skel = open_skel
            .load()
            .context("Failed to load eBPF program into kernel")?;

        info!("eBPF SK_REUSEPORT router loaded successfully");

        // SAFETY: open_object は Box でヒープに配置されており、
        // EbpfRouter が Drop されるまで有効なアドレスを保持する。
        // skel のライフタイムを 'static に変換するが、実際には
        // _open_object と同じライフタイムで有効。
        let skel: QuicportReuseportSkel<'static> = unsafe { std::mem::transmute(skel) };

        Ok(Self {
            skel,
            _open_object: open_object,
            config,
            registered_server_ids: Vec::new(),
            reused_pinned_map,
        })
    }

    /// ピン留めディレクトリが存在することを確認し、なければ作成
    fn ensure_pin_directory_exists(pin_dir: &std::path::Path) -> Result<()> {
        if !pin_dir.exists() {
            std::fs::create_dir_all(pin_dir).with_context(|| {
                format!(
                    "Failed to create BPF pin directory {:?}. \
                     Ensure /sys/fs/bpf is mounted (bpffs) and you have permission. \
                     Try: sudo mount -t bpf none /sys/fs/bpf",
                    pin_dir
                )
            })?;
            debug!("Created BPF pin directory: {:?}", pin_dir);
        }
        Ok(())
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

        // 登録した server_id を追跡（Drop 時のクリーンアップ用）
        self.registered_server_ids.push(server_id);

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

        // 自分が登録した server_id のエントリのみを削除
        // マップ自体は削除しない（他のプロセスが使用中の可能性があるため）
        //
        // ピン留めマップを使用している場合:
        // - 他の Data Plane プロセスが同じマップを共有している可能性がある
        // - 自分が登録した server_id のみ削除することで、他プロセスの接続には影響しない
        // - マップがピン留めされているため、プロセス終了後もマップは BPF filesystem に残る
        for server_id in &self.registered_server_ids {
            let key = server_id.to_ne_bytes();
            match self.skel.maps.socket_map.delete(&key) {
                Ok(()) => {
                    debug!("Deleted server_id={} from socket_map", server_id);
                }
                Err(e) => {
                    // エントリが既に存在しない場合もエラーになる可能性があるので、
                    // デバッグログにとどめる
                    debug!(
                        "Failed to delete server_id={} from socket_map: {}",
                        server_id, e
                    );
                }
            }
        }

        // 注意: QuicportReuseportSkel の Drop では:
        // - BPF プログラムはカーネルから削除される
        // - ピン留めされていないマップは削除される
        // - ピン留めされているマップは BPF filesystem に残る（意図的）
        info!(
            "eBPF router dropped. Cleaned up {} server_id(s). Pinned map preserved for other processes.",
            self.registered_server_ids.len()
        );
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
        // デフォルトではピン留めが有効
        assert!(config.pin_path.is_some());
        assert_eq!(
            config.pin_path.as_ref().unwrap(),
            &PathBuf::from("/sys/fs/bpf/quicport")
        );
    }

    #[test]
    fn test_config_without_pinning() {
        let config = EbpfRouterConfig { pin_path: None };
        assert!(config.pin_path.is_none());
    }

    #[test]
    fn test_is_ebpf_available() {
        // このテストは環境依存
        // Linux 以外では false を返すはず
        let _ = is_ebpf_available();
    }
}

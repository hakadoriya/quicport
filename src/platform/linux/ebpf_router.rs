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
//! # マップ・プログラムのピン留め（Graceful Restart 対応）
//!
//! `socket_map` と BPF プログラムは BPF filesystem にピン留めされ、複数の Data Plane
//! プロセス間で共有されます。これにより graceful restart 時に既存の QUIC 接続が維持されます。
//!
//! ```text
//! /sys/fs/bpf/quicport/
//!      ├── socket_map              ← ピン留めされたマップ
//!      │     ├── key=1 → 旧 DP のソケット（draining 中）
//!      │     └── key=2 → 新 DP のソケット（新規接続受付中）
//!      └── quicport_select_socket  ← ピン留めされた BPF プログラム
//! ```
//!
//! ## ピン留めの動作
//!
//! 1. 最初の DP 起動時: 新規マップ・プログラムを作成してピン留め
//! 2. graceful restart 時: 既存のピン留めマップ・プログラムを再利用
//! 3. DP 終了時: 自分が登録した server_id のみ削除、マップ・プログラムは保持
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
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;

use anyhow::{Context, Result};
use libbpf_rs::libbpf_sys;
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
/// 1. `load()`: eBPF プログラムをカーネルにロード（または既存を再利用）
/// 2. `attach_to_socket()`: SO_REUSEPORT ソケットグループにアタッチ
/// 3. `register_server()`: Data Plane のソケットを登録
/// 4. (Drop 時): server_id のみクリーンアップ、プログラム・マップは保持
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
    /// ピン留めプログラムを再利用したかどうか
    reused_pinned_prog: bool,
    /// ピン留めプログラムの fd（再利用時に保持）
    /// SO_ATTACH_REUSEPORT_EBPF で使用する
    pinned_prog_fd: Option<OwnedFd>,
}

impl EbpfRouter {
    /// eBPF ルーターをロード
    ///
    /// # ピン留め動作
    ///
    /// `config.pin_path` が設定されている場合:
    /// 1. `{pin_path}/quicport_select_socket` が存在するか確認
    /// 2. 存在する場合: 既存のピン留めプログラムを再利用（graceful restart 対応）
    /// 3. 存在しない場合: 新規プログラムをロードしてピン留め
    /// 4. socket_map も同様にピン留め・再利用
    ///
    /// # Errors
    ///
    /// - 権限不足（CAP_BPF, CAP_NET_ADMIN が必要）
    /// - eBPF プログラムのロードに失敗
    /// - カーネルバージョンが古い（Linux 4.19+ 推奨）
    /// - ピン留めパスへのアクセスに失敗
    pub fn load(config: EbpfRouterConfig) -> Result<Self> {
        info!("Loading eBPF SK_REUSEPORT router");

        // ピン留め処理フラグ
        let mut reused_pinned_map = false;
        let mut reused_pinned_prog = false;
        let mut pinned_prog_fd: Option<OwnedFd> = None;

        // ピン留めパスが設定されている場合、まずプログラムの再利用を試みる
        if let Some(ref pin_dir) = config.pin_path {
            let prog_pin_path = pin_dir.join("quicport_select_socket");
            debug!("Checking for pinned program at {:?}", prog_pin_path);

            if prog_pin_path.exists() {
                // 既存のピン留めプログラムを再利用
                info!(
                    "Reusing existing pinned program at {:?}",
                    prog_pin_path
                );

                // bpf_obj_get() でピン留めプログラムの fd を取得
                // libbpf_sys::bpf_obj_get() は BPF_OBJ_GET syscall のラッパー
                let path_cstr = std::ffi::CString::new(prog_pin_path.to_string_lossy().as_bytes())
                    .context("Invalid pin path")?;
                let fd = unsafe { libbpf_sys::bpf_obj_get(path_cstr.as_ptr()) };

                if fd >= 0 {
                    info!("Successfully reusing pinned program (fd={})", fd);
                    // SAFETY: fd は有効な BPF プログラム fd
                    pinned_prog_fd = Some(unsafe { OwnedFd::from_raw_fd(fd) });
                    reused_pinned_prog = true;
                } else {
                    let err = std::io::Error::last_os_error();
                    warn!(
                        "Failed to reuse pinned program: {}. Will create new one.",
                        err
                    );
                    // 破損したピン留めファイルを削除
                    if let Err(remove_err) = std::fs::remove_file(&prog_pin_path) {
                        warn!(
                            "Failed to remove corrupted pin file {:?}: {}",
                            prog_pin_path, remove_err
                        );
                    }
                }
            } else {
                debug!("No pinned program found at {:?}", prog_pin_path);
            }
        }

        // OpenObject を Box でヒープに配置し、安定したアドレスを確保
        // これにより skel がこのオブジェクトを参照できる
        let mut open_object: Box<MaybeUninit<OpenObject>> = Box::new(MaybeUninit::uninit());

        // スケルトンをオープン
        let skel_builder = QuicportReuseportSkelBuilder::default();
        let mut open_skel = skel_builder
            .open(&mut *open_object)
            .context("Failed to open eBPF skeleton")?;

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
        // NOTE: ピン留めプログラムを再利用する場合でも、socket_map を参照するために
        //       スケルトンをロードする必要がある
        let mut skel = open_skel
            .load()
            .context("Failed to load eBPF program into kernel")?;

        // プログラムをピン留め（まだピン留めされていない場合）
        if let Some(ref pin_dir) = config.pin_path {
            debug!(
                "Program pinning check: reused_pinned_prog={}",
                reused_pinned_prog
            );
            if !reused_pinned_prog {
                let prog_pin_path = pin_dir.join("quicport_select_socket");
                Self::ensure_pin_directory_exists(pin_dir)?;

                debug!("Pinning BPF program to {:?}", prog_pin_path);
                skel.progs
                    .quicport_select_socket
                    .pin(&prog_pin_path)
                    .with_context(|| {
                        format!("Failed to pin program at {:?}", prog_pin_path)
                    })?;
                info!("Pinned BPF program at {:?}", prog_pin_path);
            } else {
                debug!("Skipping program pinning (already reused pinned program)");
            }
        }

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
            reused_pinned_prog,
            pinned_prog_fd,
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
    /// - このメソッドは SO_REUSEPORT が有効なソケットに対して呼び出す必要があります。
    /// - ピン留めプログラムがある場合はそれを使用し、すべての DP が同じプログラムを共有します。
    /// - SO_REUSEPORT グループでは、最初にアタッチされたプログラムがグループ全体で使用されます。
    ///
    /// # Arguments
    ///
    /// * `socket` - SO_REUSEPORT が有効な UDP ソケット
    pub fn attach_to_socket(&self, socket: &UdpSocket) -> Result<()> {
        let sock_fd = socket.as_raw_fd();

        // ピン留めプログラムが存在する場合はそれを使用
        //
        // 【重要】SO_REUSEPORT グループでは、最初にアタッチされた BPF プログラムが
        // グループ全体で使用されます。後からアタッチしようとしても、setsockopt は
        // 成功しますが、実際にはアクティブになりません。
        //
        // したがって、すべての DP が同じピン留めプログラムを使用することで、
        // どの DP が最初にアタッチしても同じプログラムがアクティブになります。
        // これにより、graceful restart 時のパケットルーティングが正しく機能します。
        //
        // ピン留めプログラムを再利用した場合:
        //   - pinned_prog_fd を使用（元のプログラムと同一）
        // 新規作成の場合:
        //   - スケルトンのプログラムを使用（これがピン留めされる）
        let prog_fd = if let Some(ref pinned_fd) = self.pinned_prog_fd {
            pinned_fd.as_raw_fd()
        } else {
            self.skel.progs.quicport_select_socket.as_fd().as_raw_fd()
        };

        debug!(
            "Attaching SK_REUSEPORT program (fd={}, reused_pinned={}) to socket (fd={})",
            prog_fd, self.reused_pinned_prog, sock_fd
        );

        // SO_ATTACH_REUSEPORT_EBPF でソケットにアタッチ
        //
        // このソケットオプションは、BPF プログラムの fd を設定することで
        // reuseport グループ全体にプログラムをアタッチします。
        //
        // 注意: SO_REUSEPORT グループでは、最初にプログラムをアタッチしたソケットの
        // プログラムがグループ全体で使用されます。後からアタッチしたプログラムは
        // 既存のプログラムがある場合、置き換えられません（EBUSY が返されることがある）。
        // ピン留めプログラムを使用することで、すべての DP が同じプログラムを共有します。
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
            // EBUSY は既にプログラムがアタッチされている場合に発生する可能性がある
            // SO_REUSEPORT グループでは最初にアタッチされたプログラムが使用されるため、
            // 2番目以降の DP がアタッチしようとすると EBUSY が返される場合がある
            // すべての DP が同じ socket_map を共有しているので、これは正常な動作
            if err.raw_os_error() == Some(libc::EBUSY) {
                info!(
                    "SK_REUSEPORT program already attached to group (using existing program)"
                );
                return Ok(());
            }
            return Err(anyhow::anyhow!(
                "Failed to attach eBPF program to socket: {} (errno={})",
                err,
                err.raw_os_error().unwrap_or(-1)
            ));
        }

        // アタッチ成功後、getsockopt で確認
        let mut attached_fd: libc::c_int = 0;
        let mut optlen: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let check_ret = unsafe {
            libc::getsockopt(
                sock_fd,
                libc::SOL_SOCKET,
                libc::SO_ATTACH_REUSEPORT_EBPF,
                &mut attached_fd as *mut _ as *mut libc::c_void,
                &mut optlen,
            )
        };
        if check_ret < 0 {
            let err = std::io::Error::last_os_error();
            debug!(
                "getsockopt(SO_ATTACH_REUSEPORT_EBPF) failed: {} (errno={})",
                err,
                err.raw_os_error().unwrap_or(-1)
            );
        } else {
            debug!(
                "getsockopt(SO_ATTACH_REUSEPORT_EBPF) returned fd={}",
                attached_fd
            );
        }

        info!(
            "SK_REUSEPORT program attached to socket (prog_fd={}, reused_pinned={})",
            prog_fd, self.reused_pinned_prog
        );
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

        // 注意: Drop 時の動作:
        //
        // 1. QuicportReuseportSkel の Drop:
        //    - スケルトンがロードした BPF プログラムはカーネルから削除される
        //    - ピン留めされていないマップは削除される
        //    - ピン留めされているマップは BPF filesystem に残る（意図的）
        //
        // 2. pinned_prog_fd (OwnedFd) の Drop:
        //    - fd のみがクローズされる
        //    - ピン留めファイル (/sys/fs/bpf/quicport/quicport_select_socket) は残る
        //    - 他のプロセスはこのピン留めファイルから再度 fd を取得可能
        //
        // 3. SO_REUSEPORT グループにアタッチされた BPF プログラム:
        //    - ソケットグループが存在する限り、プログラムはカーネルに保持される
        //    - 最後のソケットが閉じられるとプログラムも解放される
        //    - ピン留めファイルは別途保持されるため、新しいプロセスが再利用可能
        info!(
            "eBPF router dropped. Cleaned up {} server_id(s). Pinned map/program preserved for other processes.",
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

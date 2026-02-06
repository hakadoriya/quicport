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
    /// ピン留めプログラム・マップを再利用した場合は None（skel をロードしない）
    skel: Option<QuicportReuseportSkel<'static>>,
    /// OpenObject の所有権を保持（skel がこれを参照する）
    /// Box<MaybeUninit<...>> で安定したアドレスを確保
    /// skel が None の場合は None
    _open_object: Option<Box<MaybeUninit<OpenObject>>>,
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
    /// ピン留めマップの fd（skel なしで map を操作するために使用）
    pinned_map_fd: Option<OwnedFd>,
    /// ピン留め active_server_id_map の fd（skel なしで map を操作するために使用）
    pinned_active_map_fd: Option<OwnedFd>,
}

// SAFETY: EbpfRouter は単一の tokio タスクに move されて使用される。
// 内部の libbpf オブジェクトは生ポインタを含むが、fd ベースのカーネルインターフェースを
// 使用しており、所有権が単一タスクに移動する限りスレッド間の移動は安全。
unsafe impl Send for EbpfRouter {}

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

        // ピン留めプログラムを再利用できた場合、ピン留めマップも直接開いて
        // skel のロードをスキップする（新しい BPF プログラムをカーネルに作成しない）
        if reused_pinned_prog {
            if let Some(ref pin_dir) = config.pin_path {
                let socket_map_pin_path = pin_dir.join("socket_map");
                if socket_map_pin_path.exists() {
                    match Self::open_pinned_map(&socket_map_pin_path) {
                        Ok(map_fd) => {
                            // active_server_id_map も開く
                            let active_map_pin_path = pin_dir.join("active_server_id_map");
                            let active_map_fd = if active_map_pin_path.exists() {
                                match Self::open_pinned_map(&active_map_pin_path) {
                                    Ok(fd) => Some(fd),
                                    Err(e) => {
                                        warn!(
                                            "Failed to open pinned active_server_id_map: {}. Continuing without it.",
                                            e
                                        );
                                        None
                                    }
                                }
                            } else {
                                None
                            };

                            info!(
                                "Reusing pinned program and map without skel load (no new BPF program created)"
                            );
                            return Ok(Self {
                                skel: None,
                                _open_object: None,
                                config,
                                registered_server_ids: Vec::new(),
                                reused_pinned_map: true,
                                reused_pinned_prog: true,
                                pinned_prog_fd,
                                pinned_map_fd: Some(map_fd),
                                pinned_active_map_fd: active_map_fd,
                            });
                        }
                        Err(e) => {
                            warn!(
                                "Failed to open pinned socket_map: {}. Falling back to full skel load.",
                                e
                            );
                        }
                    }
                } else {
                    warn!("Pinned program exists but pinned map not found, falling back to full skel load");
                }
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

            // active_server_id_map のピン留め設定
            let active_map_pin_path = pin_dir.join("active_server_id_map");
            if active_map_pin_path.exists() {
                info!(
                    "Reusing existing pinned active_server_id_map at {:?}",
                    active_map_pin_path
                );
                match open_skel.maps.active_server_id_map.reuse_pinned_map(&active_map_pin_path) {
                    Ok(()) => {
                        info!("Successfully reusing pinned active_server_id_map");
                    }
                    Err(e) => {
                        warn!(
                            "Failed to reuse pinned active_server_id_map: {}. Recreating...",
                            e
                        );
                        if let Err(remove_err) = std::fs::remove_file(&active_map_pin_path) {
                            warn!(
                                "Failed to remove corrupted pin file {:?}: {}",
                                active_map_pin_path, remove_err
                            );
                        }
                        open_skel
                            .maps
                            .active_server_id_map
                            .set_pin_path(&active_map_pin_path)
                            .with_context(|| {
                                format!(
                                    "Failed to set pin path for active_server_id_map: {:?}",
                                    active_map_pin_path
                                )
                            })?;
                    }
                }
            } else {
                info!("Creating new pinned active_server_id_map at {:?}", active_map_pin_path);
                open_skel
                    .maps
                    .active_server_id_map
                    .set_pin_path(&active_map_pin_path)
                    .with_context(|| {
                        format!(
                            "Failed to set pin path for active_server_id_map: {:?}",
                            active_map_pin_path
                        )
                    })?;
            }
        }

        // eBPF プログラムをカーネルにロード
        // NOTE: ここに到達するのは以下のケース:
        //   - 初回起動（ピン留めプログラム・マップが存在しない）
        //   - ピン留めプログラムはあるがマップのオープンに失敗した場合（フォールバック）
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
            skel: Some(skel),
            _open_object: Some(open_object),
            config,
            registered_server_ids: Vec::new(),
            reused_pinned_map,
            reused_pinned_prog,
            pinned_prog_fd,
            pinned_map_fd: None,
            pinned_active_map_fd: None,
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

    /// ピン留めされた socket_map の fd を取得するヘルパー
    ///
    /// `cleanup_unresponsive_entry()` や skel スキップパスで共通的に使用する。
    fn open_pinned_map(socket_map_pin_path: &std::path::Path) -> Result<OwnedFd> {
        let path_cstr = std::ffi::CString::new(socket_map_pin_path.to_string_lossy().as_bytes())
            .context("Invalid pin path for socket_map")?;
        let map_fd = unsafe { libbpf_sys::bpf_obj_get(path_cstr.as_ptr()) };
        if map_fd < 0 {
            let err = std::io::Error::last_os_error();
            return Err(anyhow::anyhow!(
                "Failed to open pinned socket_map at {:?}: {}",
                socket_map_pin_path, err
            ));
        }
        Ok(unsafe { OwnedFd::from_raw_fd(map_fd) })
    }

    /// socket_map にエントリを追加・更新する内部ヘルパー
    ///
    /// skel がある場合は skel 経由で、ない場合は pinned_map_fd 経由で操作する。
    fn map_update(&self, key: &[u8], value: &[u8]) -> Result<()> {
        if let Some(ref skel) = self.skel {
            skel.maps.socket_map.update(key, value, MapFlags::ANY)
                .context("Failed to update socket_map via skel")?;
        } else if let Some(ref map_fd) = self.pinned_map_fd {
            let ret = unsafe {
                libbpf_sys::bpf_map_update_elem(
                    map_fd.as_raw_fd(),
                    key.as_ptr() as *const std::ffi::c_void,
                    value.as_ptr() as *const std::ffi::c_void,
                    libbpf_sys::BPF_ANY as u64,
                )
            };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                return Err(anyhow::anyhow!("Failed to update socket_map via pinned fd: {}", err));
            }
        } else {
            return Err(anyhow::anyhow!("No map handle available (neither skel nor pinned_map_fd)"));
        }
        Ok(())
    }

    /// socket_map からエントリを削除する内部ヘルパー
    ///
    /// skel がある場合は skel 経由で、ない場合は pinned_map_fd 経由で操作する。
    /// エントリが存在しない場合 (ENOENT) は成功として扱う。
    fn map_delete(&self, key: &[u8]) -> Result<()> {
        if let Some(ref skel) = self.skel {
            skel.maps.socket_map.delete(key)
                .context("Failed to delete from socket_map via skel")?;
        } else if let Some(ref map_fd) = self.pinned_map_fd {
            let ret = unsafe {
                libbpf_sys::bpf_map_delete_elem(
                    map_fd.as_raw_fd(),
                    key.as_ptr() as *const std::ffi::c_void,
                )
            };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                let errno = err.raw_os_error().unwrap_or(-1);
                if errno == libc::ENOENT {
                    return Ok(());
                }
                return Err(anyhow::anyhow!("Failed to delete from socket_map via pinned fd: {}", err));
            }
        } else {
            return Err(anyhow::anyhow!("No map handle available (neither skel nor pinned_map_fd)"));
        }
        Ok(())
    }

    /// active_server_id_map にエントリを書き込む内部ヘルパー
    ///
    /// skel がある場合は skel 経由で、ない場合は pinned_active_map_fd 経由で操作する。
    /// ARRAY マップなので key は常に 0。
    fn active_map_update(&self, value: u32) -> Result<()> {
        let key = 0u32.to_ne_bytes();
        let value_bytes = value.to_ne_bytes();

        if let Some(ref skel) = self.skel {
            skel.maps.active_server_id_map.update(&key, &value_bytes, MapFlags::ANY)
                .context("Failed to update active_server_id_map via skel")?;
        } else if let Some(ref map_fd) = self.pinned_active_map_fd {
            let ret = unsafe {
                libbpf_sys::bpf_map_update_elem(
                    map_fd.as_raw_fd(),
                    key.as_ptr() as *const std::ffi::c_void,
                    value_bytes.as_ptr() as *const std::ffi::c_void,
                    libbpf_sys::BPF_ANY as u64,
                )
            };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                return Err(anyhow::anyhow!("Failed to update active_server_id_map via pinned fd: {}", err));
            }
        } else {
            return Err(anyhow::anyhow!("No active_server_id_map handle available"));
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
        } else if let Some(ref skel) = self.skel {
            skel.progs.quicport_select_socket.as_fd().as_raw_fd()
        } else {
            return Err(anyhow::anyhow!(
                "No program handle available (neither pinned_prog_fd nor skel)"
            ));
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
            let errno = err.raw_os_error().unwrap_or(-1);
            // EBUSY は既にプログラムがアタッチされている場合に発生する可能性がある
            // SO_REUSEPORT グループでは最初にアタッチされたプログラムが使用されるため、
            // 2番目以降の DP がアタッチしようとすると EBUSY が返される場合がある
            // すべての DP が同じ socket_map を共有しているので、これは正常な動作
            if errno == libc::EBUSY {
                info!(
                    "SK_REUSEPORT program already attached to group (EBUSY). \
                     Using existing program. prog_fd={}, sock_fd={}, reused_pinned={}",
                    prog_fd, sock_fd, self.reused_pinned_prog
                );
                return Ok(());
            }
            return Err(anyhow::anyhow!(
                "setsockopt(SO_ATTACH_REUSEPORT_EBPF) failed: {} (errno={}). \
                 prog_fd={}, sock_fd={}, reused_pinned={}",
                err,
                errno,
                prog_fd,
                sock_fd,
                self.reused_pinned_prog
            ));
        }

        // setsockopt() 成功 - 詳細をログ出力
        info!(
            "setsockopt(SO_ATTACH_REUSEPORT_EBPF) succeeded: prog_fd={}, sock_fd={}, reused_pinned={}",
            prog_fd, sock_fd, self.reused_pinned_prog
        );

        // アタッチ成功後、getsockopt で確認を試みる
        //
        // 【重要】getsockopt(SO_ATTACH_REUSEPORT_EBPF) は Linux カーネルでサポートされていない
        // ENOPROTOOPT (errno=92) が返されるのは正常な動作であり、アタッチ失敗を意味しない
        // setsockopt() は「設定専用」のオプションであり、getsockopt() では取得できない
        //
        // 参考: https://elixir.bootlin.com/linux/latest/source/net/core/sock.c
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
            let errno = err.raw_os_error().unwrap_or(-1);
            // ENOPROTOOPT (92) は正常 - getsockopt はこのオプションをサポートしていない
            if errno == libc::ENOPROTOOPT {
                debug!(
                    "getsockopt(SO_ATTACH_REUSEPORT_EBPF) returned ENOPROTOOPT (expected - not supported for get)"
                );
            } else {
                warn!(
                    "getsockopt(SO_ATTACH_REUSEPORT_EBPF) failed with unexpected error: {} (errno={})",
                    err, errno
                );
            }
        } else {
            info!(
                "getsockopt(SO_ATTACH_REUSEPORT_EBPF) succeeded: attached_fd={}",
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

        // ソケットの状態を確認（デバッグ用）
        let local_addr = socket.local_addr();
        info!(
            "Registering server_id={} with socket fd={}, local_addr={:?}",
            server_id, sock_fd, local_addr
        );

        // REUSEPORT_SOCKARRAY マップにソケットを登録
        //
        // マップの型は:
        //   key: u32 (server_id)
        //   value: socket (カーネルが fd から参照を取得)
        //
        // 【重要】REUSEPORT_SOCKARRAY は特殊なマップで:
        // - 値として socket fd を渡すと、カーネルが実際のソケット参照を格納
        // - ソケットは **bind 済み** かつ **SO_REUSEPORT が有効** である必要がある
        // - bind されていないソケットを登録すると EINVAL が返される
        //
        // libbpf-rs では、update() に fd をバイト配列として渡すと、
        // カーネルが適切にソケット参照を設定します。
        let key = server_id.to_ne_bytes();
        let value = (sock_fd as u64).to_ne_bytes();

        self.map_update(&key, &value)
            .with_context(|| {
                format!(
                    "Failed to register server_id={} in socket_map. sock_fd={}, local_addr={:?}. \
                     Ensure socket is bound with SO_REUSEPORT enabled.",
                    server_id, sock_fd, local_addr
                )
            })?;

        // 登録した server_id を追跡（Drop 時のクリーンアップ用）
        self.registered_server_ids.push(server_id);

        info!(
            "Registered server_id={} in REUSEPORT_SOCKARRAY: sock_fd={}, local_addr={:?}",
            server_id, sock_fd, local_addr
        );
        Ok(())
    }

    /// ACTIVE な server_id を設定
    ///
    /// active_server_id_map に ACTIVE な server_id を登録します。
    /// eBPF プログラムが server_id ルックアップに失敗した際、この値を使って
    /// socket_map から間接ルックアップします。
    /// `MapFlags::ANY` で常に上書きするため、新しい ACTIVE DP が起動すると自動的に切り替わります。
    ///
    /// # Arguments
    ///
    /// * `server_id` - ACTIVE な DP の server_id
    pub fn set_active_server_id(&mut self, server_id: u32) -> Result<()> {
        info!(
            "Setting active_server_id={} in active_server_id_map",
            server_id
        );

        self.active_map_update(server_id)
            .with_context(|| {
                format!(
                    "Failed to set active_server_id={} in active_server_id_map",
                    server_id
                )
            })?;

        info!("Set active_server_id={}", server_id);
        Ok(())
    }

    /// ACTIVE な server_id をクリア
    ///
    /// active_server_id_map の値を 0 に設定します。
    /// ARRAY マップは delete できないため、0 を書き込んでクリアとみなします。
    pub fn clear_active_server_id(&mut self) -> Result<()> {
        self.active_map_update(0)
            .with_context(|| "Failed to clear active_server_id in active_server_id_map")?;

        debug!("Cleared active_server_id");
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

        self.map_delete(&key)
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
            match self.map_delete(&key) {
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

        // NOTE: key=0（デフォルト ACTIVE DP）は drop では削除しない。
        //       複数 DP で共有される可能性があるため、CP 側の定期 GC に任せる。

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

/// ピン留めされた eBPF map から応答不能エントリを削除
///
/// `EbpfRouter` のインスタンスを作らず、ピン留めされた map だけを操作する軽量な関数。
/// CP がバックグラウンドタスクで応答不能な DP のエントリを削除するために使用する。
///
/// # Arguments
///
/// * `pin_path` - eBPF map のピン留めディレクトリ（例: `/sys/fs/bpf/quicport`）
/// * `server_id` - 削除する server_id
///
/// # Errors
///
/// - ピン留めされた map が存在しない
/// - map fd の取得に失敗
/// - エントリの削除に失敗
pub fn cleanup_unresponsive_entry(pin_path: &std::path::Path, server_id: u32) -> Result<()> {
    let socket_map_pin_path = pin_path.join("socket_map");

    if !socket_map_pin_path.exists() {
        debug!(
            "Pinned socket_map not found at {:?}, skipping cleanup for server_id={}",
            socket_map_pin_path, server_id
        );
        return Ok(());
    }

    // ピン留めされた map の fd を取得
    let map_fd = EbpfRouter::open_pinned_map(&socket_map_pin_path)?;

    // bpf_map_delete_elem() で server_id のエントリを削除
    let key = server_id.to_ne_bytes();
    let ret = unsafe {
        libbpf_sys::bpf_map_delete_elem(map_fd.as_raw_fd(), key.as_ptr() as *const std::ffi::c_void)
    };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        let errno = err.raw_os_error().unwrap_or(-1);
        // ENOENT はエントリが既に存在しない場合 - 正常なケース
        if errno == libc::ENOENT {
            debug!(
                "server_id={} not found in socket_map (already removed)",
                server_id
            );
            return Ok(());
        }
        return Err(anyhow::anyhow!(
            "Failed to delete server_id={} from pinned socket_map: {} (errno={})",
            server_id,
            err,
            errno
        ));
    }

    info!(
        "Cleaned up unresponsive eBPF map entry: server_id={} from {:?}",
        server_id, socket_map_pin_path
    );
    Ok(())
}

/// ピン留めされた active_server_id_map をクリア
///
/// `EbpfRouter` のインスタンスを作らず、ピン留めされた map だけを操作する軽量な関数。
/// CP が ACTIVE な DP が存在しなくなった際に呼び出す。
///
/// # Arguments
///
/// * `pin_path` - eBPF map のピン留めディレクトリ（例: `/sys/fs/bpf/quicport`）
///
/// # Errors
///
/// - ピン留めされた map が存在しない
/// - map fd の取得に失敗
/// - 値の書き込みに失敗
pub fn clear_active_server_id_entry(pin_path: &std::path::Path) -> Result<()> {
    let active_map_pin_path = pin_path.join("active_server_id_map");

    if !active_map_pin_path.exists() {
        debug!(
            "Pinned active_server_id_map not found at {:?}, skipping clear",
            active_map_pin_path
        );
        return Ok(());
    }

    // ピン留めされた map の fd を取得
    let path_cstr = std::ffi::CString::new(active_map_pin_path.to_string_lossy().as_bytes())
        .context("Invalid pin path for active_server_id_map")?;
    let map_fd = unsafe { libbpf_sys::bpf_obj_get(path_cstr.as_ptr()) };
    if map_fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(anyhow::anyhow!(
            "Failed to open pinned active_server_id_map at {:?}: {}",
            active_map_pin_path,
            err
        ));
    }
    let map_fd = unsafe { OwnedFd::from_raw_fd(map_fd) };

    // ARRAY マップなので key=0 に value=0 を書き込んでクリア
    let key = 0u32.to_ne_bytes();
    let value = 0u32.to_ne_bytes();
    let ret = unsafe {
        libbpf_sys::bpf_map_update_elem(
            map_fd.as_raw_fd(),
            key.as_ptr() as *const std::ffi::c_void,
            value.as_ptr() as *const std::ffi::c_void,
            libbpf_sys::BPF_ANY as u64,
        )
    };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        return Err(anyhow::anyhow!(
            "Failed to clear active_server_id_map: {}",
            err
        ));
    }

    info!(
        "Cleared active_server_id_map (no ACTIVE DP exists) at {:?}",
        active_map_pin_path
    );
    Ok(())
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

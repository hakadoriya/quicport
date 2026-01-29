//! Linux 固有の機能
//!
//! # eBPF ルーティング
//!
//! Linux では eBPF ベースのパケットルーティングが常に有効です。
//! これは BPF_PROG_TYPE_SK_REUSEPORT を使用して、
//! QUIC Connection ID に基づいてパケットを正しい Data Plane プロセスに
//! ルーティングします。
//!
//! # 使用方法
//!
//! ```ignore
//! #[cfg(target_os = "linux")]
//! {
//!     use quicport::platform::linux::{EbpfRouter, EbpfRouterConfig, is_ebpf_available};
//!
//!     if is_ebpf_available() {
//!         let mut router = EbpfRouter::load(EbpfRouterConfig::default())?;
//!         router.attach_to_socket(&socket)?;
//!         router.register_server(server_id, &socket)?;
//!     }
//! }
//! ```

pub mod ebpf_router;

pub use ebpf_router::{
    EbpfRouter,
    EbpfRouterConfig,
    cleanup_stale_entry,
    is_ebpf_available,
    ebpf_unavailable_reason,
};

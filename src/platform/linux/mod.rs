//! Linux 固有の機能
//!
//! # eBPF ルーティング
//!
//! `ebpf` feature が有効な場合、`EbpfRouter` が利用可能になります。
//! これは BPF_PROG_TYPE_SK_REUSEPORT を使用して、
//! QUIC Connection ID に基づいてパケットを正しい Data Plane プロセスに
//! ルーティングします。
//!
//! # 使用方法
//!
//! ```ignore
//! #[cfg(all(target_os = "linux", feature = "ebpf"))]
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

#[cfg(feature = "ebpf")]
pub mod ebpf_router;

#[cfg(feature = "ebpf")]
pub use ebpf_router::{
    EbpfRouter,
    EbpfRouterConfig,
    is_ebpf_available,
    ebpf_unavailable_reason,
};

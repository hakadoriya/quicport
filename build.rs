//! quicport ビルドスクリプト
//!
//! このスクリプトは以下の処理を行います:
//!
//! # Linux 環境
//! 1. libbpf-cargo を使用して eBPF プログラム (C) をコンパイル
//! 2. Rust バインディング (スケルトン) を自動生成
//! 3. 生成されたコードを OUT_DIR に配置
//!
//! # 必要な外部ツール
//! - clang: BPF バイトコードへのコンパイル
//! - bpftool (オプション): vmlinux.h の生成 (手動で用意済みのため不要)

fn main() {
    // 再ビルドトリガー
    println!("cargo:rerun-if-changed=build.rs");

    // eBPF プログラムソースの変更を監視
    println!("cargo:rerun-if-changed=platform/linux/bpf/quicport_reuseport.bpf.c");
    println!("cargo:rerun-if-changed=platform/linux/bpf/quicport_reuseport.h");
    println!("cargo:rerun-if-changed=platform/linux/bpf/bpf_helpers.h");
    println!("cargo:rerun-if-changed=platform/linux/bpf/vmlinux.h");

    // Linux の場合のみ eBPF プログラムをビルド
    #[cfg(target_os = "linux")]
    build_ebpf();
}

/// eBPF プログラムをビルドし、Rust スケルトンを生成
///
/// libbpf-cargo の SkeletonBuilder を使用して:
/// 1. platform/linux/bpf/quicport_reuseport.bpf.c を BPF バイトコードにコンパイル
/// 2. Rust バインディングを生成
#[cfg(target_os = "linux")]
fn build_ebpf() {
    use libbpf_cargo::SkeletonBuilder;
    use std::env;
    use std::path::PathBuf;

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let bpf_dir = manifest_dir.join("platform/linux/bpf");

    // eBPF ソースファイル
    let bpf_source = bpf_dir.join("quicport_reuseport.bpf.c");

    // 出力先
    let skel_output = out_dir.join("quicport_reuseport.skel.rs");
    let obj_output = out_dir.join("quicport_reuseport.bpf.o");

    // eBPF ディレクトリが存在するか確認
    if !bpf_source.exists() {
        println!(
            "cargo:warning=eBPF source not found: {}",
            bpf_source.display()
        );
        return;
    }

    // eBPF デバッグモードの判定
    //
    // 以下の条件でデバッグが有効化される:
    // 1. 環境変数 QUICPORT_BPF_DEBUG=1 が設定されている
    // 2. Rust のデバッグビルド (cargo build without --release)
    //
    // 使用例: QUICPORT_BPF_DEBUG=1 cargo build --release
    let enable_bpf_debug = env::var("QUICPORT_BPF_DEBUG").is_ok();

    #[cfg(debug_assertions)]
    let enable_bpf_debug = true;

    // clang 引数を構築
    let mut clang_args: Vec<&str> = vec![
        // インクルードパスを設定
        "-I",
        bpf_dir.to_str().unwrap(),
        // 最適化レベル
        "-O2",
    ];

    if enable_bpf_debug {
        clang_args.push("-DDEBUG");
        println!("cargo:warning=eBPF DEBUG mode enabled (bpf_printk active)");
    }

    // 環境変数の変更を監視
    println!("cargo:rerun-if-env-changed=QUICPORT_BPF_DEBUG");

    // SkeletonBuilder で BPF プログラムをビルド
    //
    // libbpf-cargo は内部で clang を呼び出し:
    // 1. C ソースを BPF バイトコード (.bpf.o) にコンパイル
    // 2. BTF (BPF Type Format) 情報を生成
    // 3. Rust スケルトンコードを生成
    let result = SkeletonBuilder::new()
        .source(&bpf_source)
        .clang_args(clang_args)
        .obj(&obj_output)
        .build_and_generate(&skel_output);

    match result {
        Ok(_) => {
            println!(
                "cargo:warning=eBPF program built successfully: {}",
                obj_output.display()
            );
        }
        Err(e) => {
            // ビルド失敗時のエラーメッセージ
            //
            // 一般的な原因:
            // - clang がインストールされていない
            // - clang が BPF ターゲットをサポートしていない
            // - C ソースコードにエラーがある
            println!("cargo:warning=Failed to build eBPF program: {}", e);
            println!("cargo:warning=Make sure clang is installed with BPF target support");
            println!("cargo:warning=On Ubuntu/Debian: sudo apt install clang llvm");
            println!("cargo:warning=On Fedora/RHEL: sudo dnf install clang llvm");

            // ビルドを失敗させる（ebpf feature が明示的に有効なため）
            panic!("eBPF build failed: {}", e);
        }
    }
}

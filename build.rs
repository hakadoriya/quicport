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

/// コマンドを実行し、stdout を文字列として返す。失敗時は fallback を返す。
fn run_command(program: &str, args: &[&str], fallback: &str) -> String {
    std::process::Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

/// ビルド時のメタ情報を cargo:rustc-env で埋め込む
fn emit_build_info() {
    // Git コミットハッシュ
    let git_hash = run_command("git", &["rev-parse", "HEAD"], "unknown");
    let git_hash_short = run_command("git", &["rev-parse", "--short", "HEAD"], "unknown");

    // ビルドプロファイル（debug or release）
    let build_profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };

    // ビルドタイムスタンプ (UTC, ISO 8601)
    let build_timestamp = {
        use std::time::SystemTime;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // 手動で ISO 8601 形式に変換（追加クレート不要）
        let (secs_per_day, secs_per_hour, secs_per_min) = (86400u64, 3600u64, 60u64);
        let days = now / secs_per_day;
        let time_of_day = now % secs_per_day;
        let hours = time_of_day / secs_per_hour;
        let minutes = (time_of_day % secs_per_hour) / secs_per_min;
        let seconds = time_of_day % secs_per_min;

        // 日数からグレゴリオ暦の年月日を計算（Unix epoch = 1970-01-01）
        // civil_from_days アルゴリズム (Howard Hinnant)
        let z = days as i64 + 719468;
        let era = if z >= 0 { z } else { z - 146096 } / 146097;
        let doe = (z - era * 146097) as u64;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let y = yoe as i64 + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };

        format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, hours, minutes, seconds)
    };

    // ターゲットトリプル
    let build_target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());

    // Rustc バージョン
    let rustc_version = run_command("rustc", &["--version"], "unknown");

    // cargo:rustc-env で環境変数をセット
    println!("cargo:rustc-env=BUILD_PROFILE={}", build_profile);
    println!("cargo:rustc-env=BUILD_GIT_HASH={}", git_hash);
    println!("cargo:rustc-env=BUILD_GIT_HASH_SHORT={}", git_hash_short);
    println!("cargo:rustc-env=BUILD_TIMESTAMP={}", build_timestamp);
    println!("cargo:rustc-env=BUILD_TARGET={}", build_target);
    println!("cargo:rustc-env=BUILD_RUSTC_VERSION={}", rustc_version);

    // Git HEAD の変更を監視して再ビルドをトリガー
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");
}

fn main() {
    // ビルド情報の埋め込み
    emit_build_info();

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
    // debug ビルド (cargo build) → bpf_printk 有効
    // release ビルド (cargo build --release) → bpf_printk 無効
    let enable_bpf_debug = cfg!(debug_assertions);

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

//! 埋め込みフロントエンド配信
//!
//! Vite でビルドした SPA を `rust-embed` でバイナリに埋め込み、
//! 単一バイナリから静的ファイルを配信する。
//!
//! ダッシュボードは `/dashboard` パス以下で配信される。
//! `nest("/dashboard", ...)` により、このモジュールにはプレフィックスが除去された
//! 相対パスが渡されるため、ロジック変更は不要。

use axum::{
    http::{header, StatusCode, Uri},
    response::IntoResponse,
};
use rust_embed::Embed;

/// Vite ビルド成果物を埋め込む
///
/// `cargo build` 時に `web/dist/` ディレクトリの内容がバイナリに埋め込まれる。
/// ディレクトリが存在しない場合でもコンパイルは成功する（空の埋め込みになる）。
#[derive(Embed)]
#[folder = "web/dist"]
struct FrontendAssets;

/// フロントエンド静的ファイル配信ハンドラ
///
/// - リクエストパスに対応するファイルが見つかれば、MIME タイプを判定して返却
/// - 見つからなければ `index.html` を返却（SPA フォールバック）
pub async fn serve_frontend(uri: Uri) -> impl IntoResponse {
    // URI パスから先頭の "/" を除去してファイルパスに変換
    let path = uri.path().trim_start_matches('/');

    // パスが空（"/"）の場合は index.html を返す
    let path = if path.is_empty() { "index.html" } else { path };

    // まずリクエストされたパスでファイルを探す
    if let Some(file) = FrontendAssets::get(path) {
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, mime.as_ref().to_string())],
            file.data.into(),
        )
    } else if let Some(index) = FrontendAssets::get("index.html") {
        // SPA フォールバック: ファイルが見つからない場合は index.html を返す
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html".to_string())],
            index.data.into(),
        )
    } else {
        // index.html も見つからない場合（フロントエンドがビルドされていない）
        (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "text/plain".to_string())],
            Vec::from("Frontend not built. Run: cd web && pnpm install && pnpm run build"),
        )
    }
}

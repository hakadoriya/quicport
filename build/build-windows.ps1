param(
    [Parameter(Mandatory=$true)][string]$Target
)

$ErrorActionPreference = "Stop"

# ps1 は Windows 上でしか動かす想定にないので固定値
$OsName = "Windows"

# $env:PROCESSOR_ARCHITECTURE を uname -m 相当の文字列にマッピング
$Arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { "x86_64" }
    "ARM64" { "arm64" }
    "x86"   { "i686" }
    default { Write-Error "Unknown architecture: $env:PROCESSOR_ARCHITECTURE"; exit 1 }
}

$BinName = "quicport"

# ビルド
cargo build --release --locked --target $Target

# パッケージング
$Stage = "stage\$Target"
$Out = "out"

New-Item -ItemType Directory -Force -Path $Stage | Out-Null
New-Item -ItemType Directory -Force -Path $Out | Out-Null

Copy-Item "target\$Target\release\$BinName.exe" "$Stage\$BinName.exe" -Force
if (Test-Path "README.md") { Copy-Item "README.md" "$Stage\" -Force }
if (Test-Path "LICENSE")   { Copy-Item "LICENSE"   "$Stage\" -Force }

$Archive = "${BinName}_${OsName}_${Arch}.zip"
Compress-Archive -Path "$Stage\*" -DestinationPath "$Out\$Archive" -Force

$hash = (Get-FileHash "$Out\$Archive" -Algorithm SHA256).Hash.ToLower()
"$hash  $Archive" | Out-File -FilePath "$Out\$Archive.sha256" -Encoding ascii

Write-Host "Created: $Out\$Archive"

param(
    [Parameter(Mandatory=$true)][string]$Target,
    [Parameter(Mandatory=$true)][string]$OsName,
    [Parameter(Mandatory=$true)][string]$Arch
)

$ErrorActionPreference = "Stop"

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

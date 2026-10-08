# CI only. Select ADB/connectivity files; never bundle flashing utilities.
$ErrorActionPreference = 'Stop'
$url = 'https://dl.google.com/android/repository/platform-tools_r37.0.1-win.zip'
$expected = '45f4d63113e895ebde0c90f194099a4676b6ac653bd28d54314a9e022bbc1a99'
$zip = Join-Path $env:RUNNER_TEMP 'cline-platform-tools-37.0.1.zip'
Invoke-WebRequest $url -OutFile $zip
if ((Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) { throw 'Official platform-tools digest mismatch' }
$staging = Join-Path $env:RUNNER_TEMP 'cline-platform-tools-unpack'
Expand-Archive -LiteralPath $zip -DestinationPath $staging -Force
$root = Join-Path $PSScriptRoot '../apps/examples/desktop-app/src-tauri/resources/android-platform-tools'
New-Item -ItemType Directory -Path $root -Force | Out-Null
foreach ($name in @('adb.exe','AdbWinApi.dll','AdbWinUsbApi.dll','libwinpthread-1.dll','NOTICE.txt','source.properties')) {
 Copy-Item -LiteralPath (Join-Path $staging "platform-tools/$name") -Destination (Join-Path $root $name) -Force
}
& (Join-Path $root 'adb.exe') version
if ($LASTEXITCODE -ne 0) { throw 'Bundled ADB version fixture failed' }
& bun scripts/write-platform-tools-manifest.ts $root
if ($LASTEXITCODE -ne 0) { throw 'ADB integrity manifest failed' }

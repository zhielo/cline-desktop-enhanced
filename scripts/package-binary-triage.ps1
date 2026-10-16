# Fixed CI provisioning only. Installed investigations never download dependencies/rules.
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$lock = Get-Content (Join-Path $PSScriptRoot 'binary-triage-tools.lock.json') -Raw | ConvertFrom-Json
$root = Join-Path $repo 'apps/examples/desktop-app/src-tauri/resources/binary-triage'
if (Test-Path $root) { Remove-Item $root -Recurse -Force }
New-Item -ItemType Directory -Path $root -Force | Out-Null
foreach ($tool in $lock.tools) {
    $dir = Join-Path $root $tool.id
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $zip = Join-Path $env:RUNNER_TEMP $tool.archive
    Invoke-WebRequest $tool.url -OutFile $zip
    if ((Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant() -ne $tool.sha256) { throw "Tool archive digest mismatch: $($tool.id)" }
    Expand-Archive -LiteralPath $zip -DestinationPath $dir
    $notice = Join-Path $dir 'UPSTREAM-LICENSE.txt'
    Invoke-WebRequest $tool.licenseUrl -OutFile $notice
    if ((Get-FileHash $notice -Algorithm SHA256).Hash.ToLowerInvariant() -ne $tool.licenseSha256) { throw 'License digest mismatch' }
    if (-not (Test-Path (Join-Path $dir $tool.executable))) { throw 'Missing pinned engine executable' }
}
Copy-Item (Join-Path $PSScriptRoot 'fixtures/binary-triage.yar') (Join-Path $root 'triage.yar')
Copy-Item (Join-Path $PSScriptRoot 'binary-triage-tools.lock.json') (Join-Path $root 'tools.lock.json')
& rustc --edition=2021 -C opt-level=1 -C debuginfo=0 (Join-Path $PSScriptRoot 'fixtures/binary-triage-owned.rs') -o (Join-Path $root 'owned-fixture.exe')
if ($LASTEXITCODE -ne 0) { throw 'Owned PE fixture compilation failed' }
$files = [ordered]@{}
Get-ChildItem $root -File -Recurse | Sort-Object FullName | ForEach-Object {
    $name = [IO.Path]::GetRelativePath($root, $_.FullName).Replace('\','/')
    $files[$name] = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
}
@{ schemaVersion=1; files=$files } | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $root 'manifest.json') -Encoding utf8
# Real SDK-to-Python-to-native acceptance, not package-presence checks.
$env:CLINE_BINARY_TRIAGE_ROOT = $root
& bun scripts/test-binary-triage-pack.ts
if ($LASTEXITCODE -ne 0) { throw 'Binary triage pack owned acceptance failed' }

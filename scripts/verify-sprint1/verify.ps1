[CmdletBinding()]
param([switch]$SelfTestInvalid)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).Path
$nonce = [guid]::NewGuid().ToString('N')
$mode = if ($SelfTestInvalid) { 'invalid' } else { 'normal' }
$savedPath = $env:PATH
$temp = $null
$script:failure = 'host-setup'
$script:exitCode = 1
$report = [ordered]@{
    schemaVersion = 1
    task = 'S1-18'
    mode = $mode
    startedAt = [DateTime]::UtcNow.ToString('o')
    hostPowerShell = $PSVersionTable.PSVersion.ToString()
    entrypoint = "powershell -NoProfile -File scripts/verify-sprint1/verify.ps1"
    cleanBuild = -not $SelfTestInvalid.IsPresent
    hostCommands = [System.Collections.Generic.List[object]]::new()
    historicalReferencesNotExecuted = @(
        'contracts/vectors/json/evidence.json (JavaScript)'
        'docs/sprint-1/evidence/xml-c14n.json (.NET Framework)'
    )
    skips = 0
}
if ($SelfTestInvalid) { $report.entrypoint += ' -SelfTestInvalid' }

function Stop-Verification([string]$Reason, [int]$Code = 1) {
    $script:failure = $Reason
    $script:exitCode = if ($Code -gt 0 -and $Code -lt 256) { $Code } else { 1 }
    throw 'Sprint 1 verification failed; see the sanitized report.'
}

function Invoke-Native([string]$Executable, [string[]]$InvocationArgs) {
    # Never emit raw Docker/validator text. Native stderr in PS 5.1 can be
    # wrapped as PowerShell errors; still record the actual native exit code.
    $ErrorActionPreference = 'Continue'
    $stdout = & $Executable @InvocationArgs 2>$null
    return @{ exitCode = $LASTEXITCODE; stdout = ($stdout -join "`n") }
}

function Read-Git([string[]]$InvocationArgs) {
    $result = Invoke-Native $git (@('--no-optional-locks', '-C', $root, '-c', 'core.quotepath=false') + $InvocationArgs)
    if ($result.exitCode -ne 0) { Stop-Verification 'git-query-failed' $result.exitCode }
    return $result.stdout
}

function Invoke-Docker([string]$Id, [string[]]$InvocationArgs, [switch]$AllowFailure) {
    $script:failure = $Id
    Write-Host "S1-18: $Id"
    $masked = @($InvocationArgs | ForEach-Object {
        $_.Replace($snapshot, '<snapshot>').Replace($temp, '<temp>').Replace('\', '/')
    })
    $case = [ordered]@{ id = $Id; command = (@('docker') + $masked); status = 'failed' }
    $report.hostCommands.Add($case)
    $result = Invoke-Native $docker $InvocationArgs
    $case['exitCode'] = $result.exitCode
    if ($result.exitCode -eq 0) {
        $case.status = 'passed'
    } elseif (-not $AllowFailure) {
        Stop-Verification $Id $result.exitCode
    }
    return @{ case = $case; stdout = $result.stdout }
}

function Inspect-Image([string]$Id, [string]$Tag) {
    $step = Invoke-Docker $Id @('image', 'inspect', $Tag, '--format', '{{json .}}')
    $image = ConvertFrom-Json -InputObject $step.stdout
    if ($image.Id -notmatch '^sha256:[a-f0-9]{64}$' -or $image.Os -ne 'linux' -or $image.Architecture -ne 'amd64') {
        Stop-Verification 'invalid-image-id-or-platform'
    }
    return @{
        imageId = $image.Id
        layers = @($image.RootFS.Layers)
        repoDigests = @($image.RepoDigests)
    }
}

function Confirm-BuildId([string]$IidPath, $Image) {
    $iid = [IO.File]::ReadAllText($IidPath).Trim()
    # BuildKit versions may write the config ID or an exported manifest digest.
    if ($iid -notmatch '^sha256:[a-f0-9]{64}$' -or
        ($iid -ne $Image.imageId -and -not ($Image.repoDigests -like "*@$iid"))) {
        Stop-Verification 'build-iid-does-not-match-inspection'
    }
    return $iid
}

function Run-Isolated([string]$Name, [string]$ImageId) {
    $tmpSize = if ($Name.StartsWith('tls-')) { '1m' } else { '16m' }
    $arguments = @(
        'run', '--rm', '--pull=never', '--platform', 'linux/amd64', '--network', 'none',
        '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
        '--user', '65534:65534', '--tmpfs', "/tmp:rw,noexec,nosuid,nodev,size=$tmpSize,mode=0700,uid=65534,gid=65534",
        '--mount', "type=bind,source=$snapshot,target=/work,readonly", '-w', '/work',
        '-e', 'PYTHONDONTWRITEBYTECODE=1', '-e', "CAFI_CODE_REVISION=$diagnosticRevision",
        $ImageId, 'python', 'scripts/verify-sprint1/verify.py', $Name
    )
    $step = Invoke-Docker $Name $arguments -AllowFailure
    $code = $step.case.exitCode
    try {
        $inside = ConvertFrom-Json -InputObject $step.stdout
        if ($null -eq $inside -or $inside.exitCode -ne $code) { throw 'invalid report' }
    } catch {
        $step.case.status = 'failed'
        $step.case['failure'] = 'missing-or-inconsistent-container-report'
        Stop-Verification "$Name-container-report" $code
    }
    $step.case['result'] = $inside
    $report.skips += $inside.skips
    if ($code -ne 0) { Stop-Verification "$Name-$($inside.failure)" $code }
    if ($inside.skips -ne 0 -or $Name -eq 'invalid') {
        $step.case.status = 'failed'
        Stop-Verification "$Name-unexpected-success"
    }
}

try {
    $git = (Get-Command git -CommandType Application | Select-Object -First 1).Source
    $revision = Read-Git @('rev-parse', '--verify', 'HEAD')
    if ($revision -notmatch '^[a-f0-9]{40}$') { Stop-Verification 'invalid-git-head' }
    $checkoutStatus = Read-Git @('status', '--porcelain=v1', '--untracked-files=all')
    $pathspec = @('.dockerignore', 'contracts', 'fixtures', 'tests/contracts', 'spikes',
        'deploy/contracts', 'deploy/spikes/Dockerfile', 'deploy/spikes/versions.json')
    $runner = @('verify.ps1', 'verify.py', 'unit_cases.py', 'README.md') |
        ForEach-Object { "scripts/verify-sprint1/$_" }
    $inputStatus = Read-Git (@('status', '--porcelain=v1', '--untracked-files=all', '--') + $pathspec + $runner)
    $report['source'] = [ordered]@{
        baseRevision = $revision
        branch = Read-Git @('rev-parse', '--abbrev-ref', 'HEAD')
        checkoutClean = (-not $checkoutStatus)
        testedCommit = $(if (-not $checkoutStatus) { $revision } else { $null })
        inputGitStatus = @($inputStatus -split "`r?`n" | Where-Object { $_ })
        inputsSHA256 = [ordered]@{}
    }
    $tempRoot = [IO.Path]::GetTempPath()
    $approvedTemp = Join-Path $tempRoot 'opencode'
    if (Test-Path -LiteralPath $approvedTemp -PathType Container) { $tempRoot = $approvedTemp }
    $temp = Join-Path $tempRoot "cafi-verify-sprint1-$nonce"
    $snapshot = Join-Path $temp 'checkout'
    [void][IO.Directory]::CreateDirectory($snapshot)
    $script:failure = 'snapshot-inputs'
    $tracked = Read-Git (@('ls-files', '--cached', '--') + $pathspec)
    $files = @($tracked -split "`r?`n" | Where-Object { $_ }) + $runner
    foreach ($relative in ($files | Sort-Object -Unique)) {
        if ($relative -notmatch '^[A-Za-z0-9._/-]+$' -or ($relative.Split('/') -contains '..')) {
            Stop-Verification 'unsupported-input-path'
        }
        $src = Get-Item -LiteralPath (Join-Path $root $relative) -Force
        if ($src.PSIsContainer -or ($src.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            Stop-Verification 'input-not-regular-file'
        }
        $dest = Join-Path $snapshot $relative
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($dest))
        [IO.File]::Copy($src.FullName, $dest)
        $report.source.inputsSHA256[$relative] = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    if ((Read-Git @('rev-parse', '--verify', 'HEAD')) -ne $revision -or
        (Read-Git @('status', '--porcelain=v1', '--untracked-files=all')) -cne $checkoutStatus) {
        Stop-Verification 'checkout-changed-during-snapshot'
    }
    [string[]]$inputNames = @($report.source.inputsSHA256.Keys)
    [Array]::Sort($inputNames, [StringComparer]::Ordinal)
    $hashList = ($inputNames | ForEach-Object { "$_ $($report.source.inputsSHA256[$_])`n" }) -join ''
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $snapshotHash = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($hashList))).
            Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
    $report.source['snapshotSHA256'] = $snapshotHash
    $diagnosticRevision = if ($checkoutStatus) { "base-$revision+snapshot-$snapshotHash" } else { $revision }
    $report['pins'] = Get-Content -LiteralPath (Join-Path $snapshot 'deploy/spikes/versions.json') -Raw | ConvertFrom-Json

    $script:failure = 'docker-discovery'
    $dockerCommand = Get-Command docker -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $dockerCommand -and $env:LOCALAPPDATA) {
        $fallback = Join-Path $env:LOCALAPPDATA 'Programs/DockerDesktop/resources/bin/docker.exe'
        if (Test-Path -LiteralPath $fallback -PathType Leaf) {
            $dockerCommand = Get-Command $fallback -CommandType Application
        }
    }
    if (-not $dockerCommand) { Stop-Verification 'docker-cli-unavailable' }
    $docker = $dockerCommand.Source
    $env:PATH = (Split-Path -Parent $docker) + [IO.Path]::PathSeparator + $env:PATH
    $version = Invoke-Docker 'docker-version' @('version', '--format', '{{json .}}')
    $dockerVersion = ConvertFrom-Json -InputObject $version.stdout
    $report['docker'] = @{
        client = $dockerVersion.Client.Version; server = $dockerVersion.Server.Version
        serverOS = $dockerVersion.Server.Os; serverArch = $dockerVersion.Server.Arch
    }
    if ($report.docker.serverOS -ne 'linux') { Stop-Verification 'docker-linux-engine-required' }

    $tagSuffix = $revision.Substring(0, 12) + '-' + $nonce
    $cryptoTag = "cafi-sprint1-crypto:$tagSuffix"
    $soapTag = "cafi-sprint1-soap:$tagSuffix"
    $cryptoIid = Join-Path $temp 'crypto.iid'
    $soapIid = Join-Path $temp 'soap.iid'
    $build = @('build', '--platform', 'linux/amd64')
    if (-not $SelfTestInvalid) { $build += '--no-cache' }
    $null = Invoke-Docker 'build-crypto' ($build + @('--iidfile', $cryptoIid, '-f',
            (Join-Path $snapshot 'deploy/spikes/Dockerfile'), '-t', $cryptoTag, $snapshot))
    $crypto = Inspect-Image 'inspect-crypto' $cryptoTag
    $report['images'] = [ordered]@{ crypto = @{ tag = $cryptoTag; imageId = $crypto.imageId;
            buildIid = (Confirm-BuildId $cryptoIid $crypto); rootfsLayers = $crypto.layers } }
    $null = Invoke-Docker 'build-soap' ($build + @('--iidfile', $soapIid, '--build-arg',
            "SPIKES_IMAGE=$cryptoTag", '--target', 'soap', '-f',
            (Join-Path $snapshot 'deploy/contracts/Dockerfile'), '-t', $soapTag, $snapshot))
    $soap = Inspect-Image 'inspect-soap' $soapTag
    $cryptoAfter = Inspect-Image 'reinspect-crypto' $cryptoTag
    if ($cryptoAfter.imageId -ne $crypto.imageId -or $soap.layers.Count -le $crypto.layers.Count -or
        ($soap.layers[0..($crypto.layers.Count - 1)] -join ',') -cne ($crypto.layers -join ',')) {
        Stop-Verification 'soap-rootfs-does-not-descend-from-verified-crypto-image'
    }
    $report.images['soap'] = @{ tag = $soapTag; imageId = $soap.imageId;
        buildIid = (Confirm-BuildId $soapIid $soap); rootfsLayers = $soap.layers }
    $report.images['verifiedCryptoLayerPrefix'] = $true
    if ($SelfTestInvalid) {
        Run-Isolated 'invalid' $soap.imageId
    } else {
        Run-Isolated 'contracts' $soap.imageId
        Run-Isolated 'ecdsa' $crypto.imageId
        Run-Isolated 'ml-dsa' $crypto.imageId
        Run-Isolated 'tls-x25519' $crypto.imageId
        Run-Isolated 'tls-hybrid-1' $crypto.imageId
        Run-Isolated 'tls-hybrid-2' $crypto.imageId
    }
    $script:failure = $null
    $script:exitCode = 0
} catch {
    # Failure location is tracked explicitly; never leak raw tool/error output.
} finally {
    $env:PATH = $savedPath
    if ($temp -and [IO.Directory]::Exists($temp)) {
        try { [IO.Directory]::Delete($temp, $true) } catch {
            if ($script:exitCode -eq 0) { $script:exitCode = 1; $script:failure = 'snapshot-cleanup' }
            $report['snapshotCleanupFailed'] = $true
        }
    }
    $report['finishedAt'] = [DateTime]::UtcNow.ToString('o')
    $report['exitCode'] = $script:exitCode
    $report['failure'] = $script:failure
    try {
        $reportDir = Join-Path $root '.spikes/verify-sprint1'
        [void][IO.Directory]::CreateDirectory($reportDir)
        $reportPath = Join-Path $reportDir "$mode-$nonce.json"
        [IO.File]::WriteAllText($reportPath, ($report | ConvertTo-Json -Depth 50) + "`n",
            [Text.UTF8Encoding]::new($false))
        Write-Host "S1-18: exit $script:exitCode; .spikes/verify-sprint1/$mode-$nonce.json"
    } catch {
        Write-Host 'S1-18: sanitized report could not be written'
        $script:exitCode = 1
    }
}
exit $script:exitCode

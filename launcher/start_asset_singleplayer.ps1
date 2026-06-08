param(
    [string]$Python = "C:\python3.13.13\python.exe",
    [string]$Profile = "singleplayer_direct",
    [string]$Account = "100000001",
    [string]$Ticket = "AAAAILocalOfflineTicket0000000000000000000000000",
    [string]$ServerName = "FinalCombat",
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

if (-not (Test-Path -LiteralPath $Python)) {
    $Python = "python"
}

$StartArgs = @(
    ".\launcher\start_local.py",
    "--asset-root", (Join-Path $Root "protocol_assets"),
    "--asset-profile", $Profile,
    "--account", $Account,
    "--ticket", $Ticket,
    "--server-name", $ServerName
)

if ($DryRun) {
    $StartArgs += "--dry-run"
}

& $Python @StartArgs @args

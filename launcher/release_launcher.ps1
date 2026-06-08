$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$script:GameDir = Join-Path $script:Root 'game'
$script:GameExe = Join-Path $script:GameDir 'FinalCombat.exe'
$script:StartLocal = Join-Path $script:Root 'launcher\start_local.py'
$script:AssetRoot = Join-Path $script:Root 'protocol_assets'
$script:PythonExe = 'C:\python3.13.13\python.exe'
if (-not (Test-Path $script:PythonExe)) { $script:PythonExe = 'python' }

$script:DefaultAccount = if ($env:FC_RELEASE_ACCOUNT) { $env:FC_RELEASE_ACCOUNT } else { '100000001' }
$script:DefaultTicket = if ($env:FC_RELEASE_TICKET) { $env:FC_RELEASE_TICKET } else { 'AAAAILocalOfflineTicket0000000000000000000000000' }
$script:DefaultServer = if ($env:FC_RELEASE_SERVER) { $env:FC_RELEASE_SERVER } else { '127.0.0.1:15000' }
$script:LocalProc = $null
$script:GameLaunched = $false
$script:LogFile = Join-Path $script:Root 'launcher_runtime.log'
$script:PendingGameArgs = @()

if ($args -contains '--dry-run') {
    "root=$script:Root"
    "game=$script:GameExe"
    "start_local=$script:StartLocal"
    "asset_root=$script:AssetRoot"
    "python=$script:PythonExe"
    exit 0
}

function Escape-Arg {
    param([string]$Value)
    if ($null -eq $Value) { return '""' }
    if ($Value -match '[\s"]') {
        return '"' + ($Value -replace '"', '\"') + '"'
    }
    return $Value
}

function Join-Args {
    param([string[]]$Values)
    return (($Values | ForEach-Object { Escape-Arg $_ }) -join ' ')
}

function Invoke-Ui {
    param([scriptblock]$Block)
    if ($script:Form -and $script:Form.InvokeRequired) {
        $action = [System.Action]{ & $Block }
        [void]$script:Form.BeginInvoke($action)
    } else {
        & $Block
    }
}

function Mask-Message {
    param([string]$Message)
    $masked = [regex]::Replace($Message, '(-login\s+)\S+', '$1<redacted>')
    $masked = [regex]::Replace($masked, 'AAAA[A-Za-z0-9+/=]{20,}', '<ticket>')
    return $masked
}

function Write-Log {
    param([string]$Message)
    $safeMessage = Mask-Message $Message
    try {
        $stampFile = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Add-Content -Path $script:LogFile -Value "[$stampFile] $safeMessage" -Encoding UTF8
    } catch {
    }
    Invoke-Ui {
        $stamp = Get-Date -Format 'HH:mm:ss'
        $script:LogBox.AppendText("[$stamp] $safeMessage`r`n")
        $script:LogBox.SelectionStart = $script:LogBox.TextLength
        $script:LogBox.ScrollToCaret()
    }
}

function Assert-GameExists {
    if (-not (Test-Path $script:GameExe)) {
        [System.Windows.Forms.MessageBox]::Show("Game file not found: $script:GameExe", 'Missing game file', 'OK', 'Error') | Out-Null
        return $false
    }
    return $true
}

function Launch-Game {
    param([string[]]$GameArgs)
    if (-not (Assert-GameExists)) { return }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $script:GameExe
    $psi.WorkingDirectory = $script:GameDir
    $psi.UseShellExecute = $true
    $psi.Arguments = Join-Args $GameArgs
    Write-Log ("Launching game: " + $psi.FileName + " " + $psi.Arguments)
    [System.Diagnostics.Process]::Start($psi) | Out-Null
}

function Parse-HostPort {
    param([string]$Text)
    $value = ($Text -replace ([string][char]0xff1a), ':').Trim()
    if (-not $value) { return @('127.0.0.1', 15000) }
    if ($value -notmatch ':') { return @($value, 15000) }
    $idx = $value.LastIndexOf(':')
    $host = $value.Substring(0, $idx).Trim()
    $portText = $value.Substring($idx + 1).Trim()
    if (-not $host) { $host = '127.0.0.1' }
    $port = 0
    if (-not [int]::TryParse($portText, [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
        throw "Port is not a valid number in range: $portText"
    }
    return @($host, $port)
}

function Get-PortOwnerPid {
    param([int]$Port)
    try {
        $pattern = "127\.0\.0\.1:$Port\s+"
        $line = netstat -ano -p tcp | Select-String -Pattern $pattern | Select-String -Pattern 'LISTENING' | Select-Object -First 1
        if ($line) {
            $parts = ($line.ToString().Trim() -split '\s+')
            return $parts[-1]
        }
    } catch {
    }
    return ''
}

function Get-BusyLocalPorts {
    $busy = @()
    foreach ($port in @(18090, 15000, 9000, 9024)) {
        $listener = $null
        try {
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('127.0.0.1'), $port)
            $listener.Start()
        } catch {
            $ownerPid = Get-PortOwnerPid $port
            if ($ownerPid) {
                $busy += "$port (pid $ownerPid)"
            } else {
                $busy += "$port"
            }
        } finally {
            if ($listener) { $listener.Stop() }
        }
    }
    return $busy
}

function Find-Ticket {
    param($Value)
    if ($null -eq $Value) { return '' }
    $keys = @('auth_ticket', 'ticket', 'login', 'token')
    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($key in $keys) {
            if ($Value.Contains($key) -and $Value[$key]) { return [string]$Value[$key] }
        }
        foreach ($item in $Value.Values) {
            $found = Find-Ticket $item
            if ($found) { return $found }
        }
    } elseif ($Value.PSObject -and $Value.PSObject.Properties) {
        foreach ($key in $keys) {
            $prop = $Value.PSObject.Properties[$key]
            if ($prop -and $prop.Value) { return [string]$prop.Value }
        }
        foreach ($prop in $Value.PSObject.Properties) {
            $found = Find-Ticket $prop.Value
            if ($found) { return $found }
        }
    } elseif ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        foreach ($item in $Value) {
            $found = Find-Ticket $item
            if ($found) { return $found }
        }
    }
    return ''
}

function Request-RemoteTicket {
    param(
        [string]$HostName,
        [int]$ProxyPort,
        [string]$Account,
        [string]$Password
    )
    $body = @{ username = $Account; account = $Account; password = $Password } | ConvertTo-Json -Compress
    $urls = @(
        "http://$HostName`:18090/auth/login",
        "http://$HostName`:18090/login"
    )
    if ($ProxyPort -ne 18090) {
        $urls += @(
            "http://$HostName`:$ProxyPort/auth/login",
            "http://$HostName`:$ProxyPort/login"
        )
    }
    $lastError = ''
    foreach ($url in $urls) {
        try {
            $response = Invoke-RestMethod -Uri $url -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 3
            $ticket = Find-Ticket $response
            if ($ticket) {
                return @{ ticket = $ticket; note = "Auth succeeded: $url" }
            }
            $lastError = "$url did not return auth_ticket/ticket/token"
        } catch {
            $lastError = "$url $($_.Exception.Message)"
        }
    }
    if ($Password.Trim()) {
        return @{ ticket = $Password.Trim(); note = "No HTTP ticket was returned; using the password/ticket field as -login. Last error: $lastError" }
    }
    throw "Could not obtain an auth ticket. Last error: $lastError"
}

function Start-LocalSingleplayer {
    try {
        if (-not (Assert-GameExists)) { return }
        if ($script:LocalProc -and -not $script:LocalProc.HasExited) {
            Write-Log 'Local services are already running'
            return
        }
        $busyPorts = Get-BusyLocalPorts
        if ($busyPorts.Count -gt 0) {
            $message = "Required local ports are already in use: " + ($busyPorts -join ', ') + ". Close the old local stub/backend process and try again."
            Write-Log $message
            [System.Windows.Forms.MessageBox]::Show($message, 'Ports busy', 'OK', 'Warning') | Out-Null
            return
        }
        $script:GameLaunched = $false
        $account = $script:LocalAccountBox.Text.Trim()
        if (-not $account) { $account = $script:DefaultAccount }
        $ticket = $script:LocalTicketBox.Text.Trim()
        if (-not $ticket) { $ticket = $script:DefaultTicket }

        $args = @(
            $script:StartLocal,
            '--asset-root', $script:AssetRoot,
            '--asset-profile', 'singleplayer_direct',
            '--account', $account,
            '--ticket', $ticket,
            '--server-name', 'FinalCombat',
            '--capture-dir=',
            '--python', $script:PythonExe
        )
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $script:PythonExe
        $psi.Arguments = Join-Args $args
        $psi.WorkingDirectory = $script:Root
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        $proc.EnableRaisingEvents = $true
        $proc.add_OutputDataReceived({
            param($sender, $eventArgs)
            if ($eventArgs.Data) { Write-Log $eventArgs.Data.TrimEnd() }
        })
        $proc.add_ErrorDataReceived({
            param($sender, $eventArgs)
            if ($eventArgs.Data) { Write-Log $eventArgs.Data.TrimEnd() }
        })
        $proc.add_Exited({
            param($sender, $eventArgs)
            Write-Log "Local service process exited: code=$($sender.ExitCode)"
            if (-not $script:GameLaunched) {
                Invoke-Ui {
                    [System.Windows.Forms.MessageBox]::Show(
                        "Local services exited before the game was launched.`r`nSee launcher_runtime.log in the release folder.",
                        'Local service exited',
                        'OK',
                        'Error'
                    ) | Out-Null
                }
            }
        })

        Write-Log 'Starting local auth, proxy, game, and channel services'
        [void]$proc.Start()
        $proc.BeginOutputReadLine()
        $proc.BeginErrorReadLine()
        $script:LocalProc = $proc

        $script:PendingGameArgs = @(
            '-info', $account,
            '-login', $ticket,
            '-proxysvrip', '127.0.0.1',
            '-proxysvrport', '15000',
            '-servername', 'FinalCombat',
            '-serverid', '1'
        )
        $timer = New-Object System.Windows.Forms.Timer
        $timer.Interval = 2500
        $timer.Add_Tick({
            param($eventSender, $eventArgs)
            try {
                $eventSender.Stop()
                $eventSender.Dispose()
                if ($script:LocalProc -and -not $script:LocalProc.HasExited -and -not $script:GameLaunched) {
                    $script:GameLaunched = $true
                    Launch-Game $script:PendingGameArgs
                } elseif ($script:LocalProc -and $script:LocalProc.HasExited) {
                    Write-Log "Local services exited before launch timer fired: code=$($script:LocalProc.ExitCode)"
                }
            } catch {
                Write-Log "Launch timer failed: $($_.Exception.Message)"
                [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Launch timer failed', 'OK', 'Error') | Out-Null
            }
        })
        $timer.Start()
    } catch {
        Write-Log "Start local failed: $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Start local failed', 'OK', 'Error') | Out-Null
    }
}

function Stop-LocalServices {
    if (-not $script:LocalProc -or $script:LocalProc.HasExited) {
        Write-Log 'No local services are running'
        return
    }
    Write-Log 'Stopping local services'
    $taskkill = Join-Path $env:SystemRoot 'System32\taskkill.exe'
    & $taskkill /F /T /PID $script:LocalProc.Id | Out-Null
}

function Start-RemoteServer {
    if (-not (Assert-GameExists)) { return }
    try {
        $parsed = Parse-HostPort $script:RemoteServerBox.Text
        $hostName = [string]$parsed[0]
        $port = [int]$parsed[1]
        $account = $script:RemoteAccountBox.Text.Trim()
        $password = $script:RemotePasswordBox.Text
        if (-not $account) { throw 'Account is required' }
        Write-Log "Requesting developer-server auth: $hostName`:$port"
        $result = Request-RemoteTicket -HostName $hostName -ProxyPort $port -Account $account -Password $password
        Write-Log $result.note
        $gameArgs = @(
            '-info', $account,
            '-login', [string]$result.ticket,
            '-proxysvrip', $hostName,
            '-proxysvrport', [string]$port,
            '-servername', 'FinalCombat',
            '-serverid', '1'
        )
        Launch-Game $gameArgs
    } catch {
        Write-Log "Remote login failed: $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Remote login failed', 'OK', 'Error') | Out-Null
    }
}

function Add-LabeledTextBox {
    param(
        [System.Windows.Forms.Control]$Parent,
        [string]$Label,
        [string]$Value,
        [bool]$Password = $false
    )
    $labelControl = New-Object System.Windows.Forms.Label
    $labelControl.Text = $Label
    $labelControl.AutoSize = $true
    $labelControl.Margin = New-Object System.Windows.Forms.Padding(0, 8, 0, 2)
    $Parent.Controls.Add($labelControl)

    $box = New-Object System.Windows.Forms.TextBox
    $box.Text = $Value
    $box.Width = 360
    $box.Anchor = 'Left,Right,Top'
    if ($Password) { $box.UseSystemPasswordChar = $true }
    $Parent.Controls.Add($box)
    return $box
}

$script:Form = New-Object System.Windows.Forms.Form
$script:Form.Text = 'FinalCombat Local Launcher'
$script:Form.Size = New-Object System.Drawing.Size(900, 600)
$script:Form.MinimumSize = New-Object System.Drawing.Size(820, 520)
$script:Form.StartPosition = 'CenterScreen'

$main = New-Object System.Windows.Forms.TableLayoutPanel
$main.Dock = 'Fill'
$main.Padding = New-Object System.Windows.Forms.Padding(12)
$main.RowCount = 2
$main.ColumnCount = 1
$main.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 240))) | Out-Null
$main.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
$script:Form.Controls.Add($main)

$columns = New-Object System.Windows.Forms.TableLayoutPanel
$columns.Dock = 'Fill'
$columns.ColumnCount = 2
$columns.RowCount = 1
$columns.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 50))) | Out-Null
$columns.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 50))) | Out-Null
$main.Controls.Add($columns, 0, 0)

$localGroup = New-Object System.Windows.Forms.GroupBox
$localGroup.Text = 'Single-player direct map'
$localGroup.Dock = 'Fill'
$localGroup.Padding = New-Object System.Windows.Forms.Padding(12)
$columns.Controls.Add($localGroup, 0, 0)

$remoteGroup = New-Object System.Windows.Forms.GroupBox
$remoteGroup.Text = 'Developer server'
$remoteGroup.Dock = 'Fill'
$remoteGroup.Padding = New-Object System.Windows.Forms.Padding(12)
$columns.Controls.Add($remoteGroup, 1, 0)

$localPanel = New-Object System.Windows.Forms.FlowLayoutPanel
$localPanel.Dock = 'Fill'
$localPanel.FlowDirection = 'TopDown'
$localPanel.WrapContents = $false
$localPanel.AutoScroll = $true
$localGroup.Controls.Add($localPanel)

$remotePanel = New-Object System.Windows.Forms.FlowLayoutPanel
$remotePanel.Dock = 'Fill'
$remotePanel.FlowDirection = 'TopDown'
$remotePanel.WrapContents = $false
$remotePanel.AutoScroll = $true
$remoteGroup.Controls.Add($remotePanel)

$script:LocalAccountBox = Add-LabeledTextBox $localPanel 'Account' $script:DefaultAccount
$script:LocalTicketBox = Add-LabeledTextBox $localPanel 'Ticket' $script:DefaultTicket

$startLocalButton = New-Object System.Windows.Forms.Button
$startLocalButton.Text = 'Start local single-player'
$startLocalButton.Width = 360
$startLocalButton.Margin = New-Object System.Windows.Forms.Padding(0, 12, 0, 2)
$startLocalButton.Add_Click({ Start-LocalSingleplayer })
$localPanel.Controls.Add($startLocalButton)

$stopLocalButton = New-Object System.Windows.Forms.Button
$stopLocalButton.Text = 'Stop local services'
$stopLocalButton.Width = 360
$stopLocalButton.Margin = New-Object System.Windows.Forms.Padding(0, 4, 0, 0)
$stopLocalButton.Add_Click({ Stop-LocalServices })
$localPanel.Controls.Add($stopLocalButton)

$script:RemoteServerBox = Add-LabeledTextBox $remotePanel 'Server IP:port' $script:DefaultServer
$script:RemoteAccountBox = Add-LabeledTextBox $remotePanel 'Account' $script:DefaultAccount
$script:RemotePasswordBox = Add-LabeledTextBox $remotePanel 'Password / ticket' '' $true

$remoteButton = New-Object System.Windows.Forms.Button
$remoteButton.Text = 'Login developer server'
$remoteButton.Width = 360
$remoteButton.Margin = New-Object System.Windows.Forms.Padding(0, 12, 0, 0)
$remoteButton.Add_Click({ Start-RemoteServer })
$remotePanel.Controls.Add($remoteButton)

$logPanel = New-Object System.Windows.Forms.Panel
$logPanel.Dock = 'Fill'
$main.Controls.Add($logPanel, 0, 1)

$logLabel = New-Object System.Windows.Forms.Label
$logLabel.Text = 'Runtime log'
$logLabel.AutoSize = $true
$logLabel.Dock = 'Top'
$logPanel.Controls.Add($logLabel)

$script:LogBox = New-Object System.Windows.Forms.TextBox
$script:LogBox.Multiline = $true
$script:LogBox.ScrollBars = 'Vertical'
$script:LogBox.ReadOnly = $true
$script:LogBox.Dock = 'Fill'
$script:LogBox.Font = New-Object System.Drawing.Font('Consolas', 9)
$logPanel.Controls.Add($script:LogBox)
$script:LogBox.BringToFront()

$script:Form.Add_FormClosing({ Stop-LocalServices })
Write-Log "Release root: $script:Root"
Write-Log "Python: $script:PythonExe"
[void]$script:Form.ShowDialog()

# =========================
# Configuration (edit here)
# =========================

# Local user for SMB read
$UserName                    = 'logs_reader'
$PasswordPlain               = 'Aa123456!'            # e.g. 'S0meStr0ngP@ss!' or $null to be prompted securely
$AccountNeverExpires         = $true            # true/false
$PasswordNeverExpires        = $true            # true/false

# SMB share
$TargetPath                  = 'C:\inetpub\logs\LogFiles'
$ShareName                   = 'LogFiles'

# Windows Exporter
$ExporterVersion             = '0.30.7'
$ExporterArch                = 'amd64'         # 'amd64' for 64-bit
$ExporterBaseUrl             = 'https://github.com/prometheus-community/windows_exporter/releases/download'
$ExporterConfigUrl           = 'https://alloy-devops-static-files.s3.us-west-2.amazonaws.com/config.yml'
$ExporterServiceName         = 'windows_exporter'
$ExporterPort                = 9182

# Networking
$OpenFirewall                = $true           # true to open inbound TCP for $ExporterPort

# =========================
# Script (do not edit below)
# =========================

function Write-Info($msg){ Write-Host "[INFO ] $msg" }
function Write-Warn($msg){ Write-Host "[WARN ] $msg" -ForegroundColor Yellow }
function Write-Err ($msg){ Write-Host "[ERROR] $msg" -ForegroundColor Red }

# --- new helper: check for installed service ---
function Is-ServiceInstalled([string]$Name) {
  try {
    $s = Get-Service -Name $Name -ErrorAction SilentlyContinue
    return $null -ne $s
  } catch {
    return $false
  }
}

# Admin check
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Err "Please run this script as Administrator."
  exit 1
}

# TLS 1.2 for downloads
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

$LocalAccount = "$env:COMPUTERNAME\$UserName"

# Ensure target folder
Write-Info "Ensuring directory exists: $TargetPath"
if (-not (Test-Path -LiteralPath $TargetPath)) {
  New-Item -ItemType Directory -Path $TargetPath -Force | Out-Null
  Write-Info "Created directory: $TargetPath"
}

# --- Local user: create/enable
Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction SilentlyContinue | Out-Null
Write-Info "Checking local user '$UserName'..."
$local = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
if (-not $local) {
  $sec = if ($PasswordPlain) {
    ConvertTo-SecureString $PasswordPlain -AsPlainText -Force
  } else {
    Read-Host -AsSecureString "Enter password for local user '$UserName'"
  }
  Write-Info "Creating local user '$UserName' (AccountNeverExpires=$AccountNeverExpires, PasswordNeverExpires=$PasswordNeverExpires)…"
  New-LocalUser -Name $UserName -Password $sec -AccountNeverExpires:$AccountNeverExpires -PasswordNeverExpires:$PasswordNeverExpires -ErrorAction Stop | Out-Null
} else {
  Write-Info "Local user '$UserName' already exists."
  $needUpdate = $false
  try {
    if ($AccountNeverExpires -ne $local.AccountNeverExpires) { $needUpdate = $true }
    if ($PasswordNeverExpires -ne $local.PasswordNeverExpires) { $needUpdate = $true }
  } catch { }
  if ($needUpdate) {
    try {
      Write-Info "Updating AccountNeverExpires=$AccountNeverExpires, PasswordNeverExpires=$PasswordNeverExpires …"
      Set-LocalUser -Name $UserName -AccountNeverExpires:$AccountNeverExpires -PasswordNeverExpires:$PasswordNeverExpires -ErrorAction Stop
    } catch {
      Write-Warn "Failed to update local user flags: $($_.Exception.Message)"
    }
  }
}
$local = Get-LocalUser -Name $UserName
if (-not $local.Enabled) {
  Write-Info "Enabling local user '$UserName'…"
  Enable-LocalUser -Name $UserName
} else {
  Write-Info "Local user '$UserName' is enabled."
}

# --- SMB share: create if path not already shared
Write-Info "Checking for existing SMB share for path '$TargetPath'…"
$existingShare = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Path -ieq $TargetPath }
if ($existingShare) {
  $actualShareName = $existingShare.Name
  Write-Info "Path already shared as '$actualShareName'."
} else {
  $nameInUse = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue
  if ($nameInUse -and ($nameInUse.Path -ne $TargetPath)) {
    $newName = "{0}_{1}" -f $ShareName, (Get-Random -Maximum 9999)
    Write-Error "Preferred share name '$ShareName' in use for another path."
    throw "Preferred share name '$ShareName' in use for another path."
    $ShareName = $newName
  }
  Write-Info "Creating SMB share '$ShareName' for '$TargetPath'…"
  # NOTE: no explicit Administrators access; Windows sets defaults (Admins + SYSTEM Full)
  New-SmbShare -Name $ShareName -Path $TargetPath -ErrorAction Stop | Out-Null
  $actualShareName = $ShareName
}

# --- Share permissions: ensure Read for user
Write-Info "Ensuring share READ for '$LocalAccount' on '$actualShareName'…"
$shareAccess = Get-SmbShareAccess -Name $actualShareName -ErrorAction Stop
$hasShareRead = $shareAccess | Where-Object {
  $_.AccountName -ieq $LocalAccount -and
  $_.AccessControlType -eq 'Allow' -and
  $_.AccessRight -in @('Read','Change','Full')
}
if (-not $hasShareRead) {
  Grant-SmbShareAccess -Name $actualShareName -AccountName $LocalAccount -AccessRight Read -Force | Out-Null
  Write-Info "Granted share READ."
} else {
  Write-Info "Share READ already granted."
}

# --- NTFS permissions: ensure Read & Execute
Write-Info "Ensuring NTFS Read/Execute on '$TargetPath' for '$LocalAccount'…"
$acl = Get-Acl -LiteralPath $TargetPath
$identity = New-Object System.Security.Principal.NTAccount($LocalAccount)

function Test-HasNtfsRead {
  param($Acl, $Identity)
  foreach ($a in $Acl.Access) {
    if ($a.IdentityReference -eq $Identity -and
        $a.AccessControlType -eq 'Allow' -and
        (($a.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::ReadAndExecute) -ne 0)) {
      return $true
    }
  }
  return $false
}

if (-not (Test-HasNtfsRead -Acl $acl -Identity $identity)) {
  $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
             [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
  $prop    = [System.Security.AccessControl.PropagationFlags]::None
  $rights  = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor `
             [System.Security.AccessControl.FileSystemRights]::Read -bor `
             [System.Security.AccessControl.FileSystemRights]::ListDirectory
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, $rights, $inherit, $prop, 'Allow')
  $acl.AddAccessRule($rule) | Out-Null
  Set-Acl -LiteralPath $TargetPath -AclObject $acl
  Write-Info "Granted NTFS Read/Execute."
} else {
  Write-Info "NTFS Read/Execute already present."
}

# --- Windows Exporter: download & install
$MsiFileName = "windows_exporter-$ExporterVersion-$ExporterArch.msi"
$MsiUrl      = "$ExporterBaseUrl/v$ExporterVersion/$MsiFileName"
$MsiPath     = Join-Path $env:TEMP 'windows_exporter.msi'


# Install only if service not present
if (-not (Is-ServiceInstalled $ExporterServiceName)) {
  Write-Info "Preparing to install windows_exporter $ExporterVersion ($ExporterArch)…"
  Write-Info "MSI URL: $MsiUrl"
  try {
    Write-Info "Downloading MSI to: $MsiPath"
    Invoke-WebRequest -Uri $MsiUrl -OutFile $MsiPath -UseBasicParsing
    Write-Info "Download complete."
  } catch {
    Write-Err "Failed to download MSI: $($_.Exception.Message)"
    throw
  }

  Write-Info "Installing windows_exporter via msiexec…"
  $args = @(
    '/i', "`"$MsiPath`"",
    "CONFIG_FILE=$ExporterConfigUrl",
    '/qn', '/norestart'
  )
  $p = Start-Process -FilePath 'msiexec.exe' -ArgumentList $args -Wait -PassThru
  if ($p.ExitCode -ne 0) {
    Write-Err "msiexec failed with exit code $($p.ExitCode)."
    throw "windows_exporter install failed."
  }
  Write-Info "Installation complete."
} else {
  Write-Info "windows_exporter already installed (service '$ExporterServiceName'). Skipping install."
}

# Ensure service startup and running
try {
  Write-Info "Setting service '$ExporterServiceName' to Automatic…"
  Set-Service -Name $ExporterServiceName -StartupType Automatic
  $svc = Get-Service -Name $ExporterServiceName -ErrorAction Stop
  if ($svc.Status -ne 'Running') {
    Write-Info "Starting service '$ExporterServiceName'…"
    Start-Service -Name $ExporterServiceName
  } else {
    Write-Info "Service '$ExporterServiceName' already running."
  }
} catch {
  Write-Warn "Failed to manage service '$ExporterServiceName': $($_.Exception.Message)"
}

# --- Firewall (optional)
if ($OpenFirewall) {
  $ruleName = "windows_exporter TCP $ExporterPort"
  Write-Info "Ensuring firewall rule '$ruleName' for TCP $ExporterPort…"
  $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
  if (-not $rule) {
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort $ExporterPort -Profile Any | Out-Null
    Write-Info "Firewall rule created."
  } else {
    Write-Info "Firewall rule already exists."
    try { Set-NetFirewallRule -DisplayName $ruleName -Enabled True | Out-Null } catch { }
  }
} else {
  Write-Info "OpenFirewall=false → skipping firewall changes."
}

# --- Summary
$finalUser = Get-LocalUser -Name $UserName
$shareInfo = Get-SmbShare -Name $actualShareName -ErrorAction SilentlyContinue
$svc2 = Get-Service -Name $ExporterServiceName -ErrorAction SilentlyContinue

Write-Host ""
Write-Info "Done."
Write-Info "Share name : $($shareInfo.Name)"
Write-Info "Share path : $TargetPath"
Write-Info "Account    : $LocalAccount (enabled: $($finalUser.Enabled))"
Write-Info "Exporter   : $ExporterServiceName v$ExporterVersion (status: $($svc2.Status))"
Write-Info "Port       : $ExporterPort (Firewall open: $OpenFirewall)"

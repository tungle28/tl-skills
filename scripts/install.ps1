# Windows launcher for scripts/install.py.
#
#   .\scripts\install.ps1                                  # all skills -> Claude Code (~\.claude)
#   .\scripts\install.ps1 -Target cursor
#   .\scripts\install.ps1 -Target all -Skills tl-code-refactor,tl-seo-audit -DryRun
#   .\scripts\install.ps1 -Target claude -Scope project -Project ..\my-app
#
# Without a clone (downloads the release archive to a temp dir, installs, deletes it):
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/tungle28/tl-skills/main/scripts/install.ps1))) -Target claude
#   ... -Target cursor -Skills tl-goal-griller -Version v0.4.0
#
# It only finds a working Python and forwards the options to install.py (see that file for
# what each one does). Unlike install.py, -Target defaults to claude. -Version picks the release
# to download when the script runs outside a clone (default: the latest release, the main branch).
#
# If script execution is blocked:
#   powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1 -Target claude

[CmdletBinding()]
param(
  [ValidateSet('claude', 'cursor', 'codex', 'all')]
  [string]$Target = 'claude',
  [ValidateSet('user', 'project')]
  [string]$Scope,
  [string]$Project,
  [string[]]$Skills,
  [switch]$NoAgents,
  [switch]$Force,
  [switch]$DryRun,
  [ValidateSet('ask', 'check', 'skip')]
  [string]$Deps,
  [ValidatePattern('^v\d+\.\d+\.\d+$')]
  [string]$Version
)

$ErrorActionPreference = 'Stop'

# Run from a downloaded string (irm | scriptblock) the script has no $PSScriptRoot, and `exit` there would
# close the user's PowerShell window: set the exit code and return instead.
function Exit-Install([int]$code) {
  if ($PSScriptRoot) { exit $code }
  $global:LASTEXITCODE = $code
}

# A name on PATH is not proof of an interpreter: Windows ships python/python3 shims in
# WindowsApps that only print "Python was not found". Skip those and check the rest runs.
function Test-Python($exe, $extra) {
  try { & $exe @extra -c 'import sys; sys.exit(sys.version_info < (3, 9))' *> $null } catch { return $false }
  return ($LASTEXITCODE -eq 0)
}

function Find-Python {
  $py = Get-Command py.exe -ErrorAction SilentlyContinue
  if ($py -and (Test-Python $py.Source @('-3'))) { return @($py.Source, '-3') }
  foreach ($name in 'python', 'python3') {
    $cmd = Get-Command "$name.exe" -ErrorAction SilentlyContinue
    if (-not $cmd -or $cmd.Source -like '*WindowsApps*') { continue }
    if (Test-Python $cmd.Source @()) { return @($cmd.Source) }
  }
  return $null
}

# Always an array: a bare one-element result would be unrolled into a string, and
# @($null) is truthy, so drop nulls to keep the not-found check (-not) working.
$python = @(Find-Python | Where-Object { $_ })
if (-not $python) {
  Write-Host 'install.ps1: no working Python 3.9+ found (install.py needs it).' -ForegroundColor Yellow
  $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
  $interactive = [Environment]::UserInteractive -and -not [Console]::IsInputRedirected
  if ($winget -and $interactive) {
    $answer = Read-Host 'Install Python now with `winget install --id Python.Python.3.12 -e`? [y/N]'
    if ($answer -notmatch '^(y|yes)$') {
      Write-Host 'Skipped. Install Python 3.9+ and re-run.'
      Exit-Install 1; return
    }
    & $winget.Source install --id Python.Python.3.12 -e --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -ne 0) { Write-Host 'install.ps1: the Python install failed.' -ForegroundColor Red; Exit-Install 1; return }
    # The installer updated PATH in the registry, not in this session: reload it.
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
    $python = @(Find-Python | Where-Object { $_ })
    if (-not $python) {
      Write-Host 'Python installed but not visible to this session; open a new terminal and re-run.' -ForegroundColor Yellow
      Exit-Install 1; return
    }
  }
  else {
    Write-Host '  Install it, then re-run this script:'
    Write-Host '    winget install --id Python.Python.3.12 -e'
    Write-Host '  or download it from https://www.python.org/downloads/'
    Write-Host '  (the "python" / "python3" entries in Settings > App execution aliases are only Store shortcuts)'
    Exit-Install 1; return
  }
}

# Inside a clone, install from it. Run from a downloaded string (irm | scriptblock) there is no
# $PSScriptRoot: download the release archive instead.
$tmp = $null
if ($PSScriptRoot -and (Test-Path (Join-Path $PSScriptRoot 'install.py')) -and (Test-Path (Join-Path $PSScriptRoot '..\skills'))) {
  if ($Version) { Write-Host "install.ps1: -Version ignored; installing from this checkout." -ForegroundColor Yellow }
  $script = Join-Path $PSScriptRoot 'install.py'
}
else {
  $repo = 'tungle28/tl-skills'
  $url = if ($Version) { "https://github.com/$repo/archive/refs/tags/$Version.zip" } else { "https://github.com/$repo/archive/refs/heads/main.zip" }
  $tmp = Join-Path ([IO.Path]::GetTempPath()) ('tl-skills-' + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $tmp | Out-Null
  # Windows PowerShell 5.1 may default to TLS 1.0, which GitHub refuses; its progress bar also
  # slows Invoke-WebRequest down a lot.
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  $ProgressPreference = 'SilentlyContinue'
  Write-Host "install.ps1: downloading $url"
  try {
    Invoke-WebRequest -Uri $url -OutFile (Join-Path $tmp 'src.zip') -UseBasicParsing
    Expand-Archive -Path (Join-Path $tmp 'src.zip') -DestinationPath $tmp
  }
  catch {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    Write-Host "install.ps1: download failed: $url ($($_.Exception.Message))" -ForegroundColor Red
    Exit-Install 1; return
  }
  $script = Get-ChildItem -Path $tmp -Directory | ForEach-Object { Join-Path $_.FullName 'scripts\install.py' } |
    Where-Object { Test-Path $_ } | Select-Object -First 1
  if (-not $script) {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    Write-Host 'install.ps1: the archive has no scripts\install.py.' -ForegroundColor Red
    Exit-Install 1; return
  }
}

$pyArgs = @($python | Select-Object -Skip 1) + @($script, '--target', $Target.ToLowerInvariant())
if ($Scope) { $pyArgs += @('--scope', $Scope.ToLowerInvariant()) }
if ($Project) {
  # Windows PowerShell 5.1 quotes a space-containing argument as "dir\" and Python reads \" as an
  # escaped quote, swallowing what follows. Drop trailing backslashes, except on a drive root.
  $projectArg = $Project
  if ($projectArg -notmatch '^[A-Za-z]:\\+$') {
    $trimmed = $projectArg.TrimEnd('\')
    if ($trimmed) { $projectArg = $trimmed }
  }
  $pyArgs += @('--project', $projectArg)
}
if ($Skills) { $pyArgs += @('--skills', ($Skills -join ',')) }
if ($NoAgents) { $pyArgs += '--no-agents' }
if ($Force) { $pyArgs += '--force' }
if ($DryRun) { $pyArgs += '--dry-run' }
if ($Deps) { $pyArgs += @('--deps', $Deps.ToLowerInvariant()) }

try { & $python[0] @pyArgs; $code = $LASTEXITCODE }
finally { if ($tmp) { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue } }
Exit-Install $code

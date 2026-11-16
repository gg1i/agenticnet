<#
.SYNOPSIS
    One-command Windows installer for NetForge MCP.
.DESCRIPTION
    Creates/reuses a local .venv (unless -SystemPython is specified), installs NetForge MCP,
    copies the Packet Tracer bridge module, optionally configures your MCP client JSON, and
    runs `netforge doctor`.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\install.ps1
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -WithGui -Client antigravity -ToolProfile advanced
#>
[CmdletBinding()]
param(
    [switch]$WithGui,
    [switch]$WithDev,
    [switch]$SystemPython,
    [switch]$NoEditable,
    [ValidateSet("none", "antigravity", "claude", "cursor", "vscode")]
    [string]$Client = "none",
    [ValidateSet("solve_lab", "advanced")]
    [string]$ToolProfile = "solve_lab",
    [ValidateSet("read-only", "planning", "configuration", "standard")]
    [string]$PermissionProfile = "standard",
    [string]$DataDir = ""
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

function Find-Python311Plus {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        foreach ($ver in @("-3.12", "-3.11", "-3")) {
            try {
                $ok = & py $ver -c "import sys; print(int(sys.version_info >= (3, 11)))" 2>$null
                if ($LASTEXITCODE -eq 0 -and $ok.Trim() -eq "1") {
                    return @("py", $ver)
                }
            } catch {}
        }
    }
    if (Get-Command python -ErrorAction SilentlyContinue) {
        $ok = & python -c "import sys; print(int(sys.version_info >= (3, 11)))" 2>$null
        if ($LASTEXITCODE -eq 0 -and $ok.Trim() -eq "1") {
            return @("python")
        }
    }
    throw "Python 3.11+ was not found on PATH. Install Python 3.11 or 3.12 and re-run."
}

Push-Location $RepoRoot
try {
    $pyCmd = Find-Python311Plus
    $pyExe = $null

    if ($SystemPython) {
        if ($pyCmd.Count -gt 1) {
            $pyExe = (& $pyCmd[0] $pyCmd[1] -c "import sys; print(sys.executable)").Trim()
        } else {
            $pyExe = (& $pyCmd[0] -c "import sys; print(sys.executable)").Trim()
        }
    } elseif ($env:VIRTUAL_ENV -and (Test-Path (Join-Path $env:VIRTUAL_ENV "Scripts\python.exe"))) {
        $pyExe = Join-Path $env:VIRTUAL_ENV "Scripts\python.exe"
    } else {
        $venvDir = Join-Path $RepoRoot ".venv"
        $venvPy = Join-Path $venvDir "Scripts\python.exe"
        if (-not (Test-Path $venvPy)) {
            Write-Host "Creating virtual environment at $venvDir ..."
            if ($pyCmd.Count -gt 1) {
                & $pyCmd[0] $pyCmd[1] -m venv $venvDir
            } else {
                & $pyCmd[0] -m venv $venvDir
            }
            if ($LASTEXITCODE -ne 0) { throw "Failed to create .venv." }
        }
        $pyExe = $venvPy
    }

    $extras = @()
    if ($WithGui) { $extras += "gui" }
    if ($WithDev) { $extras += "dev" }
    $targetSpec = if ($extras.Count -gt 0) { ".[$($extras -join ',')]" } else { "." }

    Write-Host "Installing NetForge MCP ($targetSpec) using $pyExe ..."
    if ($NoEditable) {
        & $pyExe -m pip install $targetSpec
    } else {
        & $pyExe -m pip install -e $targetSpec
    }
    if ($LASTEXITCODE -ne 0) { throw "pip install failed." }

    $setupArgs = @(
        "-m", "netforge", "setup",
        "--client", $Client,
        "--tool-profile", $ToolProfile,
        "--profile", $PermissionProfile
    )
    if ($DataDir) {
        $setupArgs += @("--data-dir", $DataDir)
    }

    Write-Host ""
    & $pyExe @setupArgs
    if ($LASTEXITCODE -ne 0) { throw "netforge setup failed." }

    Write-Host ""
    Write-Host "Running environment check (netforge doctor)..."
    & $pyExe -m netforge doctor
} finally {
    Pop-Location
}

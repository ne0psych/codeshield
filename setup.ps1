# CodeShield — Complete Setup & Usage Guide
# PowerShell Installation Script for Windows
# Run this in PowerShell as Administrator

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  CodeShield Setup — Installing Python & Dependencies" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# ── Step 1: Install Python via winget (Windows 10/11) ──────────────────────
Write-Host "`n[Step 1] Checking for Python..." -ForegroundColor Yellow

$pythonVersion = python --version 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Python not found. Installing via winget..." -ForegroundColor Yellow
    winget install --id Python.Python.3.11 --source winget --accept-source-agreements --accept-package-agreements
    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") +
                ";" +
                [System.Environment]::GetEnvironmentVariable("Path","User")
    Write-Host "  Python installed." -ForegroundColor Green
} else {
    Write-Host "  Python found: $pythonVersion" -ForegroundColor Green
}

# ── Step 2: Verify pip ──────────────────────────────────────────────────────
Write-Host "`n[Step 2] Verifying pip..." -ForegroundColor Yellow
python -m pip install --upgrade pip | Out-Null
Write-Host "  pip is ready." -ForegroundColor Green

# ── Step 3: Create project directory ───────────────────────────────────────
Write-Host "`n[Step 3] Setting up project directory..." -ForegroundColor Yellow
$projectDir = "$HOME\CodeShield"
New-Item -ItemType Directory -Force -Path $projectDir | Out-Null
New-Item -ItemType Directory -Force -Path "$projectDir\reports" | Out-Null
Write-Host "  Project directory: $projectDir" -ForegroundColor Green

# ── Step 4: Install Python dependencies ────────────────────────────────────
Write-Host "`n[Step 4] Installing Python packages..." -ForegroundColor Yellow
$packages = @("reportlab", "openpyxl")
foreach ($pkg in $packages) {
    Write-Host "  Installing $pkg..." -NoNewline
    python -m pip install $pkg --quiet
    Write-Host " done" -ForegroundColor Green
}

# ── Step 5: Copy scanner scripts ───────────────────────────────────────────
Write-Host "`n[Step 5] Copy the following files to $projectDir" -ForegroundColor Yellow
Write-Host "  - scanner.py" -ForegroundColor White
Write-Host "  - report_generator.py" -ForegroundColor White
Write-Host "  - main.py" -ForegroundColor White
Write-Host "  - requirements.txt" -ForegroundColor White

# ── Step 6: Usage instructions ─────────────────────────────────────────────
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  USAGE" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  cd $projectDir" -ForegroundColor White
Write-Host ""
Write-Host "  # Basic scan (generates PDF + Excel)" -ForegroundColor DarkGray
Write-Host "  python main.py C:\path\to\yourcode.zip" -ForegroundColor Yellow
Write-Host ""
Write-Host "  # Custom output directory" -ForegroundColor DarkGray
Write-Host "  python main.py C:\path\to\yourcode.zip --output-dir C:\reports\myproject" -ForegroundColor Yellow
Write-Host ""
Write-Host "  # PDF only" -ForegroundColor DarkGray
Write-Host "  python main.py C:\path\to\yourcode.zip --no-excel" -ForegroundColor Yellow
Write-Host ""
Write-Host "  # Excel only" -ForegroundColor DarkGray
Write-Host "  python main.py C:\path\to\yourcode.zip --no-pdf" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Reports are saved to: .\reports\" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan

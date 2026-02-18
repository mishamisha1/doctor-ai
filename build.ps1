# Build all binaries for Doctor-AI
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "Building doctor.exe..." -ForegroundColor Cyan
go build -o doctor.exe ./cmd/doctor
Write-Host "Building analyze.exe..." -ForegroundColor Cyan
go build -o analyze.exe ./cmd/analyze
Write-Host "Building agent.exe..." -ForegroundColor Cyan
go build -o agent.exe ./cmd/agent
Write-Host "Building doctor-gui.exe..." -ForegroundColor Cyan
go build -o doctor-gui.exe ./cmd/gui

Write-Host "`nOK. Binaries: doctor.exe, analyze.exe, agent.exe, doctor-gui.exe" -ForegroundColor Green
Write-Host "Run: .\doctor-gui.exe  (or: .\doctor gui)" -ForegroundColor Yellow

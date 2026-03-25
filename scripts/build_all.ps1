$ErrorActionPreference = "Stop"

Write-Host "[1/2] Check unresolved merge markers..."
$markers = Select-String -Path `
  "README.md", `
  "cmd/gui/main.go", `
  "cmd/gui/handlers_core.go", `
  "cmd/gui/handlers_scan.go", `
  "cmd/gui/handlers_settings.go", `
  "cmd/gui/handlers_update.go", `
  "internal/scanner/protect.go", `
  "internal/scanner/protect_stub.go", `
  "internal/scanner/protect_test.go" `
  -Pattern "^(<<<<<<<|=======|>>>>>>>)" -AllMatches -ErrorAction SilentlyContinue

if ($markers) {
  Write-Host "Found unresolved merge markers:"
  $markers | ForEach-Object { Write-Host ("  " + $_.Path + ":" + $_.LineNumber + " " + $_.Line.Trim()) }
  exit 1
}

Write-Host "[2/2] Build all binaries..."
go build -o doctor.exe ./cmd/doctor
go build -o agent.exe ./cmd/agent
go build -o analyze.exe ./cmd/analyze
go build -o doctor-gui.exe ./cmd/gui

Write-Host "Build complete: doctor.exe, agent.exe, analyze.exe, doctor-gui.exe"

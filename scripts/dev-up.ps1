param(
    [switch]$Logs
)

$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $root

if (-not (Test-Path ".env.debug")) {
    Copy-Item ".env.debug.example" ".env.debug"
    Write-Host "Created .env.debug from .env.debug.example"
}

docker compose -f docker-compose.debug.yml --env-file .env.debug up --build -d

Write-Host ""
Write-Host "gw-ipinfo-nginx debug stack is starting."
Write-Host "Gateway: http://127.0.0.1:8080"
Write-Host "Health : http://127.0.0.1:8080/healthz"
Write-Host "Ready  : http://127.0.0.1:8080/readyz"
Write-Host "Metrics: http://127.0.0.1:8080/metrics"
Write-Host ""
Write-Host "Quick test:"
Write-Host "curl -i http://127.0.0.1:8080/ -H 'User-Agent: Mozilla/5.0'"

if ($Logs) {
    docker compose -f docker-compose.debug.yml --env-file .env.debug logs -f gateway nginx
}

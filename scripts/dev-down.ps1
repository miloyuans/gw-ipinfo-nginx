$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $root

$envFile = ".env.debug"
if (-not (Test-Path $envFile)) {
    $envFile = ".env.debug.example"
}

docker compose -f docker-compose.debug.yml --env-file $envFile down --remove-orphans

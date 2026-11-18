# start_desk.ps1 - launch ctfdesk with LLM credentials read from the existing
# Claude Code settings (no secret is stored in this file).
#
# Usage:
#   .\start_desk.ps1                       # watch loop, workers=3
#   .\start_desk.ps1 -Once                 # one round then exit (rehearsal)
#   .\start_desk.ps1 -Workers 2 -Budget 1200
param(
  [string]$Root = (Join-Path $env:USERPROFILE "ctf-desk"),
  [int]$Workers = 3,
  [int]$Budget = 900,
  [int]$Turns = 25,
  [switch]$Once,
  [string]$Python = "C:\Users\rjq\Downloads\strix-ctf-agent\.venv\Scripts\python.exe",
  [string]$LlmBase = "https://maas.qianwenaiapi.com/compatible-mode/v1",
  [string]$LlmModel = "deepseek-v4.1-flash"
)

$ErrorActionPreference = "Stop"

$token = $env:ANTHROPIC_AUTH_TOKEN
if (-not $token) {
  $settings = Join-Path $env:USERPROFILE ".claude\settings.json"
  if (Test-Path $settings) {
    $cfg = Get-Content $settings -Raw -Encoding UTF8 | ConvertFrom-Json
    $token = $cfg.env.ANTHROPIC_AUTH_TOKEN
  }
}
if (-not $token) {
  throw "no ANTHROPIC_AUTH_TOKEN in env or ~/.claude/settings.json"
}

$env:LLM_API_KEY = $token
$env:LLM_API_BASE = $LlmBase
$env:STRIX_LLM = "openai/$LlmModel"
$env:LITELLM_LOCAL_MODEL_COST_MAP = "True"
$env:STRIX_TELEMETRY = "false"
$env:STRIX_RUNTIME_BACKEND = "local"

$script = Join-Path $PSScriptRoot "ctfdesk.py"
$argsWatch = @($script, "watch", "--root", $Root, "--workers", "$Workers",
               "--budget", "$Budget", "--turns", "$Turns")
if ($Once) { $argsWatch += "--once" }

Write-Host "[start_desk] root=$Root workers=$Workers model=$LlmModel"
& $Python @argsWatch
exit $LASTEXITCODE
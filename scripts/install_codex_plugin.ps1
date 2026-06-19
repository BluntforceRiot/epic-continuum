param(
  [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
  [string]$Root = $(if ($env:CONTINUUM_ROOT) { $env:CONTINUUM_ROOT } else { Join-Path $HOME ".continuum" }),
  [string]$Python = $(if ($env:CONTINUUM_PYTHON) { $env:CONTINUUM_PYTHON } else { "python" }),
  [string]$StageRoot = $(if ($env:CONTINUUM_CODEX_MARKETPLACE_STAGE) { $env:CONTINUUM_CODEX_MARKETPLACE_STAGE } else { Join-Path $HOME ".cache\epic-continuum\codex-marketplace" }),
  [switch]$SkipLocalMcpConfig,
  [switch]$StageOnly
)

$ErrorActionPreference = "Stop"

$StageHelper = Join-Path $RepoRoot "scripts\stage_codex_plugin.py"
$stageArgs = @(
  $StageHelper,
  "--repo-root", $RepoRoot,
  "--root", $Root,
  "--python", $Python,
  "--stage-base", $StageRoot
)
if ($SkipLocalMcpConfig) {
  $stageArgs += "--skip-local-mcp-config"
}

$StageMarketplaceRoot = (& $Python @stageArgs | Select-Object -Last 1)
if ($LASTEXITCODE -ne 0) {
  exit $LASTEXITCODE
}
$StageMarketplaceRoot = [string]$StageMarketplaceRoot
$StageMarketplaceRoot = $StageMarketplaceRoot.Trim()

if (-not $StageOnly) {
  codex plugin marketplace add $StageMarketplaceRoot
  codex plugin add continuum@epic-continuum
}

Write-Host "Epic Continuum Codex plugin installed from staged marketplace: $(Join-Path $StageMarketplaceRoot '.agents\plugins\marketplace.json')"
Write-Host "Epic Continuum root: $Root"

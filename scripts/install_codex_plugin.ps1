param(
  [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
  [string]$Root = $(if ($env:CONTINUUM_ROOT) { $env:CONTINUUM_ROOT } else { Join-Path $HOME ".continuum" }),
  [string]$Python = $(if ($env:CONTINUUM_PYTHON) { $env:CONTINUUM_PYTHON } else { "python" }),
  [string]$StageRoot = $(if ($env:CONTINUUM_CODEX_MARKETPLACE_STAGE) { $env:CONTINUUM_CODEX_MARKETPLACE_STAGE } else { Join-Path $HOME ".cache\epic-continuum\codex-marketplace" }),
  [switch]$SkipLocalMcpConfig
)

$ErrorActionPreference = "Stop"

$MarketplaceJson = Join-Path $RepoRoot ".agents\plugins\marketplace.json"
$PluginSource = Join-Path $RepoRoot "plugins\continuum"
$ContinuumSrc = Join-Path $RepoRoot "src"

if (-not (Test-Path -LiteralPath $MarketplaceJson)) {
  throw "Marketplace file not found: $MarketplaceJson"
}

if (-not (Test-Path -LiteralPath $PluginSource)) {
  throw "Plugin source not found: $PluginSource"
}

if (Test-Path -LiteralPath $StageRoot) {
  Remove-Item -LiteralPath $StageRoot -Recurse -Force
}

$StageAgents = Join-Path $StageRoot ".agents\plugins"
$StagePlugins = Join-Path $StageRoot "plugins"
$StagePlugin = Join-Path $StagePlugins "continuum"
$StageMcpJson = Join-Path $StagePlugin ".mcp.json"

New-Item -ItemType Directory -Force -Path $StageAgents | Out-Null
New-Item -ItemType Directory -Force -Path $StagePlugins | Out-Null
Copy-Item -LiteralPath $MarketplaceJson -Destination (Join-Path $StageAgents "marketplace.json")
Copy-Item -LiteralPath $PluginSource -Destination $StagePlugin -Recurse

if (-not $SkipLocalMcpConfig) {
  $mcp = [ordered]@{
    mcpServers = [ordered]@{
      continuum = [ordered]@{
        command = $Python
        args = @("-m", "continuum.mcp_server")
        env = [ordered]@{
          PYTHONPATH = $ContinuumSrc
          CONTINUUM_ROOT = $Root
        }
      }
    }
  }
  $mcp | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $StageMcpJson -Encoding UTF8
}

codex plugin marketplace add $StageRoot
codex plugin add continuum@epic-continuum

Write-Host "Epic Continuum Codex plugin installed from staged marketplace: $(Join-Path $StageAgents 'marketplace.json')"
Write-Host "Epic Continuum root: $Root"

param(
    [string]$Root = $(if ($env:CONTINUUM_ROOT) { $env:CONTINUUM_ROOT } else { Join-Path $HOME ".continuum" }),
    [string]$HermesHome = "$env:LOCALAPPDATA\hermes",
    [string]$Python = $(if ($env:CONTINUUM_PYTHON) { $env:CONTINUUM_PYTHON } else { "python" }),
    [int]$TokenBudget = 1800,
    [switch]$SkipEnable,
    [switch]$DryRun,
    [switch]$SetDefaultModel,
    [string]$ModelAlias = "",
    [string]$ModelName = "",
    [string]$ModelProvider = "custom",
    [string]$BaseUrl = "",
    [string]$ApiKey = "",
    [string]$ApiKeyEnv = "",
    [int]$ContextLength = 0,
    [int]$MaxTokens = 0
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$ContinuumSrc = Join-Path $RepoRoot "src"

$env:PYTHONPATH = $ContinuumSrc
$argsList = @(
    "-m", "continuum",
    "install-hermes-adapter",
    "--root", $Root,
    "--hermes-home", $HermesHome,
    "--continuum-src", $ContinuumSrc,
    "--token-budget", [string]$TokenBudget
)

if ($SkipEnable) { $argsList += "--skip-enable" }
if ($DryRun) { $argsList += "--dry-run" }
if ($SetDefaultModel) { $argsList += "--set-default-model" }
if ($ModelAlias) { $argsList += @("--model-alias", $ModelAlias) }
if ($ModelName) { $argsList += @("--model-name", $ModelName) }
if ($ModelProvider) { $argsList += @("--model-provider", $ModelProvider) }
if ($BaseUrl) { $argsList += @("--base-url", $BaseUrl) }
if ($ApiKey) {
    if ($ApiKey -notin @("none", "null", "false")) {
        throw "Refusing -ApiKey with a secret-looking value; use -ApiKeyEnv NAME or Hermes protected secrets instead."
    }
    $argsList += @("--api-key", $ApiKey)
}
if ($ApiKeyEnv) { $argsList += @("--api-key-env", $ApiKeyEnv) }
if ($ContextLength -gt 0) { $argsList += @("--context-length", [string]$ContextLength) }
if ($MaxTokens -gt 0) { $argsList += @("--max-tokens", [string]$MaxTokens) }

& $Python @argsList

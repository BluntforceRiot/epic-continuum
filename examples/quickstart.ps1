$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent $PSScriptRoot
$root = if ($env:CONTINUUM_ROOT) { $env:CONTINUUM_ROOT } else { Join-Path $HOME ".continuum-demo" }
$env:PYTHONPATH = "$repo\src"

python -m continuum init --root $root
python -m continuum append-event --root $root --session-id demo --role user --type message --content "Continuum starts with a Scroll."
python -m continuum append-event --root $root --session-id demo --role assistant --type message --content "The Looking Glass sees only the active pane."
python -m continuum status --root $root

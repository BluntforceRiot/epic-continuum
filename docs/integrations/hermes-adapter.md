# Hermes Adapter

Epic Continuum ships a Hermes user plugin named `epic_continuum`.

The adapter is model-agnostic. It listens to Hermes turn hooks, writes user and
assistant turns into the Scroll, and injects a bounded Looking Glass packet into
the next model call. The model itself can be Qwen, Nous, OpenAI, Anthropic, or
any OpenAI-compatible local endpoint that Hermes supports.

## Install

```powershell
$repo = "$PWD"
$env:PYTHONPATH = "$repo\src"
$env:CONTINUUM_ROOT = "$HOME\.continuum"
python -m continuum install-hermes-adapter `
  --root $env:CONTINUUM_ROOT `
  --hermes-home "$env:LOCALAPPDATA\hermes" `
  --continuum-src "$repo\src"
```

```bash
export REPO_ROOT="$PWD"
export PYTHONPATH="$REPO_ROOT/src"
export CONTINUUM_ROOT="$HOME/.continuum"
python -m continuum install-hermes-adapter \
  --root "$CONTINUUM_ROOT" \
  --hermes-home "${HERMES_HOME:-$HOME/.hermes}" \
  --continuum-src "$REPO_ROOT/src"
```

The installer copies the plugin to:

```text
%LOCALAPPDATA%\hermes\plugins\epic_continuum
```

and writes:

```text
continuum_adapter.local.json
```

Hermes can then load it with:

```powershell
hermes plugins enable epic_continuum
```

## Model Routing

Routing a local model to Hermes is separate from Continuum. For any
OpenAI-compatible endpoint, the clean Hermes shape is:

```yaml
model:
  default: "your-local-model"
  provider: "custom"
  api_key: "none"
  base_url: "http://127.0.0.1:8000/v1"
  context_length: 16384
  max_tokens: 2048
```

The repo includes examples under:

```text
integrations/hermes/model-profiles
```

Installer return payloads and generated model-profile snippets redact API keys.
Do not pass real cloud keys directly on the command line. Use Hermes' protected
secret flow when available, or provide an environment variable name with
`install-hermes-adapter --set-default-model --api-key-env HERMES_API_KEY`.
Continuum does not pass secret API keys to `hermes config set model.api_key`
through subprocess argv; it reports that step as skipped so the key cannot leak
through process inspection or shell history.

## Context Window Reality

`context_length` is the native window Hermes should expect from the model
server. Epic Continuum can make the effective working memory much larger by
retrieving and compressing old Scroll/Card material, but it does not change how
many tokens the model attends to in one inference.

To truly raise a local Qwen/vLLM context from 16K to 32K or 64K, the model,
RoPE/scaling configuration, vLLM `max_model_len`, and KV cache budget all need
to support it. Continuum should then be given a larger injection budget, but the
model route should still report the real tested native limit.

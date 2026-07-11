# Local Yarn/Qwythos With llama.cpp

Epic Continuum 0.3 can ask a local Qwythos v3 model for a short recovery
briefing. The briefing is optional, citation-bound, and explicitly
non-authoritative. The deterministic Looking Glass packet remains the recovery
source of truth and is returned unchanged when the server is offline or refused.

## Recommended model

Use the fixed v3 `Q4_K_M` GGUF from
[empero-ai/Qwythos-9B-Claude-Mythos-5-1M-GGUF](https://huggingface.co/empero-ai/Qwythos-9B-Claude-Mythos-5-1M-GGUF).
If the file was downloaded before the model card announced v3, download it
again. The Q4 file is about 5.6 GB and is the compatibility-oriented default.

Qwythos advertises a 1M-token YaRN window, but that is not a safe everyday
workstation default. Continuum starts at 16K. A machine with 32 GB VRAM and
roughly 64 GB system RAM can reasonably test 32K; increase it only after checking
headroom and stability. Keep temperature above `0.3`; the model publisher warns
that lower settings can loop.

## Start one safe local slot

Continuum does not install, start, stop, download, or reconfigure llama.cpp. Run
the server yourself so an agent cannot unexpectedly allocate the GPU.
The current [llama.cpp server documentation](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
documents the `/v1/health` alias, `/v1/models`, `/v1/chat/completions`,
`--alias`, and `--parallel` surfaces used by this adapter.

```powershell
llama-server `
  -hf empero-ai/Qwythos-9B-Claude-Mythos-5-1M-GGUF:Q4_K_M `
  --alias continuum-qwythos-q4 `
  --host 127.0.0.1 `
  --port 8080 `
  --ctx-size 16384 `
  --parallel 1 `
  --no-mmproj
```

The stable `--alias` matters: llama.cpp otherwise reports the local model path
as its API model ID. `--no-mmproj` avoids loading the vision projector because
Continuum sends text-only recovery evidence.

For this workstation's RTX 5090, test 32K by changing both `--ctx-size 32768`
and the configuration command below to `--max-input-tokens 32768`.

## Configure and verify Continuum

```powershell
continuum yarn-configure `
  --root "$HOME\.continuum" `
  --enable `
  --base-url http://127.0.0.1:8080/v1 `
  --model continuum-qwythos-q4 `
  --max-input-tokens 16384

continuum yarn-health --root "$HOME\.continuum"
continuum resume --root "$HOME\.continuum" --model-assist
```

With the default 16K input window and 768-token output allowance,
`yarn-configure` records a 9,080-token safe context ceiling. Continuum reserves
the balance for output, the serialized briefing schema, up to 100 bounded
evidence aliases, and representative quote/backslash expansion when generated
JSON/Markdown passes through both serialization layers. Smaller windows reduce
the alias limit when needed; larger windows are also capped by the unchanged
256 KiB request limit. The exact transformed request is still checked, and
unusually expansion-heavy input at or below the ceiling is trimmed with an
explicit notice to the largest exact fit. Input above the configured ceiling,
or a fixed request envelope that cannot fit, falls back deterministically.

`yarn-configure` also enables personal resume assistance. Disable it without
removing the profile:

```powershell
continuum yarn-configure --root "$HOME\.continuum" --no-enable
```

Or control personal behavior separately:

```powershell
continuum configure-profile `
  --root "$HOME\.continuum" `
  --name homelab `
  --resume-mode latest_project `
  --default-project-id epic-continuum `
  --assist-on-resume
```

Leave the Yarn-derived safe ceiling in place unless you are lowering it.

## Safety boundary

- The feature is disabled by default and uses no network while disabled.
- The default endpoint must be a literal loopback address with the `/v1` path.
- Remote endpoints require an explicit opt-in and HTTPS.
- Continuum checks `/v1/health`, exact model identity, input plus output budget,
  total wall-clock deadline, response type, response size, and schema. RAM/VRAM
  minimums are enforced when the host can measure them; unavailable measurements
  are reported as advisory rather than guessed safe.
- A process-local gate permits one inference per Continuum process. Keep
  llama.cpp at `--parallel 1` to enforce the one-slot boundary at the server too;
  a busy or unhealthy model falls back.
- Outbound evidence is already project/session scoped and is secret-redacted.
- The model must echo the request nonce and evidence hash and cite only supplied
  evidence IDs. Model output is scanned again before it is returned.
- No raw prompt or response is persisted by this adapter.
- Yarn cannot mutate Scroll, Cards, graph routes, files, or recovery authority.

If `yarn-health` reports low headroom, a circuit-open endpoint, or a model-ID
mismatch, leave deterministic recovery in place and correct the server before
trying again.

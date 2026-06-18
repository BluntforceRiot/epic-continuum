# Contributing

Thanks for taking a look at Epic Continuum.

## Development Setup

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip "setuptools>=77"
python -m pip install -e .
python -m unittest discover -s tests -v
```

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip "setuptools>=77"
python -m pip install -e .
python -m unittest discover -s tests -v
```

## Pull Request Checklist

- Keep durable memory and source code paths configurable.
- Do not add a network dependency to the core package without a strong reason.
- Preserve raw evidence unless a command is explicitly destructive and guarded.
- Add or update tests for storage, recovery, bundle verification, and adapter
  behavior when changing those contracts.
- Run `python -m unittest discover -s tests -v` before submitting.

## Design Notes

Epic Continuum is intended to sit beside existing memory tools, not replace
every one of them. Adapters should stay thin; the CLI/MCP/Python core owns the
durable memory, recovery, verification, and policy behavior.

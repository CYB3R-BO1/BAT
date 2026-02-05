# BAT — Autonomous Vulnerability Investigator for C Memory Bugs

Lightweight Python tool that scans C projects for common memory vulnerabilities (use-after-free, buffer overflows, integer overflows) and generates evidence-backed reports and suggested patches.

## Quick start

1. Create a virtual environment and install dependencies:

```bash
python -m venv .venv
.\.venv\Scripts\activate
python -m pip install -r requirements.txt
```

2. Run the scanner on a C project:

```bash
python -m BAT.cli scan path/to/c/project -o output
```

Reports are generated in `output/` as `report.json` and `report.md`.

## Development

- Run unit tests (if any):

```bash
python -m pytest
```

## Files

- `BAT/` — main package
- `test_project/` — example vulnerable code used for local testing
- `output/` — default output directory (ignored by git)

## License

MIT. See `LICENSE`.

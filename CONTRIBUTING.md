# Contributing to AgenticNet

Thank you for contributing to **AgenticNet**! We welcome contributions from networking engineers, students, educators, and AI tooling developers.

## Development Setup

1. Ensure Python 3.11+ is installed.
2. Clone the repository and install development dependencies:
   ```bash
   pip install -e .[dev]
   ```
3. Run tests and linting before submitting a pull request:
   ```bash
   pytest
   ruff check agenticnet netforge tests scripts
   ```

## Architectural Standards

- **Keep Packet Tracer GUI concerns decoupled**: Core topology, IPAM, IOS generation, and storage must run cleanly offline on Linux, macOS, and Windows without importing Win32 or GUI dependencies.
- **No fake implementations**: Do not register empty placeholder MCP tools. Every tool exposed in `agenticnet/mcp/` must have real tested behavior.
- **Never swallow errors or lie about state**: Respect `StateLevel.PLANNED`, `StateLevel.EXECUTED`, and `StateLevel.VERIFIED`.
- **Never commit Cisco proprietary binaries or `.pkt` files with copyrighted assets.**
- **Add unit tests** under `tests/unit/` for every new device profile, IOS feature, or MCP tool.

## Pull Request Process

1. Create a topic branch from `main`.
2. Update `CHANGELOG.md` and relevant docs in `docs/`.
3. Verify `pytest` and `ruff check agenticnet netforge tests scripts` pass cleanly.
4. Submit a clear PR using `.github/PULL_REQUEST_TEMPLATE.md`.

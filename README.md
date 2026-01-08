# Merklin

Merklin is a tamper-proof logging system.

## Directory Structure

- `client`: The client library, `arthur`.
- `server`: The server application, `merklin`.
- `merkle-tree`: An internal library for creating Merkle trees.

## Installation

This project uses `uv` for dependency management.

### For development

It is recommended to use the local paths for dependencies for development. The `pyproject.toml` files are already configured for this.

```bash
# Within respective project directories
uv sync
source .venv/bin/activate
```
Open your editor of choice and code away. Run the black formatter before commiting

### For production/git-based installs

To install the packages from git, you can use the following commands.

```bash
# To add the client as a dependency to your project
uv add 'arthur @ git+https://github.com/TotalyEnglizLitrate/merklin#subdirectory=client'

# To install the server into a uv managed environment
uv pip install 'merklin @ git+https://github.com/TotalyEnglizLitrate/merklin#subdirectory=server'
```

## Usage
Refer to the respective READMEs for usage

The `merkle-tree` dependency will be handled automatically by `pip`.

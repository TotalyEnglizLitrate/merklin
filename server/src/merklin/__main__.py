from dotenv import load_dotenv

import typer

from pathlib import Path
from typing import Annotated

app = typer.Typer()


@app.command()
def run(
    env_file: Annotated[
        Path,
        typer.Option(
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
            help="Path to the .env file to load environment variables from.",
        ),
    ] = Path(".env"),
):
    """Run the Merklin server."""
    load_dotenv(dotenv_path=env_file)
    from .app import main

    main()

app()
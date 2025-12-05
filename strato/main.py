"""
Entry Point.
This is the root of the CLI command tree. It should not contain business logic.
It aggregates sub-applications (like s3_app) into the main Typer app.
"""

import typer

from strato.services.s3.cli import s3_app

app = typer.Typer(help="Strato: AWS Auditor")
app.add_typer(s3_app, name="s3")

if __name__ == "__main__":
    app()

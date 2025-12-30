import typer

from strato.services.s3.cli import s3_app

app = typer.Typer(help="Strato: AWS Auditor")
app.add_typer(s3_app, name="s3")

if __name__ == "__main__":
    app()

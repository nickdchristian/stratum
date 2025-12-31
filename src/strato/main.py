import typer

from strato.services.ec2.cli import ec2_app
from strato.services.s3.cli import s3_app

app = typer.Typer(help="Strato: AWS Auditor")
app.add_typer(s3_app, name="s3")
app.add_typer(ec2_app, name="ec2")

if __name__ == "__main__":
    app()

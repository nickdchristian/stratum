import typer
from .security import app as security_app

s3_app = typer.Typer(help="S3 Audit Commands")

s3_app.add_typer(security_app, name="security")

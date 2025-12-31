import typer

from strato.services.s3.cli import inventory, security

s3_app = typer.Typer(help="S3 Auditing & Inventory")

s3_app.add_typer(security.app, name="security")
s3_app.add_typer(inventory.app, name="inventory")

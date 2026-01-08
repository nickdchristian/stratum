import typer

from strato.services.awslambda.cli import inventory

lambda_app = typer.Typer(help="Lambda Auditing & Inventory")
lambda_app.add_typer(inventory.app, name="inventory")

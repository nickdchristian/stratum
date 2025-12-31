import typer

from strato.services.ec2.cli import inventory

ec2_app = typer.Typer(help="EC2 Auditing & Inventory")
ec2_app.add_typer(inventory.app, name="inventory")

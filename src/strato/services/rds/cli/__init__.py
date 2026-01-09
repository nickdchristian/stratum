import typer

from strato.services.rds.cli import inventory, reserved

rds_app = typer.Typer(help="RDS Auditing & Inventory")
rds_app.add_typer(inventory.app, name="inventory")
rds_app.add_typer(reserved.app, name="reserved")

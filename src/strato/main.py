import typer

from strato.services.awslambda.cli import lambda_app
from strato.services.ec2.cli import ec2_app
from strato.services.rds.cli import rds_app
from strato.services.s3.cli import s3_app

app = typer.Typer(help="Strato: AWS Auditor")
app.add_typer(s3_app, name="s3")
app.add_typer(ec2_app, name="ec2")
app.add_typer(lambda_app, name="lambda")
app.add_typer(rds_app, name="rds")

if __name__ == "__main__":
    app()

import typer

app = typer.Typer()


@app.command()
def main() -> None:
    typer.echo("Hello from main")


if __name__ == "__main__":
    app()

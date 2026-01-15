from pathlib import Path

import click


@click.group()
def cli():
    """Python Cedar CLI"""
    pass


@cli.command()
def mcp():
    """Run the Cedar MCP server for AI coding assistants."""
    from cedar.mcp import mcp as mcp_server

    mcp_server.run()


@cli.group()
def schema():
    """Cedar Schema Commands"""
    pass


@schema.command(name="validate")
@click.argument(
    "policy_file", type=click.Path(exists=True, file_okay=True, dir_okay=False)
)
@click.argument(
    "schema_file", type=click.Path(exists=True, file_okay=True, dir_okay=False)
)
def validate_policy(policy_file: Path, schema_file: Path):
    """Validate a Cedar policy against a Cedar schema"""
    from cedar import PolicySet, Schema

    policy_file = Path(policy_file)
    schema_file = Path(schema_file)

    # Read policy file
    with open(policy_file, "r") as f:
        policy_text = f.read()

    # Read schema file - handle both JSON and Cedar schema formats
    schema_file_ext = schema_file.suffix.lower()
    try:
        if schema_file_ext == ".json":
            with open(schema_file, "r") as f:
                schema = Schema.from_json(f.read())
        elif schema_file_ext == ".cedarschema":
            click.echo(f"Parsing Cedar schema file: {schema_file}")
            with open(schema_file, "r") as f:
                schema = Schema.from_cedarschema(f.read())
        else:
            click.echo(
                f"Error: Unsupported schema file extension: {schema_file_ext}. "
                "Supported: .json, .cedarschema",
                err=True,
            )
            raise SystemExit(1)
    except ValueError as e:
        click.echo(f"Error: Failed to parse schema: {e}", err=True)
        raise SystemExit(1)

    # Parse policy set
    try:
        policies = PolicySet(policy_text)
    except ValueError as e:
        click.echo(f"Error: Failed to parse policies: {e}", err=True)
        raise SystemExit(1)

    # Validate policy against schema
    result = schema.validate_policyset(policies)
    error_count = len(result.errors)
    warning_count = len(result.warnings)

    if result.valid:
        click.echo("Policy validation passed!")
        if warning_count > 0:
            click.echo(
                f"Warning: Policy validation passed with {warning_count} warning(s)",
                err=True,
            )
            for warning in result.warnings:
                click.echo(f"  - {warning}", err=True)
    else:
        click.echo(
            f"Error: Policy validation failed with {error_count} error(s)",
            err=True,
        )
        for error in result.errors:
            click.echo(f"  - {error}", err=True)

    # Print summary
    click.echo(f"Validation summary: {error_count} errors, {warning_count} warnings")

    # Exit with appropriate code
    raise SystemExit(0 if result.valid else 1)

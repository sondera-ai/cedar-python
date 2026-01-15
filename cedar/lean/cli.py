"""Simplified Cedar CLI interface."""

import os
import subprocess

from pydantic_settings import BaseSettings


class EnvSettings(BaseSettings):
    """Environment settings."""

    lean_cli_path: str = "~/.cargo/bin/cedar-lean-cli"
    lean_lib_dir: str = "~/.elan/toolchains/leanprover--lean4---v4.24.0/lib/lean"
    dyld_library_path: str = "~/.elan/toolchains/leanprover--lean4---v4.24.0/lib/lean"
    ld_library_path: str = "~/.elan/toolchains/leanprover--lean4---v4.24.0/lib/lean"
    cvc5: str = "~/.local/bin/cvc5"


def cedar_lean_cli(
    command: str,
    subcommand: str,
    *positional: str,
    settings: EnvSettings = EnvSettings(),
    **kwargs,
) -> subprocess.CompletedProcess[str]:
    """Run cedar-lean-cli with the given command and arguments."""
    env = {
        "LEAN_LIB_DIR": os.path.expanduser(settings.lean_lib_dir),
        "DYLD_LIBRARY_PATH": os.path.expanduser(settings.dyld_library_path),
        "LD_LIBRARY_PATH": os.path.expanduser(settings.ld_library_path),
        "CVC5": os.path.expanduser(settings.cvc5),
    }
    cli_path = os.path.expanduser(settings.lean_cli_path)
    cmd = [cli_path] + _build_cli_args(command, subcommand, list(positional), **kwargs)
    result = subprocess.run(cmd, capture_output=True, text=True, check=False, env=env)
    return result


def _build_cli_args(
    command: str, subcommand: str, positional: list[str] | None = None, **kwargs
) -> list[str]:
    """Build CLI arguments from parameters."""
    args = [command, subcommand]

    for key, value in kwargs.items():
        if value is None:
            continue
        flag = f"--{key.replace('_', '-')}"
        if isinstance(value, bool):
            if value:
                args.append(flag)
        else:
            args.extend([flag, str(value)])

    if positional:
        args.extend(positional)

    return args

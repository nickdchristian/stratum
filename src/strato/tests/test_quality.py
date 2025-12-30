import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parents[3]


def test_ruff_formatting():
    """
    Verifies that the project code complies with ruff formatting rules.
    Fails if 'ruff format --check' returns a non-zero exit code.
    """
    try:
        subprocess.run(
            [sys.executable, "-m", "ruff", "format", "--check", "."],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.decode() if e.stderr else e.stdout.decode()
        pytest.fail(
            f"Ruff formatting check failed. Run 'ruff format .'\nOutput:\n{error_msg}"
        )


def test_ruff_linting():
    """
    Verifies that the project code passes ruff linting checks.
    Fails if 'ruff check' returns a non-zero exit code.
    """
    try:
        subprocess.run(
            [sys.executable, "-m", "ruff", "check", "."],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as e:
        error_msg = e.stdout.decode()
        pytest.fail(
            f"Ruff linting check failed. Run 'ruff check --fix .'\nOutput:\n{error_msg}"
        )

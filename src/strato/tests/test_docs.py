import subprocess
from pathlib import Path

import pytest

DOC_FILE = Path("CLI.md")
APP_MODULE = "strato.main"
APP_NAME = "sto"


def test_cli_docs_are_up_to_date(tmp_path):
    """
    Verifies that CLI.md matches the current CLI implementation.
    """

    generated_file = tmp_path / "temp_generated_docs.md"

    result = subprocess.run(
        [
            "uv",
            "run",
            "typer",
            APP_MODULE,
            "utils",
            "docs",
            "--name",
            APP_NAME,
            "--output",
            str(generated_file),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, f"Doc generation failed: {result.stderr}"

    if not DOC_FILE.exists():
        pytest.fail(
            f"File {DOC_FILE} not found. "
            f"Run: uv run typer {APP_MODULE} utils docs "
            f"--name {APP_NAME} --output {DOC_FILE}"
        )

    actual_content = DOC_FILE.read_text()
    generated_content = generated_file.read_text()

    assert actual_content == generated_content, (
        f"{DOC_FILE} is out of sync.\n"
        f"Run: uv run typer {APP_MODULE} utils docs "
        f"--name {APP_NAME} --output {DOC_FILE}"
    )

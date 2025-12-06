# Strato (sto)

**Strato** is an extensible, opinionated command-line interface (CLI) for auditing AWS infrastructure.

Built with **Python**, **Typer**, and **Boto3**, Strato provides a modular framework to scan AWS services for specific risks and inefficiencies.

## Core Capabilities

* **Multi-Domain Architecture:** A unified interface designed to support diverse auditing domains.
* **Extensible Architecture:** Built on a modular design, allowing seamless addition of new services without altering core logic.
* **Read-Only Operations:** Strictly read-only analysis. Strato scans resources but never modifies configurations.

## Currently Supported Services

* **S3:** Security auditing (Public Access, Encryption)

## Prerequisites

* **uv:** [Install uv](https://docs.astral.sh/uv/getting-started/installation/) (Required for dependency management and building).
* **Python 3.14+**
* **AWS Credentials:** You must have active credentials configured in your environment (e.g., `~/.aws/credentials` or via `AWS_PROFILE`).

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/nickdchristian/strato.git
    cd strato
    ```

2.  **Sync dependencies and install locally:**
    This command creates the virtual environment and installs the CLI in editable mode automatically.
    ```bash
    uv sync
    ```

3.  **Activate the environment:**
    ```bash
    source .venv/bin/activate
    # Or on Windows: .venv\Scripts\activate
    ```

4.  **Verify installation:**
    ```bash
    sto --help
    ```

    *Alternatively, you can run commands without activating the shell using `uv run`:*
    ```bash
    uv run sto --help
    ```

## Usage

See **[CLI.md](CLI.md)** for CLI documentation.
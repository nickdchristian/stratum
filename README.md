# Strato (sto)

**Strato** is an extensible, opinionated command-line interface (CLI) for auditing AWS infrastructure.

Built with **Python**, **Typer**, and **Boto3**, Strato provides a modular framework to scan AWS services for specific risks and inefficiencies without the overhead of heavy compliance platforms.

## Core Capabilities

* **Multi-Domain Architecture:** A unified interface designed to support diverse auditing domains. While currently focused on security and cost, the framework is built to expand into compliance, operations, and reliability checks.
* **Extensible Architecture:** Built on a modular design, allowing seamless addition of new services without altering core logic.
* **Safe Defaults:** Strictly read-only operations. Strato analyzes resources but never modifies configurations.
* **Developer-First Output:** Clean, structured terminal output designed for quick scanning by engineers, not just auditors.

## Currently Supported Services

* **S3:** Security auditing (Public Access, Encryption)

## Prerequisites

* **uv:** [Install uv](https://docs.astral.sh/uv/getting-started/installation/) (Required for dependency management and building).
* **Python 3.14+**
* **AWS Credentials:** You must have active credentials configured in your environment (e.g., `~/.aws/credentials` or via `AWS_PROFILE`).

## Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/nickdchristian/strato.git](https://github.com/nickdchristian/strato.git)
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

Strato uses the `sto` command. Commands are structured by **Service** → **Domain** → **Check**.

### S3 Audits

**Run a full security audit:**
```bash
sto s3 security all
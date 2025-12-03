# Stratum (stm)

**Stratum** is an extensible, opinionated command-line interface (CLI) for auditing AWS infrastructure. It bridges the gap between security compliance and cloud cost optimization (FinOps).

Built with **Python**, **Typer**, and **Boto3**, Stratum provides a modular framework to scan AWS services for specific risks and inefficiencies without the overhead of heavy compliance platforms.

## Core Capabilities

* **Dual-Lens Audits:** A unified interface to toggle between `security` (compliance, access control) and `cost` (waste, optimization) checks.
* **Extensible Architecture:** Built on a plugin-based design, allowing seamless addition of new services (EC2, RDS, Lambda) without altering core logic.
* **Safe Defaults:** Strictly read-only operations. Stratum analyzes resources but never modifies configurations without explicit user intervention.
* **Developer-First Output:** Clean, structured terminal output designed for quick scanning by engineers, not just auditors.

## Currently Supported Services

* **S3:**

## Prerequisites

* **Python 3.10+**
* **AWS Credentials:** You must have active credentials configured in your environment (e.g., `~/.aws/credentials` or via `AWS_PROFILE`).

## Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/nickdchristian/stratum.git](https://github.com/nickdchristian/stratum.git)
    cd stratum
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install the CLI in editable mode:**
    *This allows you to modify the code and see changes immediately without reinstalling.*
    ```bash
    pip install -e .
    ```

4.  **Verify installation:**
    ```bash
    stm --help
    ```

## Usage

Stratum uses the `stm` command. Commands are structured by **Service** → **Domain**.

### S3 Audits

**Run a full audit (Security + Cost):**
```bash
stm s3 audit
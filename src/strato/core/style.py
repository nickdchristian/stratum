from enum import StrEnum


class AuditStatus(StrEnum):
    """
    Standardized status colors for security and audit scans.
    """

    PASS = "green"
    FAIL = "red"
    WARN = "yellow"
    INFO = "blue"


def colorize(text: str, status: AuditStatus) -> str:
    """
    Wraps text in Rich-compatible color tags based on the audit status.

    Args:
        text: The string to be colored.
        status: The AuditStatus enum value (e.g., AuditStatus.PASS).

    Returns:
        String formatted as '[color]text[/color]'
    """
    return f"[{status}]{text}[/{status}]"

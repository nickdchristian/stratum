from dataclasses import dataclass, asdict, field
from typing import List, Any, Dict

from strato.core.scoring import RiskWeight


@dataclass
class AuditResult:
    """
    Base data structure for any resource audit.
    Specific domains (e.g., S3, EC2) should inherit from this.
    """

    resource_arn: str
    resource_name: str
    region: str
    risk_score: int = 0
    risk_reasons: List[str] = field(default_factory=list)

    @property
    def has_risk(self) -> bool:
        """Returns True if the resource violates any checks."""
        return self.risk_score > 0

    @property
    def risk_level(self) -> str:
        """Maps the numeric risk score to a human-readable severity string."""
        if self.risk_score >= RiskWeight.CRITICAL:
            return "CRITICAL"
        if self.risk_score >= RiskWeight.HIGH:
            return "HIGH"
        if self.risk_score >= RiskWeight.MEDIUM:
            return "MEDIUM"
        if self.risk_score >= RiskWeight.LOW:
            return "LOW"
        return "SAFE"

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the object for JSON output."""
        return asdict(self)

    @classmethod
    def get_headers(cls, check_type: str = "ALL") -> List[str]:
        """Returns column headers for Table and CSV output."""
        return ["Resource", "Region", "Risk Level", "Reasons"]

    def get_table_row(self) -> List[str]:
        """
        Returns a list of strings formatted for the Rich Table library.
        Includes color tags (e.g., [red]CRITICAL[/red]).
        """
        risk_color_map = {
            "CRITICAL": "red",
            "HIGH": "orange",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "SAFE": "green",
        }
        color = risk_color_map.get(self.risk_level, "white")

        risk_level_render = f"[{color}]{self.risk_level}[/{color}]"
        risk_reasons_render = ", ".join(self.risk_reasons) if self.risk_reasons else "-"

        return [self.resource_name, self.region, risk_level_render, risk_reasons_render]

    def get_csv_row(self) -> List[str]:
        """
        Returns a raw list of strings for CSV output.
        Color tags are stripped/omitted.
        """
        risk_reasons_render = "; ".join(self.risk_reasons)
        return [self.resource_name, self.region, self.risk_level, risk_reasons_render]

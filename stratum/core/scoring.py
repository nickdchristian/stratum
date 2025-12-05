from enum import IntEnum


class RiskWeight(IntEnum):
    """
    Standardized Risk Weights for scoring audit results.

    The score is loosely calculated based on: Impact (1-10) * Likelihood (1-10).
    """

    # Impact: Catastrophic (Data Breach, Full Compromise)
    # Likelihood: High (Publicly accessible, Default credentials)
    CRITICAL = 100

    # Impact: High (Privileged access, Unencrypted sensitive data)
    # Likelihood: Medium (Requires internal network access or specific conditions)
    HIGH = 50

    # Impact: Medium (Configuration drift, Non-compliant settings)
    # Likelihood: Medium (Requires chained exploits)
    MEDIUM = 20

    # Impact: Low (Hygiene, Tagging, Informational)
    # Likelihood: Low or N/A
    LOW = 5

    NONE = 0

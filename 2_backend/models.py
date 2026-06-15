"""
PhishGuard — Pydantic Data Models
===================================
Strict type-validated schemas for all API boundaries.
FastAPI uses these models to auto-generate the OpenAPI/Swagger spec,
enforce request validation, and serialize responses consistently.

Requires: pydantic >= 2.0
"""

from typing import List, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Request Schemas
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    """
    Incoming JSON body for POST /scan.

    Example:
        {"url": "https://secure-login-paypa1.tk/verify?account=9912"}
    """

    url: str = Field(
        ...,
        min_length=10,
        max_length=2048,
        description="Fully-qualified URL to evaluate for phishing indicators.",
        examples=["https://secure-login-paypa1.tk/verify?account=9912"],
    )

    @field_validator("url")
    @classmethod
    def must_have_http_scheme(cls, v: str) -> str:
        """
        Reject URLs that are missing an explicit scheme.
        Catches bare domains, file:// paths, javascript: URIs, etc.
        """
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError(
                "URL must begin with 'http://' or 'https://'.  "
                f"Received: '{v[:60]}{'...' if len(v) > 60 else ''}'"
            )
        return v

    model_config = {
        "json_schema_extra": {
            "example": {"url": "https://secure-login-paypa1.tk/verify"}
        }
    }


# ---------------------------------------------------------------------------
# Response Schemas
# ---------------------------------------------------------------------------

class ScanResponse(BaseModel):
    """
    Consolidated phishing threat report returned by POST /scan.

    Fields
    ------
    url               : The URL that was scanned (echoed from the request).
    is_phishing       : True when the model + CTI signals classify the URL as
                        phishing (confidence_score >= 0.50).
    confidence_score  : Probability output of the ML classifier — ranges from
                        0.0 (definitely clean) to 1.0 (definitely phishing).
    cti_matches       : Human-readable strings describing each CTI finding
                        (VirusTotal flags, URLhaus hits, suspicious WHOIS age, etc.).
    execution_time_ms : Total server-side wall-clock time for the scan in ms.
    """

    url: str = Field(description="The scanned URL, echoed from the request body")

    is_phishing: bool = Field(
        description="True if the URL is classified as a phishing threat"
    )

    confidence_score: float = Field(
        ge=0.0,
        le=1.0,
        description=(
            "ML model probability estimate: 0.0 = clean, 1.0 = phishing. "
            "is_phishing is True when this value >= 0.50."
        ),
    )

    cti_matches: List[str] = Field(
        default_factory=list,
        description=(
            "Ordered list of threat-intel findings. "
            "Empty list means no external CTI signals were triggered."
        ),
    )

    execution_time_ms: float = Field(
        description="Wall-clock processing time for the entire request, in milliseconds"
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "url": "https://secure-login-paypa1.tk/verify",
                "is_phishing": True,
                "confidence_score": 0.9312,
                "cti_matches": [
                    "VirusTotal: Flagged as malicious by 9/72 AV engines",
                    "URLhaus: Active phishing campaign detected",
                    "WHOIS: Newly registered domain — only 3 day(s) old (high risk)",
                ],
                "execution_time_ms": 187.42,
            }
        }
    }


class HealthResponse(BaseModel):
    """Response schema for GET /health — liveness and readiness probe."""

    status: str = Field(
        description="'operational' if all systems are healthy, 'degraded' otherwise"
    )
    version: str = Field(description="API + model version identifier")
    model_loaded: bool = Field(description="True when the ML model is in memory")
    uptime_seconds: Optional[float] = Field(
        default=None,
        description="Seconds elapsed since the API process started"
    )

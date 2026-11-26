from pydantic import BaseModel, Field
from typing import Optional, Literal

class Finding(BaseModel):
    finding_id: str
    title: str
    vulnerability_type: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] = "MEDIUM"
    file_path: str = ""
    line_number: Optional[int] = None
    cwe: Optional[str] = None
    evidence: str = ""
    explanation: str = ""
    remediation: str = ""
    confidence: float = Field(default=0.5, ge=0, le=1)
    validation_status: str = "Needs review"
    detection_engine: str = ""
    references: list[str] = Field(default_factory=list)
    risk_score: float = 0

class ScanReport(BaseModel):
    scan_id: str
    files_scanned: int
    findings_count: int
    summary: dict[str, int]
    findings: list[Finding]
    warnings: list[str] = Field(default_factory=list)

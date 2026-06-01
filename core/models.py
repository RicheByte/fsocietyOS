"""Data models for structured results from fsociety-reborn tools."""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Dict, Any, Optional
import json


@dataclass
class Finding:
    """Represents a single security finding."""
    title: str
    description: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    finding_type: str  # vulnerability, info, config_issue, etc.
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        d = asdict(self)
        d['timestamp'] = self.timestamp.isoformat()
        return d


@dataclass
class ScanResult:
    """Represents the complete result of a tool scan."""
    tool: str
    target: str
    timestamp: datetime = field(default_factory=datetime.now)
    status: str = "completed"  # completed, failed, partial
    findings: List[Finding] = field(default_factory=list)
    risk_level: str = "INFO"  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    raw_output: str = ""
    error_message: Optional[str] = None
    execution_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the results."""
        self.findings.append(finding)
        # Update overall risk level based on findings
        self._update_risk_level()
    
    def add_finding_dict(self, title: str, description: str, severity: str, 
                        finding_type: str, details: Dict[str, Any] = None) -> None:
        """Helper to add finding using simple parameters."""
        if details is None:
            details = {}
        finding = Finding(
            title=title,
            description=description,
            severity=severity,
            finding_type=finding_type,
            details=details
        )
        self.add_finding(finding)
    
    def _update_risk_level(self) -> None:
        """Update overall risk level based on findings."""
        if not self.findings:
            self.risk_level = "INFO"
            return
        
        severity_hierarchy = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        max_severity = max(
            severity_hierarchy.get(f.severity, 0) for f in self.findings
        )
        
        reverse_map = {5: "CRITICAL", 4: "HIGH", 3: "MEDIUM", 2: "LOW", 1: "INFO"}
        self.risk_level = reverse_map.get(max_severity, "INFO")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        d = asdict(self)
        d['timestamp'] = self.timestamp.isoformat()
        d['findings'] = [f.to_dict() for f in self.findings]
        return d
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    def save_to_file(self, filepath: str) -> None:
        """Save results to JSON file."""
        with open(filepath, 'w') as f:
            f.write(self.to_json())


@dataclass
class ToolConfig:
    """Configuration for a tool execution."""
    tool_name: str
    target: str
    timeout: int = 10
    retries: int = 3
    verbosity: int = 1  # 0=silent, 1=normal, 2=verbose, 3=debug
    proxy: Optional[str] = None
    use_tor: bool = False
    stealth_level: str = "normal"  # paranoid, sneaky, normal, aggressive, insane
    extra_args: Dict[str, Any] = field(default_factory=dict)

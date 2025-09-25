"""
Core Data Models for Zodiac Security Analyzer
Pydantic models for data validation and serialization
"""

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any, Set
from pydantic import BaseModel, Field, validator
import hashlib


class FindingCategory(str, Enum):
    """Finding validation categories"""
    TRUE_POSITIVE = "TP"
    DYNAMIC_CHECK = "DC"
    FALSE_POSITIVE = "FP"
    UNKNOWN = "UNK"


class Severity(str, Enum):
    """Security finding severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AnalysisPhase(str, Enum):
    """Analysis pipeline phases"""
    INITIALIZATION = "initialization"
    DECOMPILATION = "decompilation"
    SOURCE_INDEXING = "source_indexing"
    SCANNING = "scanning"
    VALIDATION = "validation"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"


class SourceContext(BaseModel):
    """Source code context for a finding"""
    file_path: str
    line_number: Optional[int] = None
    code_snippet: str
    method_context: Optional[str] = None
    class_context: Optional[str] = None
    package_name: Optional[str] = None
    imports: List[str] = Field(default_factory=list)
    is_test_code: bool = False
    is_example_code: bool = False
    is_third_party: bool = False
    is_generated: bool = False
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    
    @validator('code_snippet')
    def limit_snippet_length(cls, v):
        """Limit code snippet to reasonable length"""
        max_length = 2000
        if len(v) > max_length:
            return v[:max_length] + "..."
        return v
    
    def get_context_summary(self) -> str:
        """Get a summary of the context"""
        parts = []
        if self.package_name:
            parts.append(f"Package: {self.package_name}")
        if self.class_context:
            parts.append(f"Class: {self.class_context}")
        if self.method_context:
            parts.append(f"Method: {self.method_context}")
        return " | ".join(parts) if parts else "No context available"


class Finding(BaseModel):
    """Security finding model"""
    finding_id: str = Field(default_factory=lambda: hashlib.md5(
        str(datetime.now()).encode()).hexdigest()[:12])
    rule_id: str
    title: str
    description: str
    severity: Severity
    category: Optional[str] = None
    
    # Location
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    column_number: Optional[int] = None
    
    # Standards mapping
    cwe: Optional[str] = None
    owasp_mobile: Optional[str] = None
    owasp_top10: Optional[str] = None
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    
    # Detection metadata
    engine: str = "mobsfscan"
    engine_version: Optional[str] = None
    detection_confidence: float = Field(0.5, ge=0.0, le=1.0)
    
    # Validation results
    source_context: Optional[SourceContext] = None
    validation_status: FindingCategory = FindingCategory.UNKNOWN
    validation_reason: Optional[str] = None
    validation_confidence: float = Field(0.0, ge=0.0, le=1.0)
    validation_timestamp: Optional[datetime] = None
    
    # Additional metadata
    raw_data: Optional[Dict[str, Any]] = None
    tags: Set[str] = Field(default_factory=set)
    remediation: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    
    def get_risk_score(self) -> float:
        """Calculate risk score based on severity and confidence"""
        severity_weights = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.5,
            Severity.LOW: 0.3,
            Severity.INFO: 0.1
        }
        base_score = severity_weights.get(self.severity, 0.5)
        
        # Adjust based on validation
        if self.validation_status == FindingCategory.TRUE_POSITIVE:
            multiplier = 1.0
        elif self.validation_status == FindingCategory.DYNAMIC_CHECK:
            multiplier = 0.7
        elif self.validation_status == FindingCategory.FALSE_POSITIVE:
            multiplier = 0.1
        else:
            multiplier = 0.5
            
        return base_score * multiplier * self.validation_confidence
    
    class Config:
        use_enum_values = True


class APKMetadata(BaseModel):
    """APK file metadata"""
    file_path: Path
    file_name: str
    file_size: int
    sha256_hash: str
    md5_hash: str
    package_name: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[int] = None
    min_sdk_version: Optional[int] = None
    target_sdk_version: Optional[int] = None
    permissions: List[str] = Field(default_factory=list)
    activities: List[str] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    receivers: List[str] = Field(default_factory=list)
    providers: List[str] = Field(default_factory=list)
    
    @classmethod
    def from_file(cls, file_path: Path) -> "APKMetadata":
        """Create metadata from APK file"""
        import hashlib
        
        with open(file_path, 'rb') as f:
            content = f.read()
            sha256 = hashlib.sha256(content).hexdigest()
            md5 = hashlib.md5(content).hexdigest()
        
        return cls(
            file_path=file_path,
            file_name=file_path.name,
            file_size=file_path.stat().st_size,
            sha256_hash=sha256,
            md5_hash=md5
        )


class DecompilationResult(BaseModel):
    """Result of APK decompilation"""
    success: bool
    source_dir: Optional[Path] = None
    decompiler_used: str
    duration_seconds: float
    java_files_count: int = 0
    smali_files_count: int = 0
    xml_files_count: int = 0
    total_files: int = 0
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    """Security scan results"""
    scanner: str
    scan_duration: float
    total_findings: int
    findings_by_severity: Dict[str, int] = Field(default_factory=dict)
    findings: List[Finding] = Field(default_factory=list)
    scan_timestamp: datetime = Field(default_factory=datetime.now)
    scan_config: Dict[str, Any] = Field(default_factory=dict)


class ValidationResult(BaseModel):
    """Finding validation results"""
    total_processed: int
    true_positives: List[Finding] = Field(default_factory=list)
    dynamic_checks: List[Finding] = Field(default_factory=list)
    false_positives: List[Finding] = Field(default_factory=list)
    unknown: List[Finding] = Field(default_factory=list)
    validation_duration: float
    average_confidence: float
    
    def get_summary(self) -> Dict[str, Any]:
        """Get validation summary statistics"""
        return {
            "total": self.total_processed,
            "tp_count": len(self.true_positives),
            "dc_count": len(self.dynamic_checks),
            "fp_count": len(self.false_positives),
            "unknown_count": len(self.unknown),
            "tp_rate": len(self.true_positives) / self.total_processed if self.total_processed > 0 else 0,
            "fp_rate": len(self.false_positives) / self.total_processed if self.total_processed > 0 else 0,
            "avg_confidence": self.average_confidence
        }


class AnalysisState(BaseModel):
    """Current state of analysis"""
    analysis_id: str = Field(default_factory=lambda: hashlib.md5(
        str(datetime.now()).encode()).hexdigest())
    apk_metadata: Optional[APKMetadata] = None
    current_phase: AnalysisPhase = AnalysisPhase.INITIALIZATION
    phases_completed: List[AnalysisPhase] = Field(default_factory=list)
    start_time: datetime = Field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    
    # Results
    decompilation_result: Optional[DecompilationResult] = None
    scan_result: Optional[ScanResult] = None
    validation_result: Optional[ValidationResult] = None
    
    # Metrics
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    files_analyzed: int = 0
    
    # Errors and warnings
    errors: List[Dict[str, Any]] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    
    def update_phase(self, phase: AnalysisPhase):
        """Update the current analysis phase"""
        self.current_phase = phase
        if phase not in self.phases_completed and phase != AnalysisPhase.FAILED:
            self.phases_completed.append(phase)
    
    def add_error(self, phase: str, error: str, details: Optional[Dict] = None):
        """Add an error to the state"""
        self.errors.append({
            "phase": phase,
            "error": error,
            "details": details or {},
            "timestamp": datetime.now().isoformat()
        })
    
    def finalize(self):
        """Finalize the analysis state"""
        self.end_time = datetime.now()
        self.duration_seconds = (self.end_time - self.start_time).total_seconds()
        if not self.errors:
            self.current_phase = AnalysisPhase.COMPLETED


class AgentMessage(BaseModel):
    """Message between agents"""
    sender: str
    receiver: str
    message_type: str
    content: Dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.now)
    correlation_id: Optional[str] = None
    
    
class ReportData(BaseModel):
    """Data for report generation"""
    analysis_state: AnalysisState
    executive_summary: Optional[str] = None
    risk_assessment: Optional[str] = None
    recommendations: List[str] = Field(default_factory=list)
    
    # Findings grouped by category
    critical_findings: List[Finding] = Field(default_factory=list)
    high_findings: List[Finding] = Field(default_factory=list)
    medium_findings: List[Finding] = Field(default_factory=list)
    low_findings: List[Finding] = Field(default_factory=list)
    
    # Statistics
    statistics: Dict[str, Any] = Field(default_factory=dict)
    
    # RAG insights
    ai_insights: Optional[Dict[str, Any]] = None
    
    def get_risk_level(self) -> str:
        """Determine overall risk level"""
        if self.critical_findings:
            return "CRITICAL"
        elif len(self.high_findings) > 5:
            return "HIGH"
        elif self.high_findings or len(self.medium_findings) > 10:
            return "MEDIUM"
        else:
            return "LOW"


class RAGDocument(BaseModel):
    """Document for RAG system"""
    doc_id: str = Field(default_factory=lambda: hashlib.md5(
        str(datetime.now()).encode()).hexdigest())
    content: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    doc_type: str  # code, finding, report, analysis
    source_file: Optional[str] = None
    chunk_index: Optional[int] = None
    embedding: Optional[List[float]] = None
    timestamp: datetime = Field(default_factory=datetime.now)
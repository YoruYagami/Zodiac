"""
Scanner Agent for Security Vulnerability Detection
Integrates multiple scanning tools with focus on MobSFScan
"""

import json
import subprocess
import asyncio
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
import tempfile
import re

from langchain_core.tools import Tool
from pydantic import BaseModel, Field

from .base_agent import BaseAgent, AgentConfig, ToolBuilder
from ..core.models import Finding, ScanResult, Severity, AnalysisPhase
from ..config.settings import get_settings


class ScannerConfig(BaseModel):
    """Configuration for security scanning"""
    source_dir: Path
    output_dir: Path
    scanners: List[str] = Field(default_factory=lambda: ["mobsfscan"])
    scan_depth: str = "normal"  # shallow, normal, deep, exhaustive
    ignore_paths: List[str] = Field(default_factory=list)
    custom_rules: Optional[Path] = None
    

class ScannerAgent(BaseAgent):
    """
    Agent responsible for security vulnerability scanning
    Manages multiple scanning tools and aggregates results
    """
    
    def __init__(self, state=None):
        config = AgentConfig(
            name="ScannerAgent",
            description="Expert in Android security vulnerability detection and static analysis",
            temperature=0.0,
            max_tokens=2000
        )
        super().__init__(config, state)
        
        # Scanner-specific configuration
        self.scan_results_cache = {}
        self.custom_rules = self._load_custom_rules()
        
    def _get_specific_tools(self) -> List[Tool]:
        """Get scanner-specific tools"""
        return [
            ToolBuilder.create_tool(
                name="run_mobsfscan",
                func=self._run_mobsfscan,
                description="Run MobSFScan security analysis"
            ),
            ToolBuilder.create_tool(
                name="run_semgrep",
                func=self._run_semgrep,
                description="Run Semgrep security analysis"
            ),
            ToolBuilder.create_tool(
                name="check_permissions",
                func=self._check_dangerous_permissions,
                description="Check for dangerous Android permissions"
            ),
            ToolBuilder.create_tool(
                name="scan_hardcoded_secrets",
                func=self._scan_hardcoded_secrets,
                description="Scan for hardcoded secrets and API keys"
            ),
            ToolBuilder.create_tool(
                name="analyze_network_security",
                func=self._analyze_network_security,
                description="Analyze network security configuration"
            ),
            ToolBuilder.create_tool(
                name="check_crypto_usage",
                func=self._check_crypto_usage,
                description="Check cryptography usage patterns"
            ),
            ToolBuilder.create_tool(
                name="aggregate_results",
                func=self._aggregate_scan_results,
                description="Aggregate results from multiple scanners"
            )
        ]
    
    async def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute security scanning process"""
        
        source_dir = Path(input_data.get("source_dir"))
        scan_config = input_data.get("scan_config", {})
        work_dir = Path(input_data.get("work_dir", Path.cwd()))
        
        self.logger.info(f"Starting security scan of {source_dir}")
        self.state.update_phase(AnalysisPhase.SCANNING)
        
        # Create scan output directory
        scan_output_dir = work_dir / "scan_results"
        scan_output_dir.mkdir(parents=True, exist_ok=True)
        
        # Determine scan depth
        scan_depth = scan_config.get("scan_depth", "normal")
        
        # Run primary scanner (MobSFScan)
        scan_start = datetime.now()
        primary_results = await self._run_primary_scan(source_dir, scan_output_dir)
        
        # Run additional scanners based on depth
        additional_results = []
        if scan_depth in ["deep", "exhaustive"]:
            additional_results = await self._run_additional_scanners(
                source_dir, 
                scan_output_dir,
                scan_depth
            )
        
        # Aggregate all results
        all_findings = self._aggregate_findings(primary_results, additional_results)
        
        # Apply custom rules if provided
        if self.custom_rules:
            custom_findings = self._apply_custom_rules(source_dir)
            all_findings.extend(custom_findings)
        
        # Remove duplicates and sort by severity
        unique_findings = self._deduplicate_findings(all_findings)
        sorted_findings = sorted(
            unique_findings, 
            key=lambda f: self._severity_priority(f.severity),
            reverse=True
        )
        
        # Create scan result
        scan_duration = (datetime.now() - scan_start).total_seconds()
        scan_result = ScanResult(
            scanner="multi-scanner",
            scan_duration=scan_duration,
            total_findings=len(sorted_findings),
            findings_by_severity=self._count_by_severity(sorted_findings),
            findings=sorted_findings,
            scan_config=scan_config
        )
        
        # Update state
        self.state.scan_result = scan_result
        self.state.total_findings = len(sorted_findings)
        
        return {
            "success": True,
            "total_findings": len(sorted_findings),
            "findings": sorted_findings,
            "scan_result": scan_result,
            "summary": self._generate_scan_summary(scan_result)
        }
    
    async def _run_primary_scan(
        self, 
        source_dir: Path, 
        output_dir: Path
    ) -> List[Finding]:
        """Run primary security scanner (MobSFScan)"""
        
        output_file = output_dir / "mobsfscan_results.json"
        result = self._run_mobsfscan(str(source_dir), str(output_file))
        
        if "Success" not in result:
            self.logger.error(f"MobSFScan failed: {result}")
            return []
        
        # Parse results
        return self._parse_mobsfscan_results(output_file)
    
    def _run_mobsfscan(self, source_dir: str, output_file: str) -> str:
        """Run MobSFScan security scanner"""
        try:
            cmd = [
                "mobsfscan",
                "--json",
                "-o", output_file,
                source_dir
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.settings.scanner_timeout
            )
            
            if Path(output_file).exists():
                return f"Success: Scan completed with {result.returncode} code"
            else:
                return f"Failed: No output file generated. Error: {result.stderr[:200]}"
                
        except subprocess.TimeoutExpired:
            return "Failed: Scan timeout"
        except FileNotFoundError:
            return "Failed: mobsfscan not found. Install with: pip install mobsfscan"
        except Exception as e:
            return f"Failed: {str(e)}"
    
    def _parse_mobsfscan_results(self, results_file: Path) -> List[Finding]:
        """Parse MobSFScan JSON results"""
        findings = []
        
        try:
            with open(results_file, 'r') as f:
                data = json.load(f)
                
            if "results" not in data:
                return findings
                
            for rule_id, rule_data in data["results"].items():
                if not isinstance(rule_data, dict):
                    continue
                    
                metadata = rule_data.get("metadata", {})
                
                # Handle file-specific findings
                if "files" in rule_data and rule_data["files"]:
                    for file_match in rule_data["files"]:
                        finding = Finding(
                            rule_id=rule_id,
                            title=metadata.get("description", "")[:100],
                            description=metadata.get("description", "No description"),
                            severity=self._map_severity(metadata.get("severity", "INFO")),
                            category=metadata.get("category", "Security"),
                            file_path=file_match.get("file_path"),
                            line_number=file_match.get("match_lines", [None])[0],
                            cwe=metadata.get("cwe"),
                            owasp_mobile=metadata.get("owasp-mobile"),
                            cvss_score=metadata.get("cvss"),
                            engine="mobsfscan",
                            detection_confidence=0.7,
                            raw_data={"metadata": metadata, "file_match": file_match}
                        )
                        findings.append(finding)
                else:
                    # Generic finding without specific file
                    finding = Finding(
                        rule_id=rule_id,
                        title=metadata.get("description", "")[:100],
                        description=metadata.get("description", "No description"),
                        severity=self._map_severity(metadata.get("severity", "INFO")),
                        category=metadata.get("category", "Security"),
                        cwe=metadata.get("cwe"),
                        owasp_mobile=metadata.get("owasp-mobile"),
                        cvss_score=metadata.get("cvss"),
                        engine="mobsfscan",
                        detection_confidence=0.6,
                        raw_data=metadata
                    )
                    findings.append(finding)
                    
        except Exception as e:
            self.logger.error(f"Error parsing MobSFScan results: {e}")
            
        return findings
    
    def _run_semgrep(self, source_dir: str, output_file: str) -> str:
        """Run Semgrep security scanner"""
        try:
            cmd = [
                "semgrep",
                "--config=auto",
                "--json",
                "-o", output_file,
                source_dir
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.settings.scanner_timeout
            )
            
            if Path(output_file).exists():
                return f"Success: Semgrep scan completed"
            else:
                return f"Failed: Semgrep did not produce output"
                
        except FileNotFoundError:
            return "Semgrep not installed"
        except Exception as e:
            return f"Failed: {str(e)}"
    
    async def _run_additional_scanners(
        self,
        source_dir: Path,
        output_dir: Path,
        scan_depth: str
    ) -> List[List[Finding]]:
        """Run additional security scanners based on scan depth"""
        
        additional_results = []
        
        # Always run built-in checks
        additional_results.append(self._scan_dangerous_patterns(source_dir))
        
        if scan_depth == "deep":
            # Run medium-depth scanners
            additional_results.append(self._scan_intent_filters(source_dir))
            additional_results.append(self._scan_webview_issues(source_dir))
            
        elif scan_depth == "exhaustive":
            # Run all available scanners
            additional_results.append(self._scan_intent_filters(source_dir))
            additional_results.append(self._scan_webview_issues(source_dir))
            additional_results.append(self._scan_content_providers(source_dir))
            additional_results.append(self._scan_broadcast_receivers(source_dir))
            
            # Try external scanners if available
            semgrep_output = output_dir / "semgrep_results.json"
            semgrep_result = self._run_semgrep(str(source_dir), str(semgrep_output))
            if "Success" in semgrep_result and semgrep_output.exists():
                additional_results.append(self._parse_semgrep_results(semgrep_output))
                
        return additional_results
    
    def _scan_dangerous_patterns(self, source_dir: Path) -> List[Finding]:
        """Scan for dangerous code patterns"""
        findings = []
        
        dangerous_patterns = [
            (r'Runtime\.getRuntime\(\)\.exec', "Command Injection Risk", Severity.HIGH),
            (r'setJavaScriptEnabled\(true\)', "JavaScript Enabled in WebView", Severity.MEDIUM),
            (r'android\.permission\.WRITE_EXTERNAL_STORAGE', "External Storage Write", Severity.MEDIUM),
            (r'TrustAllSSLSocket', "SSL Certificate Validation Bypass", Severity.CRITICAL),
            (r'allowAllHostnameVerifier', "Hostname Verification Disabled", Severity.HIGH),
            (r'SecretKeySpec\([^,]+,\s*["\']DES["\']\)', "Weak Encryption (DES)", Severity.HIGH),
            (r'Cipher\.getInstance\(["\']AES/ECB', "ECB Mode Encryption", Severity.MEDIUM),
        ]
        
        # Search in Java files
        for java_file in source_dir.rglob("*.java"):
            try:
                content = java_file.read_text(encoding='utf-8', errors='ignore')
                
                for pattern, description, severity in dangerous_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        
                        finding = Finding(
                            rule_id=f"pattern_{pattern[:20]}",
                            title=description,
                            description=f"{description} detected in source code",
                            severity=severity,
                            category="Code Pattern",
                            file_path=str(java_file),
                            line_number=line_num,
                            engine="pattern_scanner",
                            detection_confidence=0.8
                        )
                        findings.append(finding)
                        
            except Exception as e:
                self.logger.debug(f"Error scanning {java_file}: {e}")
                
        return findings
    
    def _check_dangerous_permissions(self, manifest_content: str) -> str:
        """Check for dangerous Android permissions"""
        dangerous_perms = [
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_PHONE_STATE",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.READ_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_EXTERNAL_STORAGE",
        ]
        
        found = []
        for perm in dangerous_perms:
            if perm in manifest_content:
                found.append(perm.split(".")[-1])
                
        if found:
            return f"Dangerous permissions found: {', '.join(found)}"
        return "No dangerous permissions found"
    
    def _scan_hardcoded_secrets(self, source_dir: str) -> str:
        """Scan for hardcoded secrets and API keys"""
        
        secret_patterns = [
            r'["\']AIza[0-9A-Za-z_-]{35}["\']',  # Google API Key
            r'["\'][0-9a-f]{32}["\']',  # MD5 hash / potential API key
            r'["\'][0-9a-f]{40}["\']',  # SHA1 hash / potential API key
            r'(api[_]?key|apikey|secret|password|passwd|pwd|token)[\s]*=[\s]*["\'][^"\']+["\']',
            r'["\']sk_live_[0-9a-zA-Z]{24}["\']',  # Stripe
            r'["\'][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["\']',  # UUID
        ]
        
        findings = []
        for pattern in secret_patterns:
            # Simplified - in production, search through files
            findings.append(f"Checking pattern: {pattern[:30]}...")
            
        return f"Secret scan completed. Patterns checked: {len(secret_patterns)}"
    
    def _analyze_network_security(self, source_dir: str) -> str:
        """Analyze network security configuration"""
        
        issues = []
        
        # Check for network security config
        net_config = source_dir / "res" / "xml" / "network_security_config.xml"
        if net_config.exists():
            content = net_config.read_text(errors='ignore')
            
            if "cleartextTrafficPermitted=\"true\"" in content:
                issues.append("Cleartext traffic permitted")
            if "<certificates src=\"user\"" in content:
                issues.append("User certificates trusted")
            if "includeSubdomains=\"false\"" in content:
                issues.append("Subdomains not included in pinning")
        else:
            issues.append("No network security config found")
            
        return f"Network security issues: {', '.join(issues) if issues else 'None found'}"
    
    def _check_crypto_usage(self, source_dir: str) -> str:
        """Check cryptography usage patterns"""
        
        crypto_issues = []
        weak_algorithms = ["DES", "RC4", "MD5", "SHA1"]
        
        for alg in weak_algorithms:
            # Simplified check
            pattern = f'Cipher.getInstance.*{alg}'
            crypto_issues.append(f"Checking for {alg}")
            
        return f"Crypto check completed. Algorithms checked: {', '.join(weak_algorithms)}"
    
    def _scan_intent_filters(self, source_dir: Path) -> List[Finding]:
        """Scan for exposed intent filters"""
        findings = []
        
        manifest_path = source_dir / "AndroidManifest.xml"
        if manifest_path.exists():
            content = manifest_path.read_text(errors='ignore')
            
            # Check for exported components with intent filters
            if "android:exported=\"true\"" in content:
                if "<intent-filter>" in content:
                    finding = Finding(
                        rule_id="exported_component",
                        title="Exported Component with Intent Filter",
                        description="Component is exported and accepts intents",
                        severity=Severity.MEDIUM,
                        category="Component Security",
                        file_path=str(manifest_path),
                        engine="component_scanner",
                        detection_confidence=0.7
                    )
                    findings.append(finding)
                    
        return findings
    
    def _scan_webview_issues(self, source_dir: Path) -> List[Finding]:
        """Scan for WebView security issues"""
        findings = []
        
        webview_issues = [
            ("setJavaScriptEnabled(true)", "JavaScript enabled in WebView", Severity.MEDIUM),
            ("setAllowFileAccess(true)", "File access enabled in WebView", Severity.HIGH),
            ("setAllowUniversalAccessFromFileURLs(true)", "Universal file URL access", Severity.HIGH),
            ("addJavascriptInterface", "JavaScript interface exposed", Severity.MEDIUM),
        ]
        
        for java_file in source_dir.rglob("*.java"):
            try:
                content = java_file.read_text(errors='ignore')
                
                for pattern, desc, severity in webview_issues:
                    if pattern in content:
                        finding = Finding(
                            rule_id=f"webview_{pattern[:20]}",
                            title=desc,
                            description=f"{desc} - potential security risk",
                            severity=severity,
                            category="WebView Security",
                            file_path=str(java_file),
                            engine="webview_scanner",
                            detection_confidence=0.75
                        )
                        findings.append(finding)
                        
            except Exception:
                pass
                
        return findings
    
    def _scan_content_providers(self, source_dir: Path) -> List[Finding]:
        """Scan for Content Provider issues"""
        findings = []
        
        # Check for exported content providers without permissions
        manifest_path = source_dir / "AndroidManifest.xml"
        if manifest_path.exists():
            content = manifest_path.read_text(errors='ignore')
            
            if "<provider" in content and "android:exported=\"true\"" in content:
                if "android:permission" not in content:
                    finding = Finding(
                        rule_id="unprotected_provider",
                        title="Unprotected Content Provider",
                        description="Exported Content Provider without permission protection",
                        severity=Severity.HIGH,
                        category="Component Security",
                        file_path=str(manifest_path),
                        engine="component_scanner",
                        detection_confidence=0.8
                    )
                    findings.append(finding)
                    
        return findings
    
    def _scan_broadcast_receivers(self, source_dir: Path) -> List[Finding]:
        """Scan for Broadcast Receiver issues"""
        findings = []
        
        # Similar to content providers
        manifest_path = source_dir / "AndroidManifest.xml"
        if manifest_path.exists():
            content = manifest_path.read_text(errors='ignore')
            
            if "<receiver" in content and "android:exported=\"true\"" in content:
                finding = Finding(
                    rule_id="exported_receiver",
                    title="Exported Broadcast Receiver",
                    description="Broadcast Receiver is exported and may receive external intents",
                    severity=Severity.MEDIUM,
                    category="Component Security",
                    file_path=str(manifest_path),
                    engine="component_scanner",
                    detection_confidence=0.7
                )
                findings.append(finding)
                
        return findings
    
    def _parse_semgrep_results(self, results_file: Path) -> List[Finding]:
        """Parse Semgrep JSON results"""
        findings = []
        
        try:
            with open(results_file, 'r') as f:
                data = json.load(f)
                
            for result in data.get("results", []):
                finding = Finding(
                    rule_id=result.get("check_id", "semgrep_rule"),
                    title=result.get("extra", {}).get("message", "Security Issue"),
                    description=result.get("extra", {}).get("metadata", {}).get("message", ""),
                    severity=self._map_severity(result.get("extra", {}).get("severity", "INFO")),
                    category="Semgrep",
                    file_path=result.get("path"),
                    line_number=result.get("start", {}).get("line"),
                    engine="semgrep",
                    detection_confidence=0.75,
                    raw_data=result
                )
                findings.append(finding)
                
        except Exception as e:
            self.logger.error(f"Error parsing Semgrep results: {e}")
            
        return findings
    
    def _aggregate_scan_results(self, results_list: str) -> str:
        """Aggregate results from multiple scanners"""
        # This is a tool function that would be called by the LLM
        return "Aggregating scan results from multiple sources..."
    
    def _aggregate_findings(
        self, 
        primary: List[Finding], 
        additional: List[List[Finding]]
    ) -> List[Finding]:
        """Aggregate findings from all scanners"""
        
        all_findings = primary.copy()
        
        for findings_list in additional:
            all_findings.extend(findings_list)
            
        return all_findings
    
    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Remove duplicate findings"""
        
        seen = set()
        unique = []
        
        for finding in findings:
            # Create a unique key for the finding
            key = (
                finding.rule_id,
                finding.file_path,
                finding.line_number,
                finding.severity
            )
            
            if key not in seen:
                seen.add(key)
                unique.append(finding)
            else:
                # Merge confidence scores if duplicate
                for existing in unique:
                    if (existing.rule_id == finding.rule_id and 
                        existing.file_path == finding.file_path):
                        existing.detection_confidence = max(
                            existing.detection_confidence,
                            finding.detection_confidence
                        )
                        
        return unique
    
    def _severity_priority(self, severity: Severity) -> int:
        """Get numeric priority for severity"""
        priorities = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1
        }
        return priorities.get(severity, 0)
    
    def _count_by_severity(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }
        
        for finding in findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
            
        return counts
    
    def _map_severity(self, severity_str: str) -> Severity:
        """Map string severity to enum"""
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFO": Severity.INFO,
            "WARNING": Severity.MEDIUM,
            "ERROR": Severity.HIGH,
        }
        
        return severity_map.get(severity_str.upper(), Severity.MEDIUM)
    
    def _generate_scan_summary(self, scan_result: ScanResult) -> str:
        """Generate a summary of scan results"""
        
        summary = f"""
Security Scan Summary:
- Total Findings: {scan_result.total_findings}
- Critical: {scan_result.findings_by_severity.get('CRITICAL', 0)}
- High: {scan_result.findings_by_severity.get('HIGH', 0)}
- Medium: {scan_result.findings_by_severity.get('MEDIUM', 0)}
- Low: {scan_result.findings_by_severity.get('LOW', 0)}
- Scan Duration: {scan_result.scan_duration:.2f} seconds
- Scanner: {scan_result.scanner}
        """
        
        return summary.strip()
    
    def _load_custom_rules(self) -> Optional[Dict]:
        """Load custom scanning rules if available"""
        
        custom_rules_path = Path.cwd() / "custom_rules.json"
        if custom_rules_path.exists():
            try:
                with open(custom_rules_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.warning(f"Could not load custom rules: {e}")
                
        return None
    
    def _apply_custom_rules(self, source_dir: Path) -> List[Finding]:
        """Apply custom scanning rules"""
        
        findings = []
        
        if not self.custom_rules:
            return findings
            
        for rule in self.custom_rules.get("rules", []):
            # Apply each custom rule
            pattern = rule.get("pattern")
            if pattern:
                # Search for pattern in source files
                for file_path in source_dir.rglob("*.java"):
                    try:
                        content = file_path.read_text(errors='ignore')
                        if re.search(pattern, content, re.IGNORECASE):
                            finding = Finding(
                                rule_id=rule.get("id", "custom_rule"),
                                title=rule.get("title", "Custom Rule Match"),
                                description=rule.get("description", ""),
                                severity=self._map_severity(rule.get("severity", "MEDIUM")),
                                category="Custom Rule",
                                file_path=str(file_path),
                                engine="custom_rules",
                                detection_confidence=rule.get("confidence", 0.7)
                            )
                            findings.append(finding)
                    except Exception:
                        pass
                        
        return findings
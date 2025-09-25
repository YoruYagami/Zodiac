"""
Report Agent for Security Analysis Report Generation
Generates comprehensive reports with AI-powered insights
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging
from jinja2 import Template

from langchain_core.tools import Tool
from pydantic import BaseModel, Field

from .base_agent import BaseAgent, AgentConfig, ToolBuilder
from ..core.models import (
    Finding, FindingCategory, Severity, ReportData,
    AnalysisState, ValidationResult
)
from ..config.settings import get_settings


class ReportRequest(BaseModel):
    """Request for report generation"""
    format: str = "json"  # json, html, markdown, pdf
    include_code: bool = True
    include_remediation: bool = True
    executive_summary: bool = True
    

class ReportAgent(BaseAgent):
    """
    Agent responsible for generating security analysis reports
    Creates comprehensive reports with insights and recommendations
    """
    
    def __init__(self, state=None):
        config = AgentConfig(
            name="ReportAgent",
            description="Expert in security report generation and risk assessment",
            temperature=0.3,  # Some creativity for summaries
            max_tokens=4000
        )
        super().__init__(config, state)
        
        # Report templates
        self.templates = self._load_templates()
        
    def _get_specific_tools(self) -> List[Tool]:
        """Get report-specific tools"""
        return [
            ToolBuilder.create_tool(
                name="generate_executive_summary",
                func=self._generate_executive_summary,
                description="Generate executive summary"
            ),
            ToolBuilder.create_tool(
                name="assess_risk_level",
                func=self._assess_risk_level,
                description="Assess overall security risk level"
            ),
            ToolBuilder.create_tool(
                name="generate_recommendations",
                func=self._generate_recommendations,
                description="Generate security recommendations"
            ),
            ToolBuilder.create_tool(
                name="create_statistics",
                func=self._create_statistics,
                description="Create statistical analysis"
            ),
            ToolBuilder.create_tool(
                name="generate_remediation_plan",
                func=self._generate_remediation_plan,
                description="Generate remediation action plan"
            ),
            ToolBuilder.create_tool(
                name="export_report",
                func=self._export_report,
                description="Export report in specified format"
            )
        ]
    
    async def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute report generation
        """
        
        analysis_state = input_data.get("analysis_state")
        validation_results = input_data.get("validation_results", {})
        output_format = input_data.get("output_format", "json")
        output_dir = Path(input_data.get("output_dir", Path.cwd()))
        use_ai_insights = input_data.get("use_ai_insights", True)
        
        self.logger.info(f"Generating {output_format} report")
        
        # Prepare report data
        report_data = await self._prepare_report_data(
            analysis_state,
            validation_results,
            use_ai_insights
        )
        
        # Generate report files
        report_files = await self._generate_report_files(
            report_data,
            output_format,
            output_dir
        )
        
        return {
            "success": True,
            "report_data": report_data,
            "report_files": report_files,
            "risk_level": report_data.get_risk_level()
        }
    
    async def _prepare_report_data(
        self,
        state: AnalysisState,
        validation_results: Dict,
        use_ai: bool
    ) -> ReportData:
        """Prepare comprehensive report data"""
        
        report_data = ReportData(analysis_state=state)
        
        # Categorize findings by severity
        if state.validation_result:
            findings = state.validation_result.true_positives
            
            report_data.critical_findings = [
                f for f in findings if f.severity == Severity.CRITICAL
            ]
            report_data.high_findings = [
                f for f in findings if f.severity == Severity.HIGH
            ]
            report_data.medium_findings = [
                f for f in findings if f.severity == Severity.MEDIUM
            ]
            report_data.low_findings = [
                f for f in findings if f.severity == Severity.LOW
            ]
        
        # Generate statistics
        report_data.statistics = self._generate_statistics(state)
        
        # Generate AI-powered insights if enabled
        if use_ai:
            report_data.executive_summary = await self._generate_ai_summary(state)
            report_data.risk_assessment = await self._generate_risk_assessment(state)
            report_data.recommendations = await self._generate_ai_recommendations(state)
            report_data.ai_insights = await self._generate_ai_insights(state)
        else:
            # Basic summaries without AI
            report_data.executive_summary = self._generate_basic_summary(state)
            report_data.risk_assessment = self._assess_risk_level("")
            report_data.recommendations = self._generate_basic_recommendations(state)
        
        return report_data
    
    async def _generate_ai_summary(self, state: AnalysisState) -> str:
        """Generate AI-powered executive summary"""
        
        prompt = f"""
        Generate an executive summary for this Android security analysis:
        
        Application: {state.apk_metadata.package_name if state.apk_metadata else 'Unknown'}
        Total Findings: {state.total_findings}
        Critical Issues: {state.critical_findings}
        High Issues: {state.high_findings}
        
        Validation Results:
        - True Positives: {len(state.validation_result.true_positives) if state.validation_result else 0}
        - False Positives: {len(state.validation_result.false_positives) if state.validation_result else 0}
        - Requires Dynamic Check: {len(state.validation_result.dynamic_checks) if state.validation_result else 0}
        
        Duration: {state.duration_seconds:.1f} seconds if state.duration_seconds else 'N/A'
        
        Provide:
        1. Overall security posture (1-2 sentences)
        2. Key risks identified (2-3 bullet points)
        3. Immediate actions needed (1-2 recommendations)
        
        Be concise and focus on actionable insights.
        """
        
        response = self.run(prompt)
        return response
    
    async def _generate_risk_assessment(self, state: AnalysisState) -> str:
        """Generate comprehensive risk assessment"""
        
        # Prepare finding summaries
        critical_summary = ""
        if state.validation_result and state.validation_result.true_positives:
            critical_findings = [
                f for f in state.validation_result.true_positives 
                if f.severity in [Severity.CRITICAL, Severity.HIGH]
            ][:5]
            
            if critical_findings:
                critical_summary = "Critical findings:\n"
                for f in critical_findings:
                    critical_summary += f"- {f.title}: {f.description[:100]}\n"
        
        prompt = f"""
        Perform a risk assessment for this Android application:
        
        {critical_summary}
        
        Statistics:
        - Critical vulnerabilities: {state.critical_findings}
        - High vulnerabilities: {state.high_findings}
        - Total validated issues: {state.total_findings}
        
        Provide:
        1. Overall risk level (Critical/High/Medium/Low) with justification
        2. Attack surface analysis
        3. Potential impact if exploited
        4. Likelihood of exploitation
        5. Business risk implications
        
        Format as a professional risk assessment.
        """
        
        response = self.run(prompt)
        return response
    
    async def _generate_ai_recommendations(self, state: AnalysisState) -> List[str]:
        """Generate AI-powered recommendations"""
        
        # Get top issues for context
        top_issues = []
        if state.validation_result:
            for f in state.validation_result.true_positives[:10]:
                top_issues.append(f"{f.rule_id}: {f.title}")
        
        prompt = f"""
        Generate prioritized security recommendations based on these findings:
        
        Top Issues:
        {chr(10).join(top_issues)}
        
        Provide 5-7 specific, actionable recommendations prioritized by:
        1. Security impact
        2. Ease of implementation
        3. Business criticality
        
        Format each recommendation as:
        - [Priority] Action: Specific steps to take
        """
        
        response = self.run(prompt)
        
        # Parse recommendations
        recommendations = []
        for line in response.split('\n'):
            if line.strip().startswith('-') or line.strip().startswith('•'):
                recommendations.append(line.strip()[1:].strip())
        
        return recommendations if recommendations else [
            "Conduct thorough security review",
            "Fix critical vulnerabilities immediately",
            "Implement secure coding practices"
        ]
    
    async def _generate_ai_insights(self, state: AnalysisState) -> Dict[str, Any]:
        """Generate detailed AI insights"""
        
        insights = {}
        
        # Pattern analysis
        if state.validation_result:
            findings = state.validation_result.true_positives
            
            # Analyze patterns
            patterns_prompt = f"""
            Analyze these security findings for patterns:
            
            Findings by category:
            {self._categorize_findings(findings)}
            
            Identify:
            1. Common vulnerability patterns
            2. Systemic issues
            3. Root causes
            4. Areas of concern
            """
            
            insights["patterns"] = self.run(patterns_prompt)
            
            # Technical debt assessment
            debt_prompt = """
            Based on the security findings, assess the technical debt:
            1. Code quality issues contributing to vulnerabilities
            2. Architectural problems
            3. Missing security controls
            """
            
            insights["technical_debt"] = self.run(debt_prompt)
            
            # Compliance gaps
            insights["compliance_gaps"] = self._analyze_compliance_gaps(findings)
        
        return insights
    
    def _generate_basic_summary(self, state: AnalysisState) -> str:
        """Generate basic summary without AI"""
        
        summary = f"""
Security Analysis Summary

Application: {state.apk_metadata.package_name if state.apk_metadata else 'Unknown'}
Analysis ID: {state.analysis_id}
Duration: {state.duration_seconds:.1f} seconds if state.duration_seconds else 'In progress'

Findings Overview:
- Total Issues: {state.total_findings}
- Critical: {state.critical_findings}
- High Risk: {state.high_findings}

The application has been analyzed for security vulnerabilities using static analysis.
{'Critical issues were identified that require immediate attention.' if state.critical_findings > 0 else 'No critical issues were identified.'}
        """
        
        return summary.strip()
    
    def _generate_basic_recommendations(self, state: AnalysisState) -> List[str]:
        """Generate basic recommendations without AI"""
        
        recommendations = []
        
        if state.critical_findings > 0:
            recommendations.append("Address critical security vulnerabilities immediately")
            
        if state.high_findings > 0:
            recommendations.append("Review and fix high-risk security issues")
            
        if state.validation_result:
            if len(state.validation_result.dynamic_checks) > 5:
                recommendations.append("Perform dynamic security testing for validation")
                
            if len(state.validation_result.false_positives) > 10:
                recommendations.append("Review false positive patterns for rule tuning")
        
        recommendations.extend([
            "Implement secure coding practices",
            "Conduct regular security assessments",
            "Keep dependencies and SDKs updated"
        ])
        
        return recommendations[:7]  # Limit to 7 recommendations
    
    def _generate_statistics(self, state: AnalysisState) -> Dict[str, Any]:
        """Generate comprehensive statistics"""
        
        stats = {
            "analysis_metadata": {
                "analysis_id": state.analysis_id,
                "start_time": state.start_time.isoformat() if state.start_time else None,
                "duration_seconds": state.duration_seconds,
                "phases_completed": len(state.phases_completed)
            },
            "apk_info": {},
            "findings": {
                "total": state.total_findings,
                "by_severity": {},
                "by_category": {},
                "by_validation": {}
            },
            "validation": {},
            "performance": {}
        }
        
        # APK info
        if state.apk_metadata:
            stats["apk_info"] = {
                "package_name": state.apk_metadata.package_name,
                "version": state.apk_metadata.version_name,
                "file_size_mb": state.apk_metadata.file_size / 1024 / 1024,
                "permissions_count": len(state.apk_metadata.permissions),
                "activities_count": len(state.apk_metadata.activities),
                "services_count": len(state.apk_metadata.services)
            }
        
        # Findings breakdown
        if state.validation_result:
            val_result = state.validation_result
            
            # By severity
            for finding in val_result.true_positives:
                sev = finding.severity.value
                stats["findings"]["by_severity"][sev] = \
                    stats["findings"]["by_severity"].get(sev, 0) + 1
                    
                # By category
                cat = finding.category or "Other"
                stats["findings"]["by_category"][cat] = \
                    stats["findings"]["by_category"].get(cat, 0) + 1
            
            # Validation stats
            stats["findings"]["by_validation"] = {
                "true_positives": len(val_result.true_positives),
                "false_positives": len(val_result.false_positives),
                "dynamic_checks": len(val_result.dynamic_checks),
                "unknown": len(val_result.unknown)
            }
            
            stats["validation"] = {
                "total_processed": val_result.total_processed,
                "average_confidence": val_result.average_confidence,
                "tp_rate": len(val_result.true_positives) / val_result.total_processed if val_result.total_processed > 0 else 0,
                "fp_rate": len(val_result.false_positives) / val_result.total_processed if val_result.total_processed > 0 else 0
            }
        
        # Performance metrics
        if state.decompilation_result:
            stats["performance"]["decompilation_duration"] = state.decompilation_result.duration_seconds
            stats["performance"]["source_files"] = state.decompilation_result.total_files
            
        if state.scan_result:
            stats["performance"]["scan_duration"] = state.scan_result.scan_duration
            
        return stats
    
    async def _generate_report_files(
        self,
        report_data: ReportData,
        output_format: str,
        output_dir: Path
    ) -> List[Path]:
        """Generate report files in specified formats"""
        
        output_dir.mkdir(parents=True, exist_ok=True)
        report_files = []
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"security_report_{timestamp}"
        
        if output_format in ["json", "all"]:
            json_file = output_dir / f"{base_name}.json"
            self._write_json_report(report_data, json_file)
            report_files.append(json_file)
            
        if output_format in ["html", "all"]:
            html_file = output_dir / f"{base_name}.html"
            self._write_html_report(report_data, html_file)
            report_files.append(html_file)
            
        if output_format in ["markdown", "all"]:
            md_file = output_dir / f"{base_name}.md"
            self._write_markdown_report(report_data, md_file)
            report_files.append(md_file)
            
        self.logger.info(f"Generated {len(report_files)} report file(s)")
        return report_files
    
    def _write_json_report(self, report_data: ReportData, output_file: Path):
        """Write JSON format report"""
        
        json_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "analysis_id": report_data.analysis_state.analysis_id,
                "risk_level": report_data.get_risk_level()
            },
            "summary": {
                "executive_summary": report_data.executive_summary,
                "risk_assessment": report_data.risk_assessment,
                "total_findings": report_data.analysis_state.total_findings,
                "critical_count": len(report_data.critical_findings),
                "high_count": len(report_data.high_findings)
            },
            "findings": {
                "critical": [self._finding_to_dict(f) for f in report_data.critical_findings],
                "high": [self._finding_to_dict(f) for f in report_data.high_findings],
                "medium": [self._finding_to_dict(f) for f in report_data.medium_findings],
                "low": [self._finding_to_dict(f) for f in report_data.low_findings]
            },
            "recommendations": report_data.recommendations,
            "statistics": report_data.statistics,
            "ai_insights": report_data.ai_insights
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, default=str)
    
    def _write_html_report(self, report_data: ReportData, output_file: Path):
        """Write HTML format report"""
        
        html_template = self.templates.get("html", self._get_default_html_template())
        
        template = Template(html_template)
        html_content = template.render(
            report=report_data,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            risk_level=report_data.get_risk_level(),
            critical_count=len(report_data.critical_findings),
            high_count=len(report_data.high_findings),
            medium_count=len(report_data.medium_findings),
            low_count=len(report_data.low_findings)
        )
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _write_markdown_report(self, report_data: ReportData, output_file: Path):
        """Write Markdown format report"""
        
        md_content = f"""# Security Analysis Report

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}  
**Analysis ID:** {report_data.analysis_state.analysis_id}  
**Risk Level:** {report_data.get_risk_level()}

## Executive Summary

{report_data.executive_summary}

## Risk Assessment

{report_data.risk_assessment}

## Findings Summary

| Severity | Count |
|----------|-------|
| Critical | {len(report_data.critical_findings)} |
| High | {len(report_data.high_findings)} |
| Medium | {len(report_data.medium_findings)} |
| Low | {len(report_data.low_findings)} |

## Critical Findings

"""
        
        # Add critical findings
        for finding in report_data.critical_findings[:10]:
            md_content += f"""
### {finding.title}

- **Rule ID:** {finding.rule_id}
- **Severity:** {finding.severity.value}
- **File:** {finding.file_path or 'N/A'}
- **Line:** {finding.line_number or 'N/A'}
- **Description:** {finding.description}
- **Confidence:** {finding.validation_confidence:.1%}

"""
        
        # Add recommendations
        md_content += "## Recommendations\n\n"
        for i, rec in enumerate(report_data.recommendations, 1):
            md_content += f"{i}. {rec}\n"
            
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(md_content)
    
    def _finding_to_dict(self, finding: Finding) -> Dict[str, Any]:
        """Convert finding to dictionary for JSON"""
        
        return {
            "rule_id": finding.rule_id,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity.value,
            "file": finding.file_path,
            "line": finding.line_number,
            "confidence": finding.validation_confidence,
            "validation_status": finding.validation_status.value,
            "cwe": finding.cwe,
            "owasp": finding.owasp_mobile,
            "remediation": finding.remediation
        }
    
    def _categorize_findings(self, findings: List[Finding]) -> str:
        """Categorize findings for analysis"""
        
        categories = {}
        for f in findings:
            cat = f.category or "Other"
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(f.rule_id)
            
        result = []
        for cat, rules in categories.items():
            result.append(f"{cat}: {len(rules)} issues")
            
        return "\n".join(result)
    
    def _analyze_compliance_gaps(self, findings: List[Finding]) -> Dict[str, List[str]]:
        """Analyze compliance gaps based on findings"""
        
        gaps = {
            "OWASP Mobile Top 10": [],
            "CWE Top 25": [],
            "PCI DSS": [],
            "GDPR": []
        }
        
        for finding in findings:
            if finding.owasp_mobile:
                gaps["OWASP Mobile Top 10"].append(finding.owasp_mobile)
            if finding.cwe:
                gaps["CWE Top 25"].append(finding.cwe)
                
            # Check for PCI/GDPR relevant issues
            if "crypto" in finding.rule_id.lower() or "payment" in finding.description.lower():
                gaps["PCI DSS"].append(finding.rule_id)
            if "privacy" in finding.rule_id.lower() or "data" in finding.description.lower():
                gaps["GDPR"].append(finding.rule_id)
                
        # Remove duplicates
        for key in gaps:
            gaps[key] = list(set(gaps[key]))
            
        return gaps
    
    def _load_templates(self) -> Dict[str, str]:
        """Load report templates"""
        
        templates = {}
        
        # Try to load from files
        template_dir = Path(__file__).parent.parent / "templates"
        if template_dir.exists():
            for template_file in template_dir.glob("*.html"):
                template_name = template_file.stem
                templates[template_name] = template_file.read_text()
                
        return templates
    
    def _get_default_html_template(self) -> str:
        """Get default HTML template"""
        
        return """<!DOCTYPE html>
<html>
<head>
    <title>Security Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        .summary { background: #f0f0f0; padding: 15px; border-radius: 5px; }
        .critical { color: #d9534f; }
        .high { color: #f0ad4e; }
        .medium { color: #5bc0de; }
        .low { color: #5cb85c; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
    </style>
</head>
<body>
    <h1>Security Analysis Report</h1>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Risk Level:</strong> <span class="{{ risk_level|lower }}">{{ risk_level }}</span></p>
        <p><strong>Generated:</strong> {{ generated_at }}</p>
        <p>{{ report.executive_summary }}</p>
    </div>
    
    <h2>Findings Summary</h2>
    <table>
        <tr>
            <th>Severity</th>
            <th>Count</th>
        </tr>
        <tr class="critical">
            <td>Critical</td>
            <td>{{ critical_count }}</td>
        </tr>
        <tr class="high">
            <td>High</td>
            <td>{{ high_count }}</td>
        </tr>
        <tr class="medium">
            <td>Medium</td>
            <td>{{ medium_count }}</td>
        </tr>
        <tr class="low">
            <td>Low</td>
            <td>{{ low_count }}</td>
        </tr>
    </table>
    
    <h2>Recommendations</h2>
    <ol>
    {% for rec in report.recommendations %}
        <li>{{ rec }}</li>
    {% endfor %}
    </ol>
</body>
</html>"""
    
    # Tool implementations
    def _generate_executive_summary(self, context: str) -> str:
        """Tool: Generate executive summary"""
        return "Generating executive summary based on analysis results..."
    
    def _assess_risk_level(self, findings_summary: str) -> str:
        """Tool: Assess risk level"""
        return "Assessing overall risk level based on findings..."
    
    def _generate_recommendations(self, findings: str) -> str:
        """Tool: Generate recommendations"""
        return "Generating prioritized security recommendations..."
    
    def _create_statistics(self, data: str) -> str:
        """Tool: Create statistics"""
        return "Creating statistical analysis of findings..."
    
    def _generate_remediation_plan(self, critical_findings: str) -> str:
        """Tool: Generate remediation plan"""
        return "Creating detailed remediation action plan..."
    
    def _export_report(self, format: str) -> str:
        """Tool: Export report"""
        return f"Exporting report in {format} format..."
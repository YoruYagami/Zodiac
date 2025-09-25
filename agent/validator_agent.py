"""
Validator Agent for Security Finding Validation
Specialized agent for validating and categorizing security findings
"""

import re
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import logging

from langchain_core.tools import Tool
from pydantic import BaseModel, Field

from .base_agent import BaseAgent, AgentConfig, ToolBuilder
from ..core.models import (
    Finding, FindingCategory, SourceContext, 
    ValidationResult, Severity, AnalysisPhase
)
from ..config.settings import get_settings, VALIDATION_RULES


class ValidationRequest(BaseModel):
    """Schema for validation requests"""
    finding: Finding
    source_context: Optional[SourceContext] = None
    validation_depth: str = "standard"  # quick, standard, deep
    

class ValidationResponse(BaseModel):
    """Schema for validation responses"""
    finding_id: str
    validation_status: FindingCategory
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    recommendations: List[str] = Field(default_factory=list)
    requires_dynamic_check: bool = False
    

class ValidatorAgent(BaseAgent):
    """
    Specialized agent for validating security findings
    Determines if findings are True Positives, False Positives, or require Dynamic Checking
    """
    
    def __init__(self, state=None):
        config = AgentConfig(
            name="ValidatorAgent",
            description="Expert in validating Android security findings and reducing false positives",
            temperature=0.1,  # Low temperature for consistent validation
            max_tokens=3000,
            verbose=get_settings().debug
        )
        super().__init__(config, state)
        
        # Validation-specific attributes
        self.validation_rules = self._load_validation_rules()
        self.validation_cache: Dict[str, ValidationResponse] = {}
        self.pattern_cache: Dict[str, re.Pattern] = {}
        
    def _load_validation_rules(self) -> Dict[str, Dict]:
        """Load and compile validation rules"""
        rules = VALIDATION_RULES.copy()
        
        # Compile regex patterns for efficiency
        for rule_id, rule_data in rules.items():
            if "patterns" in rule_data:
                rule_data["compiled_patterns"] = [
                    re.compile(pattern, re.IGNORECASE | re.DOTALL) 
                    for pattern in rule_data["patterns"]
                ]
            if "anti_patterns" in rule_data:
                rule_data["compiled_anti_patterns"] = [
                    re.compile(pattern, re.IGNORECASE | re.DOTALL) 
                    for pattern in rule_data["anti_patterns"]
                ]
                
        return rules
    
    def _get_specific_tools(self) -> List[Tool]:
        """Get validator-specific tools"""
        return [
            ToolBuilder.create_tool(
                name="validate_finding",
                func=self._validate_finding_tool,
                description="Validate a security finding with context analysis"
            ),
            ToolBuilder.create_tool(
                name="check_false_positive_indicators",
                func=self._check_fp_indicators,
                description="Check for false positive indicators in code"
            ),
            ToolBuilder.create_tool(
                name="analyze_code_pattern",
                func=self._analyze_code_pattern,
                description="Analyze code patterns for vulnerability confirmation"
            ),
            ToolBuilder.create_tool(
                name="check_third_party",
                func=self._check_third_party_library,
                description="Check if code belongs to third-party library"
            ),
            ToolBuilder.create_tool(
                name="assess_severity",
                func=self._assess_severity,
                description="Reassess finding severity based on context"
            ),
            ToolBuilder.create_tool(
                name="get_remediation",
                func=self._get_remediation_guidance,
                description="Get remediation guidance for validated finding"
            )
        ]
    
    async def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute validation for a batch of findings
        """
        findings = input_data.get("findings", [])
        validation_level = input_data.get("validation_level", "moderate")
        
        self.logger.info(f"Starting validation of {len(findings)} findings")
        self.state.update_phase(AnalysisPhase.VALIDATION)
        
        results = ValidationResult(
            total_processed=len(findings),
            validation_duration=0
        )
        
        start_time = datetime.now()
        
        for finding in findings:
            try:
                validated_finding = await self._validate_single_finding(
                    finding, 
                    validation_level
                )
                
                # Categorize the validated finding
                if validated_finding.validation_status == FindingCategory.TRUE_POSITIVE:
                    results.true_positives.append(validated_finding)
                elif validated_finding.validation_status == FindingCategory.DYNAMIC_CHECK:
                    results.dynamic_checks.append(validated_finding)
                elif validated_finding.validation_status == FindingCategory.FALSE_POSITIVE:
                    results.false_positives.append(validated_finding)
                else:
                    results.unknown.append(validated_finding)
                    
            except Exception as e:
                self.logger.error(f"Error validating finding {finding.finding_id}: {e}")
                results.unknown.append(finding)
        
        # Calculate metrics
        results.validation_duration = (datetime.now() - start_time).total_seconds()
        results.average_confidence = self._calculate_average_confidence(results)
        
        # Update state
        self.state.validation_result = results
        self.state.total_findings = len(findings)
        self.state.critical_findings = len([
            f for f in results.true_positives 
            if f.severity == Severity.CRITICAL
        ])
        
        return {
            "status": "success",
            "results": results.dict(),
            "summary": results.get_summary()
        }
    
    async def _validate_single_finding(
        self, 
        finding: Finding, 
        validation_level: str
    ) -> Finding:
        """Validate a single finding"""
        
        # Check cache first
        cache_key = f"{finding.rule_id}_{finding.file_path}_{finding.line_number}"
        if cache_key in self.validation_cache:
            cached = self.validation_cache[cache_key]
            finding.validation_status = cached.validation_status
            finding.validation_confidence = cached.confidence
            finding.validation_reason = cached.reasoning
            return finding
        
        # Get matching validation rule
        rule = self._get_matching_rule(finding.rule_id)
        
        if rule and finding.source_context:
            validation_result = self._apply_rule_validation(
                finding, 
                rule, 
                validation_level
            )
        else:
            # Fallback to heuristic validation
            validation_result = self._heuristic_validation(finding)
        
        # Apply LLM-based validation for complex cases
        if validation_result.confidence < 0.6 and finding.source_context:
            llm_result = await self._llm_validation(finding)
            # Combine results
            validation_result = self._combine_validation_results(
                validation_result, 
                llm_result
            )
        
        # Update finding with validation results
        finding.validation_status = validation_result.validation_status
        finding.validation_confidence = validation_result.confidence
        finding.validation_reason = validation_result.reasoning
        finding.validation_timestamp = datetime.now()
        
        # Add to cache
        self.validation_cache[cache_key] = validation_result
        
        return finding
    
    def _get_matching_rule(self, rule_id: str) -> Optional[Dict]:
        """Get matching validation rule"""
        # Direct match
        if rule_id in self.validation_rules:
            return self.validation_rules[rule_id]
        
        # Fuzzy match
        rule_id_lower = rule_id.lower()
        for key, rule in self.validation_rules.items():
            if key in rule_id_lower or rule_id_lower in key:
                return rule
                
        return None
    
    def _apply_rule_validation(
        self, 
        finding: Finding, 
        rule: Dict, 
        validation_level: str
    ) -> ValidationResponse:
        """Apply rule-based validation"""
        
        context = finding.source_context
        confidence = 0.5  # Base confidence
        reasons = []
        
        # Check positive patterns
        pattern_matches = 0
        for pattern in rule.get("compiled_patterns", []):
            if pattern.search(context.code_snippet):
                pattern_matches += 1
                confidence += 0.15
                
        # Check anti-patterns (reduce confidence)
        for anti_pattern in rule.get("compiled_anti_patterns", []):
            if anti_pattern.search(context.code_snippet):
                confidence -= 0.2
                reasons.append(f"Anti-pattern detected")
                
        # Check context factors
        if context.is_test_code:
            confidence -= 0.4
            reasons.append("Test code")
            
        if context.is_third_party:
            confidence -= 0.3
            reasons.append("Third-party library")
            
        if context.is_example_code:
            confidence -= 0.3
            reasons.append("Example/demo code")
            
        # Check for dynamic indicators
        requires_dynamic = False
        for indicator in rule.get("dynamic_indicators", []):
            if indicator.lower() in context.code_snippet.lower():
                requires_dynamic = True
                reasons.append(f"Dynamic check needed: {indicator}")
                
        # Apply validation level adjustments
        if validation_level == "strict":
            confidence *= 0.9
        elif validation_level == "lenient":
            confidence *= 1.1
            
        # Determine final status
        confidence = max(0, min(1, confidence))
        
        if confidence >= 0.8 and not requires_dynamic:
            status = FindingCategory.TRUE_POSITIVE
            reasoning = "High confidence vulnerability detected"
        elif confidence >= 0.4 or requires_dynamic:
            status = FindingCategory.DYNAMIC_CHECK
            reasoning = "Requires runtime verification"
        else:
            status = FindingCategory.FALSE_POSITIVE
            reasoning = "Low confidence - likely false positive"
            
        if reasons:
            reasoning += f" ({', '.join(reasons)})"
            
        return ValidationResponse(
            finding_id=finding.finding_id,
            validation_status=status,
            confidence=confidence,
            reasoning=reasoning,
            requires_dynamic_check=requires_dynamic
        )
    
    def _heuristic_validation(self, finding: Finding) -> ValidationResponse:
        """Apply heuristic validation when no specific rule exists"""
        
        # Base confidence on severity
        severity_confidence = {
            Severity.CRITICAL: 0.8,
            Severity.HIGH: 0.7,
            Severity.MEDIUM: 0.5,
            Severity.LOW: 0.3,
            Severity.INFO: 0.2
        }
        
        confidence = severity_confidence.get(finding.severity, 0.5)
        
        # Adjust based on available context
        if not finding.source_context:
            confidence *= 0.5
            status = FindingCategory.DYNAMIC_CHECK
            reasoning = "No source context - requires dynamic verification"
        elif confidence >= 0.6:
            status = FindingCategory.TRUE_POSITIVE
            reasoning = f"Validated based on {finding.severity.value} severity"
        elif confidence >= 0.3:
            status = FindingCategory.DYNAMIC_CHECK
            reasoning = "Moderate confidence - requires verification"
        else:
            status = FindingCategory.FALSE_POSITIVE
            reasoning = "Low confidence finding"
            
        return ValidationResponse(
            finding_id=finding.finding_id,
            validation_status=status,
            confidence=confidence,
            reasoning=reasoning
        )
    
    async def _llm_validation(self, finding: Finding) -> ValidationResponse:
        """Use LLM for complex validation cases"""
        
        prompt = f"""
        Analyze this security finding for an Android application:
        
        Rule: {finding.rule_id}
        Description: {finding.description}
        Severity: {finding.severity.value}
        File: {finding.file_path}
        
        Code Context:
        ```
        {finding.source_context.code_snippet if finding.source_context else 'No context available'}
        ```
        
        Determine if this is:
        1. TRUE_POSITIVE - A real security vulnerability
        2. FALSE_POSITIVE - Not a real issue (test code, example, properly handled, etc.)
        3. DYNAMIC_CHECK - Requires runtime verification
        
        Provide your assessment with confidence level (0-1) and reasoning.
        """
        
        response = self.run(prompt)
        
        # Parse LLM response (simplified - in production use structured output)
        if "TRUE_POSITIVE" in response.upper():
            status = FindingCategory.TRUE_POSITIVE
        elif "FALSE_POSITIVE" in response.upper():
            status = FindingCategory.FALSE_POSITIVE
        else:
            status = FindingCategory.DYNAMIC_CHECK
            
        # Extract confidence (simplified parsing)
        confidence = 0.6  # Default
        if "high confidence" in response.lower():
            confidence = 0.9
        elif "low confidence" in response.lower():
            confidence = 0.3
            
        return ValidationResponse(
            finding_id=finding.finding_id,
            validation_status=status,
            confidence=confidence,
            reasoning=f"LLM Analysis: {response[:200]}"
        )
    
    def _combine_validation_results(
        self, 
        rule_result: ValidationResponse,
        llm_result: ValidationResponse
    ) -> ValidationResponse:
        """Combine rule-based and LLM validation results"""
        
        # Weight the results
        rule_weight = 0.6
        llm_weight = 0.4
        
        combined_confidence = (
            rule_result.confidence * rule_weight + 
            llm_result.confidence * llm_weight
        )
        
        # If they agree, increase confidence
        if rule_result.validation_status == llm_result.validation_status:
            combined_confidence = min(1.0, combined_confidence * 1.2)
            status = rule_result.validation_status
            reasoning = f"{rule_result.reasoning} (LLM confirmed)"
        else:
            # If they disagree, prefer DYNAMIC_CHECK
            status = FindingCategory.DYNAMIC_CHECK
            reasoning = f"Mixed signals: Rule={rule_result.validation_status.value}, LLM={llm_result.validation_status.value}"
            
        return ValidationResponse(
            finding_id=rule_result.finding_id,
            validation_status=status,
            confidence=combined_confidence,
            reasoning=reasoning,
            requires_dynamic_check=rule_result.requires_dynamic_check or llm_result.requires_dynamic_check
        )
    
    def _calculate_average_confidence(self, results: ValidationResult) -> float:
        """Calculate average confidence across all validated findings"""
        all_findings = (
            results.true_positives + 
            results.dynamic_checks + 
            results.false_positives
        )
        
        if not all_findings:
            return 0.0
            
        total_confidence = sum(f.validation_confidence for f in all_findings)
        return total_confidence / len(all_findings)
    
    # Tool implementations
    def _validate_finding_tool(self, finding_description: str) -> str:
        """Tool: Validate a finding based on description"""
        return f"Validating: {finding_description}. Analysis in progress..."
    
    def _check_fp_indicators(self, code_snippet: str) -> str:
        """Tool: Check for false positive indicators"""
        fp_indicators = [
            "test", "mock", "example", "demo", "sample",
            "TODO", "FIXME", "deprecated", "@Ignore"
        ]
        
        found_indicators = [
            ind for ind in fp_indicators 
            if ind.lower() in code_snippet.lower()
        ]
        
        if found_indicators:
            return f"False positive indicators found: {', '.join(found_indicators)}"
        return "No obvious false positive indicators detected"
    
    def _analyze_code_pattern(self, pattern: str, code: str) -> str:
        """Tool: Analyze specific code patterns"""
        try:
            if re.search(pattern, code, re.IGNORECASE):
                return f"Pattern '{pattern}' found in code"
            return f"Pattern '{pattern}' not found"
        except Exception as e:
            return f"Error analyzing pattern: {e}"
    
    def _check_third_party_library(self, file_path: str) -> str:
        """Tool: Check if file belongs to third-party library"""
        third_party_indicators = [
            "com/google/", "com/facebook/", "androidx/",
            "android/support/", "okhttp", "retrofit", 
            "gson", "glide", "org/apache/"
        ]
        
        for indicator in third_party_indicators:
            if indicator in file_path.replace("\\", "/"):
                return f"Third-party library detected: {indicator}"
                
        return "Appears to be application code (not third-party)"
    
    def _assess_severity(self, finding_details: str) -> str:
        """Tool: Reassess finding severity"""
        # Simplified severity assessment
        critical_keywords = ["rce", "sql injection", "command injection", "xxe"]
        high_keywords = ["xss", "path traversal", "idor", "authentication"]
        
        details_lower = finding_details.lower()
        
        if any(kw in details_lower for kw in critical_keywords):
            return "Severity Assessment: CRITICAL"
        elif any(kw in details_lower for kw in high_keywords):
            return "Severity Assessment: HIGH"
        else:
            return "Severity Assessment: MEDIUM"
    
    def _get_remediation_guidance(self, vulnerability_type: str) -> str:
        """Tool: Get remediation guidance"""
        remediation_db = {
            "sql_injection": "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.",
            "hardcoded_secrets": "Store secrets in secure storage (Android Keystore) or environment variables. Never hardcode in source.",
            "ssl_pinning": "Implement proper certificate pinning. Avoid disabling SSL verification.",
            "webview": "Disable JavaScript if not needed. Validate all loaded URLs. Use setAllowFileAccess(false).",
        }
        
        for key, guidance in remediation_db.items():
            if key in vulnerability_type.lower():
                return f"Remediation: {guidance}"
                
        return "Remediation: Follow secure coding best practices for this vulnerability type"
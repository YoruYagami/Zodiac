"""
Source Analyzer Agent for Code Context Extraction
Analyzes source code to provide context for security findings
"""

import re
import ast
from pathlib import Path
from typing import Dict, Any, List, Optional, Set, Tuple
from datetime import datetime
import logging

from langchain_core.tools import Tool
from pydantic import BaseModel, Field

from .base_agent import BaseAgent, AgentConfig, ToolBuilder
from ..core.models import Finding, SourceContext, AnalysisPhase
from ..config.settings import get_settings


class CodeAnalysisRequest(BaseModel):
    """Request for code analysis"""
    file_path: Path
    line_number: Optional[int] = None
    context_lines: int = 10
    extract_dependencies: bool = True
    

class SourceAnalyzerAgent(BaseAgent):
    """
    Agent specialized in analyzing source code context
    Provides deep code analysis for security findings
    """
    
    def __init__(self, state=None):
        config = AgentConfig(
            name="SourceAnalyzerAgent",
            description="Expert in Android source code analysis and context extraction",
            temperature=0.0,
            max_tokens=2000
        )
        super().__init__(config, state)
        
        # Source analysis cache
        self.file_cache: Dict[str, List[str]] = {}
        self.class_cache: Dict[str, Dict] = {}
        self.import_cache: Dict[str, List[str]] = {}
        
        # Code patterns
        self.patterns = self._load_patterns()
        
    def _load_patterns(self) -> Dict[str, re.Pattern]:
        """Load regex patterns for code analysis"""
        return {
            "class_def": re.compile(r'(?:public\s+)?(?:abstract\s+)?(?:final\s+)?class\s+(\w+)'),
            "method_def": re.compile(r'(?:public|private|protected)?\s*(?:static\s+)?(?:final\s+)?(?:synchronized\s+)?(?:\w+(?:\[\])?(?:\<[^>]+\>)?)\s+(\w+)\s*\([^)]*\)'),
            "import_stmt": re.compile(r'import\s+((?:static\s+)?[\w.]+(?:\.\*)?);'),
            "package_stmt": re.compile(r'package\s+([\w.]+);'),
            "annotation": re.compile(r'@(\w+)(?:\([^)]*\))?'),
            "string_literal": re.compile(r'"([^"\\]*(\\.[^"\\]*)*)"'),
            "api_key_pattern": re.compile(r'(?i)(api[_]?key|secret|token|password)\s*=\s*["\']([^"\']+)["\']'),
            "url_pattern": re.compile(r'https?://[^\s"\'>]+'),
            "intent_extra": re.compile(r'(?:getStringExtra|getIntExtra|getBooleanExtra)\s*\(["\']([^"\']+)["\']'),
            "sql_query": re.compile(r'(?:SELECT|INSERT|UPDATE|DELETE)\s+(?:FROM|INTO)?\s+\w+', re.IGNORECASE),
            "crypto_usage": re.compile(r'(?:Cipher|MessageDigest|KeyGenerator|SecretKey)\.'),
        }
    
    def _get_specific_tools(self) -> List[Tool]:
        """Get source analyzer specific tools"""
        return [
            ToolBuilder.create_tool(
                name="extract_method_context",
                func=self._extract_method_context,
                description="Extract the method containing a specific line"
            ),
            ToolBuilder.create_tool(
                name="extract_class_context",
                func=self._extract_class_context,
                description="Extract class information from a file"
            ),
            ToolBuilder.create_tool(
                name="analyze_data_flow",
                func=self._analyze_data_flow,
                description="Analyze data flow in code"
            ),
            ToolBuilder.create_tool(
                name="find_entry_points",
                func=self._find_entry_points,
                description="Find entry points (activities, services, etc.)"
            ),
            ToolBuilder.create_tool(
                name="detect_code_patterns",
                func=self._detect_patterns,
                description="Detect specific code patterns"
            ),
            ToolBuilder.create_tool(
                name="analyze_dependencies",
                func=self._analyze_dependencies,
                description="Analyze file dependencies and imports"
            ),
            ToolBuilder.create_tool(
                name="check_security_annotations",
                func=self._check_security_annotations,
                description="Check for security-related annotations"
            )
        ]
    
    async def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute source analysis for findings
        """
        findings = input_data.get("findings", [])
        source_dir = Path(input_data.get("source_dir"))
        use_rag = input_data.get("use_rag", False)
        
        self.logger.info(f"Analyzing source context for {len(findings)} findings")
        
        # Build file index
        self._build_file_index(source_dir)
        
        # Process each finding
        analyzed_findings = []
        for finding in findings:
            try:
                # Extract source context
                context = await self._analyze_finding_context(finding, source_dir)
                
                if context:
                    finding.source_context = context
                    
                    # Enhance with LLM analysis if complex
                    if self._needs_llm_analysis(context):
                        enhanced_context = await self._llm_enhance_context(context, finding)
                        if enhanced_context:
                            finding.source_context = enhanced_context
                            
                analyzed_findings.append(finding)
                
            except Exception as e:
                self.logger.error(f"Error analyzing finding {finding.finding_id}: {e}")
                analyzed_findings.append(finding)
        
        return {
            "success": True,
            "findings": analyzed_findings,
            "files_analyzed": len(self.file_cache),
            "contexts_extracted": len([f for f in analyzed_findings if f.source_context])
        }
    
    def _build_file_index(self, source_dir: Path):
        """Build an index of source files"""
        
        self.java_files = list(source_dir.rglob("*.java"))
        self.kotlin_files = list(source_dir.rglob("*.kt"))
        self.xml_files = list(source_dir.rglob("*.xml"))
        self.smali_files = list(source_dir.rglob("*.smali"))
        
        self.logger.info(f"Indexed {len(self.java_files)} Java, {len(self.kotlin_files)} Kotlin, "
                        f"{len(self.xml_files)} XML, {len(self.smali_files)} Smali files")
    
    async def _analyze_finding_context(
        self, 
        finding: Finding, 
        source_dir: Path
    ) -> Optional[SourceContext]:
        """Analyze context for a specific finding"""
        
        if not finding.file_path:
            return None
            
        # Find the actual source file
        source_file = self._locate_source_file(finding.file_path, source_dir)
        if not source_file:
            return None
            
        # Read file content
        lines = self._get_file_lines(source_file)
        if not lines:
            return None
            
        # Extract context
        line_num = finding.line_number or 0
        context_start = max(0, line_num - 15)
        context_end = min(len(lines), line_num + 15)
        
        code_snippet = ''.join(lines[context_start:context_end])
        
        # Extract additional context
        method_context = self._extract_method_at_line(lines, line_num)
        class_info = self._extract_class_info(lines)
        imports = self._extract_imports(lines)
        package_name = self._extract_package(lines)
        
        # Determine code characteristics
        is_test = self._is_test_code(source_file, class_info.get("class_name", ""))
        is_example = self._is_example_code(source_file, class_info.get("class_name", ""))
        is_third_party = self._is_third_party_code(source_file, package_name)
        is_generated = self._is_generated_code(lines)
        
        # Calculate context confidence
        confidence = self._calculate_context_confidence(
            has_method=bool(method_context),
            has_class=bool(class_info),
            is_test=is_test,
            is_third_party=is_third_party
        )
        
        return SourceContext(
            file_path=str(source_file),
            line_number=line_num,
            code_snippet=code_snippet,
            method_context=method_context,
            class_context=class_info.get("class_name"),
            package_name=package_name,
            imports=imports,
            is_test_code=is_test,
            is_example_code=is_example,
            is_third_party=is_third_party,
            is_generated=is_generated,
            confidence=confidence
        )
    
    def _locate_source_file(self, file_hint: str, source_dir: Path) -> Optional[Path]:
        """Locate the actual source file from a hint"""
        
        # Try direct path first
        if Path(file_hint).exists():
            return Path(file_hint)
            
        # Try relative to source dir
        potential = source_dir / file_hint
        if potential.exists():
            return potential
            
        # Search by filename
        filename = Path(file_hint).name
        for file_list in [self.java_files, self.kotlin_files, self.xml_files, self.smali_files]:
            for f in file_list:
                if f.name == filename:
                    return f
                    
        # Fuzzy search
        for file_list in [self.java_files, self.kotlin_files, self.xml_files, self.smali_files]:
            for f in file_list:
                if file_hint in str(f):
                    return f
                    
        return None
    
    def _get_file_lines(self, file_path: Path) -> List[str]:
        """Get cached file lines"""
        
        path_str = str(file_path)
        if path_str not in self.file_cache:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    self.file_cache[path_str] = f.readlines()
            except Exception as e:
                self.logger.warning(f"Error reading {file_path}: {e}")
                return []
                
        return self.file_cache.get(path_str, [])
    
    def _extract_method_at_line(self, lines: List[str], target_line: int) -> str:
        """Extract method containing the target line"""
        
        if target_line <= 0 or target_line > len(lines):
            return ""
            
        # Search backwards for method signature
        brace_count = 0
        method_start = -1
        
        for i in range(target_line - 1, max(0, target_line - 100), -1):
            line = lines[i]
            
            # Count braces
            brace_count += line.count('}') - line.count('{')
            
            # Check for method pattern
            if brace_count >= 0 and self.patterns["method_def"].search(line):
                method_start = i
                break
                
        if method_start == -1:
            return ""
            
        # Extract method signature
        method_lines = []
        for i in range(method_start, min(method_start + 5, len(lines))):
            method_lines.append(lines[i].strip())
            if '{' in lines[i]:
                break
                
        return ' '.join(method_lines)
    
    def _extract_class_info(self, lines: List[str]) -> Dict[str, Any]:
        """Extract class information from file"""
        
        class_info = {
            "class_name": None,
            "extends": None,
            "implements": [],
            "annotations": [],
            "modifiers": []
        }
        
        for i, line in enumerate(lines[:100]):  # Check first 100 lines
            # Find class declaration
            class_match = self.patterns["class_def"].search(line)
            if class_match:
                class_info["class_name"] = class_match.group(1)
                
                # Check for extends
                extends_match = re.search(r'extends\s+(\w+)', line)
                if extends_match:
                    class_info["extends"] = extends_match.group(1)
                    
                # Check for implements
                implements_match = re.search(r'implements\s+(.+?)(?:\s*\{|$)', line)
                if implements_match:
                    class_info["implements"] = [
                        impl.strip() for impl in implements_match.group(1).split(',')
                    ]
                    
                # Check annotations on previous lines
                for j in range(max(0, i - 5), i):
                    ann_matches = self.patterns["annotation"].findall(lines[j])
                    class_info["annotations"].extend(ann_matches)
                    
                break
                
        return class_info
    
    def _extract_imports(self, lines: List[str]) -> List[str]:
        """Extract import statements"""
        
        imports = []
        for line in lines[:200]:  # Usually imports are at the top
            import_match = self.patterns["import_stmt"].search(line)
            if import_match:
                imports.append(import_match.group(1))
                
        return imports
    
    def _extract_package(self, lines: List[str]) -> Optional[str]:
        """Extract package name"""
        
        for line in lines[:50]:
            package_match = self.patterns["package_stmt"].search(line)
            if package_match:
                return package_match.group(1)
                
        return None
    
    def _extract_method_context(self, file_path: str, line_number: str) -> str:
        """Tool: Extract method context"""
        
        path = Path(file_path)
        if not path.exists():
            return "File not found"
            
        lines = self._get_file_lines(path)
        line_num = int(line_number) if line_number.isdigit() else 0
        
        method = self._extract_method_at_line(lines, line_num)
        return method if method else "No method found at specified line"
    
    def _extract_class_context(self, file_path: str) -> str:
        """Tool: Extract class context"""
        
        path = Path(file_path)
        if not path.exists():
            return "File not found"
            
        lines = self._get_file_lines(path)
        class_info = self._extract_class_info(lines)
        
        if class_info["class_name"]:
            result = f"Class: {class_info['class_name']}"
            if class_info["extends"]:
                result += f" extends {class_info['extends']}"
            if class_info["implements"]:
                result += f" implements {', '.join(class_info['implements'])}"
            if class_info["annotations"]:
                result += f"\nAnnotations: {', '.join(class_info['annotations'])}"
            return result
        else:
            return "No class found in file"
    
    def _analyze_data_flow(self, code_snippet: str) -> str:
        """Tool: Analyze data flow in code"""
        
        flows = []
        
        # Check for intent extras
        intent_extras = self.patterns["intent_extra"].findall(code_snippet)
        if intent_extras:
            flows.append(f"Intent extras accessed: {', '.join(intent_extras)}")
            
        # Check for SQL queries
        sql_queries = self.patterns["sql_query"].findall(code_snippet)
        if sql_queries:
            flows.append(f"SQL operations detected: {len(sql_queries)}")
            
        # Check for crypto operations
        crypto_ops = self.patterns["crypto_usage"].findall(code_snippet)
        if crypto_ops:
            flows.append("Cryptographic operations detected")
            
        # Check for URLs
        urls = self.patterns["url_pattern"].findall(code_snippet)
        if urls:
            flows.append(f"URLs found: {len(urls)}")
            
        return "\n".join(flows) if flows else "No significant data flow patterns detected"
    
    def _find_entry_points(self, source_dir: str) -> str:
        """Tool: Find application entry points"""
        
        entry_points = {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": []
        }
        
        # Look for Android components
        for java_file in Path(source_dir).rglob("*.java"):
            try:
                content = java_file.read_text(errors='ignore')
                
                if "extends Activity" in content or "extends AppCompatActivity" in content:
                    entry_points["activities"].append(java_file.name)
                elif "extends Service" in content:
                    entry_points["services"].append(java_file.name)
                elif "extends BroadcastReceiver" in content:
                    entry_points["receivers"].append(java_file.name)
                elif "extends ContentProvider" in content:
                    entry_points["providers"].append(java_file.name)
                    
            except Exception:
                pass
                
        result = []
        for comp_type, components in entry_points.items():
            if components:
                result.append(f"{comp_type.capitalize()}: {len(components)} found")
                
        return "\n".join(result) if result else "No entry points found"
    
    def _detect_patterns(self, code_snippet: str) -> str:
        """Tool: Detect code patterns"""
        
        detected = []
        
        # API keys
        api_keys = self.patterns["api_key_pattern"].findall(code_snippet)
        if api_keys:
            detected.append(f"Potential API keys/secrets: {len(api_keys)}")
            
        # String literals
        strings = self.patterns["string_literal"].findall(code_snippet)
        if strings:
            detected.append(f"String literals: {len(strings)}")
            
        # Annotations
        annotations = self.patterns["annotation"].findall(code_snippet)
        if annotations:
            detected.append(f"Annotations: {', '.join(set(annotations))}")
            
        return "\n".join(detected) if detected else "No specific patterns detected"
    
    def _analyze_dependencies(self, file_path: str) -> str:
        """Tool: Analyze file dependencies"""
        
        path = Path(file_path)
        if not path.exists():
            return "File not found"
            
        lines = self._get_file_lines(path)
        imports = self._extract_imports(lines)
        
        # Categorize imports
        android_imports = [i for i in imports if i.startswith("android.")]
        java_imports = [i for i in imports if i.startswith("java.")]
        third_party = [i for i in imports if not i.startswith(("android.", "java."))]
        
        result = f"Total imports: {len(imports)}\n"
        result += f"Android: {len(android_imports)}\n"
        result += f"Java: {len(java_imports)}\n"
        result += f"Third-party: {len(third_party)}"
        
        if third_party:
            result += f"\nThird-party libs: {', '.join(third_party[:5])}"
            
        return result
    
    def _check_security_annotations(self, file_path: str) -> str:
        """Tool: Check for security annotations"""
        
        security_annotations = [
            "RequiresPermission",
            "RequiresApi",
            "RestrictTo",
            "VisibleForTesting",
            "Deprecated",
            "SuppressLint",
            "TargetApi"
        ]
        
        path = Path(file_path)
        if not path.exists():
            return "File not found"
            
        content = path.read_text(errors='ignore')
        found = []
        
        for annotation in security_annotations:
            if f"@{annotation}" in content:
                count = content.count(f"@{annotation}")
                found.append(f"{annotation}: {count}")
                
        return "\n".join(found) if found else "No security annotations found"
    
    def _is_test_code(self, file_path: Path, class_name: str) -> bool:
        """Check if code is test code"""
        
        test_indicators = ['test', 'Test', 'mock', 'Mock', 'spec', 'Spec']
        path_str = str(file_path).lower()
        
        # Check path
        if any(ind in path_str for ind in ['test', 'androidtest', 'mock']):
            return True
            
        # Check class name
        if class_name and any(ind in class_name for ind in test_indicators):
            return True
            
        return False
    
    def _is_example_code(self, file_path: Path, class_name: str) -> bool:
        """Check if code is example/demo code"""
        
        example_indicators = ['example', 'Example', 'demo', 'Demo', 'sample', 'Sample']
        path_str = str(file_path)
        
        return any(ind in path_str or (class_name and ind in class_name) 
                  for ind in example_indicators)
    
    def _is_third_party_code(self, file_path: Path, package_name: Optional[str]) -> bool:
        """Check if code is third-party"""
        
        third_party_packages = [
            'com.google', 'com.facebook', 'com.squareup', 'com.github',
            'org.apache', 'io.reactivex', 'retrofit2', 'okhttp3',
            'androidx', 'android.support'
        ]
        
        path_str = str(file_path).replace('\\', '/')
        
        # Check package name
        if package_name:
            return any(package_name.startswith(pkg) for pkg in third_party_packages)
            
        # Check path
        return any(pkg.replace('.', '/') in path_str for pkg in third_party_packages)
    
    def _is_generated_code(self, lines: List[str]) -> bool:
        """Check if code is generated"""
        
        generated_indicators = [
            'Generated', 'generated', 'AUTO-GENERATED', 'auto-generated',
            'DO NOT EDIT', 'do not edit', 'Autogenerated'
        ]
        
        # Check first 10 lines
        for line in lines[:10]:
            if any(ind in line for ind in generated_indicators):
                return True
                
        return False
    
    def _calculate_context_confidence(
        self,
        has_method: bool,
        has_class: bool,
        is_test: bool,
        is_third_party: bool
    ) -> float:
        """Calculate confidence score for context"""
        
        confidence = 0.5
        
        if has_method:
            confidence += 0.2
        if has_class:
            confidence += 0.2
        if is_test:
            confidence -= 0.3
        if is_third_party:
            confidence -= 0.2
            
        return max(0.0, min(1.0, confidence))
    
    def _needs_llm_analysis(self, context: SourceContext) -> bool:
        """Determine if context needs LLM enhancement"""
        
        # Complex patterns that benefit from LLM analysis
        complex_indicators = [
            'reflection', 'invoke', 'Class.forName',
            'Runtime.exec', 'ProcessBuilder',
            'Cipher', 'Signature', 'KeyStore',
            'ContentResolver', 'ContentProvider'
        ]
        
        return any(ind in context.code_snippet for ind in complex_indicators)
    
    async def _llm_enhance_context(
        self, 
        context: SourceContext,
        finding: Finding
    ) -> SourceContext:
        """Enhance context using LLM analysis"""
        
        prompt = f"""
        Analyze this Android code context for security implications:
        
        Finding: {finding.title}
        Rule: {finding.rule_id}
        
        Code:
        ```java
        {context.code_snippet[:1000]}
        ```
        
        Provide:
        1. What is the security concern?
        2. Is this likely a false positive? (consider: test={context.is_test_code}, third-party={context.is_third_party})
        3. What is the risk level?
        """
        
        try:
            response = self.run(prompt)
            
            # Update confidence based on LLM analysis
            if "false positive" in response.lower():
                context.confidence *= 0.5
            elif "high risk" in response.lower():
                context.confidence = min(1.0, context.confidence * 1.3)
                
        except Exception as e:
            self.logger.warning(f"LLM enhancement failed: {e}")
            
        return context
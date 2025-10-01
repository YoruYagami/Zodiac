#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Android Security Agent con Validazione Sorgente + RAG
Pipeline: APK → Decompile → MobSFScan (sorgente) → Source Validation → TP/DC/FP → RAG Q&A

Requisiti:
  pip install mobsfscan langchain langchain-openai langchain-chroma pydantic rich jadx

Tool esterni:
  - apktool (preferito) o jadx per decompilazione
"""

import argparse
import json
import os
import re
import subprocess
import sys
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from rich.console import Console
from rich.progress import track
from rich.table import Table
from pydantic import BaseModel, Field
import hashlib
import tempfile
import datetime
from dotenv import load_dotenv

load_dotenv()

console = Console()

# ===================== Config RAG (OpenAI) =====================
# Usa variabili d'ambiente:
# - OPENAI_API_KEY: chiave OpenAI
# - OPENAI_LLM_MODEL (opzionale): override modello LLM
# - OPENAI_EMBEDDING_MODEL (opzionale): override modello di embedding
DEFAULT_OPENAI_LLM_MODEL = os.getenv("OPENAI_LLM_MODEL", "gpt-5-mini-2025-08-07")
DEFAULT_OPENAI_EMBEDDING_MODEL = os.getenv("OPENAI_EMBEDDING_MODEL", "text-embedding-3-large")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# ===================== LangChain imports =====================
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from langchain_chroma import Chroma
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.chains import RetrievalQA
from langchain.memory import ConversationBufferMemory
from langchain.schema import Document

# ===================== Helper OpenAI builders =====================
def build_openai_llm(model: Optional[str] = None):
    llm_kwargs: Dict[str, Any] = {
        "model": model or DEFAULT_OPENAI_LLM_MODEL,
        "temperature": 0,
        "max_tokens": 1000,
    }
    if OPENAI_BASE_URL:
        llm_kwargs["base_url"] = OPENAI_BASE_URL
    if OPENAI_API_KEY:
        llm_kwargs["api_key"] = OPENAI_API_KEY
    return ChatOpenAI(**llm_kwargs)

def build_openai_embeddings(embedding_model: Optional[str] = None):
    embedding_kwargs: Dict[str, Any] = {
        "model": embedding_model or DEFAULT_OPENAI_EMBEDDING_MODEL,
    }
    if OPENAI_BASE_URL:
        embedding_kwargs["base_url"] = OPENAI_BASE_URL
    if OPENAI_API_KEY:
        embedding_kwargs["api_key"] = OPENAI_API_KEY
    return OpenAIEmbeddings(**embedding_kwargs)

# ===================== Validation Config =====================
class ValidationLevel(Enum):
    STRICT = "strict"
    MODERATE = "moderate"
    LENIENT = "lenient"

class FindingCategory(Enum):
    TRUE_POSITIVE = "TP"
    DYNAMIC_CHECK = "DC"
    FALSE_POSITIVE = "FP"

# ===================== Data Models =====================
@dataclass
class SourceContext:
    file_path: str
    line_number: int
    code_snippet: str
    method_context: str
    class_context: str
    imports: List[str]
    is_test_code: bool = False
    is_example_code: bool = False
    is_third_party: bool = False
    confidence: float = 0.0

@dataclass
class Finding:
    rule_id: str
    description: str
    severity: str
    file: Optional[str] = None
    line: Optional[int] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    cvss: Optional[float] = None
    engine: str = "mobsfscan"
    raw: Optional[dict] = None

    source_context: Optional[SourceContext] = None
    validation_status: Optional[FindingCategory] = None
    validation_reason: Optional[str] = None
    validation_confidence: float = 0.0

@dataclass
class ValidationRule:
    rule_id: str
    patterns: List[str]
    anti_patterns: List[str]
    context_required: List[str]
    dynamic_indicators: List[str]
    min_confidence: float = 0.7

# ===================== APK Decompilation =====================
class APKDecompiler:
    def __init__(self, work_dir: Path):
        self.work_dir = work_dir
        self.source_dir = work_dir / "source"
        self.source_dir.mkdir(exist_ok=True)
        self.apktool_path = os.getenv("APKTOOL_PATH")
        self.jadx_path = os.getenv("JADX_PATH")

    def decompile(self, apk_path: Path) -> Path:
        console.print("[bold blue]Decompiling APK...[/bold blue]")
        if self._has_apktool():
            return self._decompile_apktool(apk_path)
        elif self._has_jadx():
            console.print("[yellow]apktool non trovato, uso JADX[/yellow]")
            return self._decompile_jadx(apk_path)
        else:
            console.print("[red]Installa apktool o jadx[/red]")
            sys.exit(1)

    def _has_jadx(self) -> bool:
        if self.jadx_path:
            candidate = Path(self.jadx_path)
            if candidate.suffix.lower() == ".jar":
                return candidate.exists()
            if candidate.exists():
                return True
            return shutil.which(self.jadx_path) is not None
        return shutil.which("jadx") is not None

    def _has_apktool(self) -> bool:
        if self.apktool_path:
            candidate = Path(self.apktool_path)
            if candidate.suffix.lower() == ".jar":
                return candidate.exists()
            if candidate.exists():
                return True
            return shutil.which(self.apktool_path) is not None
        return shutil.which("apktool") is not None

    def _apktool_command(self) -> List[str]:
        if self.apktool_path:
            candidate = Path(self.apktool_path)
            if candidate.suffix.lower() == ".jar":
                return ["java", "-jar", str(candidate)]
            return [str(candidate)]
        inferred = self._default_windows_apktool()
        if inferred:
            if inferred.suffix.lower() == ".jar":
                return ["java", "-jar", str(inferred)]
            return [str(inferred)]
        return ["apktool"]

    def _default_windows_apktool(self) -> Optional[Path]:
        if os.name != "nt":
            return None
        common_locations = [
            Path("C:/Windows/System32/apktool.bat"),
            Path("C:/Windows/apktool.bat"),
            Path("C:/Program Files/apktool/apktool.jar"),
            Path("C:/Program Files (x86)/apktool/apktool.jar"),
        ]
        for location in common_locations:
            if location.exists():
                return location
        return None

    def _jadx_command(self) -> List[str]:
        if self.jadx_path:
            candidate = Path(self.jadx_path)
            if candidate.suffix.lower() == ".jar":
                return ["java", "-jar", str(candidate)]
            return [str(candidate)]
        return ["jadx"]

    def _decompile_apktool(self, apk_path: Path) -> Path:
        output_dir = self.source_dir / "apktool_output"
        if output_dir.exists():
            shutil.rmtree(output_dir)
        
        # Comandi apktool con opzioni ottimizzate per velocità
        cmd = self._apktool_command() + [
            "d", "-f", 
            "--no-debug-info",  # Skip debug info per velocità
            "--no-assets",      # Skip assets se non necessari
            "-o", str(output_dir), 
            str(apk_path)
        ]
        
        console.print(f"[dim]apktool decompiling {apk_path.name} (timeout: 300s)...[/dim]")
        
        try:
            # Aumentato timeout e aggiunto output in tempo reale
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Monitora il processo con timeout più lungo
            try:
                stdout, stderr = process.communicate(timeout=300)  # 5 minuti
                
                if process.returncode != 0:
                    console.print(f"[yellow]apktool exit code: {process.returncode}[/yellow]")
                    if stderr:
                        console.print(f"[yellow]apktool stderr: {stderr[:500]}[/yellow]")
                    
                    # Se fallisce, prova JADX come fallback
                    if not output_dir.exists() or not any(output_dir.iterdir()):
                        console.print("[yellow]apktool failed, trying JADX fallback[/yellow]")
                        return self._decompile_jadx(apk_path)
                
                # Verifica risultati
                if output_dir.exists():
                    smali_count = len(list(output_dir.rglob("*.smali")))
                    xml_count = len(list(output_dir.rglob("*.xml")))
                    console.print(f"[green]✓ Decompiled: {smali_count} smali, {xml_count} xml[/green]")
                else:
                    console.print("[yellow]apktool completed but no output directory found[/yellow]")
                    return self._decompile_jadx(apk_path)
                    
            except subprocess.TimeoutExpired:
                console.print("[yellow]apktool timeout after 5 minutes, terminating...[/yellow]")
                process.kill()
                process.wait()
                
                # Verifica se ha prodotto risultati parziali
                if output_dir.exists() and any(output_dir.iterdir()):
                    console.print("[yellow]Using partial apktool results[/yellow]")
                else:
                    console.print("[yellow]apktool timeout, trying JADX fallback[/yellow]")
                    return self._decompile_jadx(apk_path)
                    
        except FileNotFoundError:
            console.print("[yellow]apktool command not found, attempting JADX fallback[/yellow]")
            return self._decompile_jadx(apk_path)
        except Exception as e:
            console.print(f"[yellow]apktool error: {e}, trying JADX fallback[/yellow]")
            return self._decompile_jadx(apk_path)
            
        return output_dir

    def _decompile_jadx(self, apk_path: Path) -> Path:
        output_dir = self.source_dir / "jadx_output"
        if output_dir.exists():
            shutil.rmtree(output_dir)
        cmd = self._jadx_command() + [
            "-d", str(output_dir),
            "--no-res", "--no-debug-info",
            "--threads", "4", str(apk_path)
        ]
        console.print("[dim]JADX decompiling...[/dim]")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            if result.returncode != 0 and result.stderr:
                console.print(f"[yellow]jadx stderr: {result.stderr[:400]}[/yellow]")
            java_count = len(list(output_dir.rglob("*.java")))
            console.print(f"[green]✓ Decompiled: {java_count} java files[/green]")
        except FileNotFoundError as e:
            raise RuntimeError(
                "JADX executable not found. Install jadx or set the JADX_PATH environment "
                "variable to the executable (.exe) or JAR."
            ) from e
        except subprocess.TimeoutExpired:
            console.print("[yellow]jadx timeout[/yellow]")
        return output_dir

# ===================== Source Analyzer =====================
class SourceAnalyzer:
    def __init__(self, source_dir: Path):
        self.source_dir = source_dir
        self.file_cache: Dict[str, List[str]] = {}
        self._build_file_index()

    def _build_file_index(self):
        console.print("[dim]Indicizzazione sorgenti...[/dim]")
        self.java_files = list(self.source_dir.rglob("*.java"))
        self.smali_files = list(self.source_dir.rglob("*.smali"))
        self.xml_files = list(self.source_dir.rglob("*.xml"))
        console.print(f"[dim]Trovati: {len(self.java_files)} .java, {len(self.smali_files)} .smali, {len(self.xml_files)} .xml[/dim]")

    def extract_context(self, file_path: str, line_number: Optional[int] = None) -> Optional[SourceContext]:
        matched_file = self._find_source_file(file_path)
        if not matched_file:
            return None
        try:
            with open(matched_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            if not lines:
                return None
            line_idx = (line_number - 1) if line_number else 0
            line_idx = max(0, min(line_idx, len(lines) - 1))
            context_start = max(0, line_idx - 10)
            context_end = min(len(lines), line_idx + 11)
            code_snippet = ''.join(lines[context_start:context_end])
            method_context = self._extract_method_context(lines, line_idx)
            class_context = self._extract_class_context(lines)
            imports = self._extract_imports(lines)
            is_test = self._is_test_code(matched_file, class_context)
            is_example = self._is_example_code(matched_file, class_context)
            is_third_party = self._is_third_party(matched_file)
            return SourceContext(
                file_path=str(matched_file),
                line_number=line_number or 0,
                code_snippet=code_snippet,
                method_context=method_context,
                class_context=class_context,
                imports=imports,
                is_test_code=is_test,
                is_example_code=is_example,
                is_third_party=is_third_party
            )
        except Exception as e:
            console.print(f"[yellow]Errore lettura {matched_file}: {e}[/yellow]")
            return None

    def _find_source_file(self, file_hint: str) -> Optional[Path]:
        if not file_hint:
            return None
        for f in self.java_files + self.smali_files + self.xml_files:
            if file_hint in str(f):
                return f
        base_name = Path(file_hint).name
        for f in self.java_files + self.smali_files + self.xml_files:
            if f.name == base_name:
                return f
        return None

    def _extract_method_context(self, lines: List[str], line_idx: int) -> str:
        for i in range(line_idx, max(0, line_idx - 50), -1):
            line = lines[i].strip()
            if any(kw in line for kw in ['public ', 'private ', 'protected ', 'static ']) and '(' in line and ')' in line:
                return line
        return ""

    def _extract_class_context(self, lines: List[str]) -> str:
        for line in lines[:50]:
            if 'class ' in line:
                m = re.search(r'class\s+(\w+)', line)
                if m:
                    return m.group(1)
        return ""

    def _extract_imports(self, lines: List[str]) -> List[str]:
        imports = []
        for line in lines[:100]:
            if line.strip().startswith('import '):
                imports.append(line.strip())
        return imports

    def _is_test_code(self, file_path: Path, class_name: str) -> bool:
        indicators = ['test', 'mock', 'example', 'demo']
        path_str = str(file_path).lower()
        return any(ind in path_str for ind in indicators) or any(ind in class_name.lower() for ind in indicators)

    def _is_example_code(self, file_path: Path, class_name: str) -> bool:
        indicators = ['example', 'sample', 'demo', 'tutorial']
        path_str = str(file_path).lower()
        return any(ind in path_str for ind in indicators)

    def _is_third_party(self, file_path: Path) -> bool:
        third = ['com/google/', 'com/facebook/', 'androidx/', 'android/support/', 'okhttp', 'retrofit', 'gson', 'glide', 'butterknife']
        path_str = str(file_path).replace('\\', '/')
        return any(ind in path_str for ind in third)

# ===================== Validation Engine =====================
class ValidationEngine:
    def __init__(self, source_analyzer: SourceAnalyzer, level: ValidationLevel = ValidationLevel.MODERATE):
        self.analyzer = source_analyzer
        self.level = level
        self.rules = self._load_validation_rules()

    def _load_validation_rules(self) -> Dict[str, ValidationRule]:
        rules = {
            # MobSFScan rule IDs - match actual output
            "android_manifest_missing_explicit_allow_backup": ValidationRule(
                rule_id="android_manifest_missing_explicit_allow_backup",
                patterns=[r'android:allowBackup\s*=\s*["\']true["\']', r'<application(?![^>]*android:allowBackup)'],
                anti_patterns=[r'android:allowBackup\s*=\s*["\']false["\']', r'<!-- *backup disabled'],
                context_required=[],
                dynamic_indicators=[],
                min_confidence=0.6
            ),
            "android_task_hijacking2": ValidationRule(
                rule_id="android_task_hijacking2",
                patterns=[r'<activity[^>]*android:exported\s*=\s*["\']true["\']', r'<intent-filter>'],
                anti_patterns=[r'android:taskAffinity\s*=\s*["\']["\']', r'android:launchMode\s*=\s*["\']singleInstance["\']'],
                context_required=[],
                dynamic_indicators=[],
                min_confidence=0.7
            ),
            "android_sql_injection": ValidationRule(
                rule_id="android_sql_injection",
                patterns=[r'rawQuery\s*\([^,]+\+', r'execSQL\s*\([^)]*\+', r'query\([^)]*\+[^)]*\)'],
                anti_patterns=[r'ContentValues', r'SQLiteQueryBuilder', r'selectionArgs\s*=', r'@Test'],
                context_required=[],
                dynamic_indicators=['user input', 'intent.get', 'EditText'],
                min_confidence=0.8
            ),
            "android_ssl_pinning": ValidationRule(
                rule_id="android_ssl_pinning",
                patterns=[r'TrustManager.*{.*}', r'HostnameVerifier.*{.*return\s+true', r'setDefaultHostnameVerifier', r'SSLSocketFactory'],
                anti_patterns=[r'// *TODO', r'@Deprecated', r'BuildConfig\.DEBUG'],
                context_required=['javax.net.ssl', 'SSLContext'],
                dynamic_indicators=['HttpsURLConnection', 'OkHttpClient'],
                min_confidence=0.75
            ),
            "android_hardcoded": ValidationRule(
                rule_id="android_hardcoded",
                patterns=[r'(api[_]?key|apikey|secret|password|token)\s*=\s*["\'][^"\']+["\']', r'["\'][0-9a-f]{32,}["\']'],
                anti_patterns=[r'BuildConfig', r'R\.string\.', r'getResources\(\)', r'SharedPreferences', r'example\.com', r'test'],
                context_required=[],
                dynamic_indicators=[],
                min_confidence=0.7
            ),
            "android_webview": ValidationRule(
                rule_id="android_webview",
                patterns=[r'setJavaScriptEnabled\s*\(\s*true', r'setAllowFileAccess\s*\(\s*true', r'setAllowUniversalAccessFromFileURLs\s*\(\s*true', r'addJavascriptInterface'],
                anti_patterns=[r'if\s*\(.*BuildConfig\.DEBUG', r'webView\.destroy\(\)'],
                context_required=['android.webkit.WebView'],
                dynamic_indicators=['loadUrl', 'loadDataWithBaseURL'],
                min_confidence=0.8
            ),
        }
        return rules

    def validate_finding(self, finding: Finding) -> Finding:
        context = self.analyzer.extract_context(finding.file, finding.line)
        finding.source_context = context
        if not context:
            finding.validation_status = FindingCategory.DYNAMIC_CHECK
            finding.validation_reason = "Sorgente non trovato - richiede verifica dinamica"
            finding.validation_confidence = 0.3
            return finding
        rule = self._get_matching_rule(finding.rule_id)
        if rule:
            res = self._apply_rule(rule, context, finding)
        else:
            res = self._heuristic_validation(finding, context)
        finding.validation_status = res['category']
        finding.validation_reason = res['reason']
        finding.validation_confidence = res['confidence']
        return finding

    def _get_matching_rule(self, rule_id: str) -> Optional[ValidationRule]:
        if rule_id in self.rules:
            return self.rules[rule_id]
        for key, rule in self.rules.items():
            if key in rule_id.lower() or rule_id.lower() in key:
                return rule
        return None

    def _apply_rule(self, rule: ValidationRule, context: SourceContext, finding: Finding) -> Dict:
        confidence = 0.5
        reasons = []
        pattern_matches = 0
        for pattern in rule.patterns:
            if re.search(pattern, context.code_snippet, re.IGNORECASE):
                pattern_matches += 1
                confidence += 0.15
        for anti_pattern in rule.anti_patterns:
            if re.search(anti_pattern, context.code_snippet, re.IGNORECASE):
                confidence -= 0.2
                reasons.append(f"Anti-pattern: {anti_pattern[:30]}")
        if rule.context_required:
            has_ctx = any(any(req in imp for imp in context.imports) for req in rule.context_required)
            if not has_ctx:
                confidence -= 0.2
                reasons.append("Contesto richiesto mancante")
        if context.is_test_code:
            confidence -= 0.4
            reasons.append("Codice di test")
        if context.is_example_code:
            confidence -= 0.3
            reasons.append("Codice di esempio")
        if context.is_third_party:
            confidence -= 0.2
            reasons.append("Libreria third-party")
        needs_dynamic = False
        for indicator in rule.dynamic_indicators:
            if indicator.lower() in context.code_snippet.lower():
                needs_dynamic = True
                reasons.append(f"Richiede test dinamico: {indicator}")
        confidence = max(0, min(1, confidence))
        if confidence < 0.3:
            category = FindingCategory.FALSE_POSITIVE
            reason = "Bassa confidenza: " + ", ".join(reasons[:2]) if reasons else "Pattern non confermati"
        elif confidence >= rule.min_confidence and not needs_dynamic:
            category = FindingCategory.TRUE_POSITIVE
            reason = f"Vulnerabilità confermata (confidence: {confidence:.2f})"
        elif needs_dynamic or confidence >= 0.4:
            category = FindingCategory.DYNAMIC_CHECK
            reason = "Richiede validazione dinamica: " + ", ".join(reasons[:2]) if reasons else "Conferma runtime necessaria"
        else:
            category = FindingCategory.FALSE_POSITIVE
            reason = "Probabile FP"
        return {'category': category, 'reason': reason, 'confidence': confidence}

    def _heuristic_validation(self, finding: Finding, context: SourceContext) -> Dict:
        severity_map = {'HIGH': 0.7, 'MEDIUM': 0.5, 'LOW': 0.3}
        confidence = severity_map.get(finding.severity.upper(), 0.5)
        reasons = []
        if context.is_test_code:
            confidence -= 0.4
            reasons.append("Test code")
        if context.is_example_code:
            confidence -= 0.3
            reasons.append("Example code")
        dynamic_keywords = ['network', 'http', 'ssl', 'crypto', 'intent', 'broadcast', 'permission', 'storage', 'database', 'webview', 'javascript']
        snippet_lower = context.code_snippet.lower()
        if any(kw in snippet_lower for kw in dynamic_keywords):
            category = FindingCategory.DYNAMIC_CHECK
            reason = "Componente runtime - richiede validazione dinamica"
        elif confidence >= 0.6:
            category = FindingCategory.TRUE_POSITIVE
            reason = f"Probabile vulnerabilità (confidence: {confidence:.2f})"
        elif confidence >= 0.3:
            category = FindingCategory.DYNAMIC_CHECK
            reason = "Incerto - richiede verifica dinamica"
        else:
            category = FindingCategory.FALSE_POSITIVE
            reason = "Bassa confidenza"
        return {'category': category, 'reason': reason, 'confidence': confidence}

# ===================== Report Generator =====================
class ReportGenerator:
    def __init__(self):
        self.console = Console()

    def generate_report(self, findings: List[Finding], output_file: Path):
        tp_findings = [f for f in findings if f.validation_status == FindingCategory.TRUE_POSITIVE]
        dc_findings = [f for f in findings if f.validation_status == FindingCategory.DYNAMIC_CHECK]
        fp_findings = [f for f in findings if f.validation_status == FindingCategory.FALSE_POSITIVE]

        report = {
            "summary": {
                "total_findings": len(findings),
                "true_positives": len(tp_findings),
                "dynamic_checks": len(dc_findings),
                "false_positives": len(fp_findings),
                "confidence_avg": sum(f.validation_confidence for f in findings) / len(findings) if findings else 0
            },
            "true_positives": self._findings_to_dict(tp_findings),
            "dynamic_checks": self._findings_to_dict(dc_findings),
            "false_positives": self._findings_to_dict(fp_findings, include_reason=True)
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        self._print_summary_table(tp_findings, dc_findings, fp_findings)
        self._print_critical_findings(tp_findings)
        self.console.print(f"\n[green]Report salvato in: {output_file}[/green]")

    def _findings_to_dict(self, findings: List[Finding], include_reason: bool = False) -> List[Dict]:
        results = []
        for f in findings:
            item = {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "description": f.description,
                "file": f.file,
                "line": f.line,
                "confidence": round(f.validation_confidence, 2),
                "cwe": f.cwe,
                "owasp": f.owasp
            }
            if include_reason and f.validation_reason:
                item["validation_reason"] = f.validation_reason
            if f.source_context and f.validation_status != FindingCategory.FALSE_POSITIVE:
                snip = f.source_context.code_snippet
                item["code_snippet"] = (snip[:200] + "...") if len(snip) > 200 else snip
            results.append(item)
        return results

    def _print_summary_table(self, tp: List[Finding], dc: List[Finding], fp: List[Finding]):
        table = Table(title="Risultati Validazione")
        table.add_column("Categoria", style="bold")
        table.add_column("Count", justify="right")
        table.add_column("High", justify="right", style="red")
        table.add_column("Medium", justify="right", style="yellow")
        table.add_column("Low", justify="right", style="green")

        for category, findings, style in [
            ("True Positives", tp, "red"),
            ("Dynamic Checks", dc, "yellow"),
            ("False Positives", fp, "dim")
        ]:
            high = len([f for f in findings if f.severity.upper() == "HIGH"])
            medium = len([f for f in findings if f.severity.upper() == "MEDIUM"])
            low = len([f for f in findings if f.severity.upper() == "LOW"])
            table.add_row(category, str(len(findings)), str(high), str(medium), str(low), style=style)

        self.console.print(table)

    def _print_critical_findings(self, tp_findings: List[Finding]):
        critical = [f for f in tp_findings if f.severity.upper() == "HIGH"]
        if not critical:
            return
        self.console.print("\n[bold red]⚠️  Vulnerabilità Critiche Confermate:[/bold red]")
        for f in critical[:5]:
            self.console.print(f"  • {f.rule_id}: {f.description[:80]}...")
            if f.file:
                self.console.print(f"    📍 {f.file}:{f.line or '?'}")
            self.console.print(f"    🎯 Confidence: {f.validation_confidence:.0%}")

# ===================== MobSFScan Parser/Runner =====================
class AndroidSecurityAgent:
    def __init__(self, work_dir: Path, validation_level: ValidationLevel = ValidationLevel.MODERATE):
        self.work_dir = work_dir
        self.work_dir.mkdir(exist_ok=True)
        self.validation_level = validation_level
        self.decompiler = APKDecompiler(work_dir)

    def analyze(self, apk_path: Path) -> Path:
        console.print(f"\n[bold cyan]🔍 Android Security Analysis Pipeline[/bold cyan]")
        console.print(f"APK: {apk_path.name}\n")
        with console.status("[bold blue]Decompiling APK..."):
            source_dir = self.decompiler.decompile(apk_path)

        console.print("\n[bold blue]Running MobSFScan...[/bold blue]")
        scan_output = self.work_dir / "mobsfscan_results.json"
        self._run_mobsfscan(source_dir, scan_output)

        findings = self._parse_mobsfscan_output(scan_output)
        console.print(f"[green]Trovati {len(findings)} findings iniziali[/green]")

        analyzer = SourceAnalyzer(source_dir)
        validator = ValidationEngine(analyzer, self.validation_level)

        console.print("\n[bold blue]Validating findings against source code...[/bold blue]")
        validated_findings = []
        for finding in track(findings, description="Validating..."):
            validated_findings.append(validator.validate_finding(finding))

        report_path = self.work_dir / "security_analysis_report.json"
        reporter = ReportGenerator()
        reporter.generate_report(validated_findings, report_path)
        return report_path

    def _run_mobsfscan(self, source_dir: Path, output_path: Path):
        console.print(f"[dim]Scanning source directory: {source_dir}[/dim]")
        cmd = ["mobsfscan", "--json", "-o", str(output_path), str(source_dir)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode != 0 and result.stderr:
                console.print(f"[yellow]MobSFScan stderr: {result.stderr[:500]}[/yellow]")
            if output_path.exists():
                with open(output_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                total_findings = 0
                if "results" in data:
                    for _, items in data["results"].items():
                        if isinstance(items, dict):
                            if "files" in items:
                                total_findings += len(items["files"])
                            else:
                                total_findings += 1
                console.print(f"[green]✓ MobSFScan completed: {total_findings} potential issues found[/green]")
            else:
                console.print("[yellow]MobSFScan non ha prodotto output, creo file vuoto[/yellow]")
                with open(output_path, 'w') as f:
                    json.dump({"results": {}}, f)
        except FileNotFoundError:
            console.print("[red]mobsfscan non trovato. pip install mobsfscan[/red]")
            sys.exit(1)
        except subprocess.TimeoutExpired:
            console.print("[yellow]MobSFScan timeout - risultati parziali[/yellow]")
            if not output_path.exists():
                with open(output_path, 'w') as f:
                    json.dump({"results": {}}, f)

    def _parse_mobsfscan_output(self, json_path: Path) -> List[Finding]:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        findings: List[Finding] = []
        if "results" not in data:
            return findings
        for rule_id, rule_data in data["results"].items():
            if not isinstance(rule_data, dict):
                continue
            metadata = rule_data.get("metadata", {})
            if "files" in rule_data and rule_data["files"]:
                for file_match in rule_data["files"]:
                    findings.append(Finding(
                        rule_id=rule_id,
                        description=metadata.get("description", "No description"),
                        severity=metadata.get("severity", "INFO"),
                        file=file_match.get("file_path"),
                        line=file_match.get("match_lines", [None])[0] if file_match.get("match_lines") else None,
                        cwe=metadata.get("cwe"),
                        owasp=metadata.get("owasp-mobile"),
                        cvss=metadata.get("cvss"),
                        raw={"metadata": metadata, "file_match": file_match}
                    ))
            else:
                findings.append(Finding(
                    rule_id=rule_id,
                    description=metadata.get("description", "No description"),
                    severity=metadata.get("severity", "INFO"),
                    file=None,
                    line=None,
                    cwe=metadata.get("cwe"),
                    owasp=metadata.get("owasp-mobile"),
                    cvss=metadata.get("cvss"),
                    raw=metadata
                ))
        console.print(f"[dim]Parsed {len(findings)} findings from MobSFScan[/dim]")
        return findings

# ===================== RAG Tracker =====================
class AnalysisRAGTracker:
    """RAG per tracciare/interrogare lo stato dell'analisi + navigazione codice"""
    def __init__(self, work_dir: Path, model: str = "openai/gpt-5"):
        self.work_dir = work_dir
        self.rag_dir = work_dir / "rag_store"
        self.rag_dir.mkdir(exist_ok=True)

        self.enabled = True
        self.llm: Optional[Any] = None
        self.embeddings = None
        self.vectorstore: Optional[Chroma] = None

        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            console.print("[yellow]RAG disabled: OPENAI_API_KEY not set[/yellow]")
            self.enabled = False
        else:
            try:
                self.llm = build_openai_llm(model)
                self.embeddings = build_openai_embeddings()
                self.vectorstore = Chroma(
                    persist_directory=str(self.rag_dir),
                    embedding_function=self.embeddings
                )
            except Exception as e:
                console.print(f"[yellow]RAG disabled due to initialization failure: {e}[/yellow]")
                self.enabled = False

        self.memory = ConversationBufferMemory(
            memory_key="chat_history",
            return_messages=True
        )

        self.analysis_state = {
            "apk_name": "",
            "start_time": None,
            "current_phase": "not_started",
            "phases_completed": [],
            "findings_count": 0,
            "validated_count": 0,
            "critical_issues": []
        }

    def _flatten_metadata(self, data: Dict[str, Any]) -> Dict[str, Any]:
        flat = {}
        for k, v in data.items():
            if isinstance(v, (dict, list)):
                flat[k] = json.dumps(v)
            elif v is None:
                flat[k] = ""
            elif isinstance(v, (str, int, float, bool)):
                flat[k] = v
            else:
                flat[k] = str(v)
        return flat

    def log_phase(self, phase: str, data: Dict[str, Any]):
        timestamp = datetime.datetime.now().isoformat()
        self.analysis_state["current_phase"] = phase
        if phase not in self.analysis_state["phases_completed"]:
            self.analysis_state["phases_completed"].append(phase)

        content = f"""
        Phase: {phase}
        Timestamp: {timestamp}
        Status: Completed

        Details:
        {json.dumps(data, indent=2)}

        Current Analysis State:
        - APK: {self.analysis_state['apk_name']}
        - Phases Completed: {', '.join(self.analysis_state['phases_completed'])}
        - Total Findings: {self.analysis_state['findings_count']}
        - Validated: {self.analysis_state['validated_count']}
        """
        flat_meta = self._flatten_metadata({"phase": phase, "timestamp": timestamp, "apk": self.analysis_state["apk_name"], **data})
        if self.enabled and self.vectorstore:
            doc = Document(page_content=content, metadata=flat_meta)
            try:
                self.vectorstore.add_documents([doc])
                console.print(f"[dim]📝 RAG: Logged phase '{phase}'[/dim]")
            except Exception as e:
                console.print(f"[yellow]RAG logging disabled due to error: {e}[/yellow]")
                self.enabled = False
                self.vectorstore = None
        else:
            console.print(f"[dim]RAG disabled - phase '{phase}' not indexed[/dim]")

    def log_finding_validation(self, finding: Finding):
        content = f"""
        Finding Validation:
        - Rule ID: {finding.rule_id}
        - Severity: {finding.severity}
        - Description: {finding.description}
        - Validation Status: {finding.validation_status.value if finding.validation_status else 'unknown'}
        - Confidence: {finding.validation_confidence:.2%}
        - Reason: {finding.validation_reason}

        Source Context:
        - File: {finding.file}
        - Line: {finding.line}
        - Is Test Code: {finding.source_context.is_test_code if finding.source_context else 'N/A'}
        - Is Third Party: {finding.source_context.is_third_party if finding.source_context else 'N/A'}
        """
        flat_meta = self._flatten_metadata({
            "type": "finding_validation",
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "status": finding.validation_status.value if finding.validation_status else "unknown",
            "confidence": finding.validation_confidence
        })
        if self.enabled and self.vectorstore:
            try:
                self.vectorstore.add_documents([Document(page_content=content, metadata=flat_meta)])
            except Exception as e:
                console.print(f"[yellow]RAG logging disabled due to error: {e}[/yellow]")
                self.enabled = False
                self.vectorstore = None

    def query(self, question: str) -> str:
        if not (self.enabled and self.vectorstore and self.llm):
            return "RAG tracking is disabled."
        try:
            qa = RetrievalQA.from_chain_type(
                llm=self.llm,
                chain_type="stuff",
                retriever=self.vectorstore.as_retriever(search_kwargs={"k": 5}),
                return_source_documents=True
            )
            context = f"""
            Current analysis state:
            - Phase: {self.analysis_state['current_phase']}
            - Completed: {', '.join(self.analysis_state['phases_completed'])}
            - Findings: {self.analysis_state['findings_count']}
            - Critical Issues: {len(self.analysis_state['critical_issues'])}

            Question: {question}
            """
            result = qa.invoke({"query": context})
            return result["result"]
        except Exception as e:
            console.print(f"[yellow]RAG query failed: {e}[/yellow]")
            self.enabled = False
            self.vectorstore = None
            return "RAG tracking encountered an error and has been disabled."

    def generate_intelligent_summary(self) -> Dict[str, Any]:
        metrics = {
            "total_findings": self.analysis_state["findings_count"],
            "validated": self.analysis_state["validated_count"],
            "phases_completed": len(self.analysis_state["phases_completed"])
        }
        if not (self.enabled and self.llm):
            return {
                "executive_summary": "RAG features were disabled; no AI summary available.",
                "metrics": metrics
            }
        
        # Create a direct summary based on analysis state without complex RAG queries
        synthesis_prompt = f"""
        Analizza i seguenti risultati di sicurezza Android e crea un riassunto esecutivo in italiano:

        Stato dell'analisi:
        - APK analizzato: {self.analysis_state.get('apk_name', 'Unknown')}
        - Fasi completate: {', '.join(self.analysis_state.get('phases_completed', []))}
        - Totale findings: {self.analysis_state.get('findings_count', 0)}
        - Findings validati: {self.analysis_state.get('validated_count', 0)}
        - Issues critici: {len(self.analysis_state.get('critical_issues', []))}

        Crea un riassunto che includa:
        1) Riassunto esecutivo (2-3 frasi)
        2) Livello di rischio generale (Critical/High/Medium/Low)
        3) Raccomandazioni principali

        Rispondi in italiano, sii conciso ma informativo.
        """
        
        try:
            response = self.llm.invoke(synthesis_prompt).content
            if not response or response.strip() == "":
                # Fallback summary if LLM returns empty
                response = f"Analisi completata per {self.analysis_state.get('apk_name', 'APK')}. " \
                          f"Trovati {self.analysis_state.get('findings_count', 0)} findings, " \
                          f"{self.analysis_state.get('validated_count', 0)} validati. " \
                          f"Livello di rischio: {'High' if len(self.analysis_state.get('critical_issues', [])) > 0 else 'Medium'}."
        except Exception as e:
            console.print(f"[yellow]AI summary generation failed: {e}[/yellow]")
            response = f"Errore nella generazione del riassunto AI. Analisi completata con {self.analysis_state.get('findings_count', 0)} findings."
        
        return {
            "executive_summary": response,
            "metrics": metrics
        }

# ===================== Enhanced Pipeline con RAG & Indexing =====================
class EnhancedAndroidSecurityAgent(AndroidSecurityAgent):
    def __init__(self, work_dir: Path, validation_level: ValidationLevel = ValidationLevel.MODERATE,
                 use_rag: bool = True, model: str = DEFAULT_OPENAI_LLM_MODEL):
        super().__init__(work_dir, validation_level)
        self.rag_tracker: Optional[AnalysisRAGTracker] = None
        self.use_rag = use_rag
        if use_rag:
            tracker = AnalysisRAGTracker(work_dir, model)
            if getattr(tracker, "enabled", False):
                self.rag_tracker = tracker
            else:
                console.print("[yellow]RAG features disabled - continuing without RAG[/yellow]")
                self.use_rag = False

    def analyze(self, apk_path: Path, interactive: bool = False) -> Tuple[Path, Optional[Dict]]:
        console.print(f"\n[bold cyan]🔍 Enhanced Security Analysis with RAG Tracking[/bold cyan]")
        console.print(f"APK: {apk_path.name}\n")

        if self.use_rag and self.rag_tracker:
            self.rag_tracker.analysis_state["apk_name"] = apk_path.name
            self.rag_tracker.analysis_state["start_time"] = datetime.datetime.now().isoformat()
            self.rag_tracker.log_phase("initialization", {
                "apk_size": apk_path.stat().st_size,
                "apk_hash": self._calculate_hash(apk_path)
            })

        with console.status("[bold blue]Decompiling APK with apktool/JADX...[/bold blue]"):
            source_dir = self.decompiler.decompile(apk_path)

        if self.use_rag and self.rag_tracker:
            self.rag_tracker.log_phase("decompilation", {
                "source_dir": str(source_dir),
                "files_extracted": len(list(source_dir.rglob('*')))
            })
            # Indicizza sorgente in RAG (java + xml) con gestione batch per grandi APK
            console.print("\n[bold blue]Indexing source code into RAG...[/bold blue]")
            docs: List[Document] = []
            splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=50)  # Chunk più piccoli
            
            # Limita il numero di file per evitare token limit
            max_files = 200  # Limite per evitare overflow
            file_count = 0
            
            for ext in ("*.java", "*.xml"):
                for file in source_dir.rglob(ext):
                    if file_count >= max_files:
                        console.print(f"[yellow]Limiting indexing to {max_files} files to avoid token limits[/yellow]")
                        break
                    try:
                        text = file.read_text(errors="ignore")
                        if len(text) > 10000:  # Skip file molto grandi
                            text = text[:10000] + "... [truncated]"
                        for chunk in splitter.split_text(text):
                            if len(chunk.strip()) > 50:  # Solo chunk significativi
                                docs.append(Document(page_content=chunk, metadata={"file": str(file)}))
                        file_count += 1
                    except Exception as e:
                        console.print(f"[yellow]Skip file {file}: {e}[/yellow]")
                        
            if docs and getattr(self.rag_tracker, "enabled", False) and getattr(self.rag_tracker, "vectorstore", None):
                try:
                    # Indicizza in batch per evitare token limit
                    batch_size = 50
                    for i in range(0, len(docs), batch_size):
                        batch = docs[i:i+batch_size]
                        self.rag_tracker.vectorstore.add_documents(batch)
                        console.print(f"[dim]Indexed batch {i//batch_size + 1}/{(len(docs)-1)//batch_size + 1}[/dim]")
                except Exception as e:
                    console.print(f"[yellow]RAG source indexing disabled due to error: {e}[/yellow]")
                    self.rag_tracker.enabled = False
                    self.rag_tracker.vectorstore = None
            self.rag_tracker.log_phase("source_indexed", {"files_indexed": len(docs)})

        console.print("\n[bold blue]Running MobSFScan on decompiled source...[/bold blue]")
        scan_output = self.work_dir / "mobsfscan_results.json"
        self._run_mobsfscan(source_dir, scan_output)

        findings = self._parse_mobsfscan_output(scan_output)
        console.print(f"[green]Found {len(findings)} initial findings[/green]")

        if self.use_rag and self.rag_tracker:
            self.rag_tracker.analysis_state["findings_count"] = len(findings)
            self.rag_tracker.log_phase("scanning", {
                "tool": "mobsfscan",
                "findings_count": len(findings),
                "severity_distribution": self._get_severity_distribution(findings)
            })

        analyzer = SourceAnalyzer(source_dir)
        validator = ValidationEngine(analyzer, self.validation_level)

        console.print("\n[bold blue]Validating findings against source code...[/bold blue]")
        validated_findings = []
        for finding in track(findings, description="Validating..."):
            validated = validator.validate_finding(finding)
            validated_findings.append(validated)
            if self.use_rag and self.rag_tracker:
                self.rag_tracker.log_finding_validation(validated)

        if self.use_rag and self.rag_tracker:
            tp_count = len([f for f in validated_findings if f.validation_status == FindingCategory.TRUE_POSITIVE])
            critical = [f for f in validated_findings if f.validation_status == FindingCategory.TRUE_POSITIVE and f.severity.upper() == "HIGH"]
            self.rag_tracker.analysis_state["validated_count"] = len(validated_findings)
            self.rag_tracker.analysis_state["critical_issues"] = [{"rule_id": f.rule_id, "description": f.description[:100]} for f in critical]
            self.rag_tracker.log_phase("validation_complete", {
                "true_positives": tp_count,
                "dynamic_checks": len([f for f in validated_findings if f.validation_status == FindingCategory.DYNAMIC_CHECK]),
                "false_positives": len([f for f in validated_findings if f.validation_status == FindingCategory.FALSE_POSITIVE])
            })

        report_path = self.work_dir / "security_analysis_report.json"
        reporter = ReportGenerator()
        reporter.generate_report(validated_findings, report_path)

        intelligent_summary = None
        if self.use_rag and self.rag_tracker:
            console.print("\n[bold blue]Generating AI-powered summary...[/bold blue]")
            intelligent_summary = self.rag_tracker.generate_intelligent_summary()
            summary_path = self.work_dir / "intelligent_summary.json"
            with open(summary_path, 'w', encoding='utf-8') as f:
                json.dump(intelligent_summary, f, indent=2)
            console.print("[green]AI Summary generated[/green]")
            # Avvia la sessione interattiva se richiesta
            self._interactive_rag_session(auto_start=interactive)

        return report_path, intelligent_summary

    def _calculate_hash(self, file_path: Path) -> str:
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _get_severity_distribution(self, findings: List[Finding]) -> str:
        dist = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.severity.upper()
            if sev in dist:
                dist[sev] += 1
        return json.dumps(dist)

    def _interactive_rag_session(self, auto_start: bool = False):
        if not auto_start:
            console.print("\n[bold cyan]💬 Interactive RAG Analysis Available[/bold cyan]")
            console.print("Per avviare la sessione interattiva, usa: --interactive")
            console.print("Oppure fai query programmatiche tramite l'API RAG")
            return
            
        console.print("\n[bold cyan]💬 Interactive RAG Analysis[/bold cyan]")
        console.print("Esempi: 'Dove viene gestito SSL?', 'Quali WebView hanno JS abilitato?'")
        console.print("(Digita 'exit' per uscire)\n")
        
        while True:
            try:
                question = console.input("[bold]Q:[/bold] ")
                if question.lower() in ['exit', 'quit', 'q']:
                    break
                if not question.strip():
                    continue
                    
                answer = self.rag_tracker.query(question)
                console.print(f"[green]A:[/green] {answer}\n")
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                console.print(f"[yellow]Errore nella query: {e}[/yellow]")
                
        console.print("\n[dim]RAG session ended[/dim]")

# ===================== Main =====================
def main():
    parser = argparse.ArgumentParser(description="Android Security Agent with Source Validation and RAG (OpenAI)")
    parser.add_argument("apk", type=Path, help="Path to APK file")
    parser.add_argument("--validation-level", choices=["strict", "moderate", "lenient"], default="moderate", help="Validation strictness level")
    parser.add_argument("--no-rag", action="store_true", help="Disable RAG tracking and AI features")
    parser.add_argument("--interactive", action="store_true", help="Enable interactive RAG chat session after analysis")
    parser.add_argument("--model", default=DEFAULT_OPENAI_LLM_MODEL, help="LLM model via OpenAI (es: gpt-5-mini-2025-08-07)")
    parser.add_argument("--work-dir", type=Path, help="Working directory for analysis")

    args = parser.parse_args()
    if not args.apk.exists():
        console.print(f"[red]Error: APK not found: {args.apk}[/red]")
        sys.exit(1)
    if not args.apk.suffix.lower() in ['.apk', '.xapk']:
        console.print(f"[yellow]Warning: File may not be an APK: {args.apk}[/yellow]")

    work_dir = args.work_dir or (Path.cwd() / f"analysis_{args.apk.stem}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}")
    work_dir.mkdir(parents=True, exist_ok=True)

    if not args.no_rag and not os.getenv("OPENAI_API_KEY"):
        console.print("[yellow]Warning: OPENAI_API_KEY non impostata (chiave OpenAI). Le funzioni RAG useranno fallback nullo.[/yellow]")

    try:
        agent = EnhancedAndroidSecurityAgent(
            work_dir=work_dir,
            validation_level=ValidationLevel(args.validation_level),
            use_rag=not args.no_rag,
            model=args.model
        )
        report_path, ai_summary = agent.analyze(args.apk, interactive=args.interactive)
        console.print(f"\n[bold green]✅ Analysis Complete![/bold green]")
        console.print(f"📁 Results: {work_dir}")
        console.print(f"📊 Report: {report_path}")
        if ai_summary:
            console.print(f"\n[bold]Executive Summary:[/bold]\n{ai_summary.get('executive_summary','N/A')}")
    except Exception as e:
        console.print(f"[red]Error during analysis: {e}[/red]")
        raise

if __name__ == "__main__":
    main()

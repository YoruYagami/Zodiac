"""
Zodiac Configuration Settings
Central configuration management for the enterprise Android security analysis system
"""

import os
from pathlib import Path
from typing import Optional, Dict, Any
from pydantic import BaseSettings, Field
from enum import Enum


class ValidationLevel(str, Enum):
    """Validation strictness levels"""
    STRICT = "strict"
    MODERATE = "moderate"
    LENIENT = "lenient"


class AnalysisMode(str, Enum):
    """Analysis execution modes"""
    QUICK = "quick"
    STANDARD = "standard"
    COMPREHENSIVE = "comprehensive"
    DEEP = "deep"


class Settings(BaseSettings):
    """
    Main configuration class using Pydantic BaseSettings
    Supports environment variables and .env files
    """
    
    # Application Settings
    app_name: str = "Zodiac Security Analyzer"
    app_version: str = "2.0.0"
    debug: bool = Field(False, env="DEBUG")
    
    # Paths
    work_dir: Path = Field(Path.cwd() / "analysis", env="WORK_DIR")
    temp_dir: Path = Field(Path("/tmp/zodiac"), env="TEMP_DIR")
    reports_dir: Path = Field(Path.cwd() / "reports", env="REPORTS_DIR")
    
    # OpenRouter/OpenAI Configuration
    openai_api_key: str = Field(..., env="OPENAI_API_KEY")
    openai_base_url: str = Field(
        "https://openrouter.ai/api/v1", 
        env="OPENAI_BASE_URL"
    )
    openrouter_referrer: str = Field(
        "https://local.dev", 
        env="OPENROUTER_REFERRER"
    )
    openrouter_title: str = Field(
        "Zodiac Android Security", 
        env="OPENROUTER_TITLE"
    )
    
    # LLM Models
    llm_model: str = Field("openai/gpt-4o", env="LLM_MODEL")
    embedding_model: str = Field(
        "openai/text-embedding-3-large", 
        env="EMBEDDING_MODEL"
    )
    llm_temperature: float = Field(0.0, env="LLM_TEMPERATURE")
    llm_max_tokens: int = Field(2000, env="LLM_MAX_TOKENS")
    
    # Analysis Settings
    validation_level: ValidationLevel = Field(
        ValidationLevel.MODERATE, 
        env="VALIDATION_LEVEL"
    )
    analysis_mode: AnalysisMode = Field(
        AnalysisMode.STANDARD,
        env="ANALYSIS_MODE"
    )
    enable_rag: bool = Field(True, env="ENABLE_RAG")
    enable_source_indexing: bool = Field(True, env="ENABLE_SOURCE_INDEXING")
    
    # Tool Settings
    decompiler_timeout: int = Field(300, env="DECOMPILER_TIMEOUT")
    scanner_timeout: int = Field(300, env="SCANNER_TIMEOUT")
    max_file_size_mb: int = Field(500, env="MAX_FILE_SIZE_MB")
    
    # RAG Settings
    chunk_size: int = Field(1000, env="CHUNK_SIZE")
    chunk_overlap: int = Field(200, env="CHUNK_OVERLAP")
    retriever_k: int = Field(5, env="RETRIEVER_K")
    
    # Validation Rules
    min_confidence_threshold: float = Field(0.7, env="MIN_CONFIDENCE")
    fp_reduction_aggressive: bool = Field(False, env="FP_REDUCTION_AGGRESSIVE")
    
    # Report Settings
    report_format: str = Field("json", env="REPORT_FORMAT")  # json, html, markdown
    include_code_snippets: bool = Field(True, env="INCLUDE_CODE_SNIPPETS")
    max_snippet_length: int = Field(500, env="MAX_SNIPPET_LENGTH")
    
    # Agent Configuration
    agent_max_iterations: int = Field(10, env="AGENT_MAX_ITERATIONS")
    agent_timeout: int = Field(60, env="AGENT_TIMEOUT")
    
    # Database
    vector_db_path: Path = Field(
        Path.cwd() / "vectorstore", 
        env="VECTOR_DB_PATH"
    )
    
    class Config:
        env_file = ".env"
        case_sensitive = False
        
    def get_llm_headers(self) -> Dict[str, str]:
        """Get headers for OpenRouter API"""
        return {
            "HTTP-Referer": self.openrouter_referrer,
            "X-Title": self.openrouter_title,
        }
    
    def get_analysis_config(self) -> Dict[str, Any]:
        """Get analysis-specific configuration"""
        configs = {
            AnalysisMode.QUICK: {
                "decompiler": "jadx",
                "scan_depth": "shallow",
                "validation_samples": 0.3,
                "rag_enabled": False
            },
            AnalysisMode.STANDARD: {
                "decompiler": "apktool",
                "scan_depth": "normal",
                "validation_samples": 0.7,
                "rag_enabled": True
            },
            AnalysisMode.COMPREHENSIVE: {
                "decompiler": "both",
                "scan_depth": "deep",
                "validation_samples": 1.0,
                "rag_enabled": True
            },
            AnalysisMode.DEEP: {
                "decompiler": "both",
                "scan_depth": "exhaustive",
                "validation_samples": 1.0,
                "rag_enabled": True,
                "cross_reference": True,
                "taint_analysis": True
            }
        }
        return configs.get(self.analysis_mode, configs[AnalysisMode.STANDARD])
    
    def ensure_directories(self):
        """Ensure all required directories exist"""
        for dir_path in [self.work_dir, self.temp_dir, self.reports_dir, self.vector_db_path]:
            dir_path.mkdir(parents=True, exist_ok=True)


# Singleton pattern for settings
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get or create settings singleton"""
    global _settings
    if _settings is None:
        _settings = Settings()
        _settings.ensure_directories()
    return _settings


# Validation rules configuration
VALIDATION_RULES = {
    "android_sql_injection": {
        "severity": "HIGH",
        "confidence_weight": 0.9,
        "patterns": [
            r'rawQuery\s*\([^,]+\+',
            r'execSQL\s*\([^)]*\+',
            r'query\([^)]*\+[^)]*\)'
        ],
        "anti_patterns": [
            r'ContentValues',
            r'SQLiteQueryBuilder',
            r'selectionArgs\s*=',
            r'@Test'
        ],
        "required_context": ["android.database.sqlite"],
        "dynamic_indicators": ["user input", "intent.get", "EditText"]
    },
    "android_ssl_pinning": {
        "severity": "HIGH",
        "confidence_weight": 0.85,
        "patterns": [
            r'TrustManager.*{.*}',
            r'HostnameVerifier.*{.*return\s+true',
            r'setDefaultHostnameVerifier'
        ],
        "anti_patterns": [
            r'// *TODO',
            r'@Deprecated',
            r'BuildConfig\.DEBUG'
        ],
        "required_context": ["javax.net.ssl", "SSLContext"],
        "dynamic_indicators": ["HttpsURLConnection", "OkHttpClient"]
    },
    "android_hardcoded_secrets": {
        "severity": "CRITICAL",
        "confidence_weight": 0.95,
        "patterns": [
            r'(api[_]?key|apikey|secret|password|token)\s*=\s*["\'][^"\']+["\']',
            r'["\'][0-9a-f]{32,}["\']'
        ],
        "anti_patterns": [
            r'BuildConfig',
            r'R\.string\.',
            r'getResources\(\)',
            r'example\.com',
            r'test'
        ]
    }
}


# Agent prompts configuration
AGENT_PROMPTS = {
    "decompiler": """You are a specialized Android APK decompilation expert.
    Your role is to efficiently extract and organize source code from APK files.
    Focus on identifying the main application code versus third-party libraries.""",
    
    "scanner": """You are an Android security scanning specialist.
    Identify potential security vulnerabilities in Android applications.
    Prioritize findings by severity and potential impact.""",
    
    "validator": """You are a security finding validation expert.
    Distinguish between true positives, false positives, and findings requiring dynamic analysis.
    Consider context, code patterns, and application architecture.""",
    
    "source_analyzer": """You are a source code analysis expert for Android.
    Extract meaningful context from code snippets and identify patterns.
    Understand the relationship between different components.""",
    
    "report": """You are a security report generation specialist.
    Create clear, actionable security reports with proper risk assessment.
    Provide remediation guidance and prioritized recommendations."""
}
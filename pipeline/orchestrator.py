"""
Pipeline Orchestrator for Zodiac Security Analyzer
Coordinates the execution of all agents in the analysis pipeline
"""

import asyncio
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from langchain.callbacks.base import BaseCallbackHandler
from langchain.schema import LLMResult

from ..agents.base_agent import AgentRegistry
from ..agents.decompiler_agent import DecompilerAgent
from ..agents.scanner_agent import ScannerAgent
from ..agents.validator_agent import ValidatorAgent
from ..agents.source_analyzer_agent import SourceAnalyzerAgent
from ..agents.report_agent import ReportAgent
from ..core.models import (
    AnalysisState, APKMetadata, AnalysisPhase, 
    Finding, ReportData
)
from ..config.settings import get_settings
from ..rag.vectorstore_manager import VectorStoreManager
from ..utils.logger import setup_logger


class AnalysisCallbackHandler(BaseCallbackHandler):
    """Callback handler for tracking LLM operations"""
    
    def __init__(self):
        self.total_tokens = 0
        self.total_cost = 0.0
        self.llm_calls = 0
        
    def on_llm_end(self, response: LLMResult, **kwargs) -> None:
        """Track LLM usage"""
        self.llm_calls += 1
        # Track tokens if available in response
        if hasattr(response, 'llm_output') and response.llm_output:
            if 'token_usage' in response.llm_output:
                usage = response.llm_output['token_usage']
                self.total_tokens += usage.get('total_tokens', 0)


class PipelineOrchestrator:
    """
    Main orchestrator for the security analysis pipeline
    Manages agent lifecycle and coordinates analysis workflow
    """
    
    def __init__(
        self,
        work_dir: Path,
        enable_rag: bool = True,
        verbose: bool = False
    ):
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        
        self.settings = get_settings()
        self.enable_rag = enable_rag
        self.verbose = verbose
        
        # Setup logging
        self.logger = setup_logger(
            "orchestrator",
            log_file=self.work_dir / "analysis.log"
        )
        
        # Initialize components
        self.state = AnalysisState()
        self.registry = AgentRegistry()
        self.callback_handler = AnalysisCallbackHandler()
        
        # RAG system
        self.vector_store = None
        if self.enable_rag:
            self.vector_store = VectorStoreManager(
                self.work_dir / "vectorstore"
            )
        
        # Thread pool for parallel operations
        self.executor = ThreadPoolExecutor(max_workers=4)
        
        # Initialize agents
        self._initialize_agents()
        
    def _initialize_agents(self):
        """Initialize and register all agents"""
        self.logger.info("Initializing agents...")
        
        # Create agents with shared state
        agents = [
            DecompilerAgent(self.state),
            ScannerAgent(self.state),
            SourceAnalyzerAgent(self.state),
            ValidatorAgent(self.state),
            ReportAgent(self.state)
        ]
        
        # Register agents
        for agent in agents:
            self.registry.register(agent)
            self.logger.info(f"Registered {agent.config.name}")
            
    async def analyze_apk(self, apk_path: Path) -> Dict[str, Any]:
        """
        Main entry point for APK analysis
        Orchestrates the entire analysis pipeline
        """
        try:
            self.logger.info(f"Starting analysis of {apk_path.name}")
            
            # Phase 1: Initialize analysis
            await self._initialize_analysis(apk_path)
            
            # Phase 2: Decompile APK
            decompilation_result = await self._decompile_phase()
            if not decompilation_result.get("success"):
                raise Exception("Decompilation failed")
                
            # Phase 3: Source indexing (if RAG enabled)
            if self.enable_rag:
                await self._index_source_phase(
                    decompilation_result.get("source_dir")
                )
            
            # Phase 4: Security scanning
            scan_results = await self._scanning_phase(
                decompilation_result.get("source_dir")
            )
            
            # Phase 5: Source analysis & context extraction
            analyzed_findings = await self._source_analysis_phase(
                scan_results.get("findings", []),
                decompilation_result.get("source_dir")
            )
            
            # Phase 6: Finding validation
            validation_results = await self._validation_phase(analyzed_findings)
            
            # Phase 7: Report generation
            report_data = await self._reporting_phase(validation_results)
            
            # Finalize
            self.state.finalize()
            
            return {
                "status": "success",
                "analysis_id": self.state.analysis_id,
                "duration": self.state.duration_seconds,
                "report": report_data,
                "metrics": self._get_analysis_metrics()
            }
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            self.state.current_phase = AnalysisPhase.FAILED
            self.state.add_error("orchestrator", str(e))
            
            return {
                "status": "failed",
                "error": str(e),
                "analysis_id": self.state.analysis_id,
                "errors": self.state.errors
            }
            
    async def _initialize_analysis(self, apk_path: Path):
        """Initialize analysis state and metadata"""
        self.logger.info("Phase 1: Initialization")
        self.state.update_phase(AnalysisPhase.INITIALIZATION)
        
        # Create APK metadata
        self.state.apk_metadata = APKMetadata.from_file(apk_path)
        
        # Broadcast initialization to all agents
        self.registry.broadcast_message(
            sender="orchestrator",
            message_type="analysis_started",
            content={
                "apk_path": str(apk_path),
                "analysis_id": self.state.analysis_id
            }
        )
        
    async def _decompile_phase(self) -> Dict[str, Any]:
        """Execute decompilation phase"""
        self.logger.info("Phase 2: Decompilation")
        self.state.update_phase(AnalysisPhase.DECOMPILATION)
        
        decompiler = self.registry.get("DecompilerAgent")
        
        result = await decompiler.execute({
            "apk_path": self.state.apk_metadata.file_path,
            "work_dir": self.work_dir,
            "decompiler": self.settings.get_analysis_config()["decompiler"]
        })
        
        # Store decompilation result
        self.state.decompilation_result = result.get("decompilation_result")
        
        return result
    
    async def _index_source_phase(self, source_dir: Path):
        """Index source code for RAG"""
        self.logger.info("Phase 3: Source Indexing")
        self.state.update_phase(AnalysisPhase.SOURCE_INDEXING)
        
        if not self.vector_store:
            return
            
        # Index source files
        indexed_count = await self.vector_store.index_source_directory(
            source_dir,
            extensions=[".java", ".xml", ".smali"],
            batch_size=50
        )
        
        self.logger.info(f"Indexed {indexed_count} documents")
        
        # Also index APK metadata
        await self.vector_store.index_metadata(self.state.apk_metadata)
        
    async def _scanning_phase(self, source_dir: Path) -> Dict[str, Any]:
        """Execute security scanning"""
        self.logger.info("Phase 4: Security Scanning")
        self.state.update_phase(AnalysisPhase.SCANNING)
        
        scanner = self.registry.get("ScannerAgent")
        
        result = await scanner.execute({
            "source_dir": source_dir,
            "scan_config": self.settings.get_analysis_config(),
            "work_dir": self.work_dir
        })
        
        # Store scan results
        self.state.scan_result = result.get("scan_result")
        self.state.total_findings = result.get("total_findings", 0)
        
        return result
    
    async def _source_analysis_phase(
        self, 
        findings: List[Finding],
        source_dir: Path
    ) -> List[Finding]:
        """Analyze source context for findings"""
        self.logger.info("Phase 5: Source Analysis")
        
        analyzer = self.registry.get("SourceAnalyzerAgent")
        
        # Process findings in batches for efficiency
        batch_size = 20
        analyzed_findings = []
        
        for i in range(0, len(findings), batch_size):
            batch = findings[i:i+batch_size]
            
            result = await analyzer.execute({
                "findings": batch,
                "source_dir": source_dir,
                "use_rag": self.enable_rag
            })
            
            analyzed_findings.extend(result.get("findings", []))
            
        return analyzed_findings
    
    async def _validation_phase(self, findings: List[Finding]) -> Dict[str, Any]:
        """Validate findings"""
        self.logger.info("Phase 6: Finding Validation")
        self.state.update_phase(AnalysisPhase.VALIDATION)
        
        validator = self.registry.get("ValidatorAgent")
        
        result = await validator.execute({
            "findings": findings,
            "validation_level": self.settings.validation_level.value
        })
        
        # Store validation results
        self.state.validation_result = result.get("results")
        
        # Update critical findings count
        if self.state.validation_result:
            self.state.critical_findings = len([
                f for f in self.state.validation_result.true_positives
                if f.severity.value in ["CRITICAL", "HIGH"]
            ])
        
        return result
    
    async def _reporting_phase(self, validation_results: Dict[str, Any]) -> ReportData:
        """Generate analysis report"""
        self.logger.info("Phase 7: Report Generation")
        self.state.update_phase(AnalysisPhase.REPORTING)
        
        reporter = self.registry.get("ReportAgent")
        
        # Prepare report data
        report_input = {
            "analysis_state": self.state,
            "validation_results": validation_results,
            "use_ai_insights": self.enable_rag,
            "output_format": self.settings.report_format,
            "output_dir": self.work_dir / "reports"
        }
        
        result = await reporter.execute(report_input)
        
        return result.get("report_data")
    
    def _get_analysis_metrics(self) -> Dict[str, Any]:
        """Get comprehensive analysis metrics"""
        metrics = {
            "performance": {
                "total_duration": self.state.duration_seconds,
                "phases_completed": len(self.state.phases_completed),
                "llm_calls": self.callback_handler.llm_calls,
                "total_tokens": self.callback_handler.total_tokens
            },
            "findings": {
                "total": self.state.total_findings,
                "critical": self.state.critical_findings,
                "validated": self.state.validation_result.total_processed if self.state.validation_result else 0
            },
            "agents": self.registry.get_metrics()
        }
        
        if self.vector_store:
            metrics["rag"] = self.vector_store.get_stats()
            
        return metrics
    
    async def query_analysis(self, query: str) -> str:
        """
        Query the analysis results using RAG
        Can be called after analysis is complete
        """
        if not self.enable_rag or not self.vector_store:
            return "RAG system is not enabled"
            
        return await self.vector_store.query(
            query,
            k=self.settings.retriever_k,
            include_metadata=True
        )
    
    def get_analysis_state(self) -> AnalysisState:
        """Get current analysis state"""
        return self.state
    
    def cleanup(self):
        """Cleanup resources"""
        self.logger.info("Cleaning up resources")
        
        # Reset all agents
        self.registry.reset_all()
        
        # Close vector store
        if self.vector_store:
            self.vector_store.close()
            
        # Shutdown executor
        self.executor.shutdown(wait=True)
        
        self.logger.info("Cleanup completed")
        

class PipelineBuilder:
    """Builder for creating customized analysis pipelines"""
    
    def __init__(self):
        self.config = {
            "work_dir": Path.cwd() / "analysis",
            "enable_rag": True,
            "verbose": False,
            "agents": [],
            "custom_validators": []
        }
        
    def set_work_dir(self, path: Path) -> "PipelineBuilder":
        """Set working directory"""
        self.config["work_dir"] = path
        return self
        
    def enable_rag(self, enabled: bool = True) -> "PipelineBuilder":
        """Enable/disable RAG system"""
        self.config["enable_rag"] = enabled
        return self
        
    def verbose(self, enabled: bool = True) -> "PipelineBuilder":
        """Enable verbose output"""
        self.config["verbose"] = enabled
        return self
        
    def add_custom_agent(self, agent_class: type) -> "PipelineBuilder":
        """Add a custom agent to the pipeline"""
        self.config["agents"].append(agent_class)
        return self
        
    def add_validator(self, validator_func) -> "PipelineBuilder":
        """Add custom validation function"""
        self.config["custom_validators"].append(validator_func)
        return self
        
    def build(self) -> PipelineOrchestrator:
        """Build the pipeline orchestrator"""
        orchestrator = PipelineOrchestrator(
            work_dir=self.config["work_dir"],
            enable_rag=self.config["enable_rag"],
            verbose=self.config["verbose"]
        )
        
        # Add custom agents if any
        for agent_class in self.config["agents"]:
            agent = agent_class(orchestrator.state)
            orchestrator.registry.register(agent)
            
        return orchestrator


# Convenience function for quick analysis
async def analyze_apk_quick(apk_path: Path, output_dir: Optional[Path] = None) -> Dict[str, Any]:
    """
    Quick analysis function for simple use cases
    
    Args:
        apk_path: Path to APK file
        output_dir: Optional output directory
        
    Returns:
        Analysis results dictionary
    """
    output_dir = output_dir or Path.cwd() / f"analysis_{apk_path.stem}"
    
    orchestrator = PipelineBuilder() \
        .set_work_dir(output_dir) \
        .enable_rag(True) \
        .build()
        
    try:
        result = await orchestrator.analyze_apk(apk_path)
        return result
    finally:
        orchestrator.cleanup()
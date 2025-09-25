"""
Zodiac - Enterprise Android Security Analyzer
Main entry point for the application
"""

import asyncio
import argparse
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.live import Live
from rich.layout import Layout

from zodiac.pipeline.orchestrator import PipelineOrchestrator, PipelineBuilder
from zodiac.config.settings import get_settings, ValidationLevel, AnalysisMode
from zodiac.utils.logger import setup_logger
from zodiac.core.models import FindingCategory, Severity

console = Console()
logger = setup_logger("main")


class ZodiacCLI:
    """Command-line interface for Zodiac"""
    
    def __init__(self):
        self.settings = get_settings()
        self.console = console
        
    def print_banner(self):
        """Print application banner"""
        banner = """
╔══════════════════════════════════════════════════════════╗
║                                                            ║
║     ███████╗ ██████╗ ██████╗ ██╗ █████╗  ██████╗         ║
║     ╚══███╔╝██╔═══██╗██╔══██╗██║██╔══██╗██╔════╝         ║
║       ███╔╝ ██║   ██║██║  ██║██║███████║██║              ║
║      ███╔╝  ██║   ██║██║  ██║██║██╔══██║██║              ║
║     ███████╗╚██████╔╝██████╔╝██║██║  ██║╚██████╗         ║
║     ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝╚═╝  ╚═╝ ╚═════╝         ║
║                                                            ║
║         Enterprise Android Security Analyzer v2.0         ║
║                    Powered by LangChain                   ║
╚══════════════════════════════════════════════════════════╝
        """
        self.console.print(banner, style="bold cyan")
        
    def print_analysis_summary(self, results: dict):
        """Print analysis results summary"""
        
        # Create summary table
        table = Table(title="Analysis Summary", show_header=True)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        
        # Basic metrics
        table.add_row("Analysis ID", results.get("analysis_id", "N/A"))
        table.add_row("Status", results.get("status", "Unknown"))
        table.add_row("Duration", f"{results.get('duration', 0):.2f} seconds")
        
        # Finding statistics
        if "report" in results and results["report"]:
            report = results["report"]
            state = report.analysis_state
            
            if state.validation_result:
                val_result = state.validation_result
                table.add_row("Total Findings", str(val_result.total_processed))
                table.add_row("True Positives", 
                            f"[red]{len(val_result.true_positives)}[/red]")
                table.add_row("Dynamic Checks", 
                            f"[yellow]{len(val_result.dynamic_checks)}[/yellow]")
                table.add_row("False Positives", 
                            f"[green]{len(val_result.false_positives)}[/green]")
                
            # Risk level
            risk_level = report.get_risk_level()
            risk_color = {
                "CRITICAL": "red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "green"
            }.get(risk_level, "white")
            table.add_row("Risk Level", f"[{risk_color}]{risk_level}[/{risk_color}]")
            
        self.console.print(table)
        
        # Print critical findings if any
        if "report" in results and results["report"]:
            self._print_critical_findings(results["report"])
            
    def _print_critical_findings(self, report):
        """Print critical findings"""
        critical = report.critical_findings[:5]  # Show top 5
        
        if not critical:
            return
            
        panel_content = ""
        for i, finding in enumerate(critical, 1):
            panel_content += f"[bold]{i}. {finding.title}[/bold]\n"
            panel_content += f"   Rule: {finding.rule_id}\n"
            panel_content += f"   File: {finding.file_path or 'N/A'}\n"
            if finding.validation_confidence:
                panel_content += f"   Confidence: {finding.validation_confidence:.0%}\n"
            panel_content += "\n"
            
        panel = Panel(
            panel_content.strip(),
            title="[red]⚠️  Critical Security Issues[/red]",
            border_style="red"
        )
        self.console.print(panel)
        
    async def analyze_interactive(self, apk_path: Path, args):
        """Run interactive analysis with progress tracking"""
        
        # Create output directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = Path(args.output) if args.output else (
            Path.cwd() / f"analysis_{apk_path.stem}_{timestamp}"
        )
        
        # Build pipeline based on arguments
        builder = PipelineBuilder() \
            .set_work_dir(output_dir) \
            .enable_rag(not args.no_rag) \
            .verbose(args.verbose)
            
        orchestrator = builder.build()
        
        # Run analysis with progress display
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            
            task = progress.add_task("Initializing analysis...", total=7)
            
            # Hook into state updates to show progress
            original_update = orchestrator.state.update_phase
            def update_with_progress(phase):
                phase_names = {
                    "initialization": "Initializing",
                    "decompilation": "Decompiling APK",
                    "source_indexing": "Indexing source code",
                    "scanning": "Scanning for vulnerabilities",
                    "validation": "Validating findings",
                    "reporting": "Generating report"
                }
                progress.update(task, 
                              description=f"{phase_names.get(phase.value, phase.value)}...",
                              advance=1)
                original_update(phase)
                
            orchestrator.state.update_phase = update_with_progress
            
            # Run analysis
            try:
                results = await orchestrator.analyze_apk(apk_path)
                progress.update(task, description="Analysis complete!", completed=7)
            except Exception as e:
                self.console.print(f"[red]Analysis failed: {e}[/red]")
                raise
            finally:
                orchestrator.cleanup()
                
        return results
        
    async def run_batch_analysis(self, apk_list_file: Path, args):
        """Run batch analysis on multiple APKs"""
        
        with open(apk_list_file, 'r') as f:
            apk_paths = [Path(line.strip()) for line in f if line.strip()]
            
        self.console.print(f"[cyan]Starting batch analysis of {len(apk_paths)} APKs[/cyan]")
        
        results = []
        for i, apk_path in enumerate(apk_paths, 1):
            if not apk_path.exists():
                self.console.print(f"[yellow]Skipping {apk_path}: File not found[/yellow]")
                continue
                
            self.console.print(f"\n[bold]Analyzing {i}/{len(apk_paths)}: {apk_path.name}[/bold]")
            
            try:
                result = await self.analyze_interactive(apk_path, args)
                results.append(result)
            except Exception as e:
                self.console.print(f"[red]Failed to analyze {apk_path}: {e}[/red]")
                results.append({"status": "failed", "error": str(e)})
                
        # Print batch summary
        self._print_batch_summary(results)
        return results
        
    def _print_batch_summary(self, results):
        """Print summary of batch analysis"""
        
        table = Table(title="Batch Analysis Summary")
        table.add_column("APK", style="cyan")
        table.add_column("Status", style="white")
        table.add_column("Findings", style="yellow")
        table.add_column("Critical", style="red")
        table.add_column("Risk", style="white")
        
        for result in results:
            if result.get("status") == "success":
                report = result.get("report")
                if report and report.analysis_state:
                    apk_name = report.analysis_state.apk_metadata.file_name
                    total = report.analysis_state.total_findings
                    critical = report.analysis_state.critical_findings
                    risk = report.get_risk_level()
                    
                    risk_style = {
                        "CRITICAL": "red",
                        "HIGH": "red", 
                        "MEDIUM": "yellow",
                        "LOW": "green"
                    }.get(risk, "white")
                    
                    table.add_row(
                        apk_name,
                        "[green]✓[/green]",
                        str(total),
                        str(critical),
                        f"[{risk_style}]{risk}[/{risk_style}]"
                    )
                else:
                    table.add_row("Unknown", "[green]✓[/green]", "?", "?", "?")
            else:
                table.add_row(
                    "Failed",
                    "[red]✗[/red]",
                    "-",
                    "-",
                    "-"
                )
                
        self.console.print(table)


def create_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser"""
    
    parser = argparse.ArgumentParser(
        description="Zodiac - Enterprise Android Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "apk",
        type=Path,
        help="Path to APK file or text file with list of APKs (for batch mode)"
    )
    
    parser.add_argument(
        "-o", "--output",
        type=Path,
        help="Output directory for analysis results"
    )
    
    parser.add_argument(
        "-m", "--mode",
        choices=["quick", "standard", "comprehensive", "deep"],
        default="standard",
        help="Analysis mode (default: standard)"
    )
    
    parser.add_argument(
        "-v", "--validation-level",
        choices=["strict", "moderate", "lenient"],
        default="moderate",
        help="Validation strictness level (default: moderate)"
    )
    
    parser.add_argument(
        "--no-rag",
        action="store_true",
        help="Disable RAG system and AI-powered features"
    )
    
    parser.add_argument(
        "--batch",
        action="store_true",
        help="Run batch analysis (APK argument should be a text file with APK paths)"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode"
    )
    
    parser.add_argument(
        "--format",
        choices=["json", "html", "markdown"],
        default="json",
        help="Output report format (default: json)"
    )
    
    parser.add_argument(
        "--query",
        action="store_true",
        help="Enter interactive query mode after analysis"
    )
    
    return parser


async def interactive_query_mode(orchestrator: PipelineOrchestrator):
    """Interactive query mode for exploring analysis results"""
    
    console.print("\n[cyan]Entering interactive query mode (type 'exit' to quit)[/cyan]")
    console.print("[dim]Ask questions about the analysis results...[/dim]\n")
    
    while True:
        try:
            query = console.input("[bold]Q:[/bold] ")
            
            if query.lower() in ['exit', 'quit', 'q']:
                break
                
            response = await orchestrator.query_analysis(query)
            console.print(f"[green]A:[/green] {response}\n")
            
        except KeyboardInterrupt:
            break
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            
    console.print("[dim]Query mode ended[/dim]")


async def main():
    """Main entry point"""
    
    parser = create_parser()
    args = parser.parse_args()
    
    # Setup environment
    if args.debug:
        import os
        os.environ["DEBUG"] = "true"
        
    # Update settings based on arguments
    settings = get_settings()
    settings.analysis_mode = AnalysisMode(args.mode)
    settings.validation_level = ValidationLevel(args.validation_level)
    settings.report_format = args.format
    settings.enable_rag = not args.no_rag
    
    # Initialize CLI
    cli = ZodiacCLI()
    cli.print_banner()
    
    try:
        # Check if APK exists
        if not args.apk.exists():
            console.print(f"[red]Error: File not found: {args.apk}[/red]")
            sys.exit(1)
            
        # Run analysis
        if args.batch:
            results = await cli.run_batch_analysis(args.apk, args)
        else:
            # Validate APK file
            if not args.apk.suffix.lower() in ['.apk', '.xapk']:
                console.print(f"[yellow]Warning: File may not be an APK: {args.apk}[/yellow]")
                
            results = await cli.analyze_interactive(args.apk, args)
            cli.print_analysis_summary(results)
            
            # Enter query mode if requested
            if args.query and not args.no_rag:
                output_dir = Path(args.output) if args.output else Path.cwd()
                orchestrator = PipelineBuilder() \
                    .set_work_dir(output_dir) \
                    .enable_rag(True) \
                    .build()
                    
                await interactive_query_mode(orchestrator)
                orchestrator.cleanup()
                
        console.print("\n[bold green]✅ Analysis complete![/bold green]")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Analysis interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Fatal error: {e}[/red]")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def run():
    """Entry point for console script"""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/yellow]")
        sys.exit(1)


if __name__ == "__main__":
    run()
"""
Decompiler Agent for APK Analysis
Handles APK decompilation using multiple tools (apktool, jadx)
"""

import subprocess
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
import tempfile
import logging

from langchain_core.tools import Tool
from pydantic import BaseModel, Field

from .base_agent import BaseAgent, AgentConfig, ToolBuilder
from ..core.models import DecompilationResult, AnalysisPhase
from ..tools.apk_tools import APKTool, JADXTool, APKAnalyzer


class DecompilerConfig(BaseModel):
    """Configuration for decompilation"""
    apk_path: Path
    output_dir: Path
    decompiler: str = "auto"  # auto, apktool, jadx, both
    timeout: int = 300
    extract_resources: bool = True
    deobfuscate: bool = False
    

class DecompilerAgent(BaseAgent):
    """
    Agent responsible for APK decompilation
    Manages different decompilation tools and strategies
    """
    
    def __init__(self, state=None):
        config = AgentConfig(
            name="DecompilerAgent",
            description="Expert in Android APK decompilation and source extraction",
            temperature=0.0,
            max_tokens=1000
        )
        super().__init__(config, state)
        
        # Initialize decompilation tools
        self.apktool = APKTool()
        self.jadx = JADXTool()
        self.apk_analyzer = APKAnalyzer()
        
    def _get_specific_tools(self) -> List[Tool]:
        """Get decompiler-specific tools"""
        return [
            ToolBuilder.create_tool(
                name="check_tool_availability",
                func=self._check_tool_availability,
                description="Check which decompilation tools are available"
            ),
            ToolBuilder.create_tool(
                name="analyze_apk_structure",
                func=self._analyze_apk_structure,
                description="Analyze APK structure and metadata"
            ),
            ToolBuilder.create_tool(
                name="decompile_with_apktool",
                func=self._decompile_apktool,
                description="Decompile APK using apktool"
            ),
            ToolBuilder.create_tool(
                name="decompile_with_jadx",
                func=self._decompile_jadx,
                description="Decompile APK using JADX"
            ),
            ToolBuilder.create_tool(
                name="extract_manifest",
                func=self._extract_manifest,
                description="Extract and parse AndroidManifest.xml"
            ),
            ToolBuilder.create_tool(
                name="count_source_files",
                func=self._count_source_files,
                description="Count extracted source files by type"
            )
        ]
    
    async def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute decompilation process"""
        
        apk_path = Path(input_data.get("apk_path"))
        work_dir = Path(input_data.get("work_dir", Path.cwd()))
        decompiler_pref = input_data.get("decompiler", "auto")
        
        self.logger.info(f"Starting decompilation of {apk_path.name}")
        
        # Create output directory
        source_dir = work_dir / "source"
        source_dir.mkdir(parents=True, exist_ok=True)
        
        # Check available tools
        available_tools = self._check_tool_availability("")
        
        # Determine which decompiler to use
        decompiler = self._select_decompiler(decompiler_pref, available_tools)
        
        # Execute decompilation
        result = await self._perform_decompilation(
            apk_path, 
            source_dir, 
            decompiler
        )
        
        # Extract additional metadata
        if result.success:
            await self._extract_apk_metadata(apk_path, source_dir)
            
        # Update state
        self.state.decompilation_result = result
        
        return {
            "success": result.success,
            "source_dir": result.source_dir,
            "decompilation_result": result,
            "metadata": self.state.apk_metadata.dict() if self.state.apk_metadata else {}
        }
    
    def _check_tool_availability(self, query: str) -> str:
        """Check which decompilation tools are available"""
        tools = {
            "apktool": shutil.which("apktool") is not None,
            "jadx": shutil.which("jadx") is not None,
            "aapt": shutil.which("aapt") is not None,
            "aapt2": shutil.which("aapt2") is not None,
            "dex2jar": shutil.which("d2j-dex2jar") is not None
        }
        
        available = [name for name, present in tools.items() if present]
        missing = [name for name, present in tools.items() if not present]
        
        return f"Available tools: {', '.join(available) or 'None'}\nMissing tools: {', '.join(missing) or 'None'}"
    
    def _select_decompiler(self, preference: str, available_tools: str) -> str:
        """Select appropriate decompiler based on preference and availability"""
        
        has_apktool = "apktool" in available_tools
        has_jadx = "jadx" in available_tools
        
        if preference == "auto":
            if has_apktool:
                return "apktool"
            elif has_jadx:
                return "jadx"
            else:
                raise Exception("No decompilation tools available. Install apktool or jadx.")
                
        elif preference == "both":
            if not (has_apktool and has_jadx):
                self.logger.warning("Both tools requested but not all available, using what's available")
            return "both"
            
        elif preference == "apktool" and not has_apktool:
            if has_jadx:
                self.logger.warning("apktool not available, falling back to jadx")
                return "jadx"
            else:
                raise Exception("apktool not available and no fallback found")
                
        elif preference == "jadx" and not has_jadx:
            if has_apktool:
                self.logger.warning("jadx not available, falling back to apktool")
                return "apktool"
            else:
                raise Exception("jadx not available and no fallback found")
                
        return preference
    
    async def _perform_decompilation(
        self, 
        apk_path: Path,
        output_dir: Path,
        decompiler: str
    ) -> DecompilationResult:
        """Perform the actual decompilation"""
        
        start_time = datetime.now()
        results = []
        
        if decompiler in ["apktool", "both"]:
            self.logger.info("Decompiling with apktool...")
            apktool_result = self._decompile_apktool(str(apk_path), str(output_dir / "apktool"))
            results.append(("apktool", apktool_result))
            
        if decompiler in ["jadx", "both"]:
            self.logger.info("Decompiling with JADX...")
            jadx_result = self._decompile_jadx(str(apk_path), str(output_dir / "jadx"))
            results.append(("jadx", jadx_result))
            
        # Merge results if using both
        if decompiler == "both" and len(results) == 2:
            merged_dir = output_dir / "merged"
            merged_dir.mkdir(exist_ok=True)
            self._merge_decompilation_results(
                output_dir / "apktool",
                output_dir / "jadx",
                merged_dir
            )
            final_source_dir = merged_dir
        else:
            final_source_dir = output_dir / results[0][0] if results else output_dir
            
        # Count files
        file_counts = self._count_source_files(str(final_source_dir))
        
        duration = (datetime.now() - start_time).total_seconds()
        
        # Parse file counts
        java_count = int(file_counts.split("Java:")[1].split()[0]) if "Java:" in file_counts else 0
        smali_count = int(file_counts.split("Smali:")[1].split()[0]) if "Smali:" in file_counts else 0
        xml_count = int(file_counts.split("XML:")[1].split()[0]) if "XML:" in file_counts else 0
        
        return DecompilationResult(
            success=any(r[1] == "Success" for r in results) if results else False,
            source_dir=final_source_dir,
            decompiler_used=decompiler,
            duration_seconds=duration,
            java_files_count=java_count,
            smali_files_count=smali_count,
            xml_files_count=xml_count,
            total_files=java_count + smali_count + xml_count,
            errors=[],
            warnings=[]
        )
    
    def _decompile_apktool(self, apk_path: str, output_dir: str) -> str:
        """Decompile using apktool"""
        output_path = Path(output_dir)
        
        # Clean output directory if exists
        if output_path.exists():
            shutil.rmtree(output_path)
            
        try:
            cmd = [
                "apktool", "d", "-f",
                "-o", str(output_path),
                apk_path
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.settings.decompiler_timeout
            )
            
            if result.returncode == 0:
                return "Success"
            else:
                self.logger.error(f"apktool error: {result.stderr}")
                return f"Failed: {result.stderr[:200]}"
                
        except subprocess.TimeoutExpired:
            return "Failed: Timeout"
        except Exception as e:
            return f"Failed: {str(e)}"
    
    def _decompile_jadx(self, apk_path: str, output_dir: str) -> str:
        """Decompile using JADX"""
        output_path = Path(output_dir)
        
        # Clean output directory if exists
        if output_path.exists():
            shutil.rmtree(output_path)
            
        try:
            cmd = [
                "jadx", "-d", str(output_path),
                "--deobf",
                "--threads", "4",
                "--no-res",  # Skip resources for speed
                apk_path
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.settings.decompiler_timeout
            )
            
            if result.returncode == 0:
                return "Success"
            else:
                self.logger.error(f"jadx error: {result.stderr}")
                return f"Failed: {result.stderr[:200]}"
                
        except subprocess.TimeoutExpired:
            return "Failed: Timeout"
        except Exception as e:
            return f"Failed: {str(e)}"
    
    def _merge_decompilation_results(
        self,
        apktool_dir: Path,
        jadx_dir: Path,
        output_dir: Path
    ):
        """Merge results from multiple decompilers"""
        
        # Copy Java files from JADX (usually better for Java)
        if jadx_dir.exists():
            for java_file in jadx_dir.rglob("*.java"):
                relative_path = java_file.relative_to(jadx_dir)
                target_path = output_dir / relative_path
                target_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(java_file, target_path)
                
        # Copy Smali and resources from apktool (better for these)
        if apktool_dir.exists():
            for pattern in ["*.smali", "*.xml", "res/**/*", "assets/**/*"]:
                for file_path in apktool_dir.rglob(pattern):
                    if file_path.is_file():
                        relative_path = file_path.relative_to(apktool_dir)
                        target_path = output_dir / relative_path
                        target_path.parent.mkdir(parents=True, exist_ok=True)
                        if not target_path.exists():
                            shutil.copy2(file_path, target_path)
    
    def _extract_manifest(self, apk_path: str) -> str:
        """Extract and parse AndroidManifest.xml"""
        try:
            # Use aapt if available
            if shutil.which("aapt"):
                cmd = ["aapt", "dump", "badging", apk_path]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    return self._parse_aapt_output(result.stdout)
                    
            return "Could not extract manifest information"
            
        except Exception as e:
            return f"Error extracting manifest: {e}"
    
    def _parse_aapt_output(self, output: str) -> str:
        """Parse aapt output for manifest information"""
        info = {}
        
        for line in output.split('\n'):
            if line.startswith("package:"):
                parts = line.split()
                for part in parts:
                    if part.startswith("name="):
                        info["package"] = part.split("'")[1]
                    elif part.startswith("versionCode="):
                        info["version_code"] = part.split("'")[1]
                    elif part.startswith("versionName="):
                        info["version_name"] = part.split("'")[1]
                        
            elif line.startswith("sdkVersion:"):
                info["min_sdk"] = line.split("'")[1]
            elif line.startswith("targetSdkVersion:"):
                info["target_sdk"] = line.split("'")[1]
            elif line.startswith("uses-permission:"):
                if "permissions" not in info:
                    info["permissions"] = []
                perm = line.split("'")[1] if "'" in line else line.split(":")[1].strip()
                info["permissions"].append(perm)
                
        # Update APK metadata
        if self.state.apk_metadata:
            self.state.apk_metadata.package_name = info.get("package")
            self.state.apk_metadata.version_code = int(info.get("version_code", 0))
            self.state.apk_metadata.version_name = info.get("version_name")
            self.state.apk_metadata.min_sdk_version = int(info.get("min_sdk", 0))
            self.state.apk_metadata.target_sdk_version = int(info.get("target_sdk", 0))
            self.state.apk_metadata.permissions = info.get("permissions", [])
            
        return f"Package: {info.get('package', 'N/A')}\nVersion: {info.get('version_name', 'N/A')}\nPermissions: {len(info.get('permissions', []))}"
    
    def _count_source_files(self, directory: str) -> str:
        """Count source files by type"""
        dir_path = Path(directory)
        
        if not dir_path.exists():
            return "Directory not found"
            
        counts = {
            "Java": len(list(dir_path.rglob("*.java"))),
            "Kotlin": len(list(dir_path.rglob("*.kt"))),
            "Smali": len(list(dir_path.rglob("*.smali"))),
            "XML": len(list(dir_path.rglob("*.xml"))),
            "Resources": len(list(dir_path.rglob("res/**/*.*"))),
        }
        
        return " ".join([f"{k}: {v}" for k, v in counts.items()])
    
    def _analyze_apk_structure(self, apk_path: str) -> str:
        """Analyze APK structure without full decompilation"""
        try:
            import zipfile
            
            path = Path(apk_path)
            if not path.exists():
                return "APK file not found"
                
            with zipfile.ZipFile(path, 'r') as apk:
                file_list = apk.namelist()
                
                structure = {
                    "total_files": len(file_list),
                    "dex_files": len([f for f in file_list if f.endswith('.dex')]),
                    "native_libs": len([f for f in file_list if f.startswith('lib/') and f.endswith('.so')]),
                    "assets": len([f for f in file_list if f.startswith('assets/')]),
                    "resources": len([f for f in file_list if f.startswith('res/')]),
                    "has_kotlin": any('kotlin' in f.lower() for f in file_list),
                    "has_flutter": any('flutter' in f.lower() for f in file_list),
                    "has_react_native": any('hermes' in f.lower() or 'libreactnative' in f.lower() for f in file_list),
                }
                
                return f"""APK Structure Analysis:
                Total files: {structure['total_files']}
                DEX files: {structure['dex_files']}
                Native libraries: {structure['native_libs']}
                Assets: {structure['assets']}
                Resources: {structure['resources']}
                Framework: {'Kotlin' if structure['has_kotlin'] else 'Flutter' if structure['has_flutter'] else 'React Native' if structure['has_react_native'] else 'Standard Java/Android'}
                """
                
        except Exception as e:
            return f"Error analyzing APK: {e}"
    
    async def _extract_apk_metadata(self, apk_path: Path, source_dir: Path):
        """Extract detailed APK metadata"""
        
        # Extract manifest info
        self._extract_manifest(str(apk_path))
        
        # Analyze components from decompiled source
        if source_dir.exists():
            manifest_path = source_dir / "AndroidManifest.xml"
            if manifest_path.exists():
                self._parse_manifest_components(manifest_path)
    
    def _parse_manifest_components(self, manifest_path: Path):
        """Parse Android components from manifest"""
        try:
            import xml.etree.ElementTree as ET
            
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            # Extract components
            if self.state.apk_metadata:
                # Activities
                activities = root.findall(".//activity")
                self.state.apk_metadata.activities = [
                    act.get("{http://schemas.android.com/apk/res/android}name", "")
                    for act in activities
                ]
                
                # Services
                services = root.findall(".//service")
                self.state.apk_metadata.services = [
                    svc.get("{http://schemas.android.com/apk/res/android}name", "")
                    for svc in services
                ]
                
                # Receivers
                receivers = root.findall(".//receiver")
                self.state.apk_metadata.receivers = [
                    rcv.get("{http://schemas.android.com/apk/res/android}name", "")
                    for rcv in receivers
                ]
                
                # Providers
                providers = root.findall(".//provider")
                self.state.apk_metadata.providers = [
                    prv.get("{http://schemas.android.com/apk/res/android}name", "")
                    for prv in providers
                ]
                
        except Exception as e:
            self.logger.warning(f"Could not parse manifest components: {e}")
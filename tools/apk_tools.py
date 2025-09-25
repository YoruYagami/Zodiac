"""
APK Tools Module
Utilities for APK manipulation and analysis
"""

import subprocess
import shutil
import zipfile
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import xml.etree.ElementTree as ET
import re
import hashlib

from ..utils.logger import setup_logger


class APKTool:
    """Wrapper for apktool functionality"""
    
    def __init__(self):
        self.logger = setup_logger("apktool")
        self.available = self._check_availability()
        
    def _check_availability(self) -> bool:
        """Check if apktool is available"""
        return shutil.which("apktool") is not None
    
    def decompile(
        self,
        apk_path: Path,
        output_dir: Path,
        force: bool = True,
        no_res: bool = False,
        no_src: bool = False
    ) -> Tuple[bool, str]:
        """
        Decompile APK using apktool
        
        Args:
            apk_path: Path to APK file
            output_dir: Output directory for decompiled files
            force: Force overwrite if output exists
            no_res: Skip resources
            no_src: Skip source files
            
        Returns:
            Tuple of (success, message)
        """
        
        if not self.available:
            return False, "apktool not available"
            
        cmd = ["apktool", "d"]
        
        if force:
            cmd.append("-f")
        if no_res:
            cmd.append("-r")
        if no_src:
            cmd.append("-s")
            
        cmd.extend(["-o", str(output_dir), str(apk_path)])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                return True, "Decompilation successful"
            else:
                return False, f"Decompilation failed: {result.stderr[:500]}"
                
        except subprocess.TimeoutExpired:
            return False, "Decompilation timeout"
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def build(
        self,
        source_dir: Path,
        output_apk: Path,
        use_aapt2: bool = True
    ) -> Tuple[bool, str]:
        """
        Build APK from decompiled sources
        
        Args:
            source_dir: Directory with decompiled sources
            output_apk: Output APK path
            use_aapt2: Use aapt2 for building
            
        Returns:
            Tuple of (success, message)
        """
        
        if not self.available:
            return False, "apktool not available"
            
        cmd = ["apktool", "b"]
        
        if use_aapt2:
            cmd.append("--use-aapt2")
            
        cmd.extend(["-o", str(output_apk), str(source_dir)])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                return True, "Build successful"
            else:
                return False, f"Build failed: {result.stderr[:500]}"
                
        except Exception as e:
            return False, f"Error: {str(e)}"


class JADXTool:
    """Wrapper for JADX functionality"""
    
    def __init__(self):
        self.logger = setup_logger("jadx")
        self.available = self._check_availability()
        
    def _check_availability(self) -> bool:
        """Check if JADX is available"""
        return shutil.which("jadx") is not None
    
    def decompile(
        self,
        apk_path: Path,
        output_dir: Path,
        deobfuscate: bool = True,
        skip_resources: bool = False,
        threads: int = 4
    ) -> Tuple[bool, str]:
        """
        Decompile APK using JADX
        
        Args:
            apk_path: Path to APK file
            output_dir: Output directory
            deobfuscate: Enable deobfuscation
            skip_resources: Skip resource decoding
            threads: Number of threads to use
            
        Returns:
            Tuple of (success, message)
        """
        
        if not self.available:
            return False, "JADX not available"
            
        cmd = ["jadx", "-d", str(output_dir)]
        
        if deobfuscate:
            cmd.append("--deobf")
        if skip_resources:
            cmd.append("--no-res")
            
        cmd.extend(["--threads", str(threads)])
        cmd.append(str(apk_path))
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                return True, "Decompilation successful"
            else:
                return False, f"Decompilation failed: {result.stderr[:500]}"
                
        except subprocess.TimeoutExpired:
            return False, "Decompilation timeout"
        except Exception as e:
            return False, f"Error: {str(e)}"


class APKAnalyzer:
    """Advanced APK analysis utilities"""
    
    def __init__(self):
        self.logger = setup_logger("apk_analyzer")
        
    def extract_manifest(self, apk_path: Path) -> Optional[Dict[str, Any]]:
        """
        Extract and parse AndroidManifest.xml
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            Parsed manifest data or None
        """
        
        try:
            # Use aapt if available
            if shutil.which("aapt"):
                return self._extract_with_aapt(apk_path)
            elif shutil.which("aapt2"):
                return self._extract_with_aapt2(apk_path)
            else:
                # Fallback to manual extraction
                return self._extract_manually(apk_path)
                
        except Exception as e:
            self.logger.error(f"Error extracting manifest: {e}")
            return None
    
    def _extract_with_aapt(self, apk_path: Path) -> Dict[str, Any]:
        """Extract manifest using aapt"""
        
        cmd = ["aapt", "dump", "badging", str(apk_path)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            raise Exception(f"aapt failed: {result.stderr}")
            
        return self._parse_aapt_output(result.stdout)
    
    def _extract_with_aapt2(self, apk_path: Path) -> Dict[str, Any]:
        """Extract manifest using aapt2"""
        
        cmd = ["aapt2", "dump", "badging", str(apk_path)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            raise Exception(f"aapt2 failed: {result.stderr}")
            
        return self._parse_aapt_output(result.stdout)
    
    def _parse_aapt_output(self, output: str) -> Dict[str, Any]:
        """Parse aapt/aapt2 output"""
        
        manifest_data = {
            "package_name": None,
            "version_code": None,
            "version_name": None,
            "min_sdk": None,
            "target_sdk": None,
            "permissions": [],
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": []
        }
        
        for line in output.split('\n'):
            line = line.strip()
            
            if line.startswith("package:"):
                # Parse package info
                match = re.search(r"name='([^']+)'", line)
                if match:
                    manifest_data["package_name"] = match.group(1)
                    
                match = re.search(r"versionCode='([^']+)'", line)
                if match:
                    manifest_data["version_code"] = match.group(1)
                    
                match = re.search(r"versionName='([^']+)'", line)
                if match:
                    manifest_data["version_name"] = match.group(1)
                    
            elif line.startswith("sdkVersion:"):
                match = re.search(r"'([^']+)'", line)
                if match:
                    manifest_data["min_sdk"] = match.group(1)
                    
            elif line.startswith("targetSdkVersion:"):
                match = re.search(r"'([^']+)'", line)
                if match:
                    manifest_data["target_sdk"] = match.group(1)
                    
            elif line.startswith("uses-permission:"):
                match = re.search(r"name='([^']+)'", line)
                if match:
                    manifest_data["permissions"].append(match.group(1))
                    
            elif line.startswith("activity:"):
                match = re.search(r"name='([^']+)'", line)
                if match:
                    manifest_data["activities"].append(match.group(1))
                    
            elif line.startswith("service:"):
                match = re.search(r"name='([^']+)'", line)
                if match:
                    manifest_data["services"].append(match.group(1))
                    
            elif line.startswith("receiver:"):
                match = re.search(r"name='([^']+)'", line)
                if match:
                    manifest_data["receivers"].append(match.group(1))
                    
            elif line.startswith("provider:"):
                match = re.search(r"name='([^']+)'", line)
                if match:
                    manifest_data["providers"].append(match.group(1))
                    
        return manifest_data
    
    def _extract_manually(self, apk_path: Path) -> Dict[str, Any]:
        """Manual extraction from APK zip"""
        
        manifest_data = {
            "package_name": None,
            "version_code": None,
            "version_name": None,
            "permissions": []
        }
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk:
                # List files for basic analysis
                file_list = apk.namelist()
                
                manifest_data["file_count"] = len(file_list)
                manifest_data["dex_files"] = len([f for f in file_list if f.endswith('.dex')])
                manifest_data["native_libs"] = len([f for f in file_list if f.endswith('.so')])
                
        except Exception as e:
            self.logger.warning(f"Manual extraction limited: {e}")
            
        return manifest_data
    
    def analyze_dex(self, apk_path: Path) -> Dict[str, Any]:
        """
        Analyze DEX files in APK
        
        Args:
            apk_path: Path to APK
            
        Returns:
            DEX analysis results
        """
        
        dex_info = {
            "dex_count": 0,
            "total_size": 0,
            "multidex": False,
            "files": []
        }
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk:
                dex_files = [f for f in apk.namelist() if f.endswith('.dex')]
                
                dex_info["dex_count"] = len(dex_files)
                dex_info["multidex"] = len(dex_files) > 1
                
                for dex_file in dex_files:
                    info = apk.getinfo(dex_file)
                    dex_info["files"].append({
                        "name": dex_file,
                        "size": info.file_size,
                        "compressed_size": info.compress_size
                    })
                    dex_info["total_size"] += info.file_size
                    
        except Exception as e:
            self.logger.error(f"Error analyzing DEX: {e}")
            
        return dex_info
    
    def analyze_native_libs(self, apk_path: Path) -> Dict[str, Any]:
        """
        Analyze native libraries in APK
        
        Args:
            apk_path: Path to APK
            
        Returns:
            Native library analysis
        """
        
        lib_info = {
            "has_native": False,
            "architectures": set(),
            "libraries": [],
            "total_size": 0
        }
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk:
                lib_files = [f for f in apk.namelist() if f.startswith('lib/') and f.endswith('.so')]
                
                lib_info["has_native"] = len(lib_files) > 0
                
                for lib_file in lib_files:
                    parts = lib_file.split('/')
                    if len(parts) >= 2:
                        arch = parts[1]
                        lib_info["architectures"].add(arch)
                        
                    info = apk.getinfo(lib_file)
                    lib_info["libraries"].append({
                        "path": lib_file,
                        "name": Path(lib_file).name,
                        "architecture": arch if len(parts) >= 2 else "unknown",
                        "size": info.file_size
                    })
                    lib_info["total_size"] += info.file_size
                    
            lib_info["architectures"] = list(lib_info["architectures"])
                    
        except Exception as e:
            self.logger.error(f"Error analyzing native libs: {e}")
            
        return lib_info
    
    def get_apk_hash(self, apk_path: Path) -> Dict[str, str]:
        """
        Calculate various hashes of APK
        
        Args:
            apk_path: Path to APK
            
        Returns:
            Dictionary of hash values
        """
        
        hashes = {}
        
        try:
            with open(apk_path, 'rb') as f:
                content = f.read()
                
            hashes["md5"] = hashlib.md5(content).hexdigest()
            hashes["sha1"] = hashlib.sha1(content).hexdigest()
            hashes["sha256"] = hashlib.sha256(content).hexdigest()
            
        except Exception as e:
            self.logger.error(f"Error calculating hashes: {e}")
            
        return hashes
    
    def extract_certificates(self, apk_path: Path) -> List[Dict[str, Any]]:
        """
        Extract signing certificates from APK
        
        Args:
            apk_path: Path to APK
            
        Returns:
            List of certificate information
        """
        
        certs = []
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk:
                # Look for certificate files
                cert_files = [f for f in apk.namelist() 
                             if f.startswith('META-INF/') and 
                             (f.endswith('.RSA') or f.endswith('.DSA') or f.endswith('.EC'))]
                
                for cert_file in cert_files:
                    cert_data = apk.read(cert_file)
                    
                    # Basic cert info (would need cryptography lib for full parsing)
                    certs.append({
                        "file": cert_file,
                        "size": len(cert_data),
                        "type": cert_file.split('.')[-1]
                    })
                    
        except Exception as e:
            self.logger.error(f"Error extracting certificates: {e}")
            
        return certs


class APKPatcher:
    """Utilities for patching APK files"""
    
    def __init__(self):
        self.logger = setup_logger("apk_patcher")
        self.apktool = APKTool()
        
    def patch_manifest(
        self,
        apk_path: Path,
        output_path: Path,
        patches: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """
        Patch AndroidManifest.xml in APK
        
        Args:
            apk_path: Original APK
            output_path: Output patched APK
            patches: Dictionary of patches to apply
            
        Returns:
            Tuple of (success, message)
        """
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            decompiled_path = temp_path / "decompiled"
            
            # Decompile
            success, msg = self.apktool.decompile(apk_path, decompiled_path)
            if not success:
                return False, f"Decompilation failed: {msg}"
                
            # Apply patches to manifest
            manifest_path = decompiled_path / "AndroidManifest.xml"
            if not manifest_path.exists():
                return False, "Manifest not found in decompiled APK"
                
            try:
                # Parse and modify manifest
                tree = ET.parse(manifest_path)
                root = tree.getroot()
                
                # Apply patches (simplified example)
                if "debuggable" in patches:
                    app_elem = root.find(".//application")
                    if app_elem is not None:
                        app_elem.set(
                            "{http://schemas.android.com/apk/res/android}debuggable",
                            str(patches["debuggable"]).lower()
                        )
                        
                # Save modified manifest
                tree.write(manifest_path, encoding='utf-8', xml_declaration=True)
                
            except Exception as e:
                return False, f"Error patching manifest: {e}"
                
            # Rebuild APK
            success, msg = self.apktool.build(decompiled_path, output_path)
            if not success:
                return False, f"Rebuild failed: {msg}"
                
        return True, "APK patched successfully"
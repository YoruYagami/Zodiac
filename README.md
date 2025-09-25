# Zodiac - Enterprise Android Security Analyzer 🔍



[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/zodiac/zodiac)

[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)

[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)



Zodiac is an enterprise-grade Android security analysis framework powered by LangChain and AI. It performs comprehensive static analysis of APK files, validates findings to reduce false positives, and generates intelligent security reports.



## 🌟 Key Features



- **Multi-Agent Architecture\*\*: Specialized agents for decompilation, scanning, validation, and reporting

- **AI-Powered Analysis\*\*: LangChain integration for intelligent finding validation and insights

- **False Positive Reduction\*\*: Advanced validation engine to minimize false positives

- **RAG System\*\*: Vector-based retrieval for contextual security analysis

- **Multiple Scanners\*\*: Integrates MobSFScan, Semgrep, and custom pattern detection

- **Source Context Analysis\*\*: Deep code analysis for accurate vulnerability assessment

- **Comprehensive Reports\*\*: Generate reports in JSON, HTML, and Markdown formats

- **Enterprise Ready\*\*: Scalable, modular architecture with extensive logging



## 🚀 Quick Start



### Prerequisites



- Python 3.8 or higher

- APK analysis tools:

- `apktool` (recommended) or `jadx` for decompilation

- `aapt` or `aapt2` for manifest extraction (optional)

- OpenRouter API key for AI features



### Installation



1. **Clone the repository:**

```bash

git clone https://github.com/zodiac/zodiac-security.git

cd zodiac-security

```



2. **Install the package:**

```bash

pip install -e .

```



Or install directly:

```bash

pip install zodiac-security

```



3. **Install APK tools:**



On Ubuntu/Debian:

```bash

sudo apt-get install apktool aapt

```



On macOS:

```bash

brew install apktool

```



For JADX:

```bash

# Download from https://github.com/skylot/jadx/releases

# Add to PATH

```



4. **Configure environment:**



Create a `.env` file:

```env

# OpenRouter Configuration (required for AI features)

OPENAI_API_KEY=your_openrouter_api_key

OPENAI_BASE_URL=https://openrouter.ai/api/v1

OPENROUTER_REFERRER=https://local.dev

OPENROUTER_TITLE=Zodiac Android Security



# Optional Settings

LLM_MODEL=openai/gpt-4o

EMBEDDING_MODEL=openai/text-embedding-3-large

VALIDATION_LEVEL=moderate

ANALYSIS_MODE=standard

ENABLE_RAG=true

DEBUG=false

```



## 📖 Usage



### Basic Analysis



```bash

# Analyze a single APK

zodiac app.apk


# Specify output directory

zodiac app.apk -o ./analysis_output


# Choose analysis mode

zodiac app.apk -m comprehensive



# Disable RAG for faster analysis

zodiac app.apk --no-rag

```



### Analysis Modes



- **quick**: Fast analysis with basic scanning

- **standard**: Default balanced analysis

- **comprehensive**: Deep analysis with all scanners

- **deep**: Exhaustive analysis with cross-references



### Validation Levels



- **strict**: Conservative validation, fewer false positives

- **moderate**: Balanced validation (default)

- **lenient**: Permissive validation, fewer false negatives



### Batch Analysis



```bash

# Create a text file with APK paths (one per line)

echo "app1.apk" > apk_list.txt

echo "app2.apk" >> apk_list.txt



# Run batch analysis

zodiac apk_list.txt --batch

```



### Interactive Query Mode



```bash

# Analyze and enter interactive RAG query mode

zodiac app.apk --query



# Example queries:

# Q: What are the most critical security issues?

# Q: Show me all SQL injection vulnerabilities

# Q: Which components are exported?

```



## 🏗️ Architecture



### Multi-Agent System



```

┌─────────────────┐

│   Orchestrator  │  Coordinates the analysis pipeline

└────────┬────────┘

        │

   ┌────▼────┬─────────┬──────────┬─────────┐

   │         │         │          │         │

┌───▼──┐ ┌───▼──┐ ┌────▼───┐ ┌───▼──┐ ┌───▼──┐

│Decom-│ │Scanner│ │ Source │ │Valid-│ │Report│

│piler │ │ Agent │ │Analyzer│ │ator  │ │Agent │

│Agent │ │       │ │  Agent │ │Agent │ │      │

└──────┘ └──────┘ └────────┘ └──────┘ └──────┘

                   │

              ┌────▼────┐

              │   RAG   │

              │ System  │

              └─────────┘

```



### Key Components



1. **Decompiler Agent**: Manages APK decompilation using apktool/jadx

2. **Scanner Agent**: Runs security scanners and aggregates findings

3. **Source Analyzer Agent**: Extracts code context for findings

4. **Validator Agent**: Validates findings as TP/FP/DC with AI assistance

5. **Report Agent**: Generates comprehensive security reports

6. **RAG System**: Provides contextual retrieval and intelligent queries



## 🔧 Advanced Configuration



### Custom Validation Rules



Create `custom_rules.json`:

```json

{

"rules": [

   {

     "id": "custom_api_key",

     "pattern": "MY_API_KEY\\s\*=\\s\*\["']\[^"']+\["']",

     "severity": "HIGH",

     "title": "Hardcoded API Key",

     "description": "Custom API key detected in source",

     "confidence": 0.9

   }

 ]

}

```



### Programmatic Usage



```python

import asyncio

from pathlib import Path

from zodiac.pipeline.orchestrator import PipelineBuilder



async def analyze():

   # Build custom pipeline

   orchestrator = PipelineBuilder() \\

       .set\_work\_dir(Path("./output")) \\

       .enable\_rag(True) \\

       .verbose(True) \\

       .build()

   

   # Analyze APK

   results = await orchestrator.analyze_apk(Path("app.apk"))

   

   # Query results

   answer = await orchestrator.query_analysis(

       "What are the critical vulnerabilities?"

   )

   print(answer)

   

   # Cleanup

   orchestrator.cleanup()



# Run analysis

asyncio.run(analyze())

```



## 📊 Output Examples



### Finding Categories



- **True Positive (TP)**: Confirmed vulnerability

- **False Positive (FP)**: Not an actual vulnerability

- **Dynamic Check (DC)**: Requires runtime verification



### Report Structure



```

analysis_output

├── security_analysis_report.json    # Detailed JSON report

├── security_analysis_report.html    # HTML report for browsers

├── security_analysis_report.md      # Markdown report

├── analysis.log                     # Detailed analysis log

├── source/                         # Decompiled source code

├── scan_results/                   # Raw scanner outputs

└── vectorstore/                    # RAG database

```



## 🤝 Contributing



We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.



### Development Setup



```bash

# Install development dependencies

pip install -e ".[dev]"



# Run tests

pytest tests/



# Run linting

flake8 zodiac/

black zodiac/



# Type checking

mypy zodiac/

```



## 📝 License



This project is licensed under the MIT License - see the \[LICENSE](LICENSE) file for details.



## 🙏 Acknowledgments



- [MobSFScan](https://github.com/MobSF/mobsfscan) for security scanning

- [LangChain](https://github.com/langchain-ai/langchain) for AI orchestration

- [OpenRouter](https://openrouter.ai) for LLM access

- [apktool](https://github.com/iBotPeaches/Apktool) and \[jadx](https://github.com/skylot/jadx) for APK analysis



## 📧 Contact



For questions, issues, or security concerns:

- Open an issue on \[GitHub](https://github.com/zodiac/zodiac-security/issues)

- Email: security@zodiac.dev



## ⚠️ Disclaimer



This tool is for educational and authorized security testing purposes only. Users are responsible for complying with applicable laws and regulations. The authors assume no liability for misuse or damage.



---



**Zodiac** - *Securing Android, One APK at a Time* 🛡️


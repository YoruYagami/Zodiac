"""
VectorStore Manager for RAG System
Handles document indexing, retrieval, and querying using ChromaDB
"""

import asyncio
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Set
from datetime import datetime
import json

from langchain_chroma import Chroma
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.schema import Document
from langchain.chains import RetrievalQA
from langchain.chains.question_answering import load_qa_chain
from langchain.prompts import PromptTemplate
from langchain.memory import ConversationSummaryMemory

from ..config.settings import get_settings
from ..core.models import RAGDocument, Finding, APKMetadata, AnalysisState
from ..utils.logger import setup_logger


class VectorStoreManager:
    """
    Manages the vector store for RAG-based retrieval and querying
    Uses ChromaDB for efficient similarity search
    """
    
    def __init__(self, persist_directory: Path):
        self.settings = get_settings()
        self.persist_directory = Path(persist_directory)
        self.persist_directory.mkdir(parents=True, exist_ok=True)
        
        self.logger = setup_logger("vectorstore")
        
        # Initialize embeddings
        self.embeddings = OpenAIEmbeddings(
            model=self.settings.embedding_model,
            base_url=self.settings.openai_base_url,
            api_key=self.settings.openai_api_key
        )
        
        # Initialize LLM for Q&A
        self.llm = ChatOpenAI(
            model=self.settings.llm_model,
            temperature=0,
            max_tokens=self.settings.llm_max_tokens,
            base_url=self.settings.openai_base_url,
            default_headers=self.settings.get_llm_headers(),
            api_key=self.settings.openai_api_key
        )
        
        # Initialize vector store
        self.vectorstore = Chroma(
            persist_directory=str(self.persist_directory),
            embedding_function=self.embeddings,
            collection_name="zodiac_analysis"
        )
        
        # Text splitter for documents
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=self.settings.chunk_size,
            chunk_overlap=self.settings.chunk_overlap,
            separators=["\n\n", "\n", " ", ""]
        )
        
        # Memory for conversational queries
        self.memory = ConversationSummaryMemory(
            llm=self.llm,
            memory_key="chat_history",
            return_messages=True
        )
        
        # Document tracking
        self.indexed_files: Set[str] = set()
        self.document_count = 0
        
    async def index_source_directory(
        self,
        source_dir: Path,
        extensions: List[str] = None,
        batch_size: int = 50
    ) -> int:
        """
        Index source code files from a directory
        
        Args:
            source_dir: Directory containing source files
            extensions: File extensions to index
            batch_size: Number of documents to process at once
            
        Returns:
            Number of documents indexed
        """
        
        if extensions is None:
            extensions = [".java", ".kt", ".xml", ".json", ".properties"]
            
        self.logger.info(f"Indexing source directory: {source_dir}")
        
        documents = []
        files_processed = 0
        
        for ext in extensions:
            for file_path in source_dir.rglob(f"*{ext}"):
                # Skip if already indexed
                file_hash = self._get_file_hash(file_path)
                if file_hash in self.indexed_files:
                    continue
                    
                try:
                    # Read and process file
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    
                    # Skip empty or very small files
                    if len(content) < 50:
                        continue
                        
                    # Create document chunks
                    chunks = self.text_splitter.split_text(content)
                    
                    for i, chunk in enumerate(chunks):
                        doc = Document(
                            page_content=chunk,
                            metadata={
                                "source": str(file_path),
                                "file_type": ext,
                                "chunk_index": i,
                                "total_chunks": len(chunks),
                                "file_hash": file_hash,
                                "indexed_at": datetime.now().isoformat()
                            }
                        )
                        documents.append(doc)
                        
                    self.indexed_files.add(file_hash)
                    files_processed += 1
                    
                    # Process batch
                    if len(documents) >= batch_size:
                        await self._index_batch(documents)
                        documents = []
                        
                except Exception as e:
                    self.logger.warning(f"Error processing {file_path}: {e}")
                    
        # Index remaining documents
        if documents:
            await self._index_batch(documents)
            
        self.logger.info(f"Indexed {files_processed} files")
        return files_processed
    
    async def index_findings(self, findings: List[Finding]) -> int:
        """
        Index security findings for retrieval
        
        Args:
            findings: List of security findings to index
            
        Returns:
            Number of findings indexed
        """
        
        self.logger.info(f"Indexing {len(findings)} findings")
        
        documents = []
        
        for finding in findings:
            # Create comprehensive finding description
            content = self._create_finding_content(finding)
            
            doc = Document(
                page_content=content,
                metadata={
                    "type": "finding",
                    "finding_id": finding.finding_id,
                    "rule_id": finding.rule_id,
                    "severity": finding.severity.value,
                    "category": finding.category,
                    "file_path": finding.file_path,
                    "validation_status": finding.validation_status.value,
                    "confidence": finding.validation_confidence,
                    "indexed_at": datetime.now().isoformat()
                }
            )
            documents.append(doc)
            
        await self._index_batch(documents)
        
        return len(documents)
    
    async def index_metadata(self, metadata: APKMetadata) -> None:
        """Index APK metadata"""
        
        content = f"""
        APK Analysis Metadata:
        Package Name: {metadata.package_name}
        Version: {metadata.version_name} ({metadata.version_code})
        File: {metadata.file_name}
        Size: {metadata.file_size / 1024 / 1024:.2f} MB
        SHA256: {metadata.sha256_hash}
        
        SDK Versions:
        - Minimum SDK: {metadata.min_sdk_version}
        - Target SDK: {metadata.target_sdk_version}
        
        Permissions ({len(metadata.permissions)}):
        {', '.join(metadata.permissions[:10])}
        
        Components:
        - Activities: {len(metadata.activities)}
        - Services: {len(metadata.services)}
        - Receivers: {len(metadata.receivers)}
        - Providers: {len(metadata.providers)}
        """
        
        doc = Document(
            page_content=content,
            metadata={
                "type": "apk_metadata",
                "package_name": metadata.package_name,
                "version": metadata.version_name,
                "indexed_at": datetime.now().isoformat()
            }
        )
        
        await self._index_batch([doc])
    
    async def index_analysis_state(self, state: AnalysisState) -> None:
        """Index the current analysis state"""
        
        content = f"""
        Analysis State:
        ID: {state.analysis_id}
        Phase: {state.current_phase.value}
        Duration: {state.duration_seconds:.2f} seconds if state.duration_seconds else 'In progress'
        
        Progress:
        - Phases Completed: {', '.join([p.value for p in state.phases_completed])}
        - Total Findings: {state.total_findings}
        - Critical Findings: {state.critical_findings}
        - High Findings: {state.high_findings}
        
        Validation Results:
        {self._format_validation_results(state.validation_result) if state.validation_result else 'Not yet validated'}
        
        Errors: {len(state.errors)}
        Warnings: {len(state.warnings)}
        """
        
        doc = Document(
            page_content=content,
            metadata={
                "type": "analysis_state",
                "analysis_id": state.analysis_id,
                "phase": state.current_phase.value,
                "indexed_at": datetime.now().isoformat()
            }
        )
        
        await self._index_batch([doc])
    
    async def query(
        self,
        query: str,
        k: int = 5,
        filter_dict: Optional[Dict] = None,
        include_metadata: bool = True
    ) -> str:
        """
        Query the vector store with RAG
        
        Args:
            query: User query string
            k: Number of documents to retrieve
            filter_dict: Optional metadata filters
            include_metadata: Whether to include document metadata in response
            
        Returns:
            Answer string
        """
        
        # Create retriever with filters if provided
        search_kwargs = {"k": k}
        if filter_dict:
            search_kwargs["filter"] = filter_dict
            
        retriever = self.vectorstore.as_retriever(search_kwargs=search_kwargs)
        
        # Create custom QA prompt
        prompt_template = """You are an Android security expert analyzing an APK.
        Use the following context to answer the question. Be specific and cite relevant findings or code when applicable.
        
        Context:
        {context}
        
        Question: {question}
        
        Answer: """
        
        prompt = PromptTemplate(
            template=prompt_template,
            input_variables=["context", "question"]
        )
        
        # Create QA chain
        qa_chain = RetrievalQA.from_chain_type(
            llm=self.llm,
            chain_type="stuff",
            retriever=retriever,
            return_source_documents=include_metadata,
            chain_type_kwargs={"prompt": prompt}
        )
        
        # Execute query
        result = qa_chain({"query": query})
        
        # Format response
        answer = result["result"]
        
        if include_metadata and "source_documents" in result:
            sources = self._format_sources(result["source_documents"])
            answer += f"\n\nSources:\n{sources}"
            
        return answer
    
    async def similarity_search(
        self,
        query: str,
        k: int = 5,
        filter_dict: Optional[Dict] = None
    ) -> List[Tuple[Document, float]]:
        """
        Perform similarity search without LLM processing
        
        Args:
            query: Query string
            k: Number of results
            filter_dict: Optional metadata filters
            
        Returns:
            List of (document, score) tuples
        """
        
        if filter_dict:
            results = self.vectorstore.similarity_search_with_score(
                query,
                k=k,
                filter=filter_dict
            )
        else:
            results = self.vectorstore.similarity_search_with_score(query, k=k)
            
        return results
    
    async def get_related_findings(
        self,
        finding: Finding,
        k: int = 5
    ) -> List[Finding]:
        """
        Get findings related to a given finding
        
        Args:
            finding: Reference finding
            k: Number of related findings to retrieve
            
        Returns:
            List of related findings
        """
        
        # Create query from finding
        query = f"{finding.rule_id} {finding.description} {finding.category}"
        
        # Search for similar findings
        results = await self.similarity_search(
            query,
            k=k * 2,  # Get more to filter
            filter_dict={"type": "finding"}
        )
        
        # Filter out the original finding and convert to Finding objects
        related = []
        for doc, score in results:
            if doc.metadata.get("finding_id") != finding.finding_id:
                # Reconstruct finding from metadata (simplified)
                related.append(doc.metadata)
                if len(related) >= k:
                    break
                    
        return related
    
    async def _index_batch(self, documents: List[Document]) -> None:
        """Index a batch of documents"""
        
        if not documents:
            return
            
        try:
            self.vectorstore.add_documents(documents)
            self.document_count += len(documents)
            self.logger.debug(f"Indexed batch of {len(documents)} documents")
        except Exception as e:
            self.logger.error(f"Error indexing batch: {e}")
    
    def _get_file_hash(self, file_path: Path) -> str:
        """Get hash of file for deduplication"""
        
        content = file_path.read_bytes()
        return hashlib.md5(content).hexdigest()
    
    def _create_finding_content(self, finding: Finding) -> str:
        """Create searchable content from finding"""
        
        content = f"""
        Security Finding: {finding.title}
        Rule ID: {finding.rule_id}
        Severity: {finding.severity.value}
        Category: {finding.category}
        
        Description: {finding.description}
        
        Location: {finding.file_path or 'Not specified'}
        Line: {finding.line_number or 'N/A'}
        
        Standards Mapping:
        - CWE: {finding.cwe or 'N/A'}
        - OWASP Mobile: {finding.owasp_mobile or 'N/A'}
        - CVSS Score: {finding.cvss_score or 'N/A'}
        
        Validation Status: {finding.validation_status.value}
        Confidence: {finding.validation_confidence:.2%}
        Reason: {finding.validation_reason or 'N/A'}
        """
        
        if finding.source_context:
            content += f"""
        
        Source Context:
        Package: {finding.source_context.package_name or 'N/A'}
        Class: {finding.source_context.class_context or 'N/A'}
        Method: {finding.source_context.method_context or 'N/A'}
        
        Code Snippet:
        {finding.source_context.code_snippet[:500] if finding.source_context.code_snippet else 'N/A'}
        """
        
        if finding.remediation:
            content += f"\nRemediation: {finding.remediation}"
            
        return content
    
    def _format_validation_results(self, validation_result) -> str:
        """Format validation results for indexing"""
        
        if not validation_result:
            return "No validation results"
            
        return f"""
        - Total Processed: {validation_result.total_processed}
        - True Positives: {len(validation_result.true_positives)}
        - Dynamic Checks: {len(validation_result.dynamic_checks)}
        - False Positives: {len(validation_result.false_positives)}
        - Average Confidence: {validation_result.average_confidence:.2%}
        """
    
    def _format_sources(self, documents: List[Document]) -> str:
        """Format source documents for display"""
        
        sources = []
        for doc in documents[:3]:  # Limit to 3 sources
            source_type = doc.metadata.get("type", "document")
            source_file = doc.metadata.get("source", "Unknown")
            
            if source_type == "finding":
                source_desc = f"Finding {doc.metadata.get('rule_id', 'Unknown')}"
            elif source_type == "apk_metadata":
                source_desc = "APK Metadata"
            elif source_file != "Unknown":
                source_desc = f"Source: {Path(source_file).name}"
            else:
                source_desc = "Document"
                
            sources.append(f"- {source_desc}")
            
        return "\n".join(sources)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get vector store statistics"""
        
        collection = self.vectorstore._collection
        
        return {
            "total_documents": self.document_count,
            "indexed_files": len(self.indexed_files),
            "collection_count": collection.count() if collection else 0,
            "persist_directory": str(self.persist_directory)
        }
    
    def clear(self) -> None:
        """Clear the vector store"""
        
        self.vectorstore.delete_collection()
        self.indexed_files.clear()
        self.document_count = 0
        self.memory.clear()
        
        self.logger.info("Vector store cleared")
    
    def close(self) -> None:
        """Close and persist the vector store"""
        
        try:
            self.vectorstore.persist()
            self.logger.info("Vector store persisted")
        except Exception as e:
            self.logger.error(f"Error persisting vector store: {e}")


class RAGQueryEngine:
    """
    Advanced query engine for complex RAG operations
    """
    
    def __init__(self, vector_store: VectorStoreManager):
        self.vector_store = vector_store
        self.settings = get_settings()
        self.logger = setup_logger("rag_query")
        
        # Specialized prompts for different query types
        self.prompts = {
            "security": """You are an Android security expert. Analyze the provided context and answer the security-related question.
            Focus on vulnerabilities, risks, and security best practices.
            
            Context: {context}
            Question: {question}
            Answer:""",
            
            "code": """You are analyzing Android application source code. Use the provided code context to answer the question.
            Be specific about code locations and patterns.
            
            Context: {context}
            Question: {question}
            Answer:""",
            
            "summary": """Provide a concise summary based on the context. Focus on key findings and actionable insights.
            
            Context: {context}
            Question: {question}
            Summary:""",
            
            "remediation": """You are providing security remediation guidance. Based on the vulnerabilities in the context,
            provide specific, actionable remediation steps.
            
            Context: {context}
            Question: {question}
            Remediation Steps:"""
        }
    
    async def query_with_type(
        self,
        query: str,
        query_type: str = "security",
        k: int = 5
    ) -> str:
        """
        Query with specific prompt type
        
        Args:
            query: User query
            query_type: Type of query (security, code, summary, remediation)
            k: Number of documents to retrieve
            
        Returns:
            Formatted answer
        """
        
        prompt_template = self.prompts.get(query_type, self.prompts["security"])
        
        prompt = PromptTemplate(
            template=prompt_template,
            input_variables=["context", "question"]
        )
        
        retriever = self.vector_store.vectorstore.as_retriever(
            search_kwargs={"k": k}
        )
        
        qa_chain = RetrievalQA.from_chain_type(
            llm=self.vector_store.llm,
            chain_type="stuff",
            retriever=retriever,
            chain_type_kwargs={"prompt": prompt}
        )
        
        result = qa_chain({"query": query})
        
        return result["result"]
    
    async def multi_query(self, queries: List[str]) -> Dict[str, str]:
        """
        Execute multiple queries in parallel
        
        Args:
            queries: List of query strings
            
        Returns:
            Dictionary of query -> answer
        """
        
        tasks = [self.vector_store.query(q) for q in queries]
        answers = await asyncio.gather(*tasks)
        
        return dict(zip(queries, answers))
    
    async def contextual_search(
        self,
        query: str,
        context_filter: Dict[str, Any],
        k: int = 5
    ) -> List[Document]:
        """
        Search with specific context filters
        
        Args:
            query: Search query
            context_filter: Metadata filters for context
            k: Number of results
            
        Returns:
            List of relevant documents
        """
        
        results = await self.vector_store.similarity_search(
            query,
            k=k,
            filter_dict=context_filter
        )
        
        return [doc for doc, score in results]

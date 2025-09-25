"""
Base Agent Implementation for Zodiac
Foundation for all specialized security analysis agents
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Type
from datetime import datetime
import logging

from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain.memory import ConversationBufferWindowMemory
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.tools import Tool, StructuredTool
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from ..core.models import AnalysisState, AgentMessage
from ..config.settings import get_settings, AGENT_PROMPTS


class AgentConfig(BaseModel):
    """Configuration for an agent"""
    name: str
    description: str
    model: str = Field(default_factory=lambda: get_settings().llm_model)
    temperature: float = 0.0
    max_tokens: int = 2000
    tools: List[Tool] = Field(default_factory=list)
    memory_window: int = 10
    verbose: bool = False
    max_iterations: int = Field(default_factory=lambda: get_settings().agent_max_iterations)
    

class BaseAgent(ABC):
    """
    Abstract base class for all Zodiac agents
    Provides common functionality for LangChain-based agents
    """
    
    def __init__(self, config: AgentConfig, state: Optional[AnalysisState] = None):
        self.config = config
        self.state = state or AnalysisState()
        self.settings = get_settings()
        self.logger = logging.getLogger(f"{__name__}.{self.config.name}")
        
        # Initialize LangChain components
        self.llm = self._create_llm()
        self.memory = self._create_memory()
        self.tools = self._initialize_tools()
        self.agent_executor = self._create_agent_executor()
        
        # Message history for inter-agent communication
        self.message_history: List[AgentMessage] = []
        
    def _create_llm(self) -> ChatOpenAI:
        """Create the LLM instance"""
        return ChatOpenAI(
            model=self.config.model,
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
            base_url=self.settings.openai_base_url,
            default_headers=self.settings.get_llm_headers(),
            api_key=self.settings.openai_api_key
        )
    
    def _create_memory(self) -> ConversationBufferWindowMemory:
        """Create conversation memory"""
        return ConversationBufferWindowMemory(
            memory_key="chat_history",
            return_messages=True,
            k=self.config.memory_window
        )
    
    def _initialize_tools(self) -> List[Tool]:
        """Initialize agent-specific tools"""
        base_tools = self.config.tools.copy()
        
        # Add common tools available to all agents
        base_tools.extend([
            Tool(
                name="get_analysis_state",
                func=self._get_analysis_state,
                description="Get current analysis state and progress"
            ),
            Tool(
                name="update_analysis_state",
                func=self._update_analysis_state,
                description="Update the analysis state with new information"
            ),
            Tool(
                name="log_message",
                func=self._log_message,
                description="Log a message for debugging or tracking"
            )
        ])
        
        # Add agent-specific tools
        specific_tools = self._get_specific_tools()
        base_tools.extend(specific_tools)
        
        return base_tools
    
    @abstractmethod
    def _get_specific_tools(self) -> List[Tool]:
        """Get agent-specific tools (to be implemented by subclasses)"""
        pass
    
    def _create_agent_executor(self) -> AgentExecutor:
        """Create the agent executor"""
        # Get the appropriate prompt for this agent type
        system_prompt = self._get_system_prompt()
        
        prompt = ChatPromptTemplate.from_messages([
            ("system", system_prompt),
            MessagesPlaceholder("chat_history", optional=True),
            ("human", "{input}"),
            MessagesPlaceholder("agent_scratchpad"),
        ])
        
        agent = create_openai_tools_agent(
            llm=self.llm,
            tools=self.tools,
            prompt=prompt
        )
        
        return AgentExecutor(
            agent=agent,
            tools=self.tools,
            memory=self.memory,
            verbose=self.config.verbose,
            max_iterations=self.config.max_iterations,
            handle_parsing_errors=True
        )
    
    def _get_system_prompt(self) -> str:
        """Get the system prompt for this agent"""
        # Try to get a predefined prompt, otherwise use a generic one
        agent_type = self.__class__.__name__.replace("Agent", "").lower()
        base_prompt = AGENT_PROMPTS.get(agent_type, self._get_default_prompt())
        
        # Add context about current analysis
        context_prompt = f"""
        
        Current Analysis Context:
        - Analysis ID: {self.state.analysis_id}
        - Current Phase: {self.state.current_phase.value}
        - APK: {self.state.apk_metadata.file_name if self.state.apk_metadata else 'Not loaded'}
        
        Your role: {self.config.description}
        """
        
        return base_prompt + context_prompt
    
    def _get_default_prompt(self) -> str:
        """Get default system prompt"""
        return f"""You are {self.config.name}, a specialized security analysis agent.
        {self.config.description}
        
        Analyze the given input carefully and provide accurate, detailed responses.
        Use the available tools to gather information and perform analysis.
        Be precise and focus on security-relevant aspects."""
    
    @abstractmethod
    async def execute(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the agent's main task
        To be implemented by each specific agent
        """
        pass
    
    def run(self, query: str) -> str:
        """Run the agent with a query"""
        try:
            result = self.agent_executor.invoke({"input": query})
            return result.get("output", "")
        except Exception as e:
            self.logger.error(f"Error running agent: {e}")
            return f"Error: {str(e)}"
    
    async def process_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """Process an incoming message from another agent"""
        self.message_history.append(message)
        
        # Default processing - override in subclasses for specific handling
        self.logger.info(f"Received message from {message.sender}: {message.message_type}")
        
        # Process based on message type
        if message.message_type == "request":
            response_content = await self._handle_request(message.content)
            return AgentMessage(
                sender=self.config.name,
                receiver=message.sender,
                message_type="response",
                content=response_content,
                correlation_id=message.correlation_id
            )
        
        return None
    
    async def _handle_request(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a request message (to be overridden)"""
        return {"status": "received", "message": "Request processed"}
    
    def send_message(self, receiver: str, message_type: str, content: Dict[str, Any]) -> AgentMessage:
        """Send a message to another agent"""
        message = AgentMessage(
            sender=self.config.name,
            receiver=receiver,
            message_type=message_type,
            content=content
        )
        self.logger.debug(f"Sending message to {receiver}: {message_type}")
        return message
    
    # Tool implementations
    def _get_analysis_state(self, query: str = "") -> str:
        """Get current analysis state"""
        return f"""Current Analysis State:
        - ID: {self.state.analysis_id}
        - Phase: {self.state.current_phase.value}
        - Findings: {self.state.total_findings}
        - Critical Issues: {self.state.critical_findings}
        - Phases Completed: {', '.join([p.value for p in self.state.phases_completed])}
        """
    
    def _update_analysis_state(self, updates: str) -> str:
        """Update analysis state (parse updates from string)"""
        # This is a simplified version - in production, parse the updates properly
        self.logger.info(f"State update requested: {updates}")
        return "State updated successfully"
    
    def _log_message(self, message: str) -> str:
        """Log a message"""
        self.logger.info(f"Agent log: {message}")
        return "Message logged"
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get agent performance metrics"""
        return {
            "name": self.config.name,
            "messages_processed": len(self.message_history),
            "memory_size": len(self.memory.chat_memory.messages) if hasattr(self.memory, 'chat_memory') else 0,
            "state": "active"
        }
    
    def reset(self):
        """Reset the agent state"""
        self.memory.clear()
        self.message_history.clear()
        self.logger.info(f"Agent {self.config.name} reset")
    
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(name={self.config.name})>"


class ToolBuilder:
    """Utility class to build tools for agents"""
    
    @staticmethod
    def create_tool(
        name: str,
        func: Any,
        description: str,
        args_schema: Optional[Type[BaseModel]] = None
    ) -> Tool:
        """Create a tool with proper configuration"""
        if args_schema:
            return StructuredTool(
                name=name,
                func=func,
                description=description,
                args_schema=args_schema
            )
        else:
            return Tool(
                name=name,
                func=func,
                description=description
            )
    
    @staticmethod
    def create_async_tool(
        name: str,
        coroutine: Any,
        description: str,
        args_schema: Optional[Type[BaseModel]] = None
    ) -> Tool:
        """Create an async tool"""
        return StructuredTool(
            name=name,
            coroutine=coroutine,
            description=description,
            args_schema=args_schema
        ) if args_schema else Tool(
            name=name,
            func=coroutine,
            description=description
        )


class AgentRegistry:
    """Registry for managing agents"""
    
    def __init__(self):
        self.agents: Dict[str, BaseAgent] = {}
        self.logger = logging.getLogger(__name__)
    
    def register(self, agent: BaseAgent) -> None:
        """Register an agent"""
        self.agents[agent.config.name] = agent
        self.logger.info(f"Registered agent: {agent.config.name}")
    
    def get(self, name: str) -> Optional[BaseAgent]:
        """Get an agent by name"""
        return self.agents.get(name)
    
    def list_agents(self) -> List[str]:
        """List all registered agents"""
        return list(self.agents.keys())
    
    def broadcast_message(self, sender: str, message_type: str, content: Dict[str, Any]) -> None:
        """Broadcast a message to all agents"""
        for name, agent in self.agents.items():
            if name != sender:
                message = AgentMessage(
                    sender=sender,
                    receiver=name,
                    message_type=message_type,
                    content=content
                )
                agent.process_message(message)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get metrics for all agents"""
        return {
            name: agent.get_performance_metrics() 
            for name, agent in self.agents.items()
        }
    
    def reset_all(self) -> None:
        """Reset all agents"""
        for agent in self.agents.values():
            agent.reset()
        self.logger.info("All agents reset")
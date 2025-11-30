"""
Configuration management for V1 Log Analyzer System.

This module handles loading and validating configuration from environment variables
using Pydantic Settings. All settings are loaded from .env file or environment.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    
    Required settings must be provided via .env file or environment variables.
    Optional settings have sensible defaults.
    
    LLM Configuration:
        groq_api_key: API key for Groq LLM service (required)
        llm_model: Model name to use for analysis (default: llama-3.3-70b-versatile)
        llm_temperature: Temperature for LLM responses (default: 0.0 for deterministic)
        chunk_size: Number of events to process per LLM call (default: 50)
    
    MCP Configuration:
        mcp_server_path: Path to MCP server script (default: ./mcp/log_server.py)
    
    Output Configuration:
        output_dir: Directory for CSV exports (default: ./output)
        csv_encoding: Character encoding for CSV files (default: utf-8)
    
    Splunk Configuration (optional):
        splunk_host: Splunk server hostname
        splunk_port: Splunk server port
        splunk_username: Splunk authentication username
        splunk_password: Splunk authentication password
    
    Additional API Keys (optional - for future features):
        abuseipdb_api_key: API key for AbuseIPDB threat intelligence
        telegram_bot_token: Telegram bot token for notifications
        telegram_chat_id: Telegram chat ID for notifications
        google_api_key: Google API key for additional services
    """
    
    # LLM Configuration (required)
    groq_api_key: str
    llm_model: str = "llama-3.3-70b-versatile"
    llm_temperature: float = 0.0
    llm_provider: str = "groq"  # "groq" or "google"
    chunk_size: int = 50
    
    # Google AI Configuration (optional)
    google_api_key: Optional[str] = None
    
    # V2: Agent-specific LLM providers (optional - defaults to llm_provider)
    analyze_agent_provider: Optional[str] = None   # "groq" or "google"
    ti_agent_provider: Optional[str] = None
    recommend_agent_provider: Optional[str] = None
    report_agent_provider: Optional[str] = None
    
    # V2: Agent-specific LLM models (optional - defaults to llm_model)
    analyze_agent_model: Optional[str] = None      # AnalyzeAgent model
    ti_agent_model: Optional[str] = None           # TIAgent model
    recommend_agent_model: Optional[str] = None    # RecommendAgent model
    report_agent_model: Optional[str] = None       # ReportAgent model
    
    # V2: Agent-specific temperatures (optional - defaults to llm_temperature)
    analyze_agent_temperature: Optional[float] = None
    ti_agent_temperature: Optional[float] = None
    recommend_agent_temperature: Optional[float] = None
    report_agent_temperature: Optional[float] = None
    
    # V3: GenRule Agent Configuration
    genrule_agent_model: Optional[str] = None
    genrule_agent_temperature: Optional[float] = 0.1
    
    # V3: QueryRAG Agent Configuration
    queryrag_agent_model: Optional[str] = None
    queryrag_agent_temperature: Optional[float] = 0.3
    
    # V3: RAG Configuration
    rag_server_path: str = "./mcp_server/rag_server.py"
    rag_top_k: int = 5
    rag_alpha: float = 0.55
    
    # V3: Feature Flags
    enable_v3: bool = True
    enable_genrule: bool = True
    enable_queryrag: bool = True
    
    # V4: LangGraph Configuration
    use_langgraph: bool = True
    graph_visualization: bool = True
    graph_max_iterations: int = 50
    graph_timeout: int = 300  # 5 minutes
    
    # V4: SupervisorAgent Configuration
    use_supervisor_agent: bool = True
    supervisor_agent_model: Optional[str] = "llama-3.3-70b-versatile"
    supervisor_agent_temperature: float = 0.1
    
    # V4: AssetAgent Configuration (Optional)
    enable_asset_agent: bool = False
    asset_agent_model: Optional[str] = "llama-3.1-8b-instant"
    asset_agent_temperature: float = 0.2
    asset_cache_ttl: int = 3600  # 1 hour
    
    # MCP Configuration
    mcp_server_path: str = "./mcp_server/log_server.py"
    
    # Output Configuration
    output_dir: str = "./output"
    csv_encoding: str = "utf-8"
    
    # Splunk Configuration (optional)
    splunk_host: Optional[str] = None
    splunk_port: Optional[int] = None
    splunk_username: Optional[str] = None
    splunk_password: Optional[str] = None
    
    # V2: Threat Intelligence API Keys (optional)
    abuseipdb_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    
    # Additional API Keys (optional)
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    
    # Helper methods for V2 agent configuration
    def get_analyze_agent_provider(self) -> str:
        """Get provider for AnalyzeAgent (defaults to llm_provider)."""
        return self.analyze_agent_provider or self.llm_provider
    
    def get_ti_agent_provider(self) -> str:
        """Get provider for TIAgent (defaults to llm_provider)."""
        return self.ti_agent_provider or self.llm_provider
    
    def get_recommend_agent_provider(self) -> str:
        """Get provider for RecommendAgent (defaults to llm_provider)."""
        return self.recommend_agent_provider or self.llm_provider
    
    def get_report_agent_provider(self) -> str:
        """Get provider for ReportAgent (defaults to llm_provider)."""
        return self.report_agent_provider or self.llm_provider
    
    def get_analyze_agent_model(self) -> str:
        """Get model for AnalyzeAgent (defaults to llm_model)."""
        return self.analyze_agent_model or self.llm_model
    
    def get_ti_agent_model(self) -> str:
        """Get model for TIAgent (defaults to llm_model)."""
        return self.ti_agent_model or self.llm_model
    
    def get_recommend_agent_model(self) -> str:
        """Get model for RecommendAgent (defaults to llm_model)."""
        return self.recommend_agent_model or self.llm_model
    
    def get_report_agent_model(self) -> str:
        """Get model for ReportAgent (defaults to llm_model)."""
        return self.report_agent_model or self.llm_model
    
    def get_analyze_agent_temperature(self) -> float:
        """Get temperature for AnalyzeAgent (defaults to llm_temperature)."""
        return self.analyze_agent_temperature if self.analyze_agent_temperature is not None else self.llm_temperature
    
    def get_ti_agent_temperature(self) -> float:
        """Get temperature for TIAgent (defaults to llm_temperature)."""
        return self.ti_agent_temperature if self.ti_agent_temperature is not None else self.llm_temperature
    
    def get_recommend_agent_temperature(self) -> float:
        """Get temperature for RecommendAgent (defaults to llm_temperature)."""
        return self.recommend_agent_temperature if self.recommend_agent_temperature is not None else self.llm_temperature
    
    def get_report_agent_temperature(self) -> float:
        """Get temperature for ReportAgent (defaults to llm_temperature)."""
        return self.report_agent_temperature if self.report_agent_temperature is not None else self.llm_temperature
    
    # V3: Helper methods for GenRule and QueryRAG agents
    def get_genrule_agent_model(self) -> str:
        """Get model for GenRuleAgent (defaults to llm_model)."""
        return self.genrule_agent_model or self.llm_model
    
    def get_queryrag_agent_model(self) -> str:
        """Get model for QueryRAGAgent (defaults to llm_model)."""
        return self.queryrag_agent_model or self.llm_model
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )


# Global settings instance
settings = Settings()

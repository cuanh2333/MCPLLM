"""
LLM Factory for creating LLM instances from different providers.

Supports:
- Groq (ChatGroq)
- Google AI (ChatGoogleGenerativeAI)
"""

import logging
from typing import Literal

from langchain_groq import ChatGroq
from langchain_google_genai import ChatGoogleGenerativeAI

from backend.config import settings


logger = logging.getLogger(__name__)


def create_llm(
    provider: Literal["groq", "google"],
    model: str,
    temperature: float,
    api_key: str = None
):
    """
    Create LLM instance based on provider.
    
    Args:
        provider: "groq" or "google"
        model: Model name
        temperature: Temperature (0.0 to 1.0)
        api_key: API key (optional, uses settings if not provided)
    
    Returns:
        LLM instance (ChatGroq or ChatGoogleGenerativeAI)
    
    Raises:
        ValueError: If provider is not supported or API key is missing
    """
    provider = provider.lower()
    
    if provider == "groq":
        api_key = api_key or settings.groq_api_key
        if not api_key:
            raise ValueError("GROQ_API_KEY not configured")
        
        logger.info(f"Creating Groq LLM: model={model}, temperature={temperature}")
        return ChatGroq(
            model=model,
            temperature=temperature,
            api_key=api_key
        )
    
    elif provider == "google":
        api_key = api_key or settings.google_api_key
        if not api_key:
            raise ValueError("GOOGLE_API_KEY not configured")
        
        logger.info(f"Creating Google AI LLM: model={model}, temperature={temperature}")
        return ChatGoogleGenerativeAI(
            model=model,
            temperature=temperature,
            google_api_key=api_key
        )
    
    else:
        raise ValueError(f"Unsupported provider: {provider}. Use 'groq' or 'google'")


def create_analyze_agent_llm():
    """Create LLM for AnalyzeAgent using configured provider and model."""
    return create_llm(
        provider=settings.get_analyze_agent_provider(),
        model=settings.get_analyze_agent_model(),
        temperature=settings.get_analyze_agent_temperature()
    )


def create_ti_agent_llm():
    """Create LLM for TIAgent using configured provider and model."""
    return create_llm(
        provider=settings.get_ti_agent_provider(),
        model=settings.get_ti_agent_model(),
        temperature=settings.get_ti_agent_temperature()
    )


def create_recommend_agent_llm():
    """Create LLM for RecommendAgent using configured provider and model."""
    return create_llm(
        provider=settings.get_recommend_agent_provider(),
        model=settings.get_recommend_agent_model(),
        temperature=settings.get_recommend_agent_temperature()
    )


def create_report_agent_llm():
    """Create LLM for ReportAgent using configured provider and model."""
    return create_llm(
        provider=settings.get_report_agent_provider(),
        model=settings.get_report_agent_model(),
        temperature=settings.get_report_agent_temperature()
    )

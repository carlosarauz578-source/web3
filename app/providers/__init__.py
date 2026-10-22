"""External model provider adapters and their internal completion contract."""

from __future__ import annotations

import os

from app.providers import gemini, groq, openai_compatible, simulated
from app.providers.common import (
    ProviderAccessDenied,
    ProviderAdapter,
    ProviderCompletion,
    ProviderError,
    ProviderInvalidCredentials,
    ProviderInvalidResponse,
    ProviderMisconfigured,
    ProviderNotConfigured,
    ProviderPreTransportError,
    ProviderRateLimited,
    ProviderRemoteError,
    ProviderRequest,
    ProviderSensitiveContent,
    ProviderSensitiveResponse,
    ProviderSettings,
    ProviderTimeout,
    ProviderTransportUnknown,
    ensure_provider_request_is_safe,
    load_settings,
)

_ADAPTERS: dict[str, ProviderAdapter] = {
    "openai": openai_compatible.OpenAIAdapter(),
    "gemini": gemini.GeminiAdapter(),
    "groq": groq.GroqAdapter(),
}


def complete(*, system_prompt: str, user_content: str) -> ProviderCompletion:
    request = ProviderRequest(system_prompt, user_content)
    ensure_provider_request_is_safe(request)
    selected_provider = os.getenv("AEGIS_AI_PROVIDER", "openai")
    if selected_provider == simulated.SIMULATED_PROVIDER_ID:
        return simulated.complete_simulated(request)
    settings = load_settings(selected_provider)
    return _ADAPTERS[selected_provider].complete(
        request,
        settings,
    )


def execution_mode(provider: object = None) -> str:
    """`simulated` only for the offline simulated provider; otherwise `real`."""
    selected = provider if isinstance(provider, str) else os.getenv("AEGIS_AI_PROVIDER", "openai")
    return "simulated" if selected == simulated.SIMULATED_PROVIDER_ID else "real"


def provider_status() -> dict[str, str]:
    if os.getenv("AEGIS_AI_PROVIDER", "openai") == simulated.SIMULATED_PROVIDER_ID:
        return {**simulated.simulated_status(), "execution_mode": "simulated"}
    try:
        settings = load_settings()
    except ProviderNotConfigured:
        return {"status": "not_configured"}
    except ProviderMisconfigured:
        return {"status": "misconfigured"}
    return {
        "status": "configured",
        "provider": settings.provider,
        "model": settings.model,
    }


__all__ = [
    "ProviderAccessDenied",
    "ProviderCompletion",
    "ProviderError",
    "ProviderInvalidCredentials",
    "ProviderInvalidResponse",
    "ProviderMisconfigured",
    "ProviderNotConfigured",
    "ProviderPreTransportError",
    "ProviderRateLimited",
    "ProviderRemoteError",
    "ProviderRequest",
    "ProviderSensitiveContent",
    "ProviderSensitiveResponse",
    "ProviderSettings",
    "ProviderTimeout",
    "ProviderTransportUnknown",
    "complete",
    "execution_mode",
    "provider_status",
]

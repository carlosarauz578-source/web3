from __future__ import annotations

import json
from urllib.request import ProxyHandler, Request, build_opener

from app.providers.common import (
    MAX_COMPLETION_TOKENS,
    MAX_PROVIDER_RESPONSE_BYTES,
    PROVIDER_TIMEOUT_SECONDS,
    ProviderAccessDenied,
    ProviderCompletion,
    ProviderError,
    ProviderInvalidCredentials,
    ProviderInvalidResponse,
    ProviderMisconfigured,
    ProviderNotConfigured,
    ProviderRateLimited,
    ProviderRemoteError,
    ProviderRequest,
    ProviderSensitiveContent,
    ProviderSettings,
    ProviderTimeout,
    _PinnedHTTPSConnection,
    _PinnedHTTPSHandler,
    _RejectRedirects,
    decode_json_response,
    ensure_provider_request_is_safe,
    load_settings,
    send_request,
)
from app.providers.common import (
    resolve_public_address as _common_resolve_public_address,
)

_resolve_public_address = _common_resolve_public_address


def _open_request(request: Request, timeout: int, address: str):
    opener = build_opener(
        ProxyHandler({}),
        _RejectRedirects,
        _PinnedHTTPSHandler(address),
    )
    return opener.open(request, timeout=timeout)


def _settings() -> ProviderSettings:
    return load_settings("openai")


class OpenAIAdapter:
    provider_id = "openai-compatible"

    def complete(
        self,
        request: ProviderRequest,
        settings: ProviderSettings,
    ) -> ProviderCompletion:
        ensure_provider_request_is_safe(request)
        body = json.dumps(
            {
                "model": settings.model,
                "messages": [
                    {"role": "system", "content": request.system_prompt},
                    {"role": "user", "content": request.user_content},
                ],
                "temperature": 0,
                "max_tokens": MAX_COMPLETION_TOKENS,
                "response_format": {"type": "json_object"},
            },
            separators=(",", ":"),
        ).encode("utf-8")
        provider_request = Request(
            settings.api_url,
            data=body,
            headers={
                "Authorization": f"Bearer {settings.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        raw_response = send_request(
            provider_request,
            settings.api_url,
            resolve_address=_resolve_public_address,
            open_connection=_open_request,
        )
        response_data = decode_json_response(raw_response)
        try:
            choices = response_data["choices"]
            if not isinstance(choices, list):
                raise TypeError
            first_choice = choices[0]
            if not isinstance(first_choice, dict):
                raise TypeError
            message = first_choice["message"]
            if not isinstance(message, dict):
                raise TypeError
            content = message["content"]
            returned_model = response_data.get("model", settings.model)
        except (KeyError, IndexError, TypeError):
            raise ProviderInvalidResponse from None
        return _completion(content, returned_model, settings)


def _completion(
    content: object,
    returned_model: object,
    settings: ProviderSettings,
) -> ProviderCompletion:
    if (
        not isinstance(content, str)
        or not content.strip()
        or not isinstance(returned_model, str)
        or len(returned_model) > 120
        or any(ord(char) < 32 for char in returned_model)
    ):
        raise ProviderInvalidResponse
    try:
        content_size = len(content.encode("utf-8"))
    except UnicodeEncodeError:
        raise ProviderInvalidResponse from None
    if content_size > MAX_PROVIDER_RESPONSE_BYTES:
        raise ProviderInvalidResponse
    return ProviderCompletion(content, settings.provider, returned_model)


def complete(*, system_prompt: str, user_content: str) -> ProviderCompletion:
    settings = _settings()
    return OpenAIAdapter().complete(
        ProviderRequest(system_prompt, user_content),
        settings,
    )


__all__ = [
    "MAX_COMPLETION_TOKENS",
    "MAX_PROVIDER_RESPONSE_BYTES",
    "PROVIDER_TIMEOUT_SECONDS",
    "ProviderAccessDenied",
    "ProviderCompletion",
    "ProviderError",
    "ProviderInvalidCredentials",
    "ProviderInvalidResponse",
    "ProviderMisconfigured",
    "ProviderNotConfigured",
    "ProviderRateLimited",
    "ProviderRemoteError",
    "ProviderSensitiveContent",
    "ProviderTimeout",
    "_PinnedHTTPSConnection",
    "_PinnedHTTPSHandler",
    "_RejectRedirects",
    "_open_request",
    "_resolve_public_address",
    "complete",
]

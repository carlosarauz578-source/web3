from __future__ import annotations

import json
from urllib.parse import quote
from urllib.request import Request

from app.providers.common import (
    MAX_COMPLETION_TOKENS,
    MAX_PROVIDER_RESPONSE_BYTES,
    ProviderCompletion,
    ProviderInvalidResponse,
    ProviderRequest,
    ProviderSettings,
    decode_json_response,
    ensure_provider_request_is_safe,
    load_settings,
    send_request,
)
from app.providers.common import (
    open_request as _open_request,
)
from app.providers.common import (
    resolve_public_address as _resolve_public_address,
)


class GeminiAdapter:
    provider_id = "gemini"

    def complete(
        self,
        request: ProviderRequest,
        settings: ProviderSettings,
    ) -> ProviderCompletion:
        ensure_provider_request_is_safe(request)
        api_url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{quote(settings.model, safe='-._~')}:generateContent"
        )
        body = json.dumps(
            {
                "systemInstruction": {"parts": [{"text": request.system_prompt}]},
                "contents": [{"role": "user", "parts": [{"text": request.user_content}]}],
                "generationConfig": {
                    "temperature": 0,
                    "maxOutputTokens": MAX_COMPLETION_TOKENS,
                    "responseMimeType": "application/json",
                },
            },
            separators=(",", ":"),
        ).encode("utf-8")
        provider_request = Request(
            api_url,
            data=body,
            headers={
                "x-goog-api-key": settings.api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        raw_response = send_request(
            provider_request,
            api_url,
            resolve_address=_resolve_public_address,
            open_connection=_open_request,
        )
        response_data = decode_json_response(raw_response)
        try:
            candidates = response_data["candidates"]
            if not isinstance(candidates, list):
                raise TypeError
            candidate = candidates[0]
            if not isinstance(candidate, dict):
                raise TypeError
            content_data = candidate["content"]
            if not isinstance(content_data, dict):
                raise TypeError
            parts = content_data["parts"]
            if not isinstance(parts, list):
                raise TypeError
            text_parts = [
                part["text"]
                for part in parts
                if isinstance(part, dict) and isinstance(part.get("text"), str)
            ]
            content = "".join(text_parts)
        except (KeyError, IndexError, TypeError):
            raise ProviderInvalidResponse from None
        try:
            content_size = len(content.encode("utf-8"))
        except UnicodeEncodeError:
            raise ProviderInvalidResponse from None
        if not content.strip() or content_size > MAX_PROVIDER_RESPONSE_BYTES:
            raise ProviderInvalidResponse
        return ProviderCompletion(content, settings.provider, settings.model)


def complete(*, system_prompt: str, user_content: str) -> ProviderCompletion:
    settings = load_settings("gemini")
    return GeminiAdapter().complete(
        ProviderRequest(system_prompt, user_content),
        settings,
    )


__all__ = ["GeminiAdapter", "complete"]

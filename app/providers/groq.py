from __future__ import annotations

import json
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


class GroqAdapter:
    provider_id = "groq"

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
    settings = load_settings("groq")
    return GroqAdapter().complete(
        ProviderRequest(system_prompt, user_content),
        settings,
    )


__all__ = ["GroqAdapter", "complete"]

from __future__ import annotations

import http.client
import ipaddress
import json
import multiprocessing
import os
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from app.sensitive_data import contains_sensitive_content

MAX_PROVIDER_RESPONSE_BYTES = 32_000
PROVIDER_TIMEOUT_SECONDS = 30
MAX_COMPLETION_TOKENS = 1_500
SUPPORTED_MODELS = {
    "openai": frozenset({"gpt-4o-2024-08-06"}),
    "gemini": frozenset(),
    "groq": frozenset({"llama-3.3-70b-versatile"}),
}
OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models"
TRANSPORT_UNKNOWN = 0
TRANSPORT_PRE_SEND = 1
TRANSPORT_SEND_STARTED = 2


class ProviderError(Exception):
    kind = "remote_error"
    http_status = 502


class ProviderNotConfigured(ProviderError):
    kind = "not_configured"
    http_status = 503


class ProviderMisconfigured(ProviderError):
    kind = "misconfigured"
    http_status = 503


class ProviderInvalidCredentials(ProviderError):
    kind = "invalid_credentials"
    http_status = 502


class ProviderAccessDenied(ProviderError):
    kind = "access_denied"
    http_status = 502


class ProviderRateLimited(ProviderError):
    kind = "rate_limited"
    http_status = 429


class ProviderTimeout(ProviderError):
    kind = "timeout"
    http_status = 504


class ProviderRemoteError(ProviderError):
    kind = "remote_error"
    http_status = 502


class ProviderPreTransportError(ProviderError):
    kind = "pre_transport_error"
    http_status = 502


class ProviderTransportUnknown(ProviderError):
    """Transport state is unknown; quota is charged without claiming remote receipt."""

    kind = "transport_unknown"
    http_status = 502


class ProviderInvalidResponse(ProviderError):
    kind = "invalid_response"
    http_status = 502


class ProviderSensitiveContent(ProviderError):
    kind = "sensitive_content"
    http_status = 422


class ProviderSensitiveResponse(ProviderError):
    kind = "sensitive_provider_response"
    http_status = 422


@dataclass(frozen=True)
class ProviderRequest:
    system_prompt: str
    user_content: str


@dataclass(frozen=True)
class ProviderSettings:
    provider: str
    api_key: str = field(repr=False)
    model: str
    api_url: str


@dataclass(frozen=True)
class ProviderCompletion:
    content: str
    provider: str
    model: str


class ProviderAdapter(Protocol):
    provider_id: str

    def complete(
        self, request: ProviderRequest, settings: ProviderSettings
    ) -> ProviderCompletion: ...


def ensure_provider_request_is_safe(request: ProviderRequest) -> None:
    if contains_sensitive_content(request.user_content) or contains_sensitive_content(
        request.system_prompt
    ):
        raise ProviderSensitiveContent from None


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        host: str,
        *,
        address: str,
        on_request_send_started: Callable[[], None] | None = None,
        **kwargs,
    ):
        self._address = address
        self._on_request_send_started = on_request_send_started
        super().__init__(host, **kwargs)

    def connect(self):
        sock = socket.create_connection(
            (self._address, self.port),
            self.timeout,
            self.source_address,
        )
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)

    def send(self, data):
        if data and self.sock is None:
            self.connect()
        if data and self._on_request_send_started is not None:
            self._on_request_send_started()
        super().send(data)


class _PinnedHTTPSHandler(HTTPSHandler):
    def __init__(self, address: str):
        super().__init__()
        self._address = address

    def https_open(self, request):
        def connection_class(host, **kwargs):
            return _PinnedHTTPSConnection(
                host,
                address=self._address,
                on_request_send_started=getattr(
                    request,
                    "_aegis_on_request_send_started",
                    None,
                ),
                **kwargs,
            )

        return self.do_open(
            connection_class,
            request,
            context=self._context,
            check_hostname=self._check_hostname,
        )


def resolve_public_address(host: str, port: int) -> str:
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (OSError, http.client.HTTPException, ValueError):
        raise ProviderRemoteError from None
    public_addresses = []
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address[4][0])
        except ValueError:
            raise ProviderMisconfigured from None
        if not ip.is_global:
            raise ProviderMisconfigured
        public_addresses.append(str(ip))
    if not public_addresses:
        raise ProviderMisconfigured
    return public_addresses[0]


def open_request(request: Request, timeout: int, address: str):
    opener = build_opener(
        ProxyHandler({}),
        _RejectRedirects,
        _PinnedHTTPSHandler(address),
    )
    return opener.open(request, timeout=timeout)


def _perform_transport(
    request: Request,
    api_url: str,
    resolve_address,
    open_connection,
    transport_state=None,
) -> bytes:
    if transport_state is not None:
        transport_state.value = TRANSPORT_PRE_SEND
    parsed_url = urlsplit(api_url)
    try:
        address = resolve_address(parsed_url.hostname, parsed_url.port or 443)
    except ProviderMisconfigured:
        raise
    except (ProviderError, OSError, http.client.HTTPException, ValueError, TimeoutError, URLError):
        raise ProviderPreTransportError from None
    request_send_started = False

    def mark_request_send_started() -> None:
        nonlocal request_send_started
        request_send_started = True
        if transport_state is not None:
            transport_state.value = TRANSPORT_SEND_STARTED

    request._aegis_on_request_send_started = mark_request_send_started
    try:
        with open_connection(
            request,
            timeout=PROVIDER_TIMEOUT_SECONDS,
            address=address,
        ) as response:
            raw_response = response.read(MAX_PROVIDER_RESPONSE_BYTES + 1)
    except HTTPError as error:
        if not request_send_started:
            raise ProviderPreTransportError from None
        if error.code == 401:
            raise ProviderInvalidCredentials from None
        if error.code == 403:
            raise ProviderAccessDenied from None
        if error.code == 429:
            raise ProviderRateLimited from None
        raise ProviderRemoteError from None
    except (TimeoutError, URLError) as error:
        if not request_send_started:
            raise ProviderPreTransportError from None
        reason = getattr(error, "reason", None)
        if isinstance(error, TimeoutError) or isinstance(reason, TimeoutError):
            raise ProviderTimeout from None
        raise ProviderRemoteError from None
    except ProviderError:
        if not request_send_started:
            raise ProviderPreTransportError from None
        raise
    except (OSError, http.client.HTTPException, ValueError):
        if not request_send_started:
            raise ProviderPreTransportError from None
        raise ProviderRemoteError from None
    finally:
        delattr(request, "_aegis_on_request_send_started")
    if len(raw_response) > MAX_PROVIDER_RESPONSE_BYTES:
        raise ProviderInvalidResponse
    return raw_response


def _provider_transport_worker(
    connection,
    request: Request,
    api_url: str,
    resolve_address,
    open_connection,
    transport_state=None,
) -> None:
    try:
        response = _perform_transport(
            request,
            api_url,
            resolve_address,
            open_connection,
            transport_state,
        )
    except ProviderError as error:
        connection.send_bytes(b"\x01" + error.kind.encode("ascii"))
    else:
        connection.send_bytes(b"\x00" + response)
    finally:
        connection.close()


def run_bounded_worker(
    worker,
    args: tuple[object, ...],
    timeout: float,
    *,
    transport_state=None,
) -> bytes:
    deadline = time.monotonic() + timeout
    try:
        context = multiprocessing.get_context("spawn")
    except ValueError:
        raise ProviderMisconfigured from None
    receiver = None
    sender = None
    try:
        receiver, sender = context.Pipe(duplex=False)
        process = context.Process(target=worker, args=(sender, *args), daemon=True)
    except Exception:  # noqa: BLE001 - setup fails before transport can start
        if receiver is not None:
            receiver.close()
        if sender is not None:
            sender.close()
        raise ProviderPreTransportError from None
    try:
        process.start()
    except Exception:  # noqa: BLE001 - process startup has not reached HTTP transport
        receiver.close()
        sender.close()
        if getattr(process, "pid", None) is not None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            process.join()
            raise ProviderTransportUnknown from None
        raise ProviderPreTransportError from None
    sender.close()

    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not receiver.poll(remaining):
            raise _transport_state_error(transport_state)
        if time.monotonic() >= deadline:
            raise _transport_state_error(transport_state)
        try:
            result = receiver.recv_bytes(MAX_PROVIDER_RESPONSE_BYTES + 128)
        except (EOFError, OSError):
            error = _transport_state_error(transport_state)
            raise error from None
        process.join(max(0, deadline - time.monotonic()))
        if process.is_alive() or time.monotonic() >= deadline:
            raise _transport_state_error(transport_state)
    except (ProviderTimeout, ProviderPreTransportError, ProviderTransportUnknown):
        try:
            process.kill()
        except ProcessLookupError:
            pass
        process.join()
        raise
    finally:
        receiver.close()

    if not result:
        raise ProviderRemoteError
    if result[0] == 0:
        return result[1:]
    if result[0] != 1:
        raise ProviderRemoteError
    error_kind = result[1:].decode("ascii", errors="ignore")
    errors_by_kind = {
        "invalid_credentials": ProviderInvalidCredentials,
        "access_denied": ProviderAccessDenied,
        "rate_limited": ProviderRateLimited,
        "timeout": ProviderTimeout,
        "remote_error": ProviderRemoteError,
        "pre_transport_error": ProviderPreTransportError,
        "transport_unknown": ProviderTransportUnknown,
        "invalid_response": ProviderInvalidResponse,
        "misconfigured": ProviderMisconfigured,
    }
    error_type = errors_by_kind.get(error_kind)
    if error_type is None:
        raise ProviderRemoteError
    raise error_type


def _transport_state_error(transport_state) -> ProviderError:
    if (
        transport_state is not None
        and transport_state.value == TRANSPORT_PRE_SEND
    ):
        return ProviderPreTransportError()
    return ProviderTransportUnknown()


def send_request(
    request: Request,
    api_url: str,
    *,
    timeout: float = PROVIDER_TIMEOUT_SECONDS,
    resolve_address=resolve_public_address,
    open_connection=open_request,
) -> bytes:
    context = multiprocessing.get_context("spawn")
    transport_state = context.Value("b", TRANSPORT_UNKNOWN)
    return run_bounded_worker(
        _provider_transport_worker,
        (request, api_url, resolve_address, open_connection, transport_state),
        timeout,
        transport_state=transport_state,
    )


def decode_json_response(raw_response: bytes) -> dict[str, object]:
    try:
        response_data = json.loads(raw_response)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProviderInvalidResponse from None
    if not isinstance(response_data, dict):
        raise ProviderInvalidResponse
    return response_data


def validate_model(provider: str, model: str) -> bool:
    return (
        provider in SUPPORTED_MODELS
        and isinstance(model, str)
        and model in SUPPORTED_MODELS[provider]
    )


def validate_openai_url(api_url: str) -> bool:
    try:
        parsed = urlsplit(api_url)
        hostname = parsed.hostname or ""
        valid_url = (
            parsed.scheme == "https"
            and bool(hostname)
            and hostname.isascii()
            and not hostname.endswith(".")
            and hostname.lower() not in {"localhost", "metadata.google.internal"}
            and not hostname.lower().endswith((".localhost", ".local", ".internal"))
            and parsed.username is None
            and parsed.password is None
            and not parsed.fragment
            and not parsed.query
            and len(api_url) <= 2048
            and (parsed.port is None or 1 <= parsed.port <= 65535)
        )
    except ValueError:
        return False
    if not valid_url:
        return False
    try:
        ip_address = ipaddress.ip_address(hostname)
    except ValueError:
        return True
    return ip_address.is_global


def load_settings(provider: str | None = None) -> ProviderSettings:
    selected_provider = provider or os.getenv("AEGIS_AI_PROVIDER", "openai")
    if selected_provider not in {"openai", "gemini", "groq"}:
        raise ProviderMisconfigured
    api_key = os.getenv("AEGIS_AI_API_KEY", "")
    model = os.getenv("AEGIS_AI_MODEL", "")
    if not api_key and not model:
        raise ProviderNotConfigured
    if (
        not api_key
        or not model
        or len(api_key) > 512
        or not api_key.isascii()
        or any(ord(char) < 33 or ord(char) > 126 for char in api_key)
        or not validate_model(selected_provider, model)
    ):
        raise ProviderMisconfigured

    if selected_provider == "openai":
        api_url = os.getenv("AEGIS_AI_API_URL", OPENAI_API_URL)
        if not validate_openai_url(api_url):
            raise ProviderMisconfigured
        provider_id = "openai-compatible"
    elif selected_provider == "gemini":
        api_url = f"{GEMINI_API_URL}/{quote(model, safe='-._~')}:generateContent"
        provider_id = "gemini"
    else:
        api_url = GROQ_API_URL
        provider_id = "groq"
    return ProviderSettings(provider_id, api_key, model, api_url)

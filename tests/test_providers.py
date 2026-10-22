from __future__ import annotations

import io
import json
import os
import socket
import time
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request

import pytest

from app.providers import (
    ProviderSensitiveContent,
    common,
    complete,
    gemini,
    groq,
    openai_compatible,
    provider_status,
)


class SlowFragmentedResponse:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, _size):
        for _ in range(100):
            time.sleep(0.05)
        return b"{}"


def slow_test_resolver(_host, _port):
    time.sleep(5)
    return "8.8.8.8"


def fast_test_resolver(_host, _port):
    return "8.8.8.8"


def failed_test_resolver(_host, _port):
    raise common.ProviderRemoteError


def slow_test_connection(request, *_args, **_kwargs):
    request._aegis_on_request_send_started()
    return SlowFragmentedResponse()


def unexpected_worker_exit(connection, *_args):
    connection.close()
    os._exit(1)


def unexpected_pre_send_exit(connection, transport_state):
    transport_state.value = common.TRANSPORT_PRE_SEND
    connection.close()
    os._exit(1)


def fail_after_send_attempt_connection(request, *_args, **_kwargs):
    request._aegis_on_request_send_started()
    raise OSError("synthetic partial write failure")


def configure_provider(monkeypatch):
    monkeypatch.setenv("AEGIS_AI_PROVIDER", "openai")
    monkeypatch.setenv("AEGIS_AI_API_KEY", "test-key-is-not-a-real-credential")
    monkeypatch.setenv("AEGIS_AI_MODEL", "gpt-4o-2024-08-06")
    monkeypatch.delenv("AEGIS_AI_API_URL", raising=False)
    monkeypatch.setattr(
        openai_compatible,
        "_resolve_public_address",
        lambda _host, _port: "8.8.8.8",
    )
    monkeypatch.setattr(
        openai_compatible,
        "send_request",
        lambda request, api_url, *, resolve_address, open_connection: (
            common._perform_transport(request, api_url, resolve_address, open_connection)
        ),
    )


def configure_mock_transport(monkeypatch, adapter):
    monkeypatch.setattr(
        adapter,
        "send_request",
        lambda request, api_url, *, resolve_address, open_connection: (
            common._perform_transport(request, api_url, resolve_address, open_connection)
        ),
    )


def call_adapter(provider, adapter, *, system_prompt="system", user_content="source"):
    if provider == "openai":
        return adapter.complete(system_prompt=system_prompt, user_content=user_content)
    model = f"{provider}-test"
    settings = common.ProviderSettings(
        provider=provider,
        api_key="synthetic-provider-key",
        model=model,
        api_url=(
            common.GEMINI_API_URL
            if provider == "gemini"
            else common.GROQ_API_URL
        ),
    )
    provider_request = common.ProviderRequest(system_prompt, user_content)
    adapter_class = gemini.GeminiAdapter if provider == "gemini" else groq.GroqAdapter
    return adapter_class().complete(provider_request, settings)


def test_provider_builds_authenticated_request_and_parses_mocked_response(monkeypatch):
    configure_provider(monkeypatch)
    captured = {}
    body = json.dumps(
        {
            "model": "test-model",
            "choices": [{"message": {"content": '{"summary":"ok"}'}}],
        }
    ).encode()

    def simulated_urlopen(request, timeout, address):
        captured["request"] = request
        captured["timeout"] = timeout
        captured["address"] = address
        return io.BytesIO(body)

    monkeypatch.setattr(openai_compatible, "_open_request", simulated_urlopen)
    result = openai_compatible.complete(system_prompt="system", user_content="source")

    assert captured["request"].get_header("Authorization") == (
        "Bearer test-key-is-not-a-real-credential"
    )
    assert captured["timeout"] == openai_compatible.PROVIDER_TIMEOUT_SECONDS
    assert captured["address"] == "8.8.8.8"
    assert json.loads(result.content) == {"summary": "ok"}
    assert result.provider == "openai-compatible"
    assert captured["request"].get_header("Cookie") is None
    assert captured["request"].get_header("X-session-token") is None
    request_body = json.loads(captured["request"].data)
    assert request_body["messages"] == [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "source"},
    ]


def test_provider_boundary_blocks_recognized_sensitive_content(monkeypatch):
    adapter_calls = []
    monkeypatch.setenv("AEGIS_AI_PROVIDER", "openai")
    monkeypatch.setattr(
        openai_compatible.OpenAIAdapter,
        "complete",
        lambda *_args, **_kwargs: adapter_calls.append(True),
    )
    synthetic_secret = "api_key=sk-" + "A" * 24

    with pytest.raises(ProviderSensitiveContent) as error:
        complete(system_prompt="system", user_content=synthetic_secret)

    assert synthetic_secret not in str(error.value)
    assert adapter_calls == []


@pytest.mark.parametrize(
    ("module", "provider"),
    [(gemini, "gemini"), (groq, "groq"), (openai_compatible, "openai")],
)
def test_direct_provider_entrypoints_block_sensitive_content_before_transport(
    monkeypatch, module, provider
):
    transport_calls = []
    settings = common.ProviderSettings(
        provider=provider,
        api_key="synthetic-provider-key",
        model="synthetic-model",
        api_url="https://provider.example.test",
    )
    if module is openai_compatible:
        monkeypatch.setattr(module, "_settings", lambda: settings)
    else:
        monkeypatch.setattr(module, "load_settings", lambda _provider: settings)
    monkeypatch.setattr(
        module,
        "send_request",
        lambda *args, **kwargs: transport_calls.append(True),
    )

    with pytest.raises(ProviderSensitiveContent):
        module.complete(
            system_prompt="system",
            user_content='{"nested":{"password":"synthetic-sensitive-value"}}',
        )

    assert transport_calls == []


def test_provider_reports_missing_and_misconfigured_settings(monkeypatch):
    monkeypatch.delenv("AEGIS_AI_API_KEY", raising=False)
    monkeypatch.delenv("AEGIS_AI_MODEL", raising=False)
    with pytest.raises(openai_compatible.ProviderNotConfigured):
        openai_compatible.complete(system_prompt="system", user_content="source")

    monkeypatch.setenv("AEGIS_AI_API_KEY", "test-key")
    monkeypatch.setenv("AEGIS_AI_MODEL", "gpt-4o-2024-08-06")
    monkeypatch.setenv("AEGIS_AI_API_URL", "http://untrusted.invalid/v1/chat/completions")
    with pytest.raises(openai_compatible.ProviderMisconfigured):
        openai_compatible.complete(system_prompt="system", user_content="source")


@pytest.mark.parametrize(
    ("status", "error_type"),
    [
        (401, openai_compatible.ProviderInvalidCredentials),
        (403, common.ProviderAccessDenied),
        (429, openai_compatible.ProviderRateLimited),
        (500, openai_compatible.ProviderRemoteError),
    ],
)
def test_provider_maps_mocked_http_errors_without_leaking_body(
    monkeypatch, status, error_type
):
    configure_provider(monkeypatch)

    def simulated_urlopen(request, timeout, address):
        request._aegis_on_request_send_started()
        raise HTTPError(
            "https://provider.invalid",
            status,
            "simulated failure",
            {},
            io.BytesIO(b"simulated-secret-provider-response"),
        )

    monkeypatch.setattr(openai_compatible, "_open_request", simulated_urlopen)
    with pytest.raises(error_type) as error:
        openai_compatible.complete(system_prompt="system", user_content="source")
    assert "simulated-secret-provider-response" not in str(error.value)


@pytest.mark.parametrize(
    ("failure", "error_type"),
    [
        (TimeoutError("simulated timeout"), openai_compatible.ProviderTimeout),
        (URLError("simulated offline"), openai_compatible.ProviderRemoteError),
    ],
)
def test_provider_maps_mocked_timeout_and_transport_errors(
    monkeypatch, failure, error_type
):
    configure_provider(monkeypatch)

    def simulated_urlopen(request, timeout, address):
        request._aegis_on_request_send_started()
        raise failure

    monkeypatch.setattr(openai_compatible, "_open_request", simulated_urlopen)
    with pytest.raises(error_type):
        openai_compatible.complete(system_prompt="system", user_content="source")


def test_provider_rejects_malformed_or_oversized_mocked_responses(monkeypatch):
    configure_provider(monkeypatch)
    monkeypatch.setattr(
        openai_compatible,
        "_open_request",
        lambda *_args, **_kwargs: io.BytesIO(b'{"choices":[]}'),
    )
    with pytest.raises(openai_compatible.ProviderInvalidResponse):
        openai_compatible.complete(system_prompt="system", user_content="source")

    monkeypatch.setattr(
        openai_compatible,
        "_open_request",
        lambda *_args, **_kwargs: io.BytesIO(
            b" " * (openai_compatible.MAX_PROVIDER_RESPONSE_BYTES + 1)
        ),
    )
    with pytest.raises(openai_compatible.ProviderInvalidResponse):
        openai_compatible.complete(system_prompt="system", user_content="source")


def test_provider_redirect_handler_refuses_redirects():
    handler = openai_compatible._RejectRedirects()
    assert (
        handler.redirect_request(
            None,
            None,
            302,
            "Found",
            {},
            "https://elsewhere.invalid",
        )
        is None
    )


def test_provider_opener_disables_proxies_and_uses_guard_handlers(monkeypatch):
    captured = {}

    class FakeOpener:
        def open(self, request, *, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return "mock-response"

    def simulated_build_opener(*handlers):
        captured["handlers"] = handlers
        return FakeOpener()

    monkeypatch.setattr(openai_compatible, "build_opener", simulated_build_opener)
    response = openai_compatible._open_request(
        Request("https://provider.example/v1/chat/completions"),
        timeout=3,
        address="8.8.8.8",
    )
    handlers = captured["handlers"]
    proxy_handler = next(handler for handler in handlers if isinstance(handler, ProxyHandler))
    pinned_handler = next(
        handler for handler in handlers if isinstance(handler, openai_compatible._PinnedHTTPSHandler)
    )
    assert response == "mock-response"
    assert proxy_handler.proxies == {}
    assert openai_compatible._RejectRedirects in handlers
    assert pinned_handler._address == "8.8.8.8"
    assert captured["timeout"] == 3


def test_pinned_https_connection_uses_validated_address_and_hostname_tls(monkeypatch):
    connected = {}
    wrapped = {}

    class FakeContext:
        def wrap_socket(self, sock, *, server_hostname):
            wrapped["socket"] = sock
            wrapped["hostname"] = server_hostname
            return "secure-socket"

    monkeypatch.setattr(
        common.socket,
        "create_connection",
        lambda address, timeout, source_address: connected.update(
            address=address,
            timeout=timeout,
            source_address=source_address,
        ) or "raw-socket",
    )
    connection = openai_compatible._PinnedHTTPSConnection(
        "provider.example",
        address="8.8.8.8",
        timeout=7,
    )
    connection._context = FakeContext()
    connection.connect()

    assert connected["address"] == ("8.8.8.8", 443)
    assert connected["timeout"] == 7
    assert wrapped == {"socket": "raw-socket", "hostname": "provider.example"}
    assert connection.sock == "secure-socket"


@pytest.mark.parametrize(
    "url",
    [
        "https://localhost/v1/chat/completions",
        "https://service.internal/v1/chat/completions",
        "https://127.0.0.1/v1/chat/completions",
        "https://169.254.169.254/latest",
    ],
)
def test_provider_rejects_local_or_private_endpoint_urls(monkeypatch, url):
    monkeypatch.setenv("AEGIS_AI_API_KEY", "test-key")
    monkeypatch.setenv("AEGIS_AI_MODEL", "gpt-4o-2024-08-06")
    monkeypatch.setenv("AEGIS_AI_API_URL", url)
    with pytest.raises(openai_compatible.ProviderMisconfigured):
        openai_compatible.complete(system_prompt="system", user_content="source")


@pytest.mark.parametrize("resolved_address", ["127.0.0.1", "10.0.0.8", "169.254.169.254"])
def test_provider_rejects_dns_names_resolving_to_internal_addresses(
    monkeypatch, resolved_address
):
    def simulated_getaddrinfo(*_args, **_kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (resolved_address, 443)),
        ]

    monkeypatch.setattr(common.socket, "getaddrinfo", simulated_getaddrinfo)
    with pytest.raises(openai_compatible.ProviderMisconfigured):
        openai_compatible._resolve_public_address("provider.example", 443)


def test_provider_rejects_dns_name_with_mixed_public_and_internal_addresses(monkeypatch):
    def simulated_getaddrinfo(*_args, **_kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.8", 443)),
        ]

    monkeypatch.setattr(common.socket, "getaddrinfo", simulated_getaddrinfo)
    with pytest.raises(openai_compatible.ProviderMisconfigured):
        openai_compatible._resolve_public_address("provider.example", 443)


@pytest.mark.parametrize(
    ("provider", "adapter", "response_data", "expected_url"),
    [
        (
            "gemini",
            gemini,
            {"candidates": [{"content": {"parts": [{"text": '{"summary":"ok"}'}]}}]},
            "generativelanguage.googleapis.com/v1beta/models/gemini-test:generateContent",
        ),
        (
            "groq",
            groq,
            {
                "model": "groq-test",
                "choices": [{"message": {"content": '{"summary":"ok"}'}}],
            },
            "api.groq.com/openai/v1/chat/completions",
        ),
    ],
)
def test_provider_specific_authentication_and_normalization(
    monkeypatch, provider, adapter, response_data, expected_url
):
    monkeypatch.setenv("AEGIS_AI_PROVIDER", provider)
    monkeypatch.setenv("AEGIS_AI_API_KEY", "synthetic-provider-key")
    monkeypatch.setenv("AEGIS_AI_MODEL", f"{provider}-test")
    captured = {}

    def simulated_request(request, timeout, address):
        captured.update(request=request, timeout=timeout, address=address)
        return io.BytesIO(json.dumps(response_data).encode())

    monkeypatch.setattr(adapter, "_resolve_public_address", lambda *_: "8.8.8.8")
    monkeypatch.setattr(adapter, "_open_request", simulated_request)
    configure_mock_transport(monkeypatch, adapter)
    result = call_adapter(provider, adapter)
    request = captured["request"]
    request_body = json.loads(request.data)

    assert expected_url in request.full_url
    assert captured["timeout"] == common.PROVIDER_TIMEOUT_SECONDS
    assert captured["address"] == "8.8.8.8"
    assert result.content == '{"summary":"ok"}'
    assert result.provider == provider
    assert request.get_header("Cookie") is None
    assert request.get_header("X-session-token") is None
    if provider == "gemini":
        assert request.get_header("X-goog-api-key") == "synthetic-provider-key"
        assert request.get_header("Authorization") is None
        assert request_body["systemInstruction"] == {"parts": [{"text": "system"}]}
        assert request_body["contents"] == [
            {"role": "user", "parts": [{"text": "source"}]},
        ]
        assert request_body["generationConfig"]["responseMimeType"] == "application/json"
    else:
        assert request.get_header("Authorization") == "Bearer synthetic-provider-key"
        assert request.get_header("X-goog-api-key") is None
        assert request_body["messages"] == [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "source"},
        ]
        assert request_body["response_format"] == {"type": "json_object"}


@pytest.mark.parametrize(
    ("provider", "adapter", "response_data"),
    [
        ("gemini", gemini, {"candidates": []}),
        ("groq", groq, {"choices": []}),
    ],
)
def test_provider_adapters_reject_empty_or_malformed_responses(
    monkeypatch, provider, adapter, response_data
):
    monkeypatch.setattr(adapter, "_resolve_public_address", lambda *_: "8.8.8.8")
    monkeypatch.setattr(
        adapter,
        "_open_request",
        lambda *_args, **_kwargs: io.BytesIO(json.dumps(response_data).encode()),
    )
    configure_mock_transport(monkeypatch, adapter)
    with pytest.raises(common.ProviderInvalidResponse):
        call_adapter(provider, adapter)


@pytest.mark.parametrize(
    ("resolver", "connection", "expected_error"),
    [
        (slow_test_resolver, common.open_request, common.ProviderPreTransportError),
        (fast_test_resolver, slow_test_connection, common.ProviderTransportUnknown),
    ],
)
def test_provider_total_deadline_covers_dns_and_fragmented_response(
    resolver, connection, expected_error
):
    request = Request("https://provider.invalid/v1/chat/completions")
    started = time.monotonic()
    context = common.multiprocessing.get_context("spawn")
    transport_state = context.Value("b", common.TRANSPORT_UNKNOWN)
    with pytest.raises(expected_error):
        common.run_bounded_worker(
            common._provider_transport_worker,
            (
                request,
                request.full_url,
                resolver,
                connection,
                transport_state,
            ),
            timeout=1,
            transport_state=transport_state,
        )
    assert time.monotonic() - started < 4


def test_worker_start_failure_is_classified_before_transport(monkeypatch):
    class PipeEnd:
        closed = False

        def close(self):
            self.closed = True

    receiver = PipeEnd()
    sender = PipeEnd()

    class FailedProcess:
        def start(self):
            raise OSError("synthetic worker start failure")

    class Context:
        def Pipe(self, *, duplex):
            assert duplex is False
            return receiver, sender

        def Process(self, **_kwargs):
            return FailedProcess()

    monkeypatch.setattr(common.multiprocessing, "get_context", lambda _method: Context())

    with pytest.raises(common.ProviderPreTransportError):
        common.run_bounded_worker(lambda *_args: None, (), timeout=1)

    assert receiver.closed is True
    assert sender.closed is True


def test_worker_construction_failure_is_classified_before_transport(monkeypatch):
    class PipeEnd:
        closed = False

        def close(self):
            self.closed = True

    receiver = PipeEnd()
    sender = PipeEnd()

    class Context:
        def Pipe(self, *, duplex):
            assert duplex is False
            return receiver, sender

        def Process(self, **_kwargs):
            raise RuntimeError("synthetic process construction failure")

    monkeypatch.setattr(common.multiprocessing, "get_context", lambda _method: Context())

    with pytest.raises(common.ProviderPreTransportError):
        common.run_bounded_worker(lambda *_args: None, (), timeout=1)

    assert receiver.closed is True
    assert sender.closed is True


def test_dns_resolution_failure_is_classified_before_connection_open():
    request = Request("https://provider.example.test/v1")
    connection_attempts = []

    def failed_resolution(*_args):
        raise common.ProviderRemoteError

    def open_connection(*_args, **_kwargs):
        connection_attempts.append(True)

    with pytest.raises(common.ProviderPreTransportError):
        common._perform_transport(
            request,
            request.full_url,
            failed_resolution,
            open_connection,
        )

    assert connection_attempts == []


def test_worker_dns_failure_is_reported_as_pretransport():
    request = Request("https://provider.example.test/v1")
    context = common.multiprocessing.get_context("spawn")
    transport_state = context.Value("b", common.TRANSPORT_UNKNOWN)

    with pytest.raises(common.ProviderPreTransportError):
        common.run_bounded_worker(
            common._provider_transport_worker,
            (
                request,
                request.full_url,
                failed_test_resolver,
                common.open_request,
                transport_state,
            ),
            timeout=3,
            transport_state=transport_state,
        )
    assert transport_state.value == common.TRANSPORT_PRE_SEND


def test_provider_error_after_transport_invocation_remains_remote_error():
    request = Request("https://provider.example.test/v1")
    transport_invoked = []

    def simulated_transport(request, *_args, **_kwargs):
        transport_invoked.append(True)
        request._aegis_on_request_send_started()
        raise common.ProviderRemoteError

    with pytest.raises(common.ProviderRemoteError):
        common._perform_transport(
            request,
            request.full_url,
            lambda *_args: "203.0.113.10",
            simulated_transport,
        )

    assert transport_invoked == [True]


def test_pinned_connection_marks_request_send_after_connection_is_open():
    request_send_started = []

    class FakeSocket:
        def sendall(self, _data):
            return None

    connection = common._PinnedHTTPSConnection(
        "provider.example.test",
        address="203.0.113.10",
        on_request_send_started=lambda: request_send_started.append(True),
    )
    connection.sock = FakeSocket()
    connection.send(b"POST /v1 HTTP/1.1\r\n")

    assert request_send_started == [True]


def test_connection_open_failure_before_request_send_is_pretransport():
    request = Request("https://provider.example.test/v1")

    def fail_before_request_send(*_args, **_kwargs):
        raise OSError("synthetic connection setup failure")

    with pytest.raises(common.ProviderPreTransportError):
        common._perform_transport(
            request,
            request.full_url,
            lambda *_args: "203.0.113.10",
            fail_before_request_send,
        )


def test_worker_unexpected_exit_before_state_report_is_unknown():
    context = common.multiprocessing.get_context("spawn")
    transport_state = context.Value("b", common.TRANSPORT_UNKNOWN)

    with pytest.raises(common.ProviderTransportUnknown):
        common.run_bounded_worker(
            unexpected_worker_exit,
            (transport_state,),
            timeout=3,
            transport_state=transport_state,
        )


def test_worker_unexpected_exit_with_pre_send_state_is_pretransport():
    context = common.multiprocessing.get_context("spawn")
    transport_state = context.Value("b", common.TRANSPORT_UNKNOWN)

    with pytest.raises(common.ProviderPreTransportError):
        common.run_bounded_worker(
            unexpected_pre_send_exit,
            (transport_state,),
            timeout=3,
            transport_state=transport_state,
        )


def test_worker_error_after_send_attempt_is_reported_without_receipt_claim():
    request = Request("https://provider.example.test/v1")

    context = common.multiprocessing.get_context("spawn")
    transport_state = context.Value("b", common.TRANSPORT_UNKNOWN)
    with pytest.raises(common.ProviderRemoteError):
        common.run_bounded_worker(
            common._provider_transport_worker,
            (
                request,
                request.full_url,
                fast_test_resolver,
                fail_after_send_attempt_connection,
                transport_state,
            ),
            timeout=3,
            transport_state=transport_state,
        )
    assert transport_state.value == common.TRANSPORT_SEND_STARTED


@pytest.mark.parametrize(
    ("provider", "adapter", "status", "error_type"),
    [
        ("openai", openai_compatible, 401, common.ProviderInvalidCredentials),
        ("openai", openai_compatible, 403, common.ProviderAccessDenied),
        ("openai", openai_compatible, 429, common.ProviderRateLimited),
        ("openai", openai_compatible, 500, common.ProviderRemoteError),
        ("openai", openai_compatible, 503, common.ProviderRemoteError),
        ("gemini", gemini, 401, common.ProviderInvalidCredentials),
        ("gemini", gemini, 403, common.ProviderAccessDenied),
        ("gemini", gemini, 429, common.ProviderRateLimited),
        ("gemini", gemini, 500, common.ProviderRemoteError),
        ("gemini", gemini, 503, common.ProviderRemoteError),
        ("groq", groq, 401, common.ProviderInvalidCredentials),
        ("groq", groq, 403, common.ProviderAccessDenied),
        ("groq", groq, 429, common.ProviderRateLimited),
        ("groq", groq, 500, common.ProviderRemoteError),
        ("groq", groq, 503, common.ProviderRemoteError),
    ],
)
def test_all_adapters_map_http_errors_without_leaking_body(
    monkeypatch, provider, adapter, status, error_type
):
    monkeypatch.setenv("AEGIS_AI_PROVIDER", provider)
    monkeypatch.setenv("AEGIS_AI_API_KEY", "synthetic-provider-key")
    monkeypatch.setenv(
        "AEGIS_AI_MODEL",
        "gpt-4o-2024-08-06" if provider == "openai" else "llama-3.3-70b-versatile",
    )
    monkeypatch.setattr(adapter, "_resolve_public_address", lambda *_: "8.8.8.8")

    def raise_http_error(request, *_args, **_kwargs):
        request._aegis_on_request_send_started()
        raise HTTPError(
            "https://provider.invalid",
            status,
            "simulated provider error",
            {},
            io.BytesIO(b"synthetic-sensitive-response"),
        )

    monkeypatch.setattr(adapter, "_open_request", raise_http_error)
    configure_mock_transport(monkeypatch, adapter)
    with pytest.raises(error_type) as error:
        call_adapter(provider, adapter)
    assert "synthetic-sensitive-response" not in str(error.value)
    assert "synthetic-provider-key" not in repr(error.value)


@pytest.mark.parametrize(
    ("provider", "adapter"),
    [("openai", openai_compatible), ("gemini", gemini), ("groq", groq)],
)
def test_all_adapters_map_timeouts_and_response_size_limits(
    monkeypatch, provider, adapter
):
    monkeypatch.setenv("AEGIS_AI_PROVIDER", provider)
    monkeypatch.setenv("AEGIS_AI_API_KEY", "synthetic-provider-key")
    monkeypatch.setenv(
        "AEGIS_AI_MODEL",
        "gpt-4o-2024-08-06" if provider == "openai" else "llama-3.3-70b-versatile",
    )
    monkeypatch.setattr(adapter, "_resolve_public_address", lambda *_: "8.8.8.8")

    def raise_timeout(request, *_args, **_kwargs):
        request._aegis_on_request_send_started()
        raise TimeoutError("synthetic timeout")

    monkeypatch.setattr(adapter, "_open_request", raise_timeout)
    configure_mock_transport(monkeypatch, adapter)
    with pytest.raises(common.ProviderTimeout):
        call_adapter(provider, adapter)

    monkeypatch.setattr(
        adapter,
        "_open_request",
        lambda *_args, **_kwargs: io.BytesIO(
            b" " * (common.MAX_PROVIDER_RESPONSE_BYTES + 1)
        ),
    )
    configure_mock_transport(monkeypatch, adapter)
    with pytest.raises(common.ProviderInvalidResponse):
        call_adapter(provider, adapter)


def test_backend_provider_and_model_configuration_is_required_and_validated(monkeypatch):
    monkeypatch.setenv("AEGIS_AI_PROVIDER", "unconfigured-provider")
    monkeypatch.setenv("AEGIS_AI_API_KEY", "synthetic-key")
    monkeypatch.setenv("AEGIS_AI_MODEL", "synthetic-model")
    assert provider_status() == {"status": "misconfigured"}
    with pytest.raises(common.ProviderMisconfigured):
        complete(system_prompt="system", user_content="source")

    monkeypatch.setenv("AEGIS_AI_PROVIDER", "gemini")
    monkeypatch.delenv("AEGIS_AI_MODEL")
    assert provider_status() == {"status": "misconfigured"}
    with pytest.raises(common.ProviderMisconfigured):
        complete(system_prompt="system", user_content="source")

    monkeypatch.delenv("AEGIS_AI_API_KEY")
    assert provider_status() == {"status": "not_configured"}
    with pytest.raises(common.ProviderNotConfigured):
        complete(system_prompt="system", user_content="source")


@pytest.mark.parametrize(
    ("provider", "model"),
    [
        ("openai", "gpt-4o-2024-08-06"),
        ("groq", "llama-3.3-70b-versatile"),
    ],
)
def test_provider_rejects_incomplete_or_unsafe_credentials_before_transport(
    monkeypatch, provider, model
):
    monkeypatch.setenv("AEGIS_AI_PROVIDER", provider)
    monkeypatch.setenv("AEGIS_AI_MODEL", model)
    attempted_requests = []
    monkeypatch.setattr(
        common,
        "run_bounded_worker",
        lambda *_args, **_kwargs: attempted_requests.append(True),
    )

    monkeypatch.delenv("AEGIS_AI_API_KEY", raising=False)
    with pytest.raises(common.ProviderMisconfigured):
        complete(system_prompt="system", user_content="source")

    monkeypatch.setenv("AEGIS_AI_API_KEY", "synthetic-provider-key")
    monkeypatch.delenv("AEGIS_AI_MODEL", raising=False)
    with pytest.raises(common.ProviderMisconfigured):
        complete(system_prompt="system", user_content="source")

    monkeypatch.setenv("AEGIS_AI_MODEL", model)
    monkeypatch.setenv("AEGIS_AI_API_KEY", "synthetic-key\nwith-newline")
    with pytest.raises(common.ProviderMisconfigured):
        complete(system_prompt="system", user_content="source")

    assert attempted_requests == []


@pytest.mark.parametrize("module", [openai_compatible, groq])
def test_bearer_header_uses_configured_key_and_errors_do_not_leak_it(monkeypatch, module):
    key = "synthetic-" + "bearer-credential"
    captured = {}
    adapter = module.OpenAIAdapter if module is openai_compatible else module.GroqAdapter
    settings = common.ProviderSettings("p", key, "m", "https://example.invalid/v1")

    def fake_send(request, _url, *, resolve_address, open_connection):
        captured["auth"] = request.get_header("Authorization")
        return b'{"choices":[{"message":{"content":"{}"}}]}'

    monkeypatch.setattr(module, "send_request", fake_send)
    adapter().complete(common.ProviderRequest("s", "u"), settings)
    assert captured["auth"] == "Bearer " + key

    def failing_send(*_args, **_kwargs):
        raise common.ProviderRemoteError

    monkeypatch.setattr(module, "send_request", failing_send)
    with pytest.raises(common.ProviderRemoteError) as caught:
        adapter().complete(common.ProviderRequest("s", "u"), settings)
    assert key not in str(caught.value) + repr(caught.value)


def test_provider_settings_repr_does_not_include_api_key():
    settings = common.ProviderSettings(
        provider="openai-compatible",
        api_key="synthetic-provider-key",
        model="gpt-4o-2024-08-06",
        api_url=common.OPENAI_API_URL,
    )
    assert "synthetic-provider-key" not in repr(settings)


@pytest.mark.parametrize(
    ("provider", "model", "expected_url"),
    [
        (
            "openai",
            "gpt-4o-2024-08-06",
            "https://api.openai.com/v1/chat/completions",
        ),
        (
            "groq",
            "llama-3.3-70b-versatile",
            common.GROQ_API_URL,
        ),
    ],
)
def test_explicitly_supported_models_are_provider_scoped(
    monkeypatch, provider, model, expected_url
):
    monkeypatch.setenv("AEGIS_AI_PROVIDER", provider)
    monkeypatch.setenv("AEGIS_AI_API_KEY", "synthetic-key")
    monkeypatch.setenv("AEGIS_AI_MODEL", model)
    settings = common.load_settings()
    assert settings.model == model
    assert settings.api_url == expected_url
    assert common.validate_model(provider, model)


@pytest.mark.parametrize(
    ("provider", "model"),
    [
        ("openai", "unknown-openai-model"),
        ("gemini", "gemini-2.5-flash"),
        ("groq", "unknown-groq-model"),
    ],
)
def test_unverified_models_are_rejected_before_transport(
    monkeypatch, provider, model
):
    monkeypatch.setenv("AEGIS_AI_PROVIDER", provider)
    monkeypatch.setenv("AEGIS_AI_API_KEY", "synthetic-key")
    monkeypatch.setenv("AEGIS_AI_MODEL", model)
    attempted_requests = []
    monkeypatch.setattr(
        common,
        "run_bounded_worker",
        lambda *_args, **_kwargs: attempted_requests.append(True),
    )
    assert not common.validate_model(provider, model)
    with pytest.raises(common.ProviderMisconfigured):
        complete(system_prompt="system", user_content="source")
    assert attempted_requests == []


@pytest.mark.parametrize(
    ("provider", "model"),
    [
        ("openai", "llama-3.3-70b-versatile"),
        ("groq", "gpt-4o-2024-08-06"),
        ("gemini", "gemini-2.5-flash"),
    ],
)
def test_models_cannot_be_reused_across_provider_allowlists(
    monkeypatch, provider, model
):
    monkeypatch.setenv("AEGIS_AI_PROVIDER", provider)
    monkeypatch.setenv("AEGIS_AI_API_KEY", "synthetic-key")
    monkeypatch.setenv("AEGIS_AI_MODEL", model)
    with pytest.raises(common.ProviderMisconfigured):
        common.load_settings()


def test_model_allowlists_reject_gemini_until_generate_content_compatibility_is_verified(
    monkeypatch,
):
    monkeypatch.setenv("AEGIS_AI_PROVIDER", "gemini")
    monkeypatch.setenv("AEGIS_AI_API_KEY", "synthetic-key")
    monkeypatch.setenv("AEGIS_AI_MODEL", "gemini-2.5-flash")
    assert common.SUPPORTED_MODELS["gemini"] == frozenset()
    with pytest.raises(common.ProviderMisconfigured):
        common.load_settings()

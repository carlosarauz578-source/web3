from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path


class DashboardParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids: list[str] = []
        self.forms: set[str] = set()

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if "id" in attributes:
            self.ids.append(attributes["id"])
        if tag == "form" and "id" in attributes:
            self.forms.add(attributes["id"])


def dashboard_source() -> str:
    return (Path(__file__).parents[1] / "app" / "index.html").read_text(encoding="utf-8")


def test_dashboard_has_conversation_controls_and_unique_dom_ids():
    source = dashboard_source()
    parser = DashboardParser()
    parser.feed(source)

    assert len(parser.ids) == len(set(parser.ids))
    assert {
        "conversation-create-form",
        "conversation-project",
        "conversation-specialty",
        "conversation-list",
        "conversation-message-form",
        "conversation-message-input",
        "conversation-messages",
        "conversation-load-older",
        "conversation-status",
        "ai-review-checkbox",
        "usage-period",
        "usage-items",
        "agent-project",
        "agent-network",
        "blockchain-agent-submit",
        "agent-run-status",
        "stellar-message",
    }.issubset(set(parser.ids))
    assert {
        "conversation-create-form",
        "conversation-message-form",
    }.issubset(parser.forms)


def test_dashboard_uses_conversation_api_and_handles_access_errors():
    source = dashboard_source()
    script = source.split("<script>", 1)[1].split("</script>", 1)[0]

    assert 'api("/api/conversations?limit=100")' in script
    assert 'api("/api/conversations", {' in script
    assert "/messages?${query}" in script
    assert "`/api/conversations/${encodeURIComponent(conversationId)}/messages`" in script
    assert "error.status === 401" in script
    assert "error.status === 403" in script
    assert "error.status === 404" in script
    assert "error.status === 429" in script
    assert 'credentials: "same-origin"' in script
    assert 'api("/api/usage")' in script
    assert 'api("/api/blockchains/stellar/status")' in script
    assert 'method: "POST"' in script
    assert 'task_type: "blockchain_health"' in script
    assert 'api("/api/agent-runs"' in script


def test_dashboard_renders_messages_as_text_and_does_not_fake_agent_replies():
    source = dashboard_source()
    script = source.split("<script>", 1)[1].split("</script>", 1)[0]

    assert "content.textContent = item.content" in script
    assert ".innerHTML" not in script
    assert "localStorage" not in script
    assert "sessionStorage" not in script
    assert "No se ha generado una respuesta de IA." in script
    assert "assistant-message" in script
    assert "request_ai_review: requestAiReview" in script
    assert "client_message_id: pendingConversationSubmission.id" in script
    assert "pendiente de validación" in script
    assert "conversationBusy" in script
    assert "conversationCreating" in script


def test_dashboard_clears_private_state_and_waits_for_account_data_before_display():
    script = dashboard_source().split("<script>", 1)[1].split("</script>", 1)[0]
    show_auth = script.split("function showAuth", 1)[1].split("async function showApp", 1)[0]
    show_app = script.split("async function showApp", 1)[1].split("async function loadProjects", 1)[0]

    assert "sessionGeneration += 1" in show_auth
    assert "clearPrivateDashboard();" in show_auth
    assert '$("history").replaceChildren();' in script
    assert '$("technical-report").textContent = "";' in script
    assert '$("agent-run-result").textContent = "";' in script
    assert "await Promise.all([" in show_app
    assert show_app.index("await Promise.all([") < show_app.index(
        '$("app-view").classList.remove("hidden")'
    )
    assert "generation !== sessionGeneration || !currentUser" in show_app


def test_dashboard_warns_when_sensitive_evidence_is_preserved():
    script = dashboard_source().split("<script>", 1)[1].split("</script>", 1)[0]

    assert "El resultado coincide con patrones de contenido sensible." in script
    assert "result.sensitive_content_detected" in script
    assert "item.sensitive_content_detected" in script

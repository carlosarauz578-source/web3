from __future__ import annotations

import json
import os
from urllib.request import Request

from app.connectors.common import validate_public_https_url
from app.providers.common import ProviderError, send_request

STELLAR_RPC_TIMEOUT_SECONDS = 5
MAX_LEDGER = 2**63 - 1


def stellar_status() -> dict[str, object]:
    endpoint = os.getenv("AEGIS_STELLAR_RPC_URL", "")
    if not endpoint:
        return {"network": "stellar", "status": "not_configured"}
    if not validate_public_https_url(endpoint):
        return {
            "network": "stellar",
            "status": "failed",
            "error": "RPC endpoint must be a valid public HTTPS URL.",
        }

    request = Request(
        endpoint,
        data=json.dumps({"jsonrpc": "2.0", "method": "getHealth", "id": 1}).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        response = json.loads(
            send_request(request, endpoint, timeout=STELLAR_RPC_TIMEOUT_SECONDS)
        )
    except ProviderError as error:
        return {"network": "stellar", "status": "failed", "error": error.kind}
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return {"network": "stellar", "status": "failed", "error": "invalid_response"}

    result = response.get("result") if isinstance(response, dict) else None
    if (
        not isinstance(response, dict)
        or response.get("jsonrpc") != "2.0"
        or type(response.get("id")) is not int
        or response.get("id") != 1
        or response.get("error") is not None
        or not isinstance(result, dict)
        or result.get("status") != "healthy"
        or type(result.get("latestLedger")) is not int
        or type(result.get("oldestLedger")) is not int
        or not 1 <= result["oldestLedger"] <= result["latestLedger"] <= MAX_LEDGER
    ):
        return {"network": "stellar", "status": "failed", "error": "invalid_response"}

    return {
        "network": "stellar",
        "status": "connected",
        "verification": "endpoint_health_only",
        "latest_ledger": result["latestLedger"],
        "oldest_ledger": result["oldestLedger"],
    }

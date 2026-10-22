from __future__ import annotations

import json
import os
from urllib.request import Request

from app.connectors.common import validate_public_https_url
from app.providers.common import ProviderError, send_request

KNOWN_CHAIN_IDS = {
    "ethereum": 1,
    "base": 8453,
    "arbitrum": 42161,
    "optimism": 10,
    "polygon": 137,
    "avalanche": 43114,
}


def evm_status(network: str) -> dict[str, object]:
    try:
        configured = json.loads(os.getenv("AEGIS_EVM_RPC_URLS", "{}"))
    except json.JSONDecodeError:
        return {"network": network, "status": "failed", "error": "Invalid RPC configuration JSON."}
    if not isinstance(configured, dict):
        return {"network": network, "status": "failed", "error": "RPC configuration must be an object."}
    endpoint = configured.get(network)
    if not isinstance(endpoint, str) or not endpoint:
        return {"network": network, "status": "not_configured"}
    if not validate_public_https_url(endpoint):
        return {"network": network, "status": "failed", "error": "RPC endpoint must be a valid public HTTPS URL."}

    payload = json.dumps({"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1}).encode()
    request = Request(endpoint, data=payload, headers={"Content-Type": "application/json"})
    try:
        raw_response = send_request(request, endpoint, timeout=5)
        result = json.loads(raw_response)
        if (
            not isinstance(result, dict)
            or result.get("jsonrpc") != "2.0"
            or type(result.get("id")) is not int
            or result.get("id") != 1
            or result.get("error") is not None
        ):
            return {"network": network, "status": "failed", "error": "RPC returned an invalid JSON-RPC response."}
        chain_id = result.get("result")
        if (
            not isinstance(chain_id, str)
            or len(chain_id) < 3
            or not chain_id.startswith("0x")
            or any(character not in "0123456789abcdefABCDEF" for character in chain_id[2:])
        ):
            return {"network": network, "status": "failed", "error": "RPC returned an invalid chain ID."}
        actual_chain_id = int(chain_id, 16)
        expected_chain_id = KNOWN_CHAIN_IDS.get(network.lower())
        if expected_chain_id is not None and actual_chain_id != expected_chain_id:
            return {
                "network": network,
                "status": "chain_mismatch",
                "expected_chain_id": expected_chain_id,
                "chain_id": actual_chain_id,
            }
        if expected_chain_id is None:
            return {
                "network": network,
                "status": "chain_unverified",
                "chain_id": actual_chain_id,
            }
        return {"network": network, "status": "connected", "chain_id": actual_chain_id}
    except ProviderError as error:
        return {"network": network, "status": "failed", "error": error.kind}
    except (TimeoutError, ValueError, OSError):
        return {"network": network, "status": "failed", "error": "invalid_response"}

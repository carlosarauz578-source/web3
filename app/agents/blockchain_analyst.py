from __future__ import annotations

from datetime import UTC, datetime

from app.connectors.evm import evm_status
from app.connectors.stellar import stellar_status

SUPPORTED_NETWORKS = frozenset({
    "ethereum",
    "base",
    "arbitrum",
    "optimism",
    "polygon",
    "avalanche",
    "stellar",
})


def analyze_network_health(network: str) -> dict[str, object]:
    if network not in SUPPORTED_NETWORKS:
        return {
            "agent": "blockchain_analyst",
            "status": "inconclusive",
            "network": network,
            "error": "network_not_supported",
            "observed_at": datetime.now(UTC).isoformat(),
            "limitations": ["Only explicitly registered read-only network checks are supported."],
        }

    observation = stellar_status() if network == "stellar" else evm_status(network)
    connected = observation.get("status") == "connected"
    fully_checked = connected and (
        network == "stellar"
        or observation.get("chain_id") is not None
    )
    return {
        "agent": "blockchain_analyst",
        "status": "completed" if fully_checked else "inconclusive",
        "network": network,
        "observed_at": datetime.now(UTC).isoformat(),
        "source": "operator_configured_read_only_rpc",
        "observation": observation,
        "limitations": [
            "Only endpoint health or EVM chain ID was queried; no account, contract, transaction, or event data was analyzed.",
            "A connected endpoint is not an independent proof of chain state.",
        ],
    }

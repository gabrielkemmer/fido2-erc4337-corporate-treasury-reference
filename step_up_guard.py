"""
Reference implementation of Defense-in-Depth Step-Up Authorization
and Deterministic Integer-Cent Auto-Vault Routing for Corporate Treasury Systems.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional
import hmac
import hashlib
import time


@dataclass(frozen=True)
class VaultRule:
    vault_id: str
    name: str
    allocation_bps: int  # Basis points (100 bps = 1.00%, 10_000 bps = 100.00%)
    asset_target: str    # e.g., "USDT", "PAXG", "USDY"


class DeterministicVaultRouter:
    """
    Routes incoming settlement amounts across corporate sub-vaults using
    integer basis points (BPS) to guarantee zero floating-point rounding drift.
    """

    def __init__(self, rules: List[VaultRule]):
        total_bps = sum(r.allocation_bps for r in rules)
        if total_bps > 10_000:
            raise ValueError(f"Total vault allocation ({total_bps} bps) cannot exceed 10,000 bps (100%).")
        for r in rules:
            if r.allocation_bps < 0:
                raise ValueError("Allocation basis points must be non-negative.")
        self.rules = rules

    def partition_settlement_cents(self, net_amount_cents: int) -> Dict[str, int]:
        if net_amount_cents <= 0:
            raise ValueError("Settlement amount must be positive.")

        allocations: Dict[str, int] = {}
        allocated_sum = 0

        for rule in self.rules:
            share = (net_amount_cents * rule.allocation_bps) // 10_000
            allocations[rule.vault_id] = share
            allocated_sum += share

        # Remainder stays in primary operating treasury
        allocations["primary_operating_treasury"] = net_amount_cents - allocated_sum
        return allocations


class StepUpAuthVerifier:
    """
    Verifies short-lived cryptographic step-up tokens bound to a specific
    high-risk treasury operation (e.g., batch PIX execution, card PAN reveal).
    """

    def __init__(self, signing_key: bytes, allowed_rp_ids: List[str], max_age_seconds: int = 120):
        self.signing_key = signing_key
        self.allowed_rp_ids = set(allowed_rp_ids)
        self.max_age_seconds = max_age_seconds

    def resolve_rp_id(self, request_host: str) -> str:
        host = (request_host or "").split(":")[0].strip().lower()
        if host in self.allowed_rp_ids:
            return host
        raise PermissionError(f"Unrecognized Relying Party host: {host}")

    def verify_step_up_challenge(
        self,
        user_id: str,
        operation_scope: str,
        timestamp_sec: int,
        provided_signature: str,
        now_sec: Optional[int] = None,
    ) -> bool:
        now = now_sec if now_sec is not None else int(time.time())
        if abs(now - timestamp_sec) > self.max_age_seconds:
            return False

        payload = f"{user_id}:{operation_scope}:{timestamp_sec}".encode("utf-8")
        expected_sig = hmac.new(self.signing_key, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected_sig, provided_signature)

"""v2 central-policy stub. v1 policy is local YAML only.

Reserved flow (see docs/ARCHITECTURE.md): fetch signed policy from
`central.policy_url`, verify with `central.verify_key`, compare `version`,
install atomically, keep last-known-good. Nothing here executes in v1.
"""


def check_for_update(cfg):
    """Return None in v1 (no central server configured/implemented)."""
    return None

GHOST_KEYWORDS = ("test", "temp", "demo", "dev", "old", "backup", "unknown")


def _calculate_ghost_confidence(identity: dict) -> float:
    """
    Returns a 0.0 - 1.0 confidence score estimating how likely
    an identity is orphaned/abandoned ('ghost').
    """
    name = str(identity.get("name", "")).lower()
    id_type = str(identity.get("identity_type", "")).upper()

    # Ephemeral Vault tokens are managed and auto-expire, not ghosts
    if "vault-token-" in name or identity.get("is_dynamic"):
        return 0.0

    confidence = 0.0

    # 1. Inactivity signal
    days_inactive = identity.get("days_inactive", 0)
    if days_inactive > 90:
        confidence += 0.40
    elif days_inactive > 30:
        confidence += 0.20

    # 2. Age / staleness signal (if provided by scanner)
    age_days = identity.get("age_days", 0)
    if age_days > 180:
        confidence += 0.25
    elif age_days > 90:
        confidence += 0.15

    # 3. Missing ownership / test-account naming signal
    if any(kw in name for kw in GHOST_KEYWORDS):
        confidence += 0.25
    if not identity.get("owner"):
        confidence += 0.10

    # Leaked Git secrets without a tracked owner are high-risk orphans
    if id_type == "EXPOSED_GIT_SECRET":
        confidence = max(confidence, 0.50)

    return min(confidence, 1.0)


def _is_correlated_leak(identity: dict, all_identities: list) -> bool:
    """
    Checks if an active cloud credential's ID appears in any
    EXPOSED_GIT_SECRET finding across the scan.
    """
    if not all_identities:
        return False

    target_id = str(identity.get("id", ""))
    if not target_id or identity.get("identity_type") == "EXPOSED_GIT_SECRET":
        return False

    for other in all_identities:
        if other.get("identity_type") == "EXPOSED_GIT_SECRET":
            if target_id in str(other.get("id", "")) or target_id in str(other.get("name", "")):
                return True
    return False


def calculate_risk(identity: dict, all_identities: list = None) -> float:
    """
    Context-aware risk scoring combining privilege, staleness,
    cross-source correlation, dynamic token discounts, and ghost confidence.
    """
    base_score = 10.0
    name = str(identity.get("name", "")).lower()
    id_type = str(identity.get("identity_type", "")).upper()

    # 1. Privilege multiplier
    if identity.get("has_admin_privileges"):
        base_score += 40.0

    # 2. Activity & Staleness tracking
    days_inactive = identity.get("days_inactive", 0)
    if days_inactive > 90:
        base_score += 30.0
    elif days_inactive > 30:
        base_score += 15.0

    age_days = identity.get("age_days", 0)
    if age_days > 180:
        base_score += 15.0
    elif age_days > 90:
        base_score += 10.0

    # 3. Credential type & Dynamic Vault discount
    if "vault-token-" in name or identity.get("is_dynamic"):
        base_score -= 10.0  # Short-lived dynamic credentials carry lower risk
    elif id_type == "AWS_ACCESS_KEY":
        base_score += 5.0
    elif id_type == "EXPOSED_GIT_SECRET":
        base_score += 35.0  # Exposed secrets in code should never sit at 10.0

    # 4. Identity Correlation (Live cloud key matched to a Git leak)
    if _is_correlated_leak(identity, all_identities):
        identity["correlated_leak"] = True
        base_score += 40.0
    else:
        identity["correlated_leak"] = False

    # 5. Ghost-Confidence Scoring (adds up to +20.0 points)
    ghost_conf = _calculate_ghost_confidence(identity)
    identity["ghost_confidence"] = round(ghost_conf * 100, 1)
    base_score += ghost_conf * 20.0

    # Clamp between 5.0 and 100.0
    return round(max(5.0, min(base_score, 100.0)), 1)
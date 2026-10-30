def calculate_risk(identity: dict) -> float:
    base_score = 10.0
    
    # Privilege multiplier
    if identity.get("has_admin_privileges"):
        base_score += 40.0
        
    # Inactivity penalty (escalates after 30 days)
    days_inactive = identity.get("days_inactive", 0)
    if days_inactive > 90:
        base_score += 40.0
    elif days_inactive > 30:
        base_score += 20.0
        
    # Type penalty
    if identity.get("identity_type") == "AWS_ACCESS_KEY":
        base_score += 5.0
        
    # Cap maximum score at 100
    return min(base_score, 100.0)
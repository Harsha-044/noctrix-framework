from pydantic import BaseModel
from typing import List

class NonHumanIdentity(BaseModel):
    id: str
    name: str
    identity_type: str
    days_inactive: int
    has_admin_privileges: bool
    ghost_confidence: float = 0.0
    correlated_leak: bool = False
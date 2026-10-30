from pydantic import BaseModel
from typing import List

class NonHumanIdentity(BaseModel):
    id: str
    name: str
    identity_type: str
    days_inactive: int
    has_admin_privileges: bool
    risk_score: float = 0.0
    policies: List[str] = []
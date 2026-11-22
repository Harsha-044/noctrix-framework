from neo4j import GraphDatabase


class GraphLoader:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def ingest_identities(self, identities):
        with self.driver.session() as session:
            for ident in identities:
                session.run(
                    """
                    MERGE (i:Identity {id: $id})
                    SET i.name = $name,
                        i.type = $type,
                        i.daysInactive = $days_inactive,
                        i.riskScore = $risk_score,
                        i.isAdmin = $has_admin,
                        i.ghostConfidence = $ghost_confidence,
                        i.correlatedLeak = $correlated_leak
                    """,
                    id=ident.get("id", "unknown_id"),
                    name=ident.get("name", "Unknown"),
                    type=ident.get("identity_type", "Unknown"),
                    days_inactive=ident.get("days_inactive", 0),
                    risk_score=ident.get("risk_score", 0.0),
                    has_admin=ident.get("has_admin_privileges", False),
                    ghost_confidence=ident.get("ghost_confidence", 0.0),
                    correlated_leak=ident.get("correlated_leak", False),
                )

                for policy in ident.get("policies", []):
                    session.run(
                        """
                        MATCH (i:Identity {id: $id})
                        MERGE (p:Policy {name: $policy_name})
                        MERGE (i)-[:HAS_POLICY]->(p)
                        """,
                        id=ident.get("id"),
                        policy_name=policy,
                    )

    def ingest_attack_paths(self, identities, buckets):
        with self.driver.session() as session:
            # 1. Ingest S3 and GCS Resources
            for b in buckets:
                b_type = b.get(
                    "type",
                    "GCS_BUCKET" if b.get("provider") == "GCP" else "S3_BUCKET",
                )
                b_id = b.get("id") or b.get("name", "unknown_bucket")
                session.run(
                    """
                    MERGE (r:Resource {id: $id})
                    SET r.name = $name,
                        r.type = $type,
                        r.isPublic = $is_public
                    """,
                    id=b_id,
                    name=b.get("name", "Unknown Bucket"),
                    type=b_type,
                    is_public=b.get("is_public", False),
                )

            # 2. Build Paths: Identity -> Policy -> Resource (for AWS Admins)
            for ident in identities:
                if ident.get("has_admin_privileges"):
                    session.run(
                        """
                        MATCH (p:Policy {name: 'AdministratorAccess'})
                        MATCH (r:Resource {type: 'S3_BUCKET'})
                        MERGE (p)-[:CAN_ACCESS]->(r)
                        """
                    )
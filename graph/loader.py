from neo4j import GraphDatabase

class GraphLoader:
    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def ingest_identities(self, identities):
        with self.driver.session() as session:
            for ident in identities:
                # 1. Merge the Identity node
                session.run(
                    """
                    MERGE (i:Identity {id: $id})
                    SET i.name = $name,
                        i.type = $type,
                        i.daysInactive = $days_inactive,
                        i.riskScore = $risk_score,
                        i.isAdmin = $has_admin
                    """,
                    id=ident['id'], name=ident['name'], 
                    type=ident['identity_type'], 
                    days_inactive=ident['days_inactive'], 
                    risk_score=ident['risk_score'],
                    has_admin=ident['has_admin_privileges']
                )
                
                # 2. Merge the Policy/File node and create the relationship
                for policy in ident.get("policies", []):
                    session.run("""
                        MATCH (i:Identity {id: $id})
                        MERGE (p:Policy {name: $policy_name})
                        MERGE (i)-[:HAS_POLICY]->(p)
                    """, id=ident["id"], policy_name=policy)

    def ingest_attack_paths(self, identities, buckets):
        with self.driver.session() as session:
            # 1. Ingest S3 Resources
            for b in buckets:
                session.run(
                    "MERGE (r:Resource {id: $id}) SET r.name = $name, r.type = $type",
                    id=b['id'], name=b['name'], type=b['type']
                )

            # 2. Build Paths: Identity -> Policy -> Resource (for AWS Admins)
            for ident in identities:
                if ident.get('has_admin_privileges'):
                    session.run("""
                        MATCH (p:Policy {name: 'AdministratorAccess'})
                        MATCH (r:Resource {type: 'S3_BUCKET'})
                        MERGE (p)-[:CAN_ACCESS]->(r)
                    """)
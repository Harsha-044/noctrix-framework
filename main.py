from scanners.aws_iam import scan_aws_keys, scan_s3_buckets
from scanners.git_scanner import scan_git_secrets 
from scanners.gcp_scanner import scan_gcp_identities
from core.schema import NonHumanIdentity
from core.risk_engine import calculate_risk
from graph.loader import GraphLoader
from remediation.aws_remediator import AWSRemediator
from rotation.vault_manager import VaultManager

def main():
    print("[*] Phase 1: Discovery")
    raw_keys = scan_aws_keys()
    buckets = scan_s3_buckets()
    git_secrets = scan_git_secrets("app/prototype/data/sample_repository/")
    gcp_identities = scan_gcp_identities()
    
    # Azure scanner removed for project freeze
    all_raw_identities = raw_keys + git_secrets + gcp_identities
    
    print(f"[*] Phase 2: Risk Analysis for {len(all_raw_identities)} identities...")
     
    remediator = AWSRemediator(slack_webhook_url="https://hooks.slack.com/services/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")
    vault = VaultManager()
    scored_identities = []
    
    for key in all_raw_identities:
        key["risk_score"] = calculate_risk(key)
        print(f"  -> Debug: {key.get('name', 'Unknown')} | Type: {key.get('identity_type')} | Score: {key['risk_score']}")
        
        if key["risk_score"] >= 50 and "AWS" in str(key.get("identity_type", "")).upper():
            if key["id"] == "AKIAVY6LN7VREXJ4FADF":
                print(f"[i] SAFELIST: Bypassing remediation for Vault root key {key['id']}")
            else:
                username = key.get("username", "noctrix-admin")
                is_disabled = remediator.disable_exposed_key(key["id"], username)
                
                if is_disabled:
                    new_access, new_secret = vault.rotate_aws_credentials()
                    if new_access:
                        print(f"[+] SUCCESS: Handed off new temporary credentials (Key: {new_access}) to the pipeline.")
            
        scored_identities.append(NonHumanIdentity(**key).model_dump())

    print("[*] Phase 3: Graph Ingestion & Attack Path Mapping")
    loader = GraphLoader("bolt://127.0.0.1:7687", "neo4j", "your_password")
    loader.ingest_identities(scored_identities)
    loader.ingest_attack_paths(scored_identities, buckets)
    loader.close()
    print("[+] Pipeline complete. Return to the Neo4j browser!")

if __name__ == "__main__":
    main()
from googleapiclient.discovery import build
import google.auth
from datetime import datetime

def scan_gcp_identities():
    """
    Authenticates to GCP using Application Default Credentials (ADC),
    retrieves Service Accounts and their keys, and maps them to NOCTRIX.
    """
    identities = []
    try:
        # Pulls local credentials from 'gcloud auth application-default login'
        credentials, project_id = google.auth.default()
        service = build('iam', 'v1', credentials=credentials)
        
        # In a real environment, you would iterate over all projects. 
        # For the prototype, we use the default authenticated project.
        if not project_id:
            print("[!] GCP Scanner: No default project found. Skipping.")
            return identities
            
        request = service.projects().serviceAccounts().list(name=f"projects/{project_id}")
        response = request.execute()
        accounts = response.get('accounts', [])
        
        for sa in accounts:
            sa_email = sa.get('email')
            # Fetch keys for each service account
            key_req = service.projects().serviceAccounts().keys().list(
                name=f"projects/{project_id}/serviceAccounts/{sa_email}"
            )
            key_res = key_req.execute()
            
            for key in key_res.get('keys', []):
                # Ignore Google-managed keys
                if key.get('keyType') == 'SYSTEM_MANAGED':
                    continue
                    
                identities.append({
                    "id": key.get('name').split('/')[-1], # Extract key ID
                    "name": sa.get('displayName', sa_email),
                    "identity_type": "GCP_SA_KEY",
                    "has_admin_privileges": False, # Updated to match Pydantic model
                    "days_inactive": 0, # GCP requires Cloud Logging for usage tracking
                    "risk_score": 15.0
                })
                
        print(f"[+] GCP Scanner: Successfully mapped {len(identities)} user-managed SA Keys.")
        
    except Exception as e:
        print(f"[!] GCP Scanner Error: {e}")
        
    return identities
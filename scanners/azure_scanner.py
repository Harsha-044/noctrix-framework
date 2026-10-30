import requests
from datetime import datetime, timezone
from azure.identity import DefaultAzureCredential

def scan_azure_identities():
    """
    Authenticates to Azure, retrieves Service Principals via Graph API,
    and maps them to the NOCTRIX NonHumanIdentity schema.
    """
    identities = []
    try:
        # Automatically handles local Azure CLI, Env Vars, or Managed Identities
        credential = DefaultAzureCredential()
        token = credential.get_token("https://graph.microsoft.com/.default").token
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        
        # Fetch Service Principals
        url = "https://graph.microsoft.com/v1.0/servicePrincipals"
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        sp_data = response.json().get("value", [])
        
        for sp in sp_data:
            # Parse creation date to establish baseline age/inactivity
            created_str = sp.get("createdDateTime", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
            created_date = datetime.strptime(created_str[:19], "%Y-%m-%dT%H:%M:%S")
            days_active = (datetime.now() - created_date).days
            
            identities.append({
                "id": sp.get("appId", "UNKNOWN_APP_ID"),
                "name": sp.get("displayName", "Unnamed_SP"),
                "identity_type": "AZURE_SP",
                "is_admin": False, # Requires secondary role assignment query
                "days_inactive": days_active, 
                "risk_score": 15.0 # Base score before main NOCTRIX engine evaluation
            })
            
        print(f"[+] Azure Scanner: Successfully mapped {len(identities)} Service Principals.")
        
    except Exception as e:
        print(f"[!] Azure Scanner Error: Ensure you are logged in via 'az login'. Details: {e}")
        
    return identities
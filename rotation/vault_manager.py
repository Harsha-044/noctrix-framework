import hvac

class VaultManager:
    def __init__(self, vault_url="http://127.0.0.1:8200", token="dev-root-token"):
        self.client = hvac.Client(url=vault_url, token=token)

    def rotate_aws_credentials(self, role_name="noctrix-admin-role"):
        print(f"[*] ROTATION TRIGGERED: Requesting new short-lived AWS credentials from Vault for '{role_name}'...")
        try:
            if not self.client.is_authenticated():
                print("[-] Vault authentication failed.")
                return None, None
                
            # Request dynamic AWS credentials
            response = self.client.secrets.aws.generate_credentials(name=role_name)
            access_key = response['data']['access_key']
            secret_key = response['data']['secret_key']
            
            print("[+] Successfully generated dynamic AWS credentials via Vault.")
            return access_key, secret_key
        except Exception as e:
            print(f"[-] Vault rotation failed: {e}")
            return None, None

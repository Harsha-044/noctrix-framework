import boto3
from datetime import datetime, timezone

# Initialize AWS clients
iam = boto3.client('iam')
s3 = boto3.client('s3') 

def scan_s3_buckets():
    print("[*] Scanning for S3 Buckets...")
    try:
        buckets = [{"id": b['Name'], "name": b['Name'], "type": "S3_BUCKET"} for b in s3.list_buckets().get('Buckets', [])]
        print(f"[+] Successfully retrieved {len(buckets)} S3 buckets.")
        return buckets
    except Exception as e:
        print(f"[-] S3 Connection Error: {e}")
        return []

def scan_aws_keys():
    print("[+] Connecting to live AWS IAM environment...")
    live_identities = []

    try:
        users = iam.list_users()['Users']
        for user in users:
            username = user['UserName']
            keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']

            # Check for admin privileges via group membership or attached policies
            is_admin = False
            
            # 1. Check Groups
            groups = iam.list_groups_for_user(UserName=username)['Groups']
            if any('admin' in g['GroupName'].lower() for g in groups):
                is_admin = True
                
            # 2. Check Directly Attached Policies
            policies = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
            if any(p['PolicyName'] == 'AdministratorAccess' for p in policies):
                is_admin = True
            
            # Extract policy names for graph mapping
            attached_policy_names = [p['PolicyName'] for p in policies]

            for key in keys:
                last_used = iam.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                last_used_date = last_used['AccessKeyLastUsed'].get('LastUsedDate')

                if last_used_date:
                    days_inactive = (datetime.now(timezone.utc) - last_used_date).days
                else:
                    days_inactive = (datetime.now(timezone.utc) - key['CreateDate']).days

                live_identities.append({
                    "id": key['AccessKeyId'],
                    "name": username,
                    "identity_type": "AWS_ACCESS_KEY",
                    "days_inactive": days_inactive,
                    "has_admin_privileges": is_admin,
                    "policies": attached_policy_names # Capture the policy names
                })
        print(f"[+] Successfully retrieved {len(live_identities)} live keys.")
    except Exception as e:
        print(f"[-] AWS Connection Error: {e}")

    return live_identities
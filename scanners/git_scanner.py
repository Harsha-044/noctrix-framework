import subprocess
import json

def scan_git_secrets(repo_path):
    print(f"[*] Running TruffleHog against {repo_path}...")
    identities = []
    try:
        # Switched from 'git' to 'filesystem' to scan raw directories directly
        cmd = ["trufflehog", "filesystem", repo_path, "--json", "--no-verification", "--no-update"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        for line in result.stdout.strip().split('\n'):
            if not line: continue
            try:
                finding = json.loads(line)
                identities.append({
                    "id": finding.get('Raw', 'N/A')[:15] + "...", 
                    "name": f"Leaked {finding.get('DetectorName', 'Secret')}",
                    "identity_type": "EXPOSED_GIT_SECRET",
                    "days_inactive": 0,
                    "has_admin_privileges": False,
                    "policies": [finding.get('RawFile', finding.get('File', 'Unknown File'))]
                })
            except json.JSONDecodeError:
                continue
                
        print(f"[+] Retrieved {len(identities)} exposed secrets from filesystem.")
    except Exception as e:
        print(f"[-] TruffleHog Error: {e}")
    return identities
import boto3
import json
import urllib.request
from botocore.exceptions import ClientError

class AWSRemediator:
    def __init__(self, slack_webhook_url=None):
        self.iam_client = boto3.client('iam')
        self.slack_webhook_url = slack_webhook_url

    def send_slack_alert(self, message):
        if not self.slack_webhook_url:
            return
        data = json.dumps({"text": message}).encode('utf-8')
        req = urllib.request.Request(self.slack_webhook_url, data=data, headers={'Content-Type': 'application/json'})
        try:
            urllib.request.urlopen(req)
        except Exception as e:
            print(f"[-] Failed to send Slack alert: {e}")

    def disable_exposed_key(self, access_key_id, username):
        print(f"[*] REMEDIATION TRIGGERED: Disabling compromised AWS key {access_key_id} for user {username}...")
        try:
            self.iam_client.update_access_key(
                UserName=username,
                AccessKeyId=access_key_id,
                Status='Inactive'
            )
            success_msg = f"[+] Successfully disabled key {access_key_id}. Risk mitigated."
            print(success_msg)
            
            # Send the alert to Slack
            self.send_slack_alert(f"🚨 *NOCTRIX REMEDIATION*: AWS Access Key `{access_key_id}` for user `{username}` was automatically disabled due to critical risk exposure.")
            return True
            
        except ClientError as e:
            print(f"[-] Remediation failed for {access_key_id}: {e}")
            return False
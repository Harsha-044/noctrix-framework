# NOCTRIX L1 SOC Triage & Remediation Runbook

## Alert Classification Matrix
| Risk Score | Severity | MITRE ATT&CK Mapping | Automated Action | L1 SLA |
| :--- | :--- | :--- | :--- | :--- |
| **75–100** | Critical | T1552.001 / T1078.004 | Key Disabled + Vault Rotation + Slack Alert | 15 mins |
| **50–74** | High | T1078.004 | Key Disabled (unless safelisted) + Slack Alert | 1 hour |
| **25–49** | Medium | T1098 | Logged to Neo4j + Flagged in Dashboard | 24 hours |
| **0–24** | Low | N/A (Dynamic Vault Tokens) | Informational | Weekly Review |

## L1 Triage Procedure
1. **Verify Alert:** Review the Slack notification and open the NOCTRIX Streamlit Dashboard (`http://localhost:8501`).
2. **Assess Blast Radius:** Locate the identity in the **Interactive Attack Path Explorer** to confirm whether it reaches sensitive S3 or GCS buckets.
3. **Validate Remediation:** Confirm the static key status is `Inactive` in AWS IAM and that a replacement `vault-token-*` credential was issued by HashiCorp Vault.
4. **Escalate to L2:** Escalate immediately if CloudTrail or GCP Audit Logs show `GetObject`, `CreateUser`, or `AttachUserPolicy` activity from the compromised key prior to revocation.

from googleapiclient.discovery import build
import google.auth

HIGH_PRIV_ROLES = {
    "roles/owner",
    "roles/editor",
    "roles/iam.serviceAccountKeyAdmin",
    "roles/iam.securityAdmin",
    "roles/resourcemanager.projectIamAdmin",
}


def _get_sa_role_map(credentials, project_id):
    """Fetches project IAM policy and maps serviceAccount emails to their roles."""
    role_map = {}
    try:
        crm_service = build("cloudresourcemanager", "v1", credentials=credentials)
        policy = crm_service.projects().getIamPolicy(
            resource=project_id, body={}
        ).execute()

        for binding in policy.get("bindings", []):
            role = binding.get("role", "")
            for member in binding.get("members", []):
                if member.startswith("serviceAccount:"):
                    sa_email = member.split("serviceAccount:", 1)[1]
                    role_map.setdefault(sa_email, []).append(role)
    except Exception as e:
        print(f"[!] GCP IAM Policy Check Warning: {e}")

    return role_map


def scan_gcp_identities():
    """
    Authenticates to GCP using ADC, retrieves Service Accounts, their keys,
    and project-level IAM role bindings, and maps them to NOCTRIX.
    """
    identities = []
    try:
        credentials, project_id = google.auth.default()
        if not project_id:
            print("[!] GCP Scanner: No default project found. Skipping.")
            return identities

        iam_service = build("iam", "v1", credentials=credentials)
        sa_role_map = _get_sa_role_map(credentials, project_id)

        request = iam_service.projects().serviceAccounts().list(
            name=f"projects/{project_id}"
        )
        response = request.execute()
        accounts = response.get("accounts", [])

        for sa in accounts:
            sa_email = sa.get("email")
            roles = sa_role_map.get(sa_email, [])
            is_admin = any(
                r in HIGH_PRIV_ROLES or r.lower().endswith("admin")
                for r in roles
            )

            key_req = iam_service.projects().serviceAccounts().keys().list(
                name=f"projects/{project_id}/serviceAccounts/{sa_email}"
            )
            key_res = key_req.execute()

            for key in key_res.get("keys", []):
                if key.get("keyType") == "SYSTEM_MANAGED":
                    continue

                identities.append({
                    "id": key.get("name").split("/")[-1],
                    "name": sa.get("displayName", sa_email),
                    "identity_type": "GCP_SA_KEY",
                    "has_admin_privileges": is_admin,
                    "days_inactive": 0,
                    "risk_score": 15.0,
                })

        print(f"[+] GCP Scanner: Successfully mapped {len(identities)} user-managed SA Keys.")

    except Exception as e:
        print(f"[!] GCP Scanner Error: {e}")

    return identities


def scan_gcp_buckets():
    """
    Lists GCS buckets in the default project and flags any with public IAM bindings
    (allUsers or allAuthenticatedUsers).
    """
    buckets = []
    try:
        credentials, project_id = google.auth.default()
        if not project_id:
            return buckets

        storage_service = build("storage", "v1", credentials=credentials)
        response = storage_service.buckets().list(project=project_id).execute()

        for bucket in response.get("items", []):
            bucket_name = bucket.get("name")
            is_public = False

            try:
                policy = storage_service.buckets().getIamPolicy(
                    bucket=bucket_name
                ).execute()
                for binding in policy.get("bindings", []):
                    members = binding.get("members", [])
                    if "allUsers" in members or "allAuthenticatedUsers" in members:
                        is_public = True
                        break
            except Exception as e:
                print(f"[!] Could not read IAM policy for GCS bucket '{bucket_name}': {e}")

            buckets.append({
                "name": bucket_name,
                "is_public": is_public,
                "provider": "GCP",
            })

        print(f"[+] GCP Scanner: Successfully retrieved {len(buckets)} GCS buckets.")

    except Exception as e:
        print(f"[!] GCP Bucket Scanner Error: {e}")

    return buckets
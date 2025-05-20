#!/usr/bin/env python3

import argparse
import json
import requests

PERMISSIONS_TO_TEST = [
    "cloudbuild.builds.create",
    "deploymentmanager.deployments.create",
    "iam.roles.update",
    "iam.serviceAccounts.getAccessToken",
    "iam.serviceAccountKeys.create",
    "iam.serviceAccounts.implicitDelegation",
    "iam.serviceAccounts.signBlob",
    "iam.serviceAccounts.signJwt",
    "cloudfunctions.functions.create",
    "cloudfunctions.functions.update",
    "compute.instances.create",
    "run.services.create",
    "cloudscheduler.jobs.create",
    "orgpolicy.policy.set",
    "storage.hmacKeys.create",
    "serviceusage.apiKeys.create",
    "serviceusage.apiKeys.list",
]

def test_permissions(project_id, access_token):
    url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}:testIamPermissions"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    body = {
        "permissions": PERMISSIONS_TO_TEST
    }

    response = requests.post(url, headers=headers, data=json.dumps(body))
    
    if response.status_code != 200:
        print(f"[!] Failed to test permissions: {response.status_code}")
        print(response.text)
        return

    result = response.json()
    granted = set(result.get("permissions", []))
    
    print(f"\n[+] Permissions granted in project '{project_id}':\n")
    for perm in PERMISSIONS_TO_TEST:
        status = "✅ ALLOWED" if perm in granted else "❌ DENIED"
        print(f"{perm:45} {status}")

def main():
    parser = argparse.ArgumentParser(description="Brute-force check GCP permissions with an access token.")
    parser.add_argument("-p", "--project-id", required=True, help="GCP project ID to test against.")
    parser.add_argument("-t", "--token", help="OAuth 2.0 access token to use for authentication.")
    args = parser.parse_args()

    access_token = args.token
    if not access_token:
        access_token = input("Enter access token: ").strip()

    test_permissions(args.project_id, access_token)

if __name__ == "__main__":
    main()

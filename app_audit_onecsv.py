#!/usr/bin/env python3
"""
Delegated Device Code Export (1 CSV)

1 row per App Registration, with:
- ALL /applications top-level fields as columns
- Related data embedded as JSON string columns:
    owners_json
    federatedIdentityCredentials_json
    servicePrincipal_json
    oauth2PermissionGrants_json
    appRoleAssignments_json
    appRoleAssignedTo_json

Auth:
- Delegated (Public Client) via Device Code using MSAL
- No client secret required

Outputs:
- app_audit_onefile.csv
- app_audit_onefile.json (raw bundle, useful for debugging)

Note:
- If your account lacks permissions for some endpoints, those columns may be empty.
"""

import os
import csv
import json
import time
import requests
import msal
from typing import Any, Dict, List, Optional

GRAPH_ROOT = "https://graph.microsoft.com/v1.0"

TENANT_ID = "2b30530b-69b6-4457-b818-481cb53d42ae"
CLIENT_ID = "f725edc3-46e0-46b8-acbe-ab8f23700507"

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"

   # Delegated scopes (what YOU consent to during device login)
SCOPES = [
    "User.Read",
    "Application.Read.All",
    "Directory.Read.All",
]

RELATED_JSON_COLUMNS = [
    "owners_json",
    "federatedIdentityCredentials_json",
    "servicePrincipal_json",
    "oauth2PermissionGrants_json",
    "appRoleAssignments_json",
    "appRoleAssignedTo_json",
]


# -------------------- Auth (Device Code) --------------------

def get_access_token_device_code(cache_path: str = ".msal_cache.bin") -> str:
    cache = msal.SerializableTokenCache()
    if os.path.exists(cache_path):
        cache.deserialize(open(cache_path, "r", encoding="utf-8").read())

    app = msal.PublicClientApplication(
        client_id=CLIENT_ID,
        authority=AUTHORITY,
        token_cache=cache
    )

    # Try silent first (so you don't have to login every run)
    accounts = app.get_accounts()
    if accounts:
        result = app.acquire_token_silent(SCOPES, account=accounts[0])
        if result and "access_token" in result:
            return result["access_token"]

    # Otherwise do device code flow
    flow = app.initiate_device_flow(scopes=SCOPES)
    if "message" not in flow:
        raise RuntimeError(f"Device flow init failed: {flow}")
    print(flow["message"])

    result = app.acquire_token_by_device_flow(flow)
    if "access_token" not in result:
        raise RuntimeError(f"Authentication failed: {result}")

    # Save cache
    if cache.has_state_changed:
        with open(cache_path, "w", encoding="utf-8") as f:
            f.write(cache.serialize())

    return result["access_token"]


# -------------------- Graph Helpers --------------------

def safe_json(resp: requests.Response) -> Any:
    try:
        return resp.json()
    except Exception:
        return resp.text


def graph_request(url: str, token: str, max_retries: int = 7) -> Dict[str, Any]:
    headers = {"Authorization": f"Bearer {token}"}

    for attempt in range(max_retries):
        r = requests.get(url, headers=headers, timeout=90)

        if r.status_code in (429, 500, 502, 503, 504):
            retry_after = int(r.headers.get("Retry-After", "2"))
            time.sleep(max(2, retry_after) * (attempt + 1))
            continue

        # Best-effort: don't die on endpoints your account can't access
        if r.status_code in (401, 403, 404):
            return {"_error": {"status": r.status_code, "body": safe_json(r), "url": url}}

        r.raise_for_status()
        return r.json()

    return {"_error": {"status": "retry_exceeded", "url": url}}


def graph_get_all(url: str, token: str) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    while url:
        payload = graph_request(url, token)
        if "_error" in payload:
            return []
        items.extend(payload.get("value", []))
        url = payload.get("@odata.nextLink")
    return items


def pick_first(items: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    return items[0] if items else None


# -------------------- CSV Helpers --------------------

def json_stringify(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False)
    return str(v)


# -------------------- Main --------------------

def main():
    token = get_access_token_device_code()

    # Pull ALL applications (full objects, no $select)
    apps = graph_get_all(f"{GRAPH_ROOT}/applications?$top=999", token)
    print(f"Pulled applications: {len(apps)}")

    if not apps:
        print("No apps returned. If you expected apps, your account may not have read access.")
        return

    # Union of all top-level /applications keys -> CSV columns
    app_keys = set()
    for a in apps:
        app_keys.update(a.keys())

    rows: List[Dict[str, Any]] = []
    raw_bundle: List[Dict[str, Any]] = []

    for i, app in enumerate(apps, start=1):
        app_obj_id = app.get("id")
        app_appid = app.get("appId")
        dn = app.get("displayName") or "(no displayName)"
        print(f"[{i}/{len(apps)}] {dn}")

        # owners
        owners = graph_get_all(f"{GRAPH_ROOT}/applications/{app_obj_id}/owners?$top=999", token)

        # federated identity creds (may 403/404 depending on tenant)
        fic_payload = graph_request(
            f"{GRAPH_ROOT}/applications/{app_obj_id}/federatedIdentityCredentials?$top=999",
            token
        )
        fics = fic_payload.get("value", []) if "_error" not in fic_payload else []

        # service principal (enterprise app)
        sps = graph_get_all(
            f"{GRAPH_ROOT}/servicePrincipals?$filter=appId eq '{app_appid}'&$top=50",
            token
        )
        sp = pick_first(sps)

        oauth2_grants: List[Dict[str, Any]] = []
        app_role_assignments: List[Dict[str, Any]] = []
        app_role_assigned_to: List[Dict[str, Any]] = []

        if sp and sp.get("id"):
            sp_id = sp["id"]

            oauth2_grants = graph_get_all(
                f"{GRAPH_ROOT}/oauth2PermissionGrants?$filter=clientId eq '{sp_id}'&$top=999",
                token
            )

            app_role_assignments = graph_get_all(
                f"{GRAPH_ROOT}/servicePrincipals/{sp_id}/appRoleAssignments?$top=999",
                token
            )

            app_role_assigned_to = graph_get_all(
                f"{GRAPH_ROOT}/servicePrincipals/{sp_id}/appRoleAssignedTo?$top=999",
                token
            )

        # Build 1 row per app: all app fields + JSON columns
        row: Dict[str, Any] = {k: app.get(k) for k in app_keys}
        row["owners_json"] = owners
        row["federatedIdentityCredentials_json"] = fics
        row["servicePrincipal_json"] = sp
        row["oauth2PermissionGrants_json"] = oauth2_grants
        row["appRoleAssignments_json"] = app_role_assignments
        row["appRoleAssignedTo_json"] = app_role_assigned_to

        rows.append(row)

        raw_bundle.append({
            "application": app,
            "owners": owners,
            "federatedIdentityCredentials": fics,
            "servicePrincipal": sp,
            "oauth2PermissionGrants": oauth2_grants,
            "appRoleAssignments": app_role_assignments,
            "appRoleAssignedTo": app_role_assigned_to,
        })

    # Write CSV
    fieldnames = sorted(app_keys) + RELATED_JSON_COLUMNS
    with open("app_audit_onefile.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            out = {k: json_stringify(r.get(k)) for k in fieldnames}
            w.writerow(out)

    # Write raw JSON (debug / backup)
    with open("app_audit_onefile.json", "w", encoding="utf-8") as f:
        json.dump(raw_bundle, f, indent=2, ensure_ascii=False)

    print("\n Done.")
    print("Created:")
    print(" - app_audit_onefile.csv")
    print(" - app_audit_onefile.json")


if __name__ == "__main__":
    main()

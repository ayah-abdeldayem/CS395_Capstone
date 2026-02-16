#!/usr/bin/env python3
"""
Export Entra App Registrations using an existing Graph Explorer access token.

Auth:
- Reads a Bearer token from graph_token.txt (Graph Explorer token)

Exports:
- ONE CSV: app_audit_onefile.csv (1 row per app)
  - all /applications top-level fields become columns
  - related datasets stored in JSON-string columns:
      owners_json
      federatedIdentityCredentials_json
      servicePrincipal_json
      oauth2PermissionGrants_json
      appRoleAssignments_json
      appRoleAssignedTo_json
      errors_json
- Backup JSON: app_audit_onefile.json

Notes:
- This is best-effort. If token lacks perms for certain endpoints, those sections will be empty
  and details will appear in errors_json.
"""

import csv
import json
import time
import requests
from typing import Any, Dict, List, Optional

GRAPH_ROOT = "https://graph.microsoft.com/v1.0"

RELATED_JSON_COLUMNS = [
    "owners_json",
    "federatedIdentityCredentials_json",
    "servicePrincipal_json",
    "oauth2PermissionGrants_json",
    "appRoleAssignments_json",
    "appRoleAssignedTo_json",
    "errors_json",
]


def read_token(path: str = "graph_token.txt") -> str:
    with open(path, "r", encoding="utf-8") as f:
        tok = f.read().strip()
    if not tok or not tok.startswith("eyJ"):
        raise SystemExit(
            f"Token file {path} doesn't look right.\n"
            "Paste your Graph Explorer access token into graph_token.txt (starts with eyJ...)."
        )
    return tok


def json_stringify(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False)
    return str(v)


def safe_json(resp: requests.Response) -> Any:
    try:
        return resp.json()
    except Exception:
        return resp.text


def graph_request(url: str, headers: Dict[str, str], max_retries: int = 7) -> Dict[str, Any]:
    for attempt in range(max_retries):
        r = requests.get(url, headers=headers, timeout=90)

        if r.status_code in (429, 500, 502, 503, 504):
            retry_after = int(r.headers.get("Retry-After", "2"))
            time.sleep(max(2, retry_after) * (attempt + 1))
            continue

        # Return error payload, don't crash
        if r.status_code in (400, 401, 403, 404):
            return {"_error": {"status": r.status_code, "body": safe_json(r), "url": url}}

        r.raise_for_status()
        return r.json()

    return {"_error": {"status": "retry_exceeded", "url": url}}


def graph_get_all(url: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    while url:
        payload = graph_request(url, headers)
        if "_error" in payload:
            return []
        items.extend(payload.get("value", []))
        url = payload.get("@odata.nextLink")
    return items


def pick_first(items: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    return items[0] if items else None


def main():
    token = read_token("graph_token.txt")
    headers = {"Authorization": f"Bearer {token}"}

    # Pull ALL applications (full objects, no $select)
    apps = graph_get_all(f"{GRAPH_ROOT}/applications?$top=999", headers)
    print(f"Pulled applications: {len(apps)}")

    if not apps:
        print("No apps returned. Your token might not include Application.Read.All, or it's expired.")
        return

    # Union of all top-level keys for columns
    app_keys = set()
    for a in apps:
        app_keys.update(a.keys())

    rows: List[Dict[str, Any]] = []
    bundle: List[Dict[str, Any]] = []

    for i, app in enumerate(apps, start=1):
        app_obj_id = app.get("id")
        app_appid = app.get("appId")
        dn = app.get("displayName") or "(no displayName)"
        print(f"[{i}/{len(apps)}] {dn}")

        errors: List[Dict[str, Any]] = []

        # owners
        owners = graph_get_all(f"{GRAPH_ROOT}/applications/{app_obj_id}/owners?$top=999", headers)

        # federated identity credentials (may 403/404)
        fic_payload = graph_request(
            f"{GRAPH_ROOT}/applications/{app_obj_id}/federatedIdentityCredentials?$top=999",
            headers
        )
        fics = []
        if "_error" in fic_payload:
            errors.append({"federatedIdentityCredentials": fic_payload["_error"]})
        else:
            fics = fic_payload.get("value", [])

        # service principal (enterprise app)
        sps = graph_get_all(
            f"{GRAPH_ROOT}/servicePrincipals?$filter=appId eq '{app_appid}'&$top=50",
            headers
        )
        sp = pick_first(sps)

        oauth2_grants: List[Dict[str, Any]] = []
        app_role_assignments: List[Dict[str, Any]] = []
        app_role_assigned_to: List[Dict[str, Any]] = []

        if sp and sp.get("id"):
            sp_id = sp["id"]

            # Delegated permission grants
            grants_payload = graph_request(
                f"{GRAPH_ROOT}/oauth2PermissionGrants?$filter=clientId eq '{sp_id}'&$top=999",
                headers
            )
            if "_error" in grants_payload:
                errors.append({"oauth2PermissionGrants": grants_payload["_error"]})
            else:
                oauth2_grants = grants_payload.get("value", [])

            # Roles this SP has
            ara_payload = graph_request(
                f"{GRAPH_ROOT}/servicePrincipals/{sp_id}/appRoleAssignments?$top=999",
                headers
            )
            if "_error" in ara_payload:
                errors.append({"appRoleAssignments": ara_payload["_error"]})
            else:
                app_role_assignments = ara_payload.get("value", [])

            # Roles this SP granted to others
            arat_payload = graph_request(
                f"{GRAPH_ROOT}/servicePrincipals/{sp_id}/appRoleAssignedTo?$top=999",
                headers
            )
            if "_error" in arat_payload:
                errors.append({"appRoleAssignedTo": arat_payload["_error"]})
            else:
                app_role_assigned_to = arat_payload.get("value", [])

        # Build one row per app
        row: Dict[str, Any] = {k: app.get(k) for k in app_keys}
        row["owners_json"] = owners
        row["federatedIdentityCredentials_json"] = fics
        row["servicePrincipal_json"] = sp
        row["oauth2PermissionGrants_json"] = oauth2_grants
        row["appRoleAssignments_json"] = app_role_assignments
        row["appRoleAssignedTo_json"] = app_role_assigned_to
        row["errors_json"] = errors

        rows.append(row)

        bundle.append({
            "application": app,
            "owners": owners,
            "federatedIdentityCredentials": fics,
            "servicePrincipal": sp,
            "oauth2PermissionGrants": oauth2_grants,
            "appRoleAssignments": app_role_assignments,
            "appRoleAssignedTo": app_role_assigned_to,
            "errors": errors,
        })

    # Write CSV
    fieldnames = sorted(app_keys) + RELATED_JSON_COLUMNS
    with open("app_audit_onefile.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            out = {k: json_stringify(r.get(k)) for k in fieldnames}
            w.writerow(out)

    # Write JSON backup
    with open("app_audit_onefile.json", "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2, ensure_ascii=False)

    print("\n Done.")
    print("Created:")
    print(" - app_audit_onefile.csv")
    print(" - app_audit_onefile.json")
    print("\nIf some related fields are empty, check errors_json for 403/401 details.")


if __name__ == "__main__":
    main()

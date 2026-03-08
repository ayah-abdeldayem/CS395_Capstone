import logging
import os
import json
import time
import random
import requests
import azure.functions as func
from datetime import datetime, timezone

from azure.identity import DefaultAzureCredential
from azure.monitor.ingestion import LogsIngestionClient

app = func.FunctionApp()

GRAPH_RESOURCE_APP_ID = "00000003-0000-0000-c000-000000000000"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"
DEBUG_APP_NAME = "Copilot API Key Guide (Microsoft Copilot Studio)"

GRAPH_TIMEOUT = int(os.environ.get("GRAPH_TIMEOUT", "30"))
MAX_RETRIES = int(os.environ.get("GRAPH_MAX_RETRIES", "6"))


def parse_dt(s: str | None):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def upload_to_dcr(records: list[dict]) -> None:
    endpoint = os.environ["DATA_COLLECTION_ENDPOINT"]
    rule_id = os.environ["LOGS_DCR_RULE_ID"]
    stream_name = os.environ["LOGS_DCR_STREAM_NAME"]

    credential = DefaultAzureCredential()
    client = LogsIngestionClient(endpoint=endpoint, credential=credential)

    chunk_size = 200
    total = len(records)

    for i in range(0, total, chunk_size):
        chunk = records[i:i + chunk_size]
        client.upload(rule_id=rule_id, stream_name=stream_name, logs=chunk)
        logging.info(f"DCR upload progress: {min(i + chunk_size, total)}/{total}")


def graph_request_json(session: requests.Session, url: str, headers: dict) -> dict:
    for attempt in range(1, MAX_RETRIES + 1):
        r = session.get(url, headers=headers, timeout=GRAPH_TIMEOUT)

        if r.status_code == 200:
            return r.json()

        if r.status_code == 429:
            retry_after = r.headers.get("Retry-After")
            sleep_s = int(retry_after) if (retry_after and retry_after.isdigit()) else min(2 ** attempt, 30)
            sleep_s += random.uniform(0, 0.5)
            logging.warning(f"Graph throttled (429). Sleeping {sleep_s:.1f}s before retry...")
            time.sleep(sleep_s)
            continue

        if r.status_code in (500, 502, 503, 504):
            sleep_s = min(2 ** attempt, 30) + random.uniform(0, 0.5)
            logging.warning(f"Graph transient error ({r.status_code}). Sleeping {sleep_s:.1f}s before retry...")
            time.sleep(sleep_s)
            continue

        raise RuntimeError(f"Graph error {r.status_code} for {url}: {r.text}")

    raise RuntimeError(f"Graph request failed after retries for {url}")


def graph_get_paged(session: requests.Session, url: str, headers: dict) -> list[dict]:
    out: list[dict] = []

    while url:
        data = graph_request_json(session, url, headers)
        out.extend(data.get("value", []))
        url = data.get("@odata.nextLink")

    return out


def get_application_description(session: requests.Session, app_object_id: str, headers: dict) -> str | None:
    if not app_object_id:
        return None

    url = f"{GRAPH_BASE}/applications/{app_object_id}?$select=description"

    try:
        data = graph_request_json(session, url, headers)
        return data.get("description")
    except Exception as e:
        logging.warning(f"Description lookup failed for {app_object_id}: {e}")
        return None


def try_get_service_principals_with_owners(session: requests.Session, headers: dict) -> list[dict] | None:
    url = (
        f"{GRAPH_BASE}/servicePrincipals"
        "?$top=999"
        "&$select=id,appId,displayName,appRoles,oauth2PermissionScopes"
        "&$expand=owners($select=id,displayName,userPrincipalName)"
    )

    try:
        logging.info("Trying servicePrincipals with expanded owners...")
        return graph_get_paged(session, url, headers)
    except Exception as e:
        logging.warning(f"$expand owners on servicePrincipals not usable: {e}")
        return None


def build_sp_maps(session: requests.Session, headers: dict) -> tuple[dict[str, list[dict]], dict[str, dict]]:
    owner_map: dict[str, list[dict]] = {}
    perm_map: dict[str, dict] = {}

    sp_with_owners = try_get_service_principals_with_owners(session, headers)

    if sp_with_owners is not None:
        for sp in sp_with_owners:
            app_id = sp.get("appId")
            if not app_id:
                continue

            owner_map[app_id] = sp.get("owners") or []
            perm_map[app_id] = {
                "appRoles": sp.get("appRoles") or [],
                "oauth2PermissionScopes": sp.get("oauth2PermissionScopes") or []
            }

        logging.info(f"Built owner map for {len(owner_map)} appIds")
        logging.info(f"Built permission map for {len(perm_map)} resource apps")
        return owner_map, perm_map

    sp_url = (
        f"{GRAPH_BASE}/servicePrincipals"
        "?$top=999"
        "&$select=id,appId,displayName,appRoles,oauth2PermissionScopes"
    )
    sps = graph_get_paged(session, sp_url, headers)

    logging.info(f"Fallback path: retrieved {len(sps)} service principals")

    for idx, sp in enumerate(sps, start=1):
        sp_id = sp.get("id")
        app_id = sp.get("appId")

        if not sp_id or not app_id:
            continue

        perm_map[app_id] = {
            "appRoles": sp.get("appRoles") or [],
            "oauth2PermissionScopes": sp.get("oauth2PermissionScopes") or []
        }

        owners_url = (
            f"{GRAPH_BASE}/servicePrincipals/{sp_id}/owners"
            "?$select=id,displayName,userPrincipalName"
            "&$top=999"
        )

        try:
            owners = graph_get_paged(session, owners_url, headers)
        except Exception as e:
            logging.warning(f"SP owners lookup failed for {sp_id}: {e}")
            owners = []

        owner_map[app_id] = owners

        if idx % 200 == 0:
            logging.info(f"Built SP maps for {idx}/{len(sps)} service principals...")

    return owner_map, perm_map


def resolve_permission(resource_app_id: str, permission_id: str, perm_type: str, perm_map: dict[str, dict]) -> tuple[str | None, str | None]:
    api_def = perm_map.get(resource_app_id)
    if not api_def:
        return None, None

    if perm_type == "Role":
        for role in api_def.get("appRoles", []):
            if str(role.get("id")) == str(permission_id):
                return role.get("value"), role.get("displayName")

    if perm_type == "Scope":
        for scope in api_def.get("oauth2PermissionScopes", []):
            if str(scope.get("id")) == str(permission_id):
                return scope.get("value"), scope.get("adminConsentDisplayName") or scope.get("userConsentDisplayName")

    return None, None


@app.timer_trigger(schedule="0 0 2 1 * *", arg_name="mytimer", run_on_startup=False)
def app_registration_audit(mytimer: func.TimerRequest) -> None:
    logging.info("Starting App Registration Audit")

    tenant_id = os.environ.get("TENANT_ID")
    client_id = os.environ.get("CLIENT_ID")
    client_secret = os.environ.get("CLIENT_SECRET")
    subscription_id = os.environ.get("SUBSCRIPTION_ID", "")

    if not all([tenant_id, client_id, client_secret]):
        logging.error("Missing TENANT_ID, CLIENT_ID, or CLIENT_SECRET")
        return

    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    token_data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    }

    try:
        token_response = requests.post(token_url, data=token_data, timeout=GRAPH_TIMEOUT)
        token_response.raise_for_status()
        access_token = token_response.json().get("access_token")
        if not access_token:
            logging.error("Token response missing access_token")
            return
        logging.info("Access token acquired successfully")
    except Exception as e:
        logging.error(f"Token request failed: {e}")
        return

    headers = {"Authorization": f"Bearer {access_token}"}
    session = requests.Session()

    apps_url = (
        f"{GRAPH_BASE}/applications"
        "?$top=999"
        "&$select=id,appId,displayName,description,publisherDomain,signInAudience,createdDateTime,passwordCredentials,keyCredentials,requiredResourceAccess"
    )

    try:
        all_apps = graph_get_paged(session, apps_url, headers)
    except Exception as e:
        logging.error(f"Applications pull failed: {e}")
        return

    logging.info(f"Total applications retrieved: {len(all_apps)}")

    try:
        sp_owner_map, perm_map = build_sp_maps(session, headers)
    except Exception as e:
        logging.error(f"Service principal map build failed: {e}")
        return

    now_dt = datetime.now(timezone.utc)
    records: list[dict] = []

    for idx, a in enumerate(all_apps, start=1):
        if idx % 100 == 0:
            logging.info(f"Building records: {idx}/{len(all_apps)}")

        app_object_id = a.get("id")
        app_id = a.get("appId")

        pw_creds = a.get("passwordCredentials") or []
        key_creds = a.get("keyCredentials") or []
        rra = a.get("requiredResourceAccess") or []

        secret_expiry_count = 0
        for c in pw_creds:
            end = parse_dt(c.get("endDateTime"))
            if end and end <= now_dt:
                secret_expiry_count += 1

        cert_expiry_count = 0
        for c in key_creds:
            end = parse_dt(c.get("endDateTime"))
            if end and end <= now_dt:
                cert_expiry_count += 1

        permissions: list[dict] = []
        for r in rra:
            resource_app_id = r.get("resourceAppId")
            for access in (r.get("resourceAccess") or []):
                perm_id = access.get("id")
                perm_type = access.get("type")

                perm_name, perm_display_name = resolve_permission(
                    resource_app_id,
                    perm_id,
                    perm_type,
                    perm_map
                )

                permissions.append({
                    "resourceAppId": resource_app_id,
                    "permissionId": perm_id,
                    "type": perm_type,
                    "permissionName": perm_name,
                    "permissionDisplayName": perm_display_name
                })

        permission_count = len(permissions)
        has_graph_permissions = any(
            p.get("resourceAppId") == GRAPH_RESOURCE_APP_ID for p in permissions
        )

        owners = sp_owner_map.get(app_id, [])
        owner_count = len(owners)

        description = a.get("description")
        if not description and app_object_id:
            description = get_application_description(session, app_object_id, headers)

        if a.get("displayName") == DEBUG_APP_NAME:
            logging.info(f"DEBUG BULK DESC: {a.get('description')}")
            logging.info(f"DEBUG FINAL DESC: {description}")
            logging.info(
                f"DEBUG APP IDS: appObjectId={app_object_id}, appId={app_id}"
            )

        owners_json = json.dumps(owners, ensure_ascii=False)
        perms_json = json.dumps(permissions, ensure_ascii=False)
        raw_json = json.dumps(a, ensure_ascii=False)

        created_dt = parse_dt(a.get("createdDateTime"))
        created_out = created_dt.isoformat() if created_dt else None

        record = {
            "TimeGenerated": now_dt.isoformat(),
            "SubscriptionId": subscription_id,

            "AppObjectId": app_object_id,
            "AppId": app_id,
            "DisplayName": a.get("displayName"),
            "Description": description,
            "PublisherDomain": a.get("publisherDomain"),
            "SignInAudience": a.get("signInAudience"),
            "CreatedDateTime": created_out,

            "SecretExpiryCount": secret_expiry_count,
            "CertExpiryCount": cert_expiry_count,

            "OwnerCount": owner_count,
            "Owners": owners_json,
            "OwnerSource": "ServicePrincipal",

            "PermissionCount": permission_count,
            "HasGraphPermissions": has_graph_permissions,
            "Permissions": perms_json,

            "RawApp": raw_json
        }

        if a.get("displayName") == DEBUG_APP_NAME:
            logging.info(f"DEBUG RECORD: {json.dumps(record, ensure_ascii=False)}")

        records.append(record)

    try:
        upload_to_dcr(records)
        logging.info(f"✅ Uploaded {len(records)} records to Log Analytics via DCR")
    except Exception as e:
        logging.exception(f"❌ DCR upload failed: {e}")
        return

    logging.info("App Registration Audit Completed")
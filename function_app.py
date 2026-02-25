import logging
import os
import requests
import azure.functions as func
from datetime import datetime, timezone

from azure.identity import DefaultAzureCredential
from azure.monitor.ingestion import LogsIngestionClient

app = func.FunctionApp()

GRAPH_RESOURCE_APP_ID = "00000003-0000-0000-c000-000000000000"


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

    CHUNK_SIZE = 200
    for i in range(0, len(records), CHUNK_SIZE):
        client.upload(rule_id=rule_id, stream_name=stream_name, logs=records[i:i + CHUNK_SIZE])


def graph_get_paged(url: str, headers: dict, timeout: int = 30) -> list[dict]:
    """Follow @odata.nextLink until done."""
    out: list[dict] = []
    while url:
        r = requests.get(url, headers=headers, timeout=timeout)
        logging.info(f"Graph call status: {r.status_code}")
        if r.status_code != 200:
            raise RuntimeError(f"Graph error {r.status_code}: {r.text}")
        data = r.json()
        out.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
    return out


def get_app_owners(app_object_id: str, headers: dict) -> list[dict]:
    """Owners are separate from the app object."""
    owners_url = (
        f"https://graph.microsoft.com/v1.0/applications/{app_object_id}/owners"
        "?$select=id,displayName,userPrincipalName"
        "&$top=999"
    )
    try:
        return graph_get_paged(owners_url, headers=headers)
    except Exception as e:
        logging.warning(f"Owners lookup failed for {app_object_id}: {e}")
        return []


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

    # 1) Get Graph token
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    token_data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    }

    try:
        token_response = requests.post(token_url, data=token_data, timeout=30)
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

    # 2) Pull apps (NO $select => most complete set of fields)
    apps_url = "https://graph.microsoft.com/v1.0/applications?$top=999"

    try:
        all_apps = graph_get_paged(apps_url, headers=headers)
    except Exception as e:
        logging.error(f"Applications pull failed: {e}")
        return

    logging.info(f"Total applications retrieved: {len(all_apps)}")

    # 3) Build records
    now_dt = datetime.now(timezone.utc)
    records: list[dict] = []

    for a in all_apps:
        app_object_id = a.get("id")

        pw_creds = a.get("passwordCredentials") or []
        key_creds = a.get("keyCredentials") or []
        rra = a.get("requiredResourceAccess") or []

        # expired secrets
        secret_expiry_count = 0
        for c in pw_creds:
            end = parse_dt(c.get("endDateTime"))
            if end and end <= now_dt:
                secret_expiry_count += 1

        # expired certs
        cert_expiry_count = 0
        for c in key_creds:
            end = parse_dt(c.get("endDateTime"))
            if end and end <= now_dt:
                cert_expiry_count += 1

        # exact permissions list (IDs + type)
        permissions: list[dict] = []
        for r in rra:
            resource_app_id = r.get("resourceAppId")
            for access in (r.get("resourceAccess") or []):
                permissions.append({
                    "resourceAppId": resource_app_id,
                    "permissionId": access.get("id"),
                    "type": access.get("type")  # "Scope" or "Role"
                })

        permission_count = len(permissions)
        has_graph_permissions = any(p.get("resourceAppId") == GRAPH_RESOURCE_APP_ID for p in permissions)

        # owners
        owners = get_app_owners(app_object_id, headers) if app_object_id else []
        owner_count = len(owners)

        records.append({
            "TimeGenerated": now_dt.isoformat(),

            "TenantId": tenant_id,
            "SubscriptionId": subscription_id,

            "AppObjectId": app_object_id,
            "AppId": a.get("appId"),
            "DisplayName": a.get("displayName"),
            "PublisherDomain": a.get("publisherDomain"),
            "SignInAudience": a.get("signInAudience"),
            "CreatedDateTime": a.get("createdDateTime"),

            "SecretExpiryCount": secret_expiry_count,
            "CertExpiryCount": cert_expiry_count,

            "OwnerCount": owner_count,
            "Owners": owners,                 # dynamic

            "PermissionCount": permission_count,
            "HasGraphPermissions": has_graph_permissions,
            "Permissions": permissions,       # dynamic

            "RawApp": a                       # dynamic (all fields you received)
        })

    # 4) Upload via DCR
    try:
        upload_to_dcr(records)
        logging.info(f"✅ Uploaded {len(records)} records to Log Analytics via DCR")
    except Exception as e:
        logging.exception(f"❌ DCR upload failed: {e}")
        return

    logging.info("App Registration Audit Completed")
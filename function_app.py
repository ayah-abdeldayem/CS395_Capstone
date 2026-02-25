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
    """Parse Graph ISO timestamps safely (handles trailing Z)."""
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

    # Upload in chunks to avoid giant payloads / timeouts
    CHUNK_SIZE = 200
    for i in range(0, len(records), CHUNK_SIZE):
        chunk = records[i:i + CHUNK_SIZE]
        client.upload(rule_id=rule_id, stream_name=stream_name, logs=chunk)


@app.timer_trigger(schedule="0 0 2 1 * *", arg_name="mytimer", run_on_startup=False)
def app_registration_audit(mytimer: func.TimerRequest) -> None:
    logging.info("Starting App Registration Audit")

    tenant_id = os.environ.get("TENANT_ID")
    client_id = os.environ.get("CLIENT_ID")
    client_secret = os.environ.get("CLIENT_SECRET")

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
        logging.error(f"Token request failed: {str(e)}")
        return

    headers = {"Authorization": f"Bearer {access_token}"}

    # 2) Pull apps with the fields we need for metrics
    select_fields = (
        "id,appId,displayName,createdDateTime,publisherDomain,signInAudience,"
        "passwordCredentials,keyCredentials,requiredResourceAccess"
    )

    url = (
        "https://graph.microsoft.com/v1.0/applications"
        f"?$top=999&$select={select_fields}"
    )

    all_apps: list[dict] = []
    while url:
        try:
            response = requests.get(url, headers=headers, timeout=30)
        except Exception as e:
            logging.error(f"Graph request failed: {e}")
            return

        logging.info(f"Graph call status: {response.status_code}")

        if response.status_code != 200:
            logging.error(f"Graph error: {response.text}")
            return

        data = response.json()
        all_apps.extend(data.get("value", []))
        url = data.get("@odata.nextLink")

    logging.info(f"Total applications retrieved: {len(all_apps)}")

    # 3) Build records for Log Analytics
    now_dt = datetime.now(timezone.utc)
    records: list[dict] = []

    for a in all_apps:
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

        # permissions
        has_graph_permissions = any(x.get("resourceAppId") == GRAPH_RESOURCE_APP_ID for x in rra)
        permission_count = sum(len(x.get("resourceAccess") or []) for x in rra)

        records.append({
            "TimeGenerated": now_dt.isoformat(),
            "AppObjectId": a.get("id"),
            "AppId": a.get("appId"),
            "DisplayName": a.get("displayName"),
            "PublisherDomain": a.get("publisherDomain"),
            "SignInAudience": a.get("signInAudience"),
            "CreatedDateTime": a.get("createdDateTime"),

            "SecretExpiryCount": secret_expiry_count,
            "CertExpiryCount": cert_expiry_count,
            "HasGraphPermissions": has_graph_permissions,
            "PermissionCount": permission_count,
        })

    # 4) Upload via DCR
    try:
        upload_to_dcr(records)
        logging.info(f"✅ Uploaded {len(records)} records to Log Analytics via DCR")
    except Exception as e:
        logging.exception(f"❌ DCR upload failed: {e}")
        return

    logging.info("App Registration Audit Completed")
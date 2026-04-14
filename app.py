import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import timedelta
from azure.identity import InteractiveBrowserCredential
from azure.monitor.query import LogsQueryClient

st.set_page_config(
    page_title="App Registration Permission Audit Dashboard",
    layout="wide",
    initial_sidebar_state="collapsed"
)

WORKSPACE_ID = "a0e912cb-6cea-49e1-9482-d07cd057f6d0"

# ---------- Custom styling ----------
st.markdown("""
<style>
:root {
    --card-bg: rgba(255,255,255,0.03);
    --card-border: rgba(255,255,255,0.08);
    --muted: rgba(255,255,255,0.72);
    --high: #ff6b6b;
    --medium: #ffb454;
    --low: #6ee7a8;
    --accent: #60a5fa;
}

.block-container {
    padding-top: 1.6rem;
    padding-bottom: 2rem;
    max-width: 96rem;
}

.main-title {
    font-size: 2.2rem;
    font-weight: 800;
    line-height: 1.1;
    margin-bottom: 0.25rem;
}

.subtext {
    color: var(--muted);
    font-size: 0.98rem;
    margin-bottom: 0.25rem;
}

.hero-card {
    background: linear-gradient(135deg, rgba(96,165,250,0.12), rgba(255,255,255,0.02));
    border: 1px solid var(--card-border);
    border-radius: 22px;
    padding: 22px 24px 18px 24px;
    margin-bottom: 18px;
}

.section-card {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 18px;
    padding: 16px 18px 12px 18px;
    margin-bottom: 18px;
}

.section-title {
    font-size: 1.08rem;
    font-weight: 700;
    margin-bottom: 0.3rem;
}

.section-caption {
    color: var(--muted);
    font-size: 0.92rem;
    margin-bottom: 0.7rem;
}

div[data-testid="stMetric"] {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    padding: 14px 16px;
    border-radius: 18px;
}

div[data-testid="stMetricLabel"] {
    font-weight: 600;
}

div[data-testid="stDataFrame"] {
    border-radius: 16px;
    overflow: hidden;
    border: 1px solid var(--card-border);
}

div[data-baseweb="select"] > div {
    border-radius: 14px !important;
}

.stTabs [data-baseweb="tab-list"] {
    gap: 8px;
}

.stTabs [data-baseweb="tab"] {
    height: 46px;
    border-radius: 14px;
    padding-left: 16px;
    padding-right: 16px;
    background: rgba(255,255,255,0.03);
}

.stTabs [aria-selected="true"] {
    background: rgba(96,165,250,0.18) !important;
}

.badge-row {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    margin-top: 6px;
    margin-bottom: 4px;
}

.badge {
    font-size: 0.82rem;
    padding: 7px 10px;
    border-radius: 999px;
    border: 1px solid var(--card-border);
    background: rgba(255,255,255,0.03);
    color: white;
}

.toolbar {
    background: rgba(255,255,255,0.025);
    border: 1px solid var(--card-border);
    border-radius: 16px;
    padding: 10px 12px 4px 12px;
    margin-bottom: 12px;
}
</style>
""", unsafe_allow_html=True)

# ---------- Auth ----------
@st.cache_resource
def get_client():
    credential = InteractiveBrowserCredential()
    return LogsQueryClient(credential)

client = get_client()

# ---------- Helpers ----------
@st.cache_data(ttl=300)
def run_query(query: str, days: int = 90) -> pd.DataFrame:
    response = client.query_workspace(
        workspace_id=WORKSPACE_ID,
        query=query,
        timespan=timedelta(days=days)
    )

    if not response.tables:
        return pd.DataFrame()

    table = response.tables[0]
    columns = [c.name if hasattr(c, "name") else str(c) for c in table.columns]
    rows = table.rows
    return pd.DataFrame(rows, columns=columns)

def clean_datetime_column(df: pd.DataFrame, col: str) -> pd.DataFrame:
    if col in df.columns:
        df[col] = pd.to_datetime(df[col], errors="coerce").dt.strftime("%Y-%m-%d %I:%M %p")
    return df

def truncate_text(val, limit=60):
    if pd.isna(val):
        return ""
    val = str(val)
    return val if len(val) <= limit else val[:limit] + "..."

def style_risk_label(val):
    val = str(val).lower()
    if val == "high":
        return "background-color: rgba(255,107,107,0.16); color: #ff8b8b; font-weight: 700;"
    if val == "medium":
        return "background-color: rgba(255,180,84,0.16); color: #ffc97d; font-weight: 700;"
    if val == "low":
        return "background-color: rgba(110,231,168,0.15); color: #8ff0bf; font-weight: 700;"
    return ""

# ---------- Queries ----------
APP_SUMMARY_QUERY = r"""
AppRegistrationAudit_CL
| summarize arg_max(TimeGenerated, *) by AppObjectId
| extend Perms = parse_json(Permissions)
| extend Perms = iif(isnull(Perms) or array_length(Perms) == 0, dynamic([{"permissionName":"","type":""}]), Perms)
| extend OwnerObjs = parse_json(Owners)
| extend OwnerObjs = iif(isnull(OwnerObjs) or array_length(OwnerObjs) == 0, dynamic([{"displayName":""}]), OwnerObjs)
| mv-expand Perm = Perms
| extend
    PermissionType = tostring(Perm.type),
    PermissionName = tostring(Perm.permissionName)
| summarize
    DisplayName = any(DisplayName),
    OwnerCount = any(OwnerCount),
    OwnerObjs = any(OwnerObjs),
    CreatedDateTime = any(CreatedDateTime),
    PermissionCount = any(PermissionCount),
    SignInAudience = any(SignInAudience),
    Description = any(Description),
    HasDelegated = countif(PermissionType == "Scope") > 0,
    HasAppOnly = countif(PermissionType == "Role") > 0,
    BroadPermissions = countif(
        PermissionName has ".All"
        or PermissionName in (
            "Mail.ReadWrite",
            "MailboxSettings.ReadWrite",
            "Files.ReadWrite.All",
            "Sites.ReadWrite.All",
            "Directory.Read.All",
            "Directory.ReadWrite.All",
            "User.Read.All",
            "User.ReadWrite.All"
        )
    ) > 0
    by AppObjectId
| mv-expand Owner = OwnerObjs
| extend OwnerName = tostring(Owner.displayName)
| summarize
    DisplayName = any(DisplayName),
    OwnerCount = any(OwnerCount),
    OwnerNames = make_set(OwnerName),
    CreatedDateTime = any(CreatedDateTime),
    PermissionCount = any(PermissionCount),
    SignInAudience = any(SignInAudience),
    Description = any(Description),
    HasDelegated = any(HasDelegated),
    HasAppOnly = any(HasAppOnly),
    BroadPermissions = any(BroadPermissions)
    by AppObjectId
| extend
    OwnerNames = strcat_array(OwnerNames, ", "),
    HasBothTypes = HasDelegated and HasAppOnly,
    NoOwner = OwnerCount == 0,
    NoDescription = isempty(trim(" ", tostring(Description))),
    ExternalAudience = SignInAudience != "AzureADMyOrg"
| extend RawRiskPoints =
    toint(HasAppOnly) +
    toint(HasBothTypes) +
    toint(BroadPermissions) +
    toint(NoOwner) +
    toint(NoDescription) +
    toint(ExternalAudience)
| extend RiskScore = case(
    RawRiskPoints <= 0, 1,
    RawRiskPoints == 1, 2,
    RawRiskPoints == 2, 3,
    RawRiskPoints == 3, 4,
    5
)
| extend RiskLabel = case(
    RiskScore >= 5, "High",
    RiskScore >= 3, "Medium",
    "Low"
)
| project
    AppObjectId,
    DisplayName,
    OwnerNames,
    OwnerCount,
    CreatedDateTime,
    PermissionCount,
    SignInAudience,
    Description,
    RiskScore,
    RiskLabel
| order by RiskScore desc, DisplayName asc
"""

TOP_PERMISSIONS_QUERY = r"""
let PermissionDescriptions = datatable(PermissionName:string, Description:string)
[
    "User.Read", "Sign in and read basic user profile",
    "client_access_api", "Access your app as the signed-in user",
    "profile", "Read basic profile info",
    "email", "Read user email address",
    "openid", "Sign in using OpenID Connect",
    "Directory.Read.All", "Read directory data (high privilege)",
    "offline_access", "Maintain access without user interaction",
    "User.Read.All", "Read all users' full profiles (high privilege)",
    "User.ReadBasic.All", "Read basic info of all users",
    "user_impersonation", "Access API on behalf of the user"
];
AppRegistrationAudit_CL
| summarize arg_max(TimeGenerated, *) by AppObjectId
| extend Perms = parse_json(Permissions)
| mv-expand Perm = Perms
| extend PermissionName = trim(" ", tostring(Perm.permissionName))
| where isnotempty(PermissionName)
| summarize Count = count() by PermissionName
| top 10 by Count desc
| join kind=leftouter PermissionDescriptions on PermissionName
| extend Description = coalesce(Description, "No description available")
| project PermissionName, Count, Description
| order by Count desc
"""

EXPIRING_CREDS_QUERY = r"""
AppRegistrationAudit_CL
| summarize arg_max(TimeGenerated, *) by AppObjectId
| where CertExpiryCount > 0 or SecretExpiryCount > 0
| extend OwnerObjs = parse_json(Owners)
| extend OwnerObjs = iif(isnull(OwnerObjs) or array_length(OwnerObjs) == 0, dynamic([{"displayName":""}]), OwnerObjs)
| mv-expand Owner = OwnerObjs
| extend OwnerName = tostring(Owner.displayName)
| where isnotempty(OwnerName)
| summarize OwnerNames = make_set(OwnerName) by AppObjectId, DisplayName, CertExpiryCount, SecretExpiryCount
| extend OwnerNames = strcat_array(OwnerNames, ", ")
| project DisplayName, OwnerNames, CertExpiryCount, SecretExpiryCount
| order by SecretExpiryCount desc, CertExpiryCount desc
"""

NO_OWNER_APPS_QUERY = r"""
AppRegistrationAudit_CL
| summarize arg_max(TimeGenerated, *) by AppObjectId
| where OwnerCount == 0
| project
    AppObjectId,
    DisplayName,
    CreatedDateTime,
    PermissionCount,
    SignInAudience,
    Description
| order by CreatedDateTime desc
"""

NEW_APPS_30_DAYS_QUERY = r"""
AppRegistrationAudit_CL
| summarize arg_max(TimeGenerated, *) by AppObjectId
| where todatetime(CreatedDateTime) >= ago(30d)
| project
    AppObjectId,
    DisplayName,
    CreatedDateTime,
    OwnerCount,
    PermissionCount,
    SignInAudience,
    Description
| order by CreatedDateTime desc
"""

HIGH_RISK_PERMISSION_LIST_QUERY = r"""
AppRegistrationAudit_CL
| summarize arg_max(TimeGenerated, *) by AppObjectId
| extend Perms = parse_json(Permissions)
| mv-expand Perm = Perms
| extend PermissionName = trim(" ", tostring(Perm.permissionName))
| where isnotempty(PermissionName)
| where PermissionName endswith ".All"
| distinct PermissionName
| order by PermissionName asc
"""

PERMISSION_APP_LIST_QUERY_TEMPLATE = r"""
AppRegistrationAudit_CL
| summarize arg_max(TimeGenerated, *) by AppObjectId
| extend Perms = parse_json(Permissions)
| extend OwnerObjs = parse_json(Owners)
| extend OwnerObjs = iif(isnull(OwnerObjs) or array_length(OwnerObjs) == 0, dynamic([{"displayName":""}]), OwnerObjs)
| mv-expand Perm = Perms
| extend
    PermissionName = trim(" ", tostring(Perm.permissionName)),
    PermissionType = tostring(Perm.type)
| where tolower(PermissionName) == tolower("__SELECTED_PERMISSION__")
| mv-expand Owner = OwnerObjs
| extend OwnerName = tostring(Owner.displayName)
| summarize
    OwnerNames = make_set(OwnerName),
    PermissionType = any(PermissionType)
    by DisplayName, PermissionName
| extend OwnerNames = strcat_array(OwnerNames, ", ")
| project DisplayName, OwnerNames, PermissionType
| order by DisplayName asc
"""

DELEGATED_VS_APP_QUERY = r"""
AppRegistrationAudit_CL
| summarize arg_max(TimeGenerated, *) by AppObjectId
| extend Perms = parse_json(Permissions)
| mv-expand Perm = Perms
| extend PermissionType = tostring(Perm.type)
| where PermissionType in ("Scope", "Role")
| summarize Count = count() by PermissionType
| order by Count desc
"""

# ---------- Load data ----------
apps_df = run_query(APP_SUMMARY_QUERY)
perms_df = run_query(TOP_PERMISSIONS_QUERY)
expiring_df = run_query(EXPIRING_CREDS_QUERY)
no_owner_df = run_query(NO_OWNER_APPS_QUERY)
new_apps_30_df = run_query(NEW_APPS_30_DAYS_QUERY)
high_risk_perm_df = run_query(HIGH_RISK_PERMISSION_LIST_QUERY)
delegated_vs_app_df = run_query(DELEGATED_VS_APP_QUERY)

# ---------- Format ----------
for df_name in [apps_df, no_owner_df, new_apps_30_df]:
    if not df_name.empty and "CreatedDateTime" in df_name.columns:
        clean_datetime_column(df_name, "CreatedDateTime")

if not apps_df.empty:
    if "OwnerNames" in apps_df.columns:
        apps_df["OwnerNames"] = apps_df["OwnerNames"].apply(lambda x: truncate_text(x, 58))
    if "Description" in apps_df.columns:
        apps_df["Description"] = apps_df["Description"].apply(lambda x: truncate_text(x, 85))

if not no_owner_df.empty and "Description" in no_owner_df.columns:
    no_owner_df["Description"] = no_owner_df["Description"].apply(lambda x: truncate_text(x, 90))

if not new_apps_30_df.empty and "Description" in new_apps_30_df.columns:
    new_apps_30_df["Description"] = new_apps_30_df["Description"].apply(lambda x: truncate_text(x, 90))

if not expiring_df.empty and "OwnerNames" in expiring_df.columns:
    expiring_df["OwnerNames"] = expiring_df["OwnerNames"].apply(lambda x: truncate_text(x, 58))

for df in [apps_df, new_apps_30_df, no_owner_df]:
    if not df.empty and "OwnerCount" in df.columns:
        df["OwnerCount"] = df["OwnerCount"].fillna(0).astype(int)

# ---------- Hero ----------
hero_left, hero_right = st.columns([5.5, 1])

with hero_left:
    st.markdown("""
    <div class="hero-card">
        <div class="main-title">App Registration Permission Audit Dashboard</div>
        <div class="subtext">Live visibility into risky app registrations, privileged permissions, ownership gaps, and expiring credentials.</div>
        <div class="badge-row">
            <div class="badge">Microsoft Graph</div>
            <div class="badge">Azure Monitor Logs</div>
            <div class="badge">Live Risk Scoring</div>
            <div class="badge">Owner & Credential Monitoring</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

with hero_right:
    st.write("")
    st.write("")
    if st.button("Refresh now", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

# ---------- KPIs ----------
k1, k2, k3, k4 = st.columns(4)
with k1:
    st.metric("Total Apps", len(apps_df))
with k2:
    st.metric("High Risk Apps", len(apps_df[apps_df["RiskScore"] >= 4]) if not apps_df.empty else 0)
with k3:
    st.metric("Apps With No Owner", len(no_owner_df))
with k4:
    st.metric("Expiring Credentials", len(expiring_df))
st.markdown("""
<div class='section-card'>
    <div class='section-title'>How Risk Score Is Calculated</div>
    <div class='section-caption'>
        1 point per indicator:
        app-only access, mixed permissions, broad permissions,
        no owner, no description, external access.
        <br><br>
        Higher total → higher risk (1–5 scale).
    </div>
</div>
""", unsafe_allow_html=True)

# ---------- Tabs ----------
tab1, tab2, tab3, tab4 = st.tabs([
    "Overview",
    "High-Privilege Permissions",
    "Ownership & New Apps",
    "Credentials"
])

with tab1:
    chart_col1, chart_col2 = st.columns([1.5, 1])

    with chart_col1:
        st.markdown("<div class='section-card'>", unsafe_allow_html=True)
        st.markdown("<div class='section-title'>Top Permission Names</div>", unsafe_allow_html=True)
        st.markdown("<div class='section-caption'>Most common permission names across app registrations.</div>", unsafe_allow_html=True)

        if not perms_df.empty:
            fig = px.bar(
                perms_df,
                x="PermissionName",
                y="Count",
                custom_data=["Description"] if "Description" in perms_df.columns else None
            )

            if "Description" in perms_df.columns:
                fig.update_traces(
                    hovertemplate=(
                        "<b>%{x}</b><br>"
                        "Count: %{y}<br>"
                        "Description: %{customdata[0]}"
                        "<extra></extra>"
                    )
                )

            fig.update_layout(
                xaxis_title="",
                yaxis_title="Count",
                margin=dict(l=8, r=8, t=10, b=8),
                height=370
            )

            st.plotly_chart(fig, use_container_width=True)

        st.markdown("</div>", unsafe_allow_html=True)

    with chart_col2:
        st.markdown("<div class='section-card'>", unsafe_allow_html=True)
        st.markdown("<div class='section-title'>Delegated vs Application</div>", unsafe_allow_html=True)
        st.markdown("<div class='section-caption'>Permission type distribution across current app registrations.</div>", unsafe_allow_html=True)

        if not delegated_vs_app_df.empty:
            fig2 = px.pie(
                delegated_vs_app_df,
                names="PermissionType",
                values="Count",
                hole=0.52
            )
            fig2.update_layout(
                margin=dict(l=8, r=8, t=10, b=8),
                height=370
            )
            st.plotly_chart(fig2, use_container_width=True)

        st.caption("Delegated permissions act on behalf of a user. Application permissions run as the app itself.")
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div class='section-card'>", unsafe_allow_html=True)
    st.markdown("<div class='section-title'>App Summary</div>", unsafe_allow_html=True)
    st.markdown("<div class='section-caption'>Filter the current inventory by risk level and app name.</div>", unsafe_allow_html=True)

    risk_options = ["All"] + (
        sorted(apps_df["RiskLabel"].dropna().unique().tolist())
        if not apps_df.empty and "RiskLabel" in apps_df.columns else []
    )

    st.markdown("<div class='toolbar'>", unsafe_allow_html=True)
    filter_col1, filter_col2 = st.columns(2)

    with filter_col1:
        selected_risk = st.selectbox("Filter by risk", risk_options, key="overview_risk")

    app_source_df = apps_df.copy()
    if selected_risk != "All" and "RiskLabel" in app_source_df.columns:
        app_source_df = app_source_df[app_source_df["RiskLabel"] == selected_risk]

    app_options = ["All"]
    if not app_source_df.empty and "DisplayName" in app_source_df.columns:
        app_options += sorted(app_source_df["DisplayName"].dropna().unique().tolist())

    with filter_col2:
        selected_app = st.selectbox("Filter by app", app_options, key="overview_app")

    st.markdown("</div>", unsafe_allow_html=True)

    filtered_apps_df = apps_df.copy()
    if selected_risk != "All" and "RiskLabel" in filtered_apps_df.columns:
        filtered_apps_df = filtered_apps_df[filtered_apps_df["RiskLabel"] == selected_risk]
    if selected_app != "All" and "DisplayName" in filtered_apps_df.columns:
        filtered_apps_df = filtered_apps_df[filtered_apps_df["DisplayName"] == selected_app]

    display_cols = [
        col for col in [
            "AppObjectId",
            "DisplayName",
            "OwnerNames",
            "OwnerCount",
            "CreatedDateTime",
            "PermissionCount",
            "SignInAudience",
            "RiskScore",
            "RiskLabel"
        ]
        if col in filtered_apps_df.columns
    ]

    styled_df = filtered_apps_df[display_cols].style.map(
        style_risk_label,
        subset=["RiskLabel"] if "RiskLabel" in filtered_apps_df.columns else []
    )

    st.dataframe(styled_df, use_container_width=True, hide_index=True, height=420)
    st.markdown("</div>", unsafe_allow_html=True)

with tab2:
    st.markdown("<div class='section-card'>", unsafe_allow_html=True)
    st.markdown("<div class='section-title'>Apps With Selected High-Privilege Permission</div>", unsafe_allow_html=True)
    st.markdown("<div class='section-caption'>Review apps assigned a selected high-privilege .All permission.</div>", unsafe_allow_html=True)

    permission_options = high_risk_perm_df["PermissionName"].dropna().tolist() if not high_risk_perm_df.empty else []

    selected_permission = st.selectbox(
        "Select a .All permission",
        options=permission_options if permission_options else ["No permissions found"],
        key="highrisk_permission"
    )

    if permission_options:
        safe_selected_permission = str(selected_permission).replace('"', "").replace("'", "")
        permission_query = PERMISSION_APP_LIST_QUERY_TEMPLATE.replace("__SELECTED_PERMISSION__", safe_selected_permission)
        permission_apps_df = run_query(permission_query)

        if not permission_apps_df.empty and "OwnerNames" in permission_apps_df.columns:
            permission_apps_df["OwnerNames"] = permission_apps_df["OwnerNames"].apply(lambda x: truncate_text(x, 58))

        st.dataframe(permission_apps_df, use_container_width=True, hide_index=True, height=360)

    st.markdown("</div>", unsafe_allow_html=True)

with tab3:
    owner_col1, owner_col2 = st.columns(2)

    with owner_col1:
        st.markdown("<div class='section-card'>", unsafe_allow_html=True)
        st.markdown("<div class='section-title'>Apps with No Owners</div>", unsafe_allow_html=True)
        st.markdown("<div class='section-caption'>Apps currently missing assigned owners.</div>", unsafe_allow_html=True)

        no_owner_cols = [
            col for col in [
                "AppObjectId",
                "DisplayName",
                "CreatedDateTime",
                "PermissionCount",
                "SignInAudience",
                "Description"
            ]
            if col in no_owner_df.columns
        ]

        st.dataframe(no_owner_df[no_owner_cols], use_container_width=True, hide_index=True, height=400)
        st.markdown("</div>", unsafe_allow_html=True)

    with owner_col2:
        st.markdown("<div class='section-card'>", unsafe_allow_html=True)
        st.markdown("<div class='section-title'>New Apps</div>", unsafe_allow_html=True)
        st.markdown("<div class='section-caption'>Apps created in the past 30 days.</div>", unsafe_allow_html=True)

        new_apps_cols = [
            col for col in [
                "AppObjectId",
                "DisplayName",
                "CreatedDateTime",
                "OwnerCount",
                "PermissionCount",
                "SignInAudience",
                "Description"
            ]
            if col in new_apps_30_df.columns
        ]

        st.dataframe(new_apps_30_df[new_apps_cols], use_container_width=True, hide_index=True, height=400)
        st.markdown("</div>", unsafe_allow_html=True)

with tab4:
    st.markdown("<div class='section-card'>", unsafe_allow_html=True)
    st.markdown("<div class='section-title'>Apps with Expiring Credentials</div>", unsafe_allow_html=True)
    st.markdown("<div class='section-caption'>Apps with expiring certificates or secrets that may require action.</div>", unsafe_allow_html=True)

    exp_cols = [
        col for col in [
            "DisplayName",
            "OwnerNames",
            "CertExpiryCount",
            "SecretExpiryCount"
        ]
        if col in expiring_df.columns
    ]

    st.dataframe(expiring_df[exp_cols], use_container_width=True, hide_index=True, height=420)
    st.markdown("</div>", unsafe_allow_html=True)
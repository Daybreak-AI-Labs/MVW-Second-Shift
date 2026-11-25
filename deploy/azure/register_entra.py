"""Create or update the Second Shift registration using Azure CLI and Microsoft Graph."""

import argparse
import json
import re
import subprocess
import sys
import time
import uuid
from urllib.parse import quote, urlencode, urlsplit

# https://learn.microsoft.com/en-us/graph/permissions-reference
GRAPH_ID = "00000003-0000-0000-c000-000000000000"
GRAPH_PERMISSIONS = {
    "read_app_assignments": "Application.Read.All",
    "read_group_members": "GroupMember.ReadBasic.All",
    "search_people": "User.Read.All",
    "read_agent_identities": "AgentIdentity.Read.All",
    "manage_agent_identities": "AgentIdentity.EnableDisable.All",
}
# https://learn.microsoft.com/en-us/microsoft-365/copilot/extensibility/plugin-authentication-entra-sso
TOKEN_STORE = "ab3be6b7-f5df-413d-ac2d-abf1e3fd9c0b"
# https://learn.microsoft.com/en-us/microsoft-365/copilot/extensibility/plugin-authentication-troubleshooting
TEAMS_REDIRECT = "https://teams.microsoft.com/api/platform/v1.0/oAuthConsentRedirect"
COPILOT_SCOPE = "SecondShift.Copilot.Read"
ROLE_NAMES = {
    "Admin": "Administrator", "GovernanceLead": "Governance lead", "Operator": "Operator",
    "Approver": "Approver", "Responder": "Responder", "Auditor": "Auditor", "Viewer": "Viewer",
}
MANAGED_TAG = "Second Shift Azure kit"
SECRET_NAME = "oidc-client-secret"


def public_origin(value):
    invalid = "Enter a public HTTPS origin, such as https://secondshift.example.com."
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ValueError(invalid) from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or port not in (None, 443)
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or not re.fullmatch(r"[a-zA-Z0-9.-]+", parsed.hostname)
        or any(char.isspace() or char in "?#" for char in value)
    ):
        raise ValueError(invalid)
    return f"https://{parsed.hostname}"


def az(*args, stdin=None, label):
    # https://learn.microsoft.com/en-us/cli/azure/reference-index?view=azure-cli-latest#az-rest
    try:
        result = subprocess.run(
            ["az", *args, "--only-show-errors", "--output", "json"],
            input=stdin, capture_output=True, check=True, timeout=90,
        )
        return json.loads(result.stdout) if result.stdout.strip() else None
    except (OSError, subprocess.SubprocessError, ValueError):
        raise ValueError(f"Azure CLI could not {label}. Check the selected tenant and your access, then retry.") from None


def graph(method, endpoint, body=None):
    url = f"https://graph.microsoft.com/v1.0/{endpoint}"
    payload = ("--headers", "Content-Type=application/json", "--body", json.dumps(body)) if body is not None else ()
    return az("rest", "--method", method, "--url", url, *payload, label=f"complete Graph {method} for {endpoint.split('?')[0]}")


def lookup_app(name, app_id):
    # https://learn.microsoft.com/en-us/graph/api/application-get?view=graph-rest-1.0
    if app_id:
        return graph("GET", f"applications(appId='{app_id}')")
    # https://learn.microsoft.com/en-us/graph/api/application-list?view=graph-rest-1.0
    expression = quote("displayName eq '" + name.replace("'", "''") + "'", safe="")
    response = graph("GET", f"applications?%24filter={expression}")
    matches = response["value"]
    if len(matches) > 1 or response.get("@odata.nextLink") or (matches and MANAGED_TAG not in (matches[0].get("tags") or [])):
        raise ValueError("The registration name is already in use. Supply its client ID with --app-id or choose a different name.")
    if matches:
        return matches[0]
    # https://learn.microsoft.com/en-us/graph/api/application-post-applications?view=graph-rest-1.0
    return graph("POST", "applications", {"displayName": name, "signInAudience": "AzureADMyOrg", "tags": [MANAGED_TAG]})


def add_unique(current, *wanted):
    return list(dict.fromkeys([*(current or []), *wanted]))


def app_changes(app, origin, copilot_uri, requested):
    # Graph collection updates replace the collection. Preserve the existing
    # ids and settings and omit the read-only role origin from update requests.
    # https://learn.microsoft.com/en-us/graph/api/application-update?view=graph-rest-1.0
    # https://learn.microsoft.com/en-us/graph/api/resources/approle?view=graph-rest-1.0
    changes = {}
    web = {**(app.get("web") or {})}
    redirects = [f"{origin}/auth/callback"]
    if copilot_uri:
        redirects.append(TEAMS_REDIRECT)
    web["redirectUris"] = add_unique(web.get("redirectUris"), *redirects)
    if web != app.get("web"):
        changes["web"] = web
    roles = [{key: value for key, value in role.items() if key != "origin"} for role in (app.get("appRoles") or [])]
    for suffix, name in ROLE_NAMES.items():
        value = f"SecondShift.{suffix}"
        existing = next((role for role in roles if role["value"] == value), None)
        if existing:
            if existing.get("allowedMemberTypes") != ["User"] or not existing.get("isEnabled"):
                raise ValueError(f"Enable the {value} app role for users and groups in Entra, then retry.")
        else:
            roles.append({
                "allowedMemberTypes": ["User"], "description": f"Use Second Shift as {name.lower()}.",
                "displayName": name, "id": str(uuid.uuid4()), "isEnabled": True, "value": value,
            })
            changes["appRoles"] = roles
    if requested:
        # https://learn.microsoft.com/en-us/graph/api/resources/requiredresourceaccess?view=graph-rest-1.0
        entries = json.loads(json.dumps(app.get("requiredResourceAccess") or []))
        access = next((entry for entry in entries if entry["resourceAppId"] == GRAPH_ID), None)
        if access is None:
            access = {"resourceAppId": GRAPH_ID, "resourceAccess": []}
            entries.append(access)
        for permission in requested.values():
            grant = {"id": permission, "type": "Role"}
            if grant not in access["resourceAccess"]:
                access["resourceAccess"].append(grant)
                changes["requiredResourceAccess"] = entries
    if copilot_uri:
        add_copilot(app, changes, copilot_uri)
    return changes


def add_copilot(app, changes, copilot_uri):
    # https://learn.microsoft.com/en-us/graph/api/resources/apiapplication?view=graph-rest-1.0
    # https://learn.microsoft.com/en-us/graph/api/resources/preauthorizedapplication?view=graph-rest-1.0
    api = json.loads(json.dumps(app.get("api") or {}))
    scopes = api.get("oauth2PermissionScopes") or []
    scope = next((entry for entry in scopes if entry["value"] == COPILOT_SCOPE), None)
    if scope is None:
        scope = {
            "id": str(uuid.uuid4()), "value": COPILOT_SCOPE, "type": "Admin", "isEnabled": True,
            "adminConsentDisplayName": "Read Second Shift from Microsoft 365 Copilot",
            "adminConsentDescription": "Read Second Shift summaries as the signed-in user.",
        }
        api["oauth2PermissionScopes"] = [*scopes, scope]
    elif not scope.get("isEnabled"):
        raise ValueError("Enable the existing Copilot delegated scope in Entra, then retry.")
    clients = api.get("preAuthorizedApplications") or []
    token_store = next((client for client in clients if client["appId"] == TOKEN_STORE), None)
    if token_store is None:
        clients.append({"appId": TOKEN_STORE, "delegatedPermissionIds": [scope["id"]]})
    else:
        token_store["delegatedPermissionIds"] = add_unique(token_store.get("delegatedPermissionIds"), scope["id"])
    api["preAuthorizedApplications"] = clients
    api["requestedAccessTokenVersion"] = 2
    if api != app.get("api"):
        changes["api"] = api
    uris = add_unique(app.get("identifierUris"), copilot_uri)
    if uris != app.get("identifierUris"):
        changes["identifierUris"] = uris


def graph_role_ids(flags):
    wanted = {permission for flag, permission in GRAPH_PERMISSIONS.items() if getattr(flags, flag)}
    if not wanted:
        return {}
    # Use the tenant's Graph service principal to resolve application role ids.
    # https://learn.microsoft.com/en-us/graph/api/serviceprincipal-get?view=graph-rest-1.0
    response = graph("GET", f"servicePrincipals(appId='{GRAPH_ID}')?%24select=appRoles")
    found = {
        role["value"]: role["id"] for role in response["appRoles"]
        if role.get("isEnabled") and "Application" in role.get("allowedMemberTypes", []) and role["value"] in wanted
    }
    if missing := sorted(wanted - found.keys()):
        raise ValueError("Microsoft Graph does not list these requested application permissions in this tenant: " + ", ".join(missing))
    return found


def enterprise(app_id):
    # https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list?view=graph-rest-1.0
    # https://learn.microsoft.com/en-us/graph/api/serviceprincipal-post-serviceprincipals?view=graph-rest-1.0
    # https://learn.microsoft.com/en-us/graph/api/serviceprincipal-update?view=graph-rest-1.0
    query = quote(f"appId eq '{app_id}'", safe="")
    matches = graph("GET", f"servicePrincipals?%24filter={query}")["value"]
    if not matches:
        try:
            return graph("POST", "servicePrincipals", {"appId": app_id, "appRoleAssignmentRequired": True})["id"]
        except ValueError:
            # Allow replication following application creation and a concurrent enterprise-app creation.
            for delay in (2, 4, 8):
                time.sleep(delay)
                matches = graph("GET", f"servicePrincipals?%24filter={query}")["value"]
                if matches:
                    break
                try:
                    return graph("POST", "servicePrincipals", {"appId": app_id, "appRoleAssignmentRequired": True})["id"]
                except ValueError:
                    continue
    if len(matches) != 1:
        raise ValueError("Could not identify the enterprise application. Wait for Entra replication, then retry.")
    if not matches[0].get("appRoleAssignmentRequired"):
        graph("PATCH", f"servicePrincipals/{matches[0]['id']}", {"appRoleAssignmentRequired": True})
    return matches[0]["id"]


def password_metadata(vault):
    # https://learn.microsoft.com/en-us/cli/azure/keyvault/secret?view=azure-cli-latest#az-keyvault-secret-list
    return az("keyvault", "secret", "list", "--vault-name", vault,
              "--query", f"[?name=='{SECRET_NAME}']", label="check the vault for the sign-in secret")


def ensure_password(app, vault):
    existing = password_metadata(vault)
    if existing:
        record = existing[0]
        tags = record.get("tags") or {}
        if tags.get("entra-app-id") != app["appId"] or not record["attributes"]["enabled"]:
            raise ValueError("The vault already has a sign-in secret with a different or unverified registration. Check it before replacing it.")
        return
    # https://learn.microsoft.com/en-us/graph/api/application-addpassword?view=graph-rest-1.0
    # https://learn.microsoft.com/en-us/graph/api/application-removepassword?view=graph-rest-1.0
    endpoint = f"applications/{app['id']}"
    credential = graph("POST", f"{endpoint}/addPassword", {"passwordCredential": {"displayName": "Second Shift Azure kit"}})
    # https://learn.microsoft.com/en-us/cli/azure/keyvault/secret?view=azure-cli-latest#az-keyvault-secret-set
    try:
        az("keyvault", "secret", "set", "--vault-name", vault, "--name", SECRET_NAME,
           "--file", "/dev/stdin", "--tags", f"entra-app-id={app['appId']}", f"entra-key-id={credential['keyId']}",
           "--query", "id", stdin=credential["secretText"].encode(), label="store the new sign-in secret in the vault")
    except ValueError as error:
        try:
            metadata = password_metadata(vault)
        except ValueError:
            raise ValueError("Could not verify the vault write. Check the vault before removing the new Entra credential.") from None
        if any((entry.get("tags") or {}).get("entra-key-id") == credential["keyId"] for entry in metadata):
            return
        try:
            graph("POST", f"{endpoint}/removePassword", {"keyId": credential["keyId"]})
        except ValueError:
            raise ValueError("The vault write failed. In Entra, remove the new Second Shift Azure kit credential before retrying.") from None
        raise error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("public_origin")
    parser.add_argument("--vault", required=True, help="Vault created for this deployment.")
    parser.add_argument("--name", default="Second Shift", help="Use a different name for a second deployment.")
    parser.add_argument("--app-id", type=uuid.UUID, help="Explicit client ID of an existing registration.")
    parser.add_argument("--copilot-uri", help="Application ID URI returned by the Microsoft Entra SSO registration.")
    for flag, permission in GRAPH_PERMISSIONS.items():
        parser.add_argument(f"--{flag.replace('_', '-')}", action="store_true", help=f"Request Graph application permission {permission}.")
    flags = parser.parse_args()
    try:
        origin = public_origin(flags.public_origin)
        if flags.copilot_uri and not re.fullmatch(r"api://[A-Za-z0-9][A-Za-z0-9./_-]*", flags.copilot_uri):
            raise ValueError("Use the api:// Application ID URI returned by the Microsoft Entra SSO registration.")
        # https://learn.microsoft.com/en-us/cli/azure/account?view=azure-cli-latest#az-account-show
        account = az("account", "show", "--query", "{tenant:tenantId,cloud:environmentName}", label="read the selected account")
        if account["cloud"] != "AzureCloud":
            raise ValueError("Select an Azure public cloud subscription before running this tool.")
        tenant = str(uuid.UUID(account["tenant"]))
        requested = graph_role_ids(flags)
        app = lookup_app(flags.name, flags.app_id)
        if app.get("signInAudience") != "AzureADMyOrg":
            raise ValueError("Choose a single-tenant application registration.")
        if changes := app_changes(app, origin, flags.copilot_uri, requested):
            graph("PATCH", f"applications/{app['id']}", changes)
        principal = enterprise(app["appId"])
        ensure_password(app, flags.vault)
    except (ValueError, TypeError, KeyError) as error:
        message = str(error) if type(error) is ValueError else "Azure returned an incomplete result. Check the selected tenant and retry."
        print(f"Second Shift registration stopped. {message}", file=sys.stderr)
        return 1
    print(f"Tenant ID: {tenant}")
    print(f"Application (client) ID: {app['appId']}")
    print(f"Application object ID: {app['id']}")
    print(f"Enterprise application object ID: {principal}")
    print(f"Key Vault secret name: {SECRET_NAME}")
    # https://learn.microsoft.com/en-us/entra/identity-platform/v2-admin-consent
    query = urlencode({"client_id": app["appId"], "scope": "https://graph.microsoft.com/.default",
                       "redirect_uri": f"{origin}/auth/callback", "state": str(uuid.uuid4())})
    print(f"Admin consent link for Graph permissions: https://login.microsoftonline.com/{tenant}/v2.0/adminconsent?{query}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

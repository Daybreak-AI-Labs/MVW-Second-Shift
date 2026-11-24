# Ask Second Shift from Microsoft 365 Copilot

The agent answers five questions using the signed-in person's Second Shift
role and workspace. It only reads information.

| Question | What the agent returns | Second Shift access |
| --- | --- | --- |
| Which agents changed this week? | Findings still shown in Second Shift that were reported since Monday at 00:00 UTC, with the recorded change summary. | Outside agents view permission |
| What needs a decision? | Pending approvals the person can open, with action, risk and request time. | Approve permission and access to each card |
| Which agents are blocked or over budget? | Agents contained for rule breaks or with access revoked, and agents over their recorded budget. | Outside agents view permission |
| What did our platform checks find? | Agents from the last successful checks that are still awaiting enrollment. | Outside agents view permission |
| What is this agent's status? | Lifecycle, spending, drift and platform presence for the enrolled name shown on Outside agents. | Outside agents view permission |

List answers return up to 50 rows and indicate when more are available. Use
the corresponding Second Shift page to see the full record or take action.

## Prepare Entra single sign-on

1. Use the same single-tenant Entra app registration that protects your
   Second Shift dashboard. Use a public HTTPS origin for the API. In the
   app registration, expose a **delegated** permission named
   `SecondShift.Copilot.Read`. Issue v2 access tokens for this application
   (`api.requestedAccessTokenVersion = 2` on the Entra application). The
   v2 token audience is the application's client ID, so the existing
   `SECOND_SHIFT_OIDC_AUDIENCE` remains the application client ID and the
   issuer remains the tenant-specific v2 issuer.
   [Entra access token claims](https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference)
2. In the Teams developer portal, go to **Tools → Microsoft Entra SSO
   client ID registration** and register the app's client ID. Set the base
   URL to the same HTTPS origin passed to the package builder, request the
   delegated permission, and restrict the registration to your organization
   and its Microsoft 365 app. Record both the **Microsoft Entra SSO
   registration ID** and the **Application ID URI** that the portal returns.
   [Configure Entra SSO](https://learn.microsoft.com/en-us/microsoft-365/copilot/extensibility/plugin-authentication-entra-sso)
3. Add the returned URI to the Entra app's `identifierUris` and register
   `https://teams.microsoft.com/api/platform/v1.0/oAuthConsentRedirect` as a
   Web redirect. Keep the existing Second Shift Web redirect. Under **Expose
   an API**, authorize the Microsoft Enterprise token store client
   `ab3be6b7-f5df-413d-ac2d-abf1e3fd9c0b` for the delegated scope. Follow
   your tenant's consent policy for that scope. The plugin manifest contains
   the registration ID. The credentials stay in the Microsoft token store.
   [Entra app registration updates](https://learn.microsoft.com/en-us/microsoft-365/copilot/extensibility/plugin-authentication-entra-sso#step-3-update-the-entra-app-registration)
4. Assign pilot users the roles they need in Second Shift. The delegated
   permission allows the integration to call the summaries. Second Shift
   applies each person's existing permissions to the results. A token
   bearing this integration scope is restricted to the Copilot read routes.
   [Sign-in roles](sign-in-roles.md)

## Build and upload the package

Run the builder from the repository root with Python 3.11 or later.
Choose a Microsoft 365 package ID once and keep it for upgrades. Set the
privacy and terms URLs to your published deployment notices. Increment
`version` in the outer manifest for each package update.

```bash
python m365-copilot/build.py \
  --origin https://second-shift.example.com \
  --package-id '<Microsoft 365 package UUID>' \
  --tenant-id '<Entra tenant UUID>' \
  --application-id-uri '<Application ID URI from the SSO registration>' \
  --auth-config-id '<Microsoft Entra SSO registration ID>' \
  --privacy-url https://second-shift.example.com/privacy \
  --terms-url https://second-shift.example.com/terms \
  --output second-shift-copilot.zip
```

In the Microsoft 365 admin center, open **Agents → All agents → Add
agent**, select the ZIP and validate its name, icon and host products.
Publish to a pilot group first, or deploy to preinstall it for those
users. Review the policies and permissions before selecting **Finish
deployment**. Test with a viewer and an approver in that group and check
that the viewer cannot see approvals. [Upload a custom agent](https://learn.microsoft.com/en-us/microsoft-agent-365/admin/agent-registry-overview#upload-custom-agent)

## Availability and licensing

- The package uses the Microsoft 365 app manifest 1.30, declarative agent
  manifest 1.9, and API plugin schema 2.4. App packaging uses Microsoft's
  generally available app schema. Microsoft lists declarative agents and
  custom actions in the regular Copilot licensing matrix. The published REST
  plugin schema and Entra SSO instructions cover this configuration without
  a preview designation.
  [App manifest](https://learn.microsoft.com/en-us/microsoft-365/extensibility/schema/?view=m365-app-1.30) ·
  [Declarative agent 1.9](https://learn.microsoft.com/en-us/microsoft-365/copilot/extensibility/declarative-agent-manifest-1.9) ·
  [API plugin 2.4](https://learn.microsoft.com/en-us/microsoft-365/copilot/extensibility/plugin-manifest-2.4) ·
  [Supported plugin authentication](https://learn.microsoft.com/en-us/microsoft-365/copilot/extensibility/plugin-authentication)
- Microsoft lists custom actions for Microsoft 365 Copilot licensed users,
  and for eligible Copilot Chat users with or without usage-based billing.
  Users need access to Copilot Chat or a supported Copilot host, an
  organization account with access to the published app, and their Second
  Shift role. Copilot Chat usage limits and tenant admin policies still
  apply. [Requirements and licensing](https://learn.microsoft.com/en-us/plugins/prerequisites#agent-capabilities-and-licensing-models)
- The ZIP upload uses the Microsoft 365 admin center. Microsoft's
  programmatic Agent Registry Graph API is a separate preview feature.
  [Admin center and Graph availability](https://learn.microsoft.com/en-us/microsoft-agent-365/admin/agent-registry-overview)

The package and OpenAPI files were validated locally. Tests use signed
Entra-shaped tokens with local signing keys. Tenant upload, token acquisition
and consent in a Microsoft 365 tenant, and invocation from Copilot Chat
remain unverified.

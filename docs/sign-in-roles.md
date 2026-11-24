# Roles from sign-in

Second Shift can take a person's role from Microsoft Entra ID when they sign
in. You decide in Entra who holds which app role, and a short table in the
Second Shift settings says which role each app role stands for.

This page assumes sign-in with Entra already works (the `[auth.oidc]` section
of `~/.maverick/config.toml`).

## The roles

| Role | Name in settings | View | Run work | Read the audit record | Administer |
| --- | --- | --- | --- | --- | --- |
| Administrator | `admin` | yes | yes | yes | yes |
| Governance lead | `governance_lead` | yes | yes | yes | no |
| Operator | `operator` | yes | yes | no | no |
| Auditor | `auditor` | yes | no | yes | no |
| Viewer | `viewer` | yes | no | no | no |

A governance lead does the day-to-day work of an operator and can also read
the audit record, without administrator rights.

## 1. Define the app roles in Entra

In the Microsoft Entra admin center, signed in as at least a Cloud Application
Administrator:

1. Go to **Entra ID** > **App registrations** and open the application you
   registered for Second Shift.
2. Select **App roles**, then **Create app role**.
3. Fill in the role:
   - **Display name**: what people see when they assign it, for example
     `Second Shift governance lead`.
   - **Allowed member types**: **Users/Groups**.
   - **Value**: the text Entra puts in the sign-in token, for example
     `SecondShift.GovernanceLead`. It cannot contain spaces. You will type
     exactly this value into the settings in step 3.
   - **Description**: a sentence about who should hold it.
4. Leave the role enabled and select **Apply**.

Create one app role for each Second Shift role you want to hand out.

## 2. Assign people or groups

1. Go to **Entra ID** > **Enterprise apps** > **All applications** and open
   the same application.
2. Select **Users and groups**, then **Add user/group**.
3. Choose the people or groups, choose the role under **Select a role**, and
   select **Assign**.

Assigning a group needs Microsoft Entra ID P1 or P2. Only direct members of an
assigned group get the role; groups nested inside it do not.

To take a role away from someone, remove their assignment here. Disabling the
app role is not enough: Entra keeps sending a disabled role for the people who
still hold it.

## 3. Tell Second Shift what each app role means

Add the table to `~/.maverick/config.toml`, with the app role **Value** on the
left and the Second Shift role name on the right:

```toml
[auth.oidc.role_map]
"SecondShift.Admin" = "admin"
"SecondShift.GovernanceLead" = "governance_lead"
"SecondShift.Operator" = "operator"
"SecondShift.Auditor" = "auditor"
"SecondShift.Viewer" = "viewer"
```

Entra sends a person's app roles in the `roles` claim of the token it issues
when they sign in, and that is the claim Second Shift reads unless you say
otherwise:

```toml
[auth.oidc]
role_claim = "roles"   # the default; change it only if your provider uses another claim
```

## Which role a person gets

Second Shift uses the first of these that applies:

1. An administrator named in settings (`[dashboard] admins`) is always an
   administrator.
2. A role already stored for that person in Second Shift's own role list.
3. The role from their sign-in, as set up on this page.
4. The default role (`[dashboard] default_role`; Viewer unless you change it).

If a person holds several app roles, they get the one that allows the most.
When two allow equally much, the one higher in the table above wins (Operator
before Auditor); for any other roles, built-in roles come first and then the
name that sorts first. To give someone both operator and auditor rights, use
Governance lead.

## Good to know

- Only values listed in the table count, and they must match exactly,
  including capital letters.
- An entry that names a role that does not exist is ignored, with one warning
  in the server log. If the table itself is malformed (for example a value
  that is not text), no role is taken from sign-in at all until it is fixed,
  also with one warning. In both cases people keep their stored or default
  role.
- With no table, nothing changes: sign-in works as it did before.
- A change you make in Entra takes effect the next time the person signs in. A
  browser session lasts at most 12 hours. Another session the person still has
  open keeps its earlier role until it ends.
- If you remove a role from the table, or remove the table, sessions that got
  that role from sign-in lose it straight away.
- A program that calls the API with a token Entra issued for this application
  is treated the same way: the `roles` claim of that token is read on every
  call.
- The role from sign-in applies to that person's own requests only. Where
  Second Shift checks the role of someone other than the person making the
  request, it uses their stored role or the default role.

## Sources

Microsoft Learn pages these steps were checked against:

- Add app roles to your application and receive them in the token:
  https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps
- Manage users and groups assignment to an application:
  https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/assign-user-or-group-access-portal
- ID token claims reference:
  https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference

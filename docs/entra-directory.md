# Entra directory lookups

Second Shift can look people up in your Microsoft Entra directory, read-only,
with its own app registration. It is **off by default**. Turn it on when:

- people get their Second Shift role from an Entra app role
  ([Roles from sign-in](sign-in-roles.md)) and some of them must receive and
  decide approval cards in Microsoft Teams ([Teams approvals](teams-approvals.md));
- you want the "is another approver available" rule to count those people;
- you want to choose an agent's owner from a list of people instead of typing
  an email.

> **Not tested against a real tenant.** The requests below were checked
> against Microsoft's documentation and run only against stand-in answers
> shaped like the documented ones. Try it on a test tenant first, and use the
> check in "If it does not work" before relying on it.

## Why it is needed

A role from an Entra app role lives in the person's own sign-in. Teams cards,
the approver rule and the owner list have no sign-in to read it from. With
the directory on, Second Shift asks Entra what the person holds now.

## What it reads

All requests are `GET` requests to `https://graph.microsoft.com/v1.0`, sent
with an app-only token (client credentials). Nothing is written.

| What | Request | Permission (application) | Why |
| --- | --- | --- | --- |
| The Second Shift app and its app roles | `GET /servicePrincipals/{id}?$select=id,appRoles` (or `/servicePrincipals(appId='{appId}')`) | `Application.Read.All` | To match an assignment's role id to the app role's value, such as `SecondShift.Approver`. |
| Who was assigned a role | `GET /servicePrincipals/{id}/appRoleAssignedTo` | `Application.Read.All` | The users and groups holding each role. |
| Who is in an assigned group | `GET /groups/{id}/members` | `GroupMember.ReadBasic.All` | A role given to a group applies to its direct members. |
| People for the owner list | `GET /users?$filter=startswith(...)&$select=id,displayName,mail,userPrincipalName,jobTitle` | `User.Read.All` | Needed only for the owner list. Leave it out and the list says it cannot search; roles still work. |

Documentation:

- Get servicePrincipal: https://learn.microsoft.com/en-us/graph/api/serviceprincipal-get?view=graph-rest-1.0
- List appRoleAssignedTo: https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-approleassignedto?view=graph-rest-1.0
- List group members: https://learn.microsoft.com/en-us/graph/api/group-list-members?view=graph-rest-1.0
- List users: https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0
- Throttling: https://learn.microsoft.com/en-us/graph/throttling
- Groups and app roles (no nesting): https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/assign-user-or-group-access-portal

Things to know about these requests:

- **Nested groups do not count.** Entra does not pass an app role down to the
  members of a group inside the assigned group, and Second Shift does not
  either. Assign the role to the group the people are directly in.
- **Group assignment needs Microsoft Entra ID P1 or P2.** That is Microsoft's
  rule for giving app roles to groups.
- Answers come in pages of up to 999. Second Shift follows the paging links,
  but only while they stay on the same Graph address.
- A throttled answer (HTTP 429 or 503) is retried after the seconds Entra asks
  for, a few times at most and never longer than ten seconds at a time. If it
  does not clear, the lookup is treated as failed.
- The permissions are the smallest the documentation lists for these requests.
  A broader one (`Directory.Read.All`) also works but is not needed.
- Unconfirmed against a live tenant: that the search filter (`startswith` on
  name, email and sign-in name, combined with `or`, sent with
  `ConsistencyLevel: eventual`) is accepted exactly as written, and that group
  members come back with `@odata.type` set when only `GroupMember.ReadBasic.All`
  is granted. If either differs, the search or the group part reports a
  failure and no role is given.

## What an administrator sets up in Entra

1. Create (or reuse) an app registration for Second Shift to read the
   directory. It can be the one used for platform checks. Add a client secret.
2. Under API permissions add the **application** permissions in the table
   (`Application.Read.All`, `GroupMember.ReadBasic.All`, and `User.Read.All`
   if you want the owner list) and grant admin consent.
3. Put the tenant id, client id and secret in environment variables on the
   server (or mounted secrets). Second Shift's settings hold only their names.
4. Find the Second Shift sign-in application in Enterprise applications. Copy
   its **Object ID** (or use its Application (client) ID).

## Settings

In `~/.maverick/config.toml`:

```toml
[entra_directory]
enable = true
tenant_id_env = "SS_GRAPH_TENANT_ID"          # names of environment variables, never the values
client_id_env = "SS_GRAPH_CLIENT_ID"
client_secret_env = "SS_GRAPH_CLIENT_SECRET"
service_principal_id = "00000000-0000-0000-0000-000000000000"   # Object ID of the Second Shift enterprise application
# app_id = "..."                              # or its Application (client) ID; with neither, [auth.oidc] client_id is used
cache_minutes = 5                             # 0 to 60; default 5
```

`[auth.oidc.role_map]` must name the app role values and the Second Shift role
each stands for, as on [Roles from sign-in](sign-in-roles.md). A secret typed
into the settings instead of a variable name is refused, without repeating it.
`MAVERICK_ENTRA_DIRECTORY=1` or `=0` overrides `enable`.

## What changes when it is on

- **Teams cards.** A person with no role stored in Second Shift gets the role
  their current Entra app roles map to (the strongest one if they hold
  several). They receive cards, and their button presses are decided under the
  same rules as anyone else's: they need the approve permission, must be able
  to open the request, high and critical risk still need the acknowledgement,
  a protected settings change is still decided on the web page, and the
  person who asked may still have to leave a high-risk request to someone else.
- **A role stored for a person comes first.** The order is: administrator named
  in settings, role stored in Second Shift, role from group mapping, role from
  the person's own sign-in, then the role from the directory, then the default
  role.
- **Another approver.** People who hold an approving role only in Entra count
  when Second Shift asks whether someone else could decide.
- **Owner list.** On **Outside agents**, an administrator can type a name or
  email, choose a person, and the agent keeps their email and Entra object id.
  The list shows a display name, email and job title and stores nothing else.
  Typing an email works whether or not the directory is on.
- A person must be known to Second Shift to receive a card: linked to a Teams
  account by an administrator, or signed in once so Second Shift recorded
  their object id. Holding the app role alone is not enough.

## How fresh it is

Answers are kept in memory for `cache_minutes` (5 by default) and never
written to disk. If you remove a person's app role, they can still decide a
request for up to that long, then are refused. Set a lower number if that is
too long; `0` asks Entra every time. A failed lookup is remembered for 30
seconds (or the cache time, if shorter) so a broken connection is not retried
on every button press.

## When it is off or fails

- **Off:** nothing is read, no request is sent, and Teams and the approver
  rule behave as before: only people with a role stored in Second Shift (or the
  default role) are counted.
- **Failing** (wrong secret, missing permission, Entra not reachable, an
  answer in an unexpected shape, or more people than the limits below): the
  answer is "no role" and "nobody". Nobody is let through on a guess. People
  with a stored role are unaffected. The server log records one plain line
  with no token or secret.
- Limits for one lookup: 80 requests, 60 seconds, 10,000 role assignments,
  50 assigned groups, 50,000 people. A tenant over a limit gets no directory
  roles until the limit is no longer crossed; assign the roles through fewer
  groups, or ask for the limits to be changed.
- **The owner list** says it could not search and asks for a typed email.

## If it does not work

1. Check the Second Shift log for a line starting `entra directory:`. It names
   the problem in words: refused sign-in (client id, secret or expiry), refused
   request (a permission not granted or not consented), no such application
   (`service_principal_id` or `app_id`), or network rules.
2. Check that the secret has not expired and consent was granted.
3. Make sure the person has been linked to Teams or has signed in.
4. Remember the cache: changes in Entra reach Second Shift within
   `cache_minutes`.

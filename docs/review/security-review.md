# Second Shift security review

Reviewed `7cb5f63587f5d17b24c8a2b410fcd4f80a21f353` from
`claude/friendly-shannon-e8jwva`. This review covers the sign-in and agent
gateway boundaries, approval decisions, outbound requests, secret handling,
and access to Ekko data. Findings are marked **SUSPECTED** when supported by
source inspection. The verification column describes defensive regression
checks. Existing tests were run against local fixtures.

## Findings

| ID | Severity and status | Finding and source | Defensive verification | Suggested fix |
| --- | --- | --- | --- | --- |
| 1 | Medium · SUSPECTED | An open browser session carries the mapped Second Shift role. The request-time check only asks whether that role still appears anywhere in the current map. An Entra assignment change or the removal of one of two mappings to the same role can leave the old privilege active until local revocation or session expiry. [Session claims](../../maverick_dashboard/oidc_login.py#L711), [role capture](../../maverick_dashboard/sign_in_roles.py#L204), [role recheck](../../maverick_dashboard/sign_in_roles.py#L243). | Extend the existing sign-in-role revocation test to require that removing a role's original mapping invalidates the claim even when another mapping grants the same role. Verify that the operational process for Entra assignment changes also revokes affected Second Shift sessions. | Bind a session to the exact originating role claim and re-evaluate the current map on every request. Use directory-driven session revocation or a deliberately short privilege lifetime for Entra assignment changes. |
| 2 | Medium · SUSPECTED | The gateway's two request-signature schemes attest the body but omit the HTTP method and target. The durable replay ledger rejects a second use of a claim. It does not establish that the first use was addressed to the intended endpoint or resource. A party able to intercept an unused signed request could change its meaning without possessing the signing key. TLS and the existing ownership checks still matter. [Gateway verification](../../maverick_dashboard/external_gateway.py#L204), [HMAC validation](../../maverick/external_identity.py#L447), [Ed25519 message](../../maverick/external_identity.py#L488). | Add verifier conformance cases requiring a signature to be valid only for its original method, path, query and audience. Keep the existing single-use nonce regression. | Version both signing formats and include the deployment audience, canonical method, path, security-relevant query values, agent identity, timestamp, nonce and body digest. Keep the replay ledger and retire the older formats. |
| 3 | Medium · SUSPECTED | The external gateway's body-reading pool is shared by all clients before agent authentication. Slow or unreliable clients can hold reader slots that enrolled agents need. The timeout and semaphore cap individual reads and memory use. Identity-based rate limits run after the shared read, and the counters are per-process. [Reader capacity](../../maverick_dashboard/app.py#L762), [middleware ordering](../../maverick_dashboard/app.py#L827), [rate limits](../../maverick_dashboard/external_gateway.py#L53). | Extend the existing body-timeout test to assert that valid agent traffic still gets timely service when unauthenticated requests are stalled. Verify independent edge connection limits and a shared quota if deploying several gateway workers. | Add edge limits on connections, header size, request rate and body read time. Reject obviously absent or invalid credentials before reading the body where the credential scheme permits it. Bound pre-authentication concurrency separately from admitted traffic. |
| 4 | Low · SUSPECTED | The browser write guard compares network locations and ignores the scheme. The logout guard already compares full origins. The impact for a TLS-only deployment using secure cookies is limited. Deployments that share a host across schemes or accept an unexpected proxy host need stronger checks. [Browser write guard](../../maverick_dashboard/app.py#L883), [logout guard](../../maverick_dashboard/oidc_login.py#L783). | Extend the existing full-origin logout test cases to cover ordinary browser writes and an explicitly configured public origin behind a proxy. | Share one normalized scheme, host and port check based on the configured public origin or a trusted proxy. Preserve rejection of missing headers and retain narrowly scoped bearer exceptions. |
| 5 | Low · SUSPECTED | External API validation errors can include raw rejected input, outside of the special routes that redact it. Accidental credentials in rejected fields can be copied into caller error logs or diagnostics. The gateway's accepted-body redaction does not cover these errors. [Screen input model](../../maverick_dashboard/external_gateway.py#L120), [validation response](../../maverick_dashboard/app.py#L1368). | Add a response contract for the external gateway that forbids submitted values in validation errors and permits a fixed field name and message. | Rebuild errors from allowlisted field names and fixed messages. Omit Pydantic's raw input, custom error context and input-derived path segments. |
| 6 | Medium · SUSPECTED | Alerts can use an SMTP connection configured with TLS disabled. A configured SMTP username still triggers authentication and the notification contents still go over that connection. Enabling this mode on an untrusted network exposes credentials and alert text. [TLS modes](../../maverick/notifications.py#L281), [transport](../../maverick/notifications.py#L356), [send](../../maverick/notifications.py#L419). | Using the existing fake SMTP transport, assert that every configuration with a username refuses delivery when TLS is disabled. | Require verified TLS before authentication. If a local plaintext relay is supported, forbid credentials there and restrict the destination to an explicitly trusted local relay. |
| 7 | Low · SUSPECTED | After one successful break-glass audit record, the bearer path skips the audit backend for up to an hour in that process. A later audit outage in the same window may leave shared-credential requests active without an audit admission check. [Sampling branch](../../maverick_dashboard/auth.py#L879), [bearer admission](../../maverick_dashboard/auth.py#L1023). | Extend the audit-availability contract for break-glass requests to cover an outage that starts after a successful audit event. Assert that the request fails closed. | Require a durable admission record per break-glass use or independently check audit health for every request. At a minimum, audit sensitive state changes individually. |

## Controls checked

- **Sign-in and privileges.** The callback validates the signed transaction
  cookie, state, nonce and token before creating a session. Existing tests
  cover transaction replay, logout revocation and session expiry. The app
  filters query strings in callback access records. The authorization dependency
  resolves explicit bearers before browser identity. The break-glass token is
  a shared unscoped credential and its use audit is sampled once per process
  per hour. Treat the sample as evidence of use during the window
  ([break-glass audit](../../maverick_dashboard/auth.py#L869)).
  Reviewed local, tenant and claim-role precedence in
  [auth.py](../../maverick_dashboard/auth.py), [rbac.py](../../maverick_dashboard/rbac.py)
  and [sign_in_roles.py](../../maverick_dashboard/sign_in_roles.py).
- **Outside agents.** Existing tests cover bearer rejection, signed-credential
  replay, rate limits, and timed and oversized bodies. The gateway test
  `test_screen_flow_and_approval_poll_over_http` verifies that another
  agent's approval reads as missing. Live-run heartbeats and completion also
  check agent ownership ([live run ownership](../../maverick/external_agents.py#L1173)).
- **Approvals.** Existing tests reject an unrelated origin, an outside
  agent's decision attempt, a wrong binding on a decision, and approval of
  an expired card. Polling validates ownership, provenance and the card's
  current authority. The poll currently allows an omitted binding. The
  screening decision is advisory for an action performed outside Second
  Shift. The integration must remember and submit its original binding,
  enforce expiry and avoid reusing a positive result. The server-controlled
  execution path has additional checks
  ([poll](../../maverick/external_agents.py#L1780),
  [execution](../../maverick/external_agents.py#L2648)).
- **Outbound requests and secrets.** For the reviewed platform HTTP calls,
  existing tests verify DNS pinning, blocking private addresses by default,
  refusing redirects, bounding response reads, and discarding error bodies
  or secret-bearing record labels. Teams uses the pinned client and suppresses
  the webhook address in connection logs. These controls are separate from
  the SMTP behavior above
  ([platform fetch](../../maverick/agent_watch.py#L473),
  [Teams delivery](../../maverick/notifications.py#L248),
  [DNS pinning](../../maverick/tools/_ssrf.py#L242)).
- **Ekko.** The recording store is constructed with the authenticated owner,
  tenant and requested device. Record reads filter on all three and decrypt
  in the corresponding scope. Existing tests check shared-database
  isolation and rejection of ciphertext copied across owner scopes. The
  review found no evidence of cross-user recording disclosure in these
  paths ([route ownership](../../maverick_dashboard/ekko_routes.py#L130),
  [event reads](../../maverick/work_discovery_store.py#L2157)).

## Verification

The full suite passed in both default and secure-default postures with
3,467 passed and 83 skipped in each.
Ruff passed. Checks used local fixtures without a PostgreSQL DSN. Live
Entra, vendor services, and multi-replica ingress behavior remain unverified.

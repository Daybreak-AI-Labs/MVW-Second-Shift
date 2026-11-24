# Sign Second Shift external agent requests

The TypeScript and .NET kits use the agent's bearer access key. Use this
contract for a client enrolled with HMAC or an Ed25519 public key instead.

Set `SECOND_SHIFT_PUBLIC_URL` to the Second Shift public HTTPS origin.
For version 2, send the following headers with the exact body bytes.

| Header | Value |
| --- | --- |
| `X-Second-Shift-Signature-Version` | `2` |
| `X-Second-Shift-Agent-Id` | Enrolled agent ID |
| `X-Second-Shift-Timestamp` | Unix time in seconds as text |
| `X-Second-Shift-Nonce` | Fresh unpredictable text for each request, at most 128 UTF-8 bytes |
| `X-Second-Shift-Signature` | For HMAC, `sha256=` followed by the lowercase hexadecimal MAC |
| `X-Second-Shift-Request-Signature` | For Ed25519, the signature as 128 hexadecimal digits |

Sign the ASCII encoding of a compact JSON array whose entries are all
strings. Escape non-ASCII characters as JSON Unicode escapes, use no spaces
between entries, and preserve this order.

1. `second-shift-external-request-v2`
2. `hmac` or `ed25519`
3. Agent ID
4. Timestamp as sent
5. Nonce as sent
6. HTTP method, such as `POST`
7. Raw percent-encoded request path, including any mounted prefix
8. Raw query string with no leading question mark, or the empty string
9. Public origin with lowercase host, no path, and no default port
10. Lowercase hexadecimal SHA-256 of the exact request body

For HMAC, compute HMAC-SHA-256 with the shared secret and these message
bytes. For Ed25519, sign the message bytes with the enrolled key's private
half. Send only the signature header for the scheme in use. Preserve path
encoding and query order from the signer to the service. The server checks
freshness and consumes the nonce in its durable ledger before admitting
the request.

New managed enrollments require version 2 when using signatures. Existing
entries without a version policy may still use version 1 during migration,
and the agent page identifies entries with that compatibility flag. Set
`allow_legacy_signatures = false` in `[external_agents]` to refuse version 1
for the whole deployment. A manually managed Agent Trust entry can also
set its own `allow_legacy_signatures` boolean. The installation-wide policy
takes precedence.

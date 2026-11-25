# Security changes for Claude to review

- [PR #9](https://github.com/Daybreak-AI-Labs/MVW-Second-Shift/pull/9), `deploy/azure/register-entra.sh` and `deploy/azure/register_entra.py` — sets up the Entra identity and optional permissions and transfers its client secret to Key Vault.
- [PR #10](https://github.com/Daybreak-AI-Labs/MVW-Second-Shift/pull/10), `deploy/azure/app.bicep` and `deploy/azure/teams.bicep` — deploys a single-tenant bot and exposes its named vault secret to the service identity when Teams is enabled.
- [PR #12](https://github.com/Daybreak-AI-Labs/MVW-Second-Shift/pull/12), `deploy/azure/check-deployment.sh` and `deploy/azure/check_deployment.py` — optionally reads a temporary administrator credential from Key Vault and uses it to check enrollment and key minting.

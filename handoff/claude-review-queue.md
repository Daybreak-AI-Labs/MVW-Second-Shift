# Security changes for Claude to review

- [PR #9](https://github.com/Daybreak-AI-Labs/MVW-Second-Shift/pull/9), `deploy/azure/register-entra.sh` and `deploy/azure/register_entra.py` — sets up the Entra identity and optional permissions and transfers its client secret to Key Vault.
- [PR #10](https://github.com/Daybreak-AI-Labs/MVW-Second-Shift/pull/10), `deploy/azure/app.bicep` and `deploy/azure/teams.bicep` — deploys a single-tenant bot and exposes its named vault secret to the service identity when Teams is enabled.
- [PR #12](https://github.com/Daybreak-AI-Labs/MVW-Second-Shift/pull/12), `deploy/azure/check-deployment.sh` and `deploy/azure/check_deployment.py` — optionally reads a temporary administrator credential from Key Vault and uses it to check enrollment and key minting.
- [PR #13](https://github.com/Daybreak-AI-Labs/MVW-Second-Shift/pull/13), `tools/load_check.py` — creates synthetic credentials for a loopback-only app and discards the local test database and login after each run.
- [PR #14](https://github.com/Daybreak-AI-Labs/MVW-Second-Shift/pull/14), `deploy/azure/service.toml`, `maverick/editable_settings.py`, `maverick/channel_approvals.py` and `maverick/safety/dual_control.py` — locks the Azure refusal policies and requires a different approver for every waiting request.

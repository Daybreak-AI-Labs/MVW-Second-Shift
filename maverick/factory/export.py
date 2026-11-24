"""Export packages: a released version of a factory agent, ready to run in one of three places, governed by
Second Shift from its first action.

* ``azure``   - a container for Azure Container Apps (the runtime, ``serve``).
* ``aws``     - an ARM64 container for Amazon Bedrock AgentCore Runtime (the same runtime, ``serve``).
* ``foundry`` - a prompt agent for Microsoft Foundry Agent Service, whose tools are the agent's skills served by
  a skills service (``serve-skills``) that screens every call with Second Shift first. Foundry runs the agent
  itself, so there is no runtime container for it.

A package holds the version's exact definition (``agent.json``), a copy of the runtime source, a container recipe,
the deployment files and a README with the exact steps. It never holds a secret: a definition names environment
variables, the deployment files name Key Vault or Secrets Manager secrets by NAME, and the agent's Second Shift
access key is minted by the caller and shown once, never written here (``mint_key`` in ``export_agent``).

Nothing here talks to Azure, AWS or Foundry. Documentation the files follow:

* Azure Container Apps secrets from Key Vault, and probes:
  https://learn.microsoft.com/azure/container-apps/manage-secrets and
  https://learn.microsoft.com/azure/container-apps/health-probes
* Bedrock AgentCore Runtime container contract (ARM64, port 8080, ``/ping``, ``/invocations``):
  https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-http-protocol-contract.html
  and deployment: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/getting-started-custom.html
  and the execution role: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-permissions.html
* Foundry prompt agent and OpenAPI tool:
  https://learn.microsoft.com/azure/foundry/agents/quickstarts/prompt-agent and
  https://learn.microsoft.com/azure/foundry/agents/how-to/tools/openapi
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import FactoryError, store
from . import definitions as defs

TARGETS = ("azure", "aws", "foundry")
TARGET_LABELS = {"azure": "Azure container", "aws": "AWS Bedrock AgentCore container", "foundry": "Microsoft Foundry agent"}
KEY_SURFACE = "rest"
SKILLS_KEY_ENV = "SECOND_SHIFT_SKILLS_KEY"
INBOUND_KEY_ENV = "SECOND_SHIFT_INBOUND_KEY"
PLACEHOLDER_SKILLS_URL = "https://SKILLS-SERVICE-ADDRESS.example.com"
PLACEHOLDER_CONNECTION = "<PROJECT-CONNECTION-RESOURCE-ID>"
_ZIP_TIME = (2020, 1, 1, 0, 0, 0)
_HTTPS = re.compile(r"https://[A-Za-z0-9][A-Za-z0-9.-]{0,252}(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?")


@dataclass(frozen=True)
class Package:
    target: str
    filename: str
    files: dict[str, bytes]

    def zip_bytes(self) -> bytes:
        root = self.filename.removesuffix(".zip")
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
            for name in sorted(self.files):
                info = zipfile.ZipInfo(f"{root}/{name}", _ZIP_TIME)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (0o644 << 16)
                archive.writestr(info, self.files[name])
        return out.getvalue()


# ---------------------------------------------------------------------------------------------------------------
# Names
# ---------------------------------------------------------------------------------------------------------------

def safe_name(value: str, *, limit: int = 40, lower: bool = True) -> str:
    text = re.sub(r"[^A-Za-z0-9]+", "-", str(value or "")).strip("-")[:limit].strip("-")
    return (text.lower() if lower else text) or "agent"


def secret_names(raw: dict[str, Any]) -> list[dict[str, str]]:
    """The secrets an exported agent needs, each as {purpose, env, name}: ``env`` is the environment variable the
    runtime reads it from (a name in the definition) and ``name`` the Key Vault or Secrets Manager secret to store
    it under. Names only."""
    base = safe_name(raw["id"], limit=48)
    out = [
        {"purpose": "The model key", "env": raw["model"]["api_key_env"], "name": f"{base}-model-key"},
        {"purpose": "The agent's Second Shift access key", "env": raw["governance"]["agent_key_env"], "name": f"{base}-second-shift-key"},
    ]
    search = search_key_env(raw)
    if search:
        out.append({"purpose": "The web search key", "env": search, "name": f"{base}-search-key"})
    return out


def search_key_env(raw: dict[str, Any]) -> str:
    """The environment variable the web search skill reads its key from, or "" when the agent has no search skill."""
    definition = defs.validate(raw)
    _d, _l, _m, skills = defs.runtime()
    bound = skills.resolve_skills(definition.skills).get("web_search")
    return bound.skill.settings["api_key_env"] if bound else ""


def key_destinations(target: str) -> list[str]:
    """Where the person stores the agent's Second Shift access key for a target, in plain words."""
    if target == "azure":
        return ["Put it in the Key Vault secret named in the README (the second-shift-key secret), as the README's step 2 shows."]
    if target == "aws":
        return ["Put it in the AWS Secrets Manager secret named in the README (the second-shift-key secret), as the README's step 2 shows."]
    return ["Put it in the Key Vault secret named in the README for the skills service (the second-shift-key secret), "
            "as the README's step 2 shows. The Foundry agent itself never holds it."]


# ---------------------------------------------------------------------------------------------------------------
# The runtime source
# ---------------------------------------------------------------------------------------------------------------

_RUNTIME_PYPROJECT = '''[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "second-shift-runtime"
version = "@@VERSION@@"
description = "A small agent runtime that asks Second Shift before every action."
requires-python = ">=3.11"
dependencies = ["httpx>=0.27,<1"]

[project.optional-dependencies]
office = ["python-docx>=1.1", "python-pptx>=1.0", "openpyxl>=3.1"]

[tool.setuptools.packages.find]
include = ["second_shift_runtime*"]
'''


def runtime_files() -> dict[str, bytes]:
    """The runtime's source as it is installed on this server, under ``runtime/``, with a project file to install it."""
    _d, _l, _m, _s = defs.runtime()
    import second_shift_runtime

    root = Path(second_shift_runtime.__file__).resolve().parent
    files: dict[str, bytes] = {}
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root.parent).as_posix()
        if "__pycache__" not in relative:
            files[f"runtime/{relative}"] = path.read_bytes()
    try:
        from importlib.metadata import version

        number = version("second-shift-runtime")
    except Exception:
        number = "0.1.0"
    files["runtime/pyproject.toml"] = _RUNTIME_PYPROJECT.replace("@@VERSION@@", number).encode()
    return files


# ---------------------------------------------------------------------------------------------------------------
# Container recipes
# ---------------------------------------------------------------------------------------------------------------

def _dockerfile(*, arm64: bool = False, aws_secrets: bool = False, skills: bool = False) -> str:
    platform = "--platform=linux/arm64 " if arm64 else ""
    extra = "RUN pip install --no-cache-dir 'boto3>=1.35'\nCOPY secret-names.json entrypoint.py /app/\n" if aws_secrets else ""
    entry = ('ENTRYPOINT ["python", "-m", "second_shift_runtime"]\nCMD ["serve-skills", "--definition", "/app/agent.json", "--host", "0.0.0.0", '
             '"--port", "8080", "--output", "/tmp/second-shift-skills", "--inbound-key-env", "' + SKILLS_KEY_ENV + '"]\n') if skills else ('ENTRYPOINT ["python", "/app/entrypoint.py"]\nCMD ["serve", "--definition", "/app/agent.json", "--host", "0.0.0.0", '
             '"--port", "8080", "--output", "/tmp/second-shift-output"]\n') if aws_secrets else (
        'ENTRYPOINT ["python", "-m", "second_shift_runtime"]\nCMD ["serve", "--definition", "/app/agent.json", "--host", "0.0.0.0", '
        '"--port", "8080", "--output", "/tmp/second-shift-output", "--inbound-key-env", "' + INBOUND_KEY_ENV + '"]\n')
    return f'''# Built from the Second Shift runtime source in ./runtime, with the [office] extra for the document skills.
FROM {platform}python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY runtime ./runtime
RUN pip install --no-cache-dir './runtime[office]' \\
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin secondshift
{extra}COPY agent.json /app/agent.json
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=4s --start-period=20s \\
    CMD ["python", "-c", "from urllib.request import urlopen; urlopen('http://127.0.0.1:8080/ping', timeout=3).close()"]
{entry}'''


_ENTRYPOINT = '''"""Container entry point for Amazon Bedrock AgentCore Runtime.

Reads the values of the secrets named in secret-names.json from AWS Secrets Manager (with the runtime's execution
role), puts each in the environment variable the agent definition names, then starts the Second Shift runtime. The
secrets are never written to disk and never printed. If one cannot be read, the container stops: an agent that
cannot reach Second Shift must not run.
"""
import json
import os
import sys


def load_secrets(client, names, environ):
    for variable, secret in names.items():
        answer = client.get_secret_value(SecretId=secret)
        value = answer.get("SecretString")
        if not value:
            raise RuntimeError("The secret named for " + variable + " has no text value.")
        environ[variable] = value


def main(argv=None, environ=None, client=None, execute=os.execvp):
    environ = os.environ if environ is None else environ
    with open("/app/secret-names.json", encoding="utf-8") as handle:
        names = json.load(handle)
    if client is None:
        import boto3

        client = boto3.client("secretsmanager")
    try:
        load_secrets(client, names, environ)
    except Exception as exc:
        print("Could not read a secret: " + type(exc).__name__, file=sys.stderr)
        return 1
    arguments = ["python", "-m", "second_shift_runtime", *(sys.argv[1:] if argv is None else argv)]
    execute("python", arguments)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


# ---------------------------------------------------------------------------------------------------------------
# Azure Bicep
# ---------------------------------------------------------------------------------------------------------------

_BICEP = '''// @@TITLE@@
// Creates one Azure Container App with its own user-assigned managed identity. The identity may read the named
// Key Vault secrets and pull the image; it can do nothing else. The file names secrets and holds no secret value.
// Container Apps secrets from Key Vault: https://learn.microsoft.com/azure/container-apps/manage-secrets
// Health probes: https://learn.microsoft.com/azure/container-apps/health-probes
targetScope = 'resourceGroup'

@description('Where to create the resources.')
param location string = resourceGroup().location

@description('Name of the Container App.')
param appName string = '@@APP_NAME@@'

@description('Resource ID of an existing Container Apps environment.')
param environmentId string

@description('Name of an existing Key Vault in this resource group that uses Azure role-based access control.')
param keyVaultName string

@description('Name of an existing container registry in this resource group.')
param registryName string

@description('Image and tag in that registry, for example @@IMAGE_EXAMPLE@@.')
param image string

@description('The address of Second Shift, starting with https://.')
param secondShiftUrl string
@@MODEL_PARAMS@@
@description('Whether the app can be reached from the internet. Leave false to keep it inside the Container Apps environment.')
param externalIngress bool = @@EXTERNAL@@

@@SECRET_PARAMS@@
var keyVaultSecretsUserRole = '4633458b-17de-408a-b874-0445c86b69e6'
var acrPullRole = '7f951dda-4ed3-4680-a7ca-43fe172d538d'

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: keyVaultName
}

resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = {
  name: registryName
}

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${appName}-identity'
  location: location
}

resource vaultAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: vault
  name: guid(vault.id, identity.id, keyVaultSecretsUserRole)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', keyVaultSecretsUserRole)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource registryAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: registry
  name: guid(registry.id, identity.id, acrPullRole)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPullRole)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource app 'Microsoft.App/containerApps@2024-03-01' = {
  name: appName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${identity.id}': {} }
  }
  properties: {
    managedEnvironmentId: environmentId
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: externalIngress
        targetPort: 8080
        transport: 'http'
        allowInsecure: false
      }
      registries: [
        { server: registry.properties.loginServer, identity: identity.id }
      ]
      secrets: [
@@SECRETS@@      ]
    }
    template: {
      scale: { minReplicas: 1, maxReplicas: 3 }
      containers: [
        {
          name: 'agent'
          image: '${registry.properties.loginServer}/${image}'
          resources: { cpu: json('0.5'), memory: '1Gi' }
          env: [
@@ENV@@          ]
          probes: [
            {
              type: 'Startup'
              httpGet: { path: '/ping', port: 8080 }
              periodSeconds: 5
              timeoutSeconds: 3
              failureThreshold: 30
            }
            {
              type: 'Liveness'
              httpGet: { path: '/ping', port: 8080 }
              periodSeconds: 15
              timeoutSeconds: 3
            }
            {
              type: 'Readiness'
              httpGet: { path: '/ping', port: 8080 }
              periodSeconds: 10
              timeoutSeconds: 5
            }
          ]
        }
      ]
    }
  }
  dependsOn: [vaultAccess, registryAccess]
}

output appFqdn string = app.properties.configuration.ingress.fqdn
output identityPrincipalId string = identity.properties.principalId
'''


def _bicep(raw: dict[str, Any], *, skills: bool) -> str:
    secrets = secret_names(raw)
    if skills:  # the skills service has no model; it has the agent's Second Shift key, the search key and its own key
        secrets = [s for s in secrets if s["purpose"] != "The model key"]
        secrets.append({"purpose": "The key Foundry sends to the skills service", "env": SKILLS_KEY_ENV,
                        "name": f"{safe_name(raw['id'], limit=48)}-skills-key"})
    else:
        secrets.append({"purpose": "The key callers must send to the agent", "env": INBOUND_KEY_ENV,
                        "name": f"{safe_name(raw['id'], limit=48)}-inbound-key"})
    params, secret_blocks, env_lines = [], [], []
    for item in secrets:
        symbol = _symbol(item["env"])
        params.append(f"@description('Key Vault secret holding {item['purpose'][0].lower() + item['purpose'][1:]}. A name, not the value.')\n"
                      f"param {symbol}SecretName string = '{item['name']}'\n")
        secret_blocks.append(f"        {{\n          name: '{_secret_ref(item['env'])}'\n"
                             f"          keyVaultUrl: '${{vault.properties.vaultUri}}secrets/${{{symbol}SecretName}}'\n"
                             "          identity: identity.id\n        }\n")
        env_lines.append(f"            {{ name: '{item['env']}', secretRef: '{_secret_ref(item['env'])}' }}\n")
    env_lines.append(f"            {{ name: '{raw['governance']['address_env']}', value: secondShiftUrl }}\n")
    model_params = ""
    if not skills:
        model_params = ("\n@description('The address of the model, for example https://<resource>.services.ai.azure.com/openai/v1.')\n"
                        "param modelEndpoint string\n")
        env_lines.append(f"            {{ name: '{raw['model']['endpoint_env']}', value: modelEndpoint }}\n")
    text = _BICEP
    for token, value in {
        "@@TITLE@@": ("Skills service for a Microsoft Foundry agent: " if skills else "Agent container: ") + raw["name"].replace("\n", " "),
        "@@APP_NAME@@": safe_name(raw["id"], limit=24) + ("-skills" if skills else ""),
        "@@IMAGE_EXAMPLE@@": f"{safe_name(raw['id'], limit=40)}:{safe_name(str(raw['version']), limit=16)}",
        "@@MODEL_PARAMS@@": model_params,
        "@@EXTERNAL@@": "true" if skills else "false",
        "@@SECRET_PARAMS@@": "\n".join(params) + "\n",
        "@@SECRETS@@": "".join(secret_blocks),
        "@@ENV@@": "".join(env_lines),
    }.items():
        text = text.replace(token, value)
    return text


def _symbol(env: str) -> str:
    parts = [p for p in re.split(r"[^A-Za-z0-9]+", env.lower()) if p]
    return parts[0] + "".join(p.capitalize() for p in parts[1:])


def _secret_ref(env: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", env.lower()).strip("-")[:60]


# ---------------------------------------------------------------------------------------------------------------
# Foundry
# ---------------------------------------------------------------------------------------------------------------

def foundry_agent_name(record: dict[str, Any]) -> str:
    return safe_name(record["agent_id"], limit=60)


def foundry_agent_body(record: dict[str, Any], version: dict[str, Any], skills_url: str, connection_id: str) -> dict[str, Any]:
    """The body of ``POST {project endpoint}/agents?api-version=v1`` for this version: a prompt agent on the model
    deployment, the definition's instructions and one OpenAPI tool, the skills service, authenticated through a
    project connection that holds the service's key.
    https://learn.microsoft.com/azure/foundry/agents/quickstarts/prompt-agent (create) and
    https://learn.microsoft.com/azure/foundry/agents/how-to/tools/openapi (the tool)"""
    definition, loop, _m, skills = defs.runtime()
    raw = version["definition"]
    parsed = defs.validate(raw)
    from second_shift_runtime.skills_service import build_openapi

    if not parsed.skills:
        raise FactoryError("This agent has no skills, so a Foundry agent would have nothing to call. "
                           "Add a skill and release a new version first.", 409)
    spec = build_openapi(parsed, skills_url)
    return {
        "name": foundry_agent_name(record),
        "description": str(raw.get("description") or raw["name"])[:500],
        "definition": {
            "kind": "prompt",
            "model": raw["model"]["deployment"],
            "instructions": raw["instructions"] + loop.DATA_NOTE,
            "tools": [{"type": "openapi", "openapi": {
                "name": "second_shift_skills",
                "description": f"The skills of {raw['name']}. Each call is checked with Second Shift before it runs.",
                "spec": spec,
                "auth": {"type": "project_connection", "security_scheme": {"project_connection_id": connection_id}}}}],
        },
    }


def check_skills_url(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if not _HTTPS.fullmatch(text):
        raise FactoryError("The skills service address must start with https:// and hold only the host name, and a path if any.", 422)
    return text.rstrip("/")


# ---------------------------------------------------------------------------------------------------------------
# READMEs
# ---------------------------------------------------------------------------------------------------------------

def _header(record: dict[str, Any], version: dict[str, Any], target: str) -> str:
    raw = version["definition"]
    return (f"# {raw['name']}, version {version['number']}: {TARGET_LABELS[target]}\n\n"
            f"This package was made by Second Shift from the released version {version['number']} of {raw['name']}.\n"
            "`agent.json` is that version's definition, unchanged. It holds the NAMES of environment variables, never a key.\n\n"
            f"* Definition digest (`config_digest`): `{version['config_digest']}`\n"
            f"* Second Shift agent id: `{record['agent_id']}`\n"
            f"* `agent.json` SHA-256: `{hashlib.sha256(_definition_bytes(version)).hexdigest()}`\n\n"
            "**No secret is in this package.** The agent's Second Shift access key is shown once on the version's page when you "
            "export; store it as step 2 says. Anyone with that key can act as the agent, so treat it like a password.\n\n"
            "The agent is governed from its first action: before each tool it asks Second Shift, waits when a person must approve, "
            "stops on the emergency stop, and reports each run. If Second Shift cannot be reached, nothing runs.\n\n")


def _secrets_table(secrets: list[dict[str, str]], store_name: str) -> str:
    rows = "\n".join(f"| {s['purpose']} | `{s['name']}` | `{s['env']}` |" for s in secrets)
    return f"| What | {store_name} secret name | Environment variable the agent reads |\n| --- | --- | --- |\n{rows}\n"


def _azure_steps(raw: dict[str, Any], secrets: list[dict[str, str]], *, skills: bool) -> str:
    base = safe_name(raw["id"], limit=40)
    image = f"{base}:{safe_name(str(raw['version']), limit=16)}"
    store_lines = "\n".join(f'az keyvault secret set --vault-name "$VAULT" --name {s["name"]} --value "<paste: {s["purpose"].lower()}>"' for s in secrets)
    extra = ("The skills key is a long random string you make now (for example `openssl rand -base64 32`). Foundry sends it to the "
             "skills service; the service checks it before anything else." if skills else
             "The inbound key is a long random string you make now (for example `openssl rand -base64 32`). Callers of "
             "`/invocations` send it as `Authorization: Bearer <key>`.")
    model_arg = "" if skills else " \\\n  modelEndpoint=\"<model address>\""
    return f'''## Steps

You need the Azure CLI, an Azure subscription, and these that already exist in one resource group: a Container Apps
environment, a Key Vault that uses Azure role-based access control, and a container registry.

```bash
RG="<resource group>"; VAULT="<key vault name>"; REGISTRY="<registry name>"
ENVIRONMENT_ID="$(az containerapp env show -g "$RG" -n "<environment name>" --query id -o tsv)"
```

1. **Open this folder** in a terminal. The container recipe is `Dockerfile`; it installs the runtime from `./runtime` with
   the document skills.

2. **Store the keys in Key Vault**, under the names below. {extra}

{_secrets_table(secrets, 'Key Vault')}
```bash
{store_lines}
```

3. **Build the image in your registry** (no local Docker needed):

```bash
az acr build --registry "$REGISTRY" --image {image} .
```

4. **Create the Container App.** `main.bicep` makes one Container App with its own user-assigned managed identity, which may
   read only the named secrets and pull the image. The keys reach the container as Container Apps secrets from Key Vault
   references, never as plain settings.

```bash
az deployment group create -g "$RG" --template-file main.bicep --parameters \\
  environmentId="$ENVIRONMENT_ID" keyVaultName="$VAULT" registryName="$REGISTRY" image="{image}" \\
  secondShiftUrl="https://<your Second Shift address>"{model_arg}
```

   The app is reachable only inside the Container Apps environment unless you pass `externalIngress=true`. Health probes
   use `GET /ping` on port 8080.

'''


def _readme_azure(record: dict[str, Any], version: dict[str, Any]) -> str:
    raw = version["definition"]
    secrets = secret_names(raw)
    return (_header(record, version, "azure") + _azure_steps(raw, secrets + [{
        "purpose": "The key callers must send to the agent", "env": INBOUND_KEY_ENV, "name": f"{safe_name(raw['id'], limit=48)}-inbound-key"}], skills=False) + f'''5. **Try it.** Send a task (from inside the environment, or with `externalIngress=true`):

```bash
curl -X POST "https://<app address>/invocations" -H "Authorization: Bearer <inbound key>" \\
  -H "Content-Type: application/json" -d '{{"prompt": "<a task>"}}'
```

   Then open **Outside agents** in Second Shift: `{record['agent_id']}` shows the run. Retire the agent in Second Shift to cut it off.

## What this does not do

* Second Shift does not deploy this for you: nothing here was pushed to Azure. Push to Azure Container Apps is not built in this version.
* The files were checked for shape and for secrets, but not deployed to a real Azure subscription by Second Shift.
''')


def _readme_aws(record: dict[str, Any], version: dict[str, Any]) -> str:
    raw = version["definition"]
    secrets = secret_names(raw)
    runtime_name = re.sub(r"[^A-Za-z0-9_]+", "_", f"{record['agent_id']}_v{version['number']}").strip("_")[:48]
    runtime_name = ("a" + runtime_name if not runtime_name[:1].isalpha() else runtime_name)[:48]
    store_lines = "\n".join(f'aws secretsmanager create-secret --name {s["name"]} --secret-string "<paste: {s["purpose"].lower()}>"' for s in secrets)
    env = {raw["governance"]["address_env"]: "https://<your Second Shift address>", raw["model"]["endpoint_env"]: "<model address>"}
    return (_header(record, version, "aws") + f'''## Steps

You need the AWS CLI (signed in to the account), Docker with buildx, and an AWS Region where Amazon Bedrock AgentCore is
available. Replace `<account id>` and `<region>` throughout.

The image must be **ARM64**: AgentCore Runtime runs only ARM64 containers, serving `GET /ping` and `POST /invocations` on
`0.0.0.0:8080`, which the runtime does. (https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-http-protocol-contract.html)

1. **Open this folder** in a terminal. `Dockerfile` installs the runtime from `./runtime` with the document skills.
   `entrypoint.py` reads the secrets below from AWS Secrets Manager when the container starts and passes them to the runtime
   as the environment variables the definition names.

2. **Store the keys in Secrets Manager**, under these names (the names are in `secret-names.json`):

{_secrets_table(secrets, 'Secrets Manager')}
```bash
{store_lines}
```

3. **Push the image to Amazon ECR:**

```bash
aws ecr create-repository --repository-name {safe_name(raw["id"], limit=60)} --region <region>
aws ecr get-login-password --region <region> | docker login --username AWS --password-stdin <account id>.dkr.ecr.<region>.amazonaws.com
docker buildx create --use
docker buildx build --platform linux/arm64 -t <account id>.dkr.ecr.<region>.amazonaws.com/{safe_name(raw["id"], limit=60)}:{version["number"]} --push .
```

4. **Create the execution role.** `trust-policy.json` lets AgentCore assume it; `execution-policy.json` is AWS's documented
   execution policy (https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-permissions.html) with the
   model-invocation statement replaced by permission to read only the secrets named above. Replace `<account id>` and
   `<region>` in both files first.

```bash
aws iam create-role --role-name {runtime_name}-role --assume-role-policy-document file://trust-policy.json
aws iam put-role-policy --role-name {runtime_name}-role --policy-name execution --policy-document file://execution-policy.json
```

5. **Create the AgentCore runtime.** The two values below are not secret. The model key and the agent's Second Shift key
   are NOT set here; the entry point reads them from Secrets Manager.

```bash
aws bedrock-agentcore-control create-agent-runtime --region <region> \\
  --agent-runtime-name {runtime_name} \\
  --agent-runtime-artifact '{{"containerConfiguration": {{"containerUri": "<account id>.dkr.ecr.<region>.amazonaws.com/{safe_name(raw["id"], limit=60)}:{version["number"]}"}}}}' \\
  --role-arn arn:aws:iam::<account id>:role/{runtime_name}-role \\
  --network-configuration '{{"networkMode": "PUBLIC"}}' \\
  --environment-variables '{json.dumps(env)}'
```

   Wait until the runtime's status is `READY`.

6. **Try it.** Calls are signed with AWS credentials (IAM), so the key is the caller's AWS identity, not a secret you manage:

```python
import boto3, json
client = boto3.client("bedrock-agentcore", region_name="<region>")
reply = client.invoke_agent_runtime(agentRuntimeArn="<runtime arn>", runtimeSessionId="<a session id of at least 33 characters>",
                                    payload=json.dumps({{"prompt": "<a task>"}}))
print(reply["response"].read().decode())
```

   Then open **Outside agents** in Second Shift: `{record['agent_id']}` shows the run.

## What this does not do

* Second Shift does not deploy this for you: nothing here was pushed to AWS. Push to AWS is not built in this version.
* The files were checked for shape and for secrets, but not deployed to a real AWS account by Second Shift.
* The session id length and the response-reading call follow AWS's sample (getting-started-custom); check them against the
  current page when you run it.
''')


def _readme_foundry(record: dict[str, Any], version: dict[str, Any], *, url_given: bool) -> str:
    raw = version["definition"]
    secrets = [s for s in secret_names(raw) if s["purpose"] != "The model key"]
    secrets.append({"purpose": "The key Foundry sends to the skills service", "env": SKILLS_KEY_ENV, "name": f"{safe_name(raw['id'], limit=48)}-skills-key"})
    name = foundry_agent_name(record)
    url_note = ("The skills service address you gave is already in `foundry-agent.json`." if url_given else
                f"`foundry-agent.json` holds `{PLACEHOLDER_SKILLS_URL}` as the skills service address. Replace it with the address "
                "from step 1 (in `servers` inside the tool's `spec`), or export again with the address filled in.")
    return (_header(record, version, "foundry") + f'''Microsoft Foundry runs this agent itself, so there is no agent container. What Second Shift can govern is
what the agent *does*: its tools are the skills service in `skills-service/`, which asks Second Shift before every call.
Foundry has no step that lets your code check a tool call before Foundry makes it
(https://learn.microsoft.com/azure/foundry/agents/how-to/tools/openapi), so **the agent must have no other tools**. Add a
tool in Foundry that does not go through the skills service and that tool is not governed.

## Steps

1. **Run the skills service in Azure.** Follow the steps in `skills-service/README.md` (it is the same container recipe as the
   Azure export, started as `serve-skills`). It needs the Second Shift key, the search key (if the agent searches) and a
   key of your choosing that Foundry will send, stored as:

{_secrets_table(secrets, 'Key Vault')}
   The service's address is the `appFqdn` the deployment prints (it is created reachable from the internet, because Foundry
   calls it; it checks the key before anything else).

2. **Store the agent's Second Shift access key.** It is shown once on the version's page when you export. Put it in the
   `...-second-shift-key` secret above. It is not in this package and the Foundry agent never holds it.

3. **Create a project connection in Foundry** that holds the skills key. In the Foundry portal, open your project, add a
   connection of type **Custom keys** with key `x-api-key` (it must match the file's security scheme) and the skills key as
   the value. Note the connection's full resource ID, which looks like
   `/subscriptions/<subscription>/resourceGroups/<group>/providers/Microsoft.CognitiveServices/accounts/<account>/projects/<project>/connections/<name>`.
   (https://learn.microsoft.com/azure/foundry/agents/how-to/tools/openapi, "Authenticate with API key")

4. **Create the agent.** {url_note} Put the connection's resource ID in `foundry-agent.json` where it says
   `{PLACEHOLDER_CONNECTION}` (`tools[0].openapi.auth.security_scheme.project_connection_id`). Then either use **Push to
   Foundry** on the version's page in Second Shift (if an administrator turned it on), or create the agent yourself:

```bash
TOKEN="$(az account get-access-token --resource https://ai.azure.com --query accessToken -o tsv)"
curl --fail-with-body -X POST "https://<resource>.services.ai.azure.com/api/projects/<project>/agents?api-version=v1" \\
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" --data @foundry-agent.json
```

   The model deployment named in the file (`{raw['model']['deployment']}`) must exist in the project.

5. **Link it in Second Shift.** Second Shift's platform check recognises the agent as `foundry:<resource>/<project>/{name}`. Push
   sets this link for you; if you created the agent by hand, set it as the agent's platform link on the Outside agents page, so
   a change made in Foundry shows up as a change to the agent.

## What is and is not governed

* Governed: every skill call (screened first, approval waited for, emergency stop obeyed, reported). Calls are grouped into one
  run that ends after two quiet minutes.
* Not governed by Second Shift: what the model says, and its cost. The model runs inside Foundry, so the run report shows cost 0.
  The step, time and cost limits in the definition are enforced by the runtime, not by Foundry.
* The agent's instructions in Foundry are the definition's instructions plus one sentence telling the model to treat tool
  results as data. Anyone who can edit the agent in Foundry can change them; the platform check reports that as a change.

## What this does not do

* Nothing here was run against a real Foundry project or Azure subscription by Second Shift.
* The exact REST body for an OpenAPI tool inside an agent definition is not shown as REST on Microsoft's page (it is shown
  for toolboxes and the SDK). `foundry-agent.json` uses the same tool shape; check it against the page if Foundry refuses it.
''')


# ---------------------------------------------------------------------------------------------------------------
# The packages
# ---------------------------------------------------------------------------------------------------------------

def _definition_bytes(version: dict[str, Any]) -> bytes:
    return (json.dumps(version["definition"], indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _trust_policy() -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": [{
        "Sid": "AssumeRolePolicy", "Effect": "Allow", "Principal": {"Service": "bedrock-agentcore.amazonaws.com"}, "Action": "sts:AssumeRole",
        "Condition": {"StringEquals": {"aws:SourceAccount": "<account id>"},
                      "ArnLike": {"aws:SourceArn": "arn:aws:bedrock-agentcore:<region>:<account id>:*"}}}]}, indent=2) + "\n"


def _execution_policy(raw: dict[str, Any]) -> str:
    account, region = "<account id>", "<region>"
    secrets = [f"arn:aws:secretsmanager:{region}:{account}:secret:{s['name']}-*" for s in secret_names(raw)]
    name = safe_name(raw["id"], limit=48)
    return json.dumps({"Version": "2012-10-17", "Statement": [
        {"Sid": "ECRImageAccess", "Effect": "Allow", "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
         "Resource": [f"arn:aws:ecr:{region}:{account}:repository/*"]},
        {"Effect": "Allow", "Action": ["logs:DescribeLogStreams", "logs:CreateLogGroup"],
         "Resource": [f"arn:aws:logs:{region}:{account}:log-group:/aws/bedrock-agentcore/runtimes/*"]},
        {"Effect": "Allow", "Action": ["logs:DescribeLogGroups"], "Resource": [f"arn:aws:logs:{region}:{account}:log-group:*"]},
        {"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": [f"arn:aws:logs:{region}:{account}:log-group:/aws/bedrock-agentcore/runtimes/*:log-stream:*"]},
        {"Sid": "ECRTokenAccess", "Effect": "Allow", "Action": ["ecr:GetAuthorizationToken"], "Resource": "*"},
        {"Effect": "Allow", "Action": ["xray:PutTraceSegments", "xray:PutTelemetryRecords", "xray:GetSamplingRules", "xray:GetSamplingTargets"],
         "Resource": ["*"]},
        {"Effect": "Allow", "Action": "cloudwatch:PutMetricData", "Resource": "*",
         "Condition": {"StringEquals": {"cloudwatch:namespace": "bedrock-agentcore"}}},
        {"Sid": "GetAgentAccessToken", "Effect": "Allow",
         "Action": ["bedrock-agentcore:GetWorkloadAccessToken", "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
                    "bedrock-agentcore:GetWorkloadAccessTokenForUserId"],
         "Resource": [f"arn:aws:bedrock-agentcore:{region}:{account}:workload-identity-directory/default",
                      f"arn:aws:bedrock-agentcore:{region}:{account}:workload-identity-directory/default/workload-identity/{name}-*"]},
        {"Sid": "ReadNamedSecrets", "Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"], "Resource": secrets},
    ]}, indent=2) + "\n"


def _skills_service_files(record: dict[str, Any], version: dict[str, Any], base: dict[str, bytes]) -> dict[str, bytes]:
    """The skills service folder: the same container recipe as the Azure export, started as ``serve-skills``."""
    raw = version["definition"]
    files = {f"skills-service/{k}": v for k, v in base.items()}
    files["skills-service/Dockerfile"] = _dockerfile(skills=True).encode()
    files["skills-service/main.bicep"] = _bicep(raw, skills=True).encode()
    secrets = [s for s in secret_names(raw) if s["purpose"] != "The model key"]
    secrets.append({"purpose": "The key Foundry sends to the skills service", "env": SKILLS_KEY_ENV,
                    "name": f"{safe_name(raw['id'], limit=48)}-skills-key"})
    files["skills-service/README.md"] = (
        f"# Skills service for {raw['name']}\n\nThis is the container that serves the agent's skills to Microsoft Foundry. "
        "It is the Azure container recipe, started as `serve-skills`. No secret is in this folder.\n\n"
        + _azure_steps(raw, secrets, skills=True) + "The service address is the `appFqdn` output. Check it with `GET <address>/ping`.\n").encode()
    return files


def build(record: dict[str, Any], version: dict[str, Any], target: str, *, skills_url: str = "", connection_id: str = "") -> Package:
    """The package for one released version and one target."""
    if target not in TARGETS:
        raise FactoryError(f"The export target must be one of: {', '.join(TARGETS)}.", 422)
    if version["state"] != "released":
        raise FactoryError("Only the released version can be exported.", 409)
    skills_url = check_skills_url(skills_url)
    raw = version["definition"]
    defs.validate(raw)  # a package is never made from a definition the runtime would refuse
    name = f"second-shift-{safe_name(record['agent_id'], limit=40)}-v{version['number']}-{target}"
    files = runtime_files()
    files["agent.json"] = _definition_bytes(version)
    if target == "azure":
        files["Dockerfile"] = _dockerfile(arm64=False, aws_secrets=False).encode()
        files["main.bicep"] = _bicep(raw, skills=False).encode()
        files["README.md"] = _readme_azure(record, version).encode()
    elif target == "aws":
        files["Dockerfile"] = _dockerfile(arm64=True, aws_secrets=True).encode()
        files["entrypoint.py"] = _ENTRYPOINT.encode()
        files["secret-names.json"] = (json.dumps({s["env"]: s["name"] for s in secret_names(raw)}, indent=2) + "\n").encode()
        files["trust-policy.json"] = _trust_policy().encode()
        files["execution-policy.json"] = _execution_policy(raw).encode()
        files["README.md"] = _readme_aws(record, version).encode()
    else:
        body = foundry_agent_body(record, version, skills_url or PLACEHOLDER_SKILLS_URL, connection_id or PLACEHOLDER_CONNECTION)
        files = {"agent.json": files["agent.json"],
                 "foundry-agent.json": (json.dumps(body, indent=2) + "\n").encode(),
                 "skills-openapi.json": (json.dumps(body["definition"]["tools"][0]["openapi"]["spec"], indent=2) + "\n").encode(),
                 "README.md": _readme_foundry(record, version, url_given=bool(skills_url)).encode(),
                 **_skills_service_files(record, version, {k: v for k, v in files.items()})}
    return Package(target, f"{name}.zip", files)


def describe(package: Package) -> dict[str, Any]:
    data = package.zip_bytes()
    return {"target": package.target, "filename": package.filename, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "files": sorted(package.files)}


def export_version(fac_id: str, number: int, target: str, *, skills_url: str = "", connection_id: str = "") -> tuple[Package, dict[str, Any]]:
    record = store.get(fac_id)
    version = store.find_version(record, number)
    return build(record, version, target, skills_url=skills_url, connection_id=connection_id), version


# ---------------------------------------------------------------------------------------------------------------
# One export: the package, and the access key when asked
# ---------------------------------------------------------------------------------------------------------------

def export_agent(fac_id: str, number: int, target: str, who: str, *, mint_key: bool = False, skills_url: str = "",
                 connection_id: str = "", mint_authority: object | None = None, mint_approval_id: int | None = None) -> dict[str, Any]:
    """Make the package for a released version and, when ``mint_key`` is set, a new access key for the agent.

    The key is minted only after the package was made, so a refused export never replaces a key. It is returned in
    this result and nowhere else: it is not in the package, a record, an audit entry or a log. Minting replaces the
    agent's current key (the old one stops working). The caller must already have checked that the person is an
    administrator."""
    import base64

    from maverick import external_agents

    package, version = export_version(fac_id, number, target, skills_url=skills_url, connection_id=connection_id)
    record = store.get(fac_id)
    enrollment = record.get("enrollment") or {}
    if mint_key and (enrollment.get("status") != "enrolled" or enrollment.get("enrolled_version") != number):
        raise FactoryError("Only the released version's agent is enrolled in Second Shift, so a key can be made only for it.", 409)
    if not _audit("factory_export_requested", record, number, target, who, key_requested=mint_key):
        raise FactoryError("The audit log could not take a record of this export, so nothing was made.", 503)
    out = {**describe(package), "package_base64": base64.b64encode(package.zip_bytes()).decode("ascii"), "key": None}
    if mint_key:
        try:
            token = external_agents.mint_token(record["agent_id"], KEY_SURFACE, minted_by=who, mint_approval_id=mint_approval_id,
                                               mint_authority=mint_authority)
        except external_agents.MintApprovalPending:
            raise
        except external_agents.ExternalAgentsError as exc:
            raise FactoryError(f"The access key could not be made: {exc}", 409) from exc
        out["key"] = {"value": token, "surface": KEY_SURFACE, "shown_once": True, "where_to_store": key_destinations(target),
                      "secret_names": [s["name"] for s in secret_names(version["definition"]) if s["purpose"].startswith("The agent's")],
                      "note": "This is the only time the key is shown. It replaces the agent's earlier key, which no longer works."}
    _audit("factory_export_made", record, number, target, who, key_minted=bool(mint_key), package_sha256=out["sha256"])
    return out


def _audit(kind: str, record: dict[str, Any], number: int, target: str, who: str, **payload: Any) -> bool:
    """One audit entry: ids, the target, who and what was done; never a key or a package."""
    from maverick.audit import audit_event

    return bool(audit_event(kind, agent="factory", factory_agent=record["id"], external_agent=record["agent_id"], version=number,
                            target=target, requested_by=who, **payload))

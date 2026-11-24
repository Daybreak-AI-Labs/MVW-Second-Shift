"""Build the Microsoft 365 installable package with deployment identifiers."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID
from zipfile import ZIP_DEFLATED, ZipFile

_PACKAGED_JSON = ("manifest.json", "declarative-agent.json", "api-plugin.json", "openapi.json")
_ICONS = ("color.png", "outline.png")


def https_address(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise argparse.ArgumentTypeError("Use a public HTTPS address without embedded credentials.")
    return value


def origin(value: str) -> str:
    parsed = urlsplit(https_address(value))
    if parsed.path not in {"", "/"} or parsed.query:
        raise argparse.ArgumentTypeError("Use the public Second Shift origin without a path or query.")
    return value.rstrip("/")


def application_uri(value: str) -> str:
    parsed = urlsplit(value)
    if (parsed.scheme not in {"https", "api"} or not parsed.netloc or parsed.username
            or parsed.password or parsed.fragment or parsed.query):
        raise argparse.ArgumentTypeError("Use the Entra application ID URI from the SSO registration.")
    return value.rstrip("/")


def auth_config_id(value: str) -> str:
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,200}", value):
        raise argparse.ArgumentTypeError("Use the Microsoft Entra SSO registration ID.")
    return value


def substitute(value, settings: dict[str, str]):
    if isinstance(value, str):
        for key, replacement in settings.items():
            value = value.replace(key, replacement)
        return value
    if isinstance(value, dict):
        return {substitute(key, settings): substitute(item, settings) for key, item in value.items()}
    if isinstance(value, list):
        return [substitute(item, settings) for item in value]
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", required=True, type=origin)
    parser.add_argument("--package-id", required=True, type=UUID)
    parser.add_argument("--tenant-id", required=True, type=UUID)
    parser.add_argument("--application-id-uri", required=True, type=application_uri)
    parser.add_argument("--auth-config-id", required=True, type=auth_config_id)
    parser.add_argument("--privacy-url", required=True, type=https_address)
    parser.add_argument("--terms-url", required=True, type=https_address)
    parser.add_argument("--output", type=Path, default=Path("second-shift-copilot.zip"))
    args = parser.parse_args()
    folder = Path(__file__).resolve().parent
    tokens = {
        "__ORIGIN__": args.origin, "__HOST__": urlsplit(args.origin).hostname,
        "__PACKAGE_ID__": str(args.package_id), "__TENANT_ID__": str(args.tenant_id),
        "__SCOPE__": args.application_id_uri + "/SecondShift.Copilot.Read",
        "__AUTH_CONFIG_ID__": args.auth_config_id, "__PRIVACY_URL__": args.privacy_url, "__TERMS_URL__": args.terms_url,
    }
    with ZipFile(args.output, "w", compression=ZIP_DEFLATED) as package:
        for name in _PACKAGED_JSON:
            template = json.loads((folder / name).read_text(encoding="utf-8"))
            package.writestr(name, json.dumps(substitute(template, tokens), ensure_ascii=False, indent=2) + "\n")
        for name in _ICONS:
            package.write(folder / name, name)
    print(f"Created {args.output}")


if __name__ == "__main__":
    main()

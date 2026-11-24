"""Build the Second Shift Teams app package (a zip of manifest and icons).

    python teams-app/build_package.py --bot-app-id <Microsoft App ID> --hostname <host> [--out second-shift-teams.zip]

``--hostname`` is where Second Shift is reached, without ``https://`` (for
example ``secondshift.contoso.com``). The package holds no secret. Upload it in
Teams (see docs/teams-approvals.md). Standard library only.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
GUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
HOST = re.compile(r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}")


def render(bot_app_id: str, hostname: str) -> str:
    if not GUID.fullmatch(bot_app_id):
        raise SystemExit("The bot app id must be the Microsoft App ID, a GUID such as 00000000-0000-0000-0000-000000000000.")
    if not HOST.fullmatch(hostname):
        raise SystemExit("Give the host name only, such as secondshift.contoso.com (no https:// and no path).")
    text = (HERE / "manifest.template.json").read_text(encoding="utf-8")
    text = text.replace("{{BOT_APP_ID}}", bot_app_id.lower()).replace("{{HOSTNAME}}", hostname.lower())
    json.loads(text)  # refuse to write a manifest that is not valid JSON
    return text


def build(bot_app_id: str, hostname: str, out: Path) -> Path:
    manifest = render(bot_app_id, hostname)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as package:
        package.writestr("manifest.json", manifest)
        package.write(HERE / "color.png", "color.png")
        package.write(HERE / "outline.png", "outline.png")
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bot-app-id", required=True)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--out", default="second-shift-teams.zip")
    args = parser.parse_args(argv)
    print(build(args.bot_app_id, args.hostname, Path(args.out)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env bash
set +x
set -euo pipefail
exec python3 "$(dirname -- "${BASH_SOURCE[0]}")/check_deployment.py" "$@"

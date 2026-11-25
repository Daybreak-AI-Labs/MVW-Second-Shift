#!/usr/bin/env bash
# The Python helper uses Azure CLI only. The password stays in memory and a pipe.
set +x
set -euo pipefail
exec python3 "$(dirname -- "${BASH_SOURCE[0]}")/register_entra.py" "$@"

#!/bin/bash
# Run pytest on the VM mirror with the environment the suite expects.
# Usage: vm_pytest.sh <basetemp-suffix> [test paths...]
set -u
suffix="${1:-base}"
shift || true
cd /home/rjq/work/strix-ctf-agent || exit 1
export TMP="/home/rjq/pt_${suffix}"
export TEMP="$TMP"
export PYTHONPATH="$PWD/src:$PWD/vendor/src"
mkdir -p "$TMP"
if [ "$#" -eq 0 ]; then
  set -- tests
fi
.venv/bin/python -m pytest "$@" -q -p no:cacheprovider --basetemp="$TMP/b" 2>&1 | tail -25
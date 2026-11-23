#!/bin/sh
# Isolated pinned-manager investigation; no CPA server or real credentials.
set -eu
task_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
task_tmp=$(mktemp -d)
trap 'rm -rf "$task_tmp"' EXIT
cat > "$task_tmp/go.mod" <<'MOD'
module example.invalid/relay-readiness-repro

go 1.26.10

require github.com/router-for-me/CLIProxyAPI/v8 v8.0.63
MOD
cd "$task_tmp"
GOTOOLCHAIN=go1.26.10 GOFLAGS=-mod=mod timeout 180s go run "$task_root/tests/stock_readiness_repro.go"

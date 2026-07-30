#!/usr/bin/env bash
# Runs the test suite inside a privileged Linux container.
# bpf(2) needs CAP_BPF/CAP_SYS_ADMIN, hence --privileged.
set -euo pipefail
cd "$(dirname "$0")/.."

exec docker run --rm --privileged \
  -v "$PWD":/src -w /src \
  -v nbpf-nuget:/root/.nuget/packages \
  -e DOTNET_CLI_TELEMETRY_OPTOUT=1 \
  mcr.microsoft.com/dotnet/sdk:8.0 \
  dotnet test tests/Ebpf.Core.Tests -l "console;verbosity=normal" "$@"

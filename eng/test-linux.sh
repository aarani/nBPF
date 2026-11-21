#!/usr/bin/env bash
# Runs the test suite inside a Linux container with the privileges bpf(2) needs
# (CAP_BPF/CAP_SYS_ADMIN). Uses Apple's `container` on macOS when installed, docker
# otherwise — see eng/container-runtime.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
source eng/container-runtime.sh

# A named volume keeps the NuGet cache across runs.
if [ "$CONTAINER_RUNTIME" = container ]; then
    container volume inspect nbpf-nuget >/dev/null 2>&1 || container volume create nbpf-nuget >/dev/null
fi

exec "$CONTAINER_RUNTIME" run --rm "${BPF_PRIVILEGE[@]}" \
  -v "$PWD":/src -w /src \
  -v nbpf-nuget:/root/.nuget/packages \
  -e DOTNET_CLI_TELEMETRY_OPTOUT=1 \
  mcr.microsoft.com/dotnet/sdk:10.0 \
  dotnet test tests/Nbpf.Core.Tests -l "console;verbosity=normal" "$@"

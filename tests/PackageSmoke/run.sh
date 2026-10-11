#!/usr/bin/env bash
# Restores, builds and runs two console apps against packed RealTree.Authzn and RealTree.Authzn.CSharp packages, as
# a consumer installs them: from a package source, with only their declared dependencies. The C#
# app references RealTree.Authzn.CSharp alone, so it also runs on the FSharp.Core version RealTree.Authzn declares.
#
# Usage: tests/PackageSmoke/run.sh <folder holding RealTree.Authzn.*.nupkg and RealTree.Authzn.CSharp.*.nupkg>
set -euo pipefail

feed="$(cd "$1" && pwd)"
here="$(cd "$(dirname "$0")" && pwd)"

package="$(ls "$feed"/RealTree.Authzn.CSharp.*.nupkg | head -n 1)"
version="$(basename "$package" .nupkg)"
version="${version#RealTree.Authzn.CSharp.}"

# A private package folder, so a package of the same version restored earlier is not reused.
packages="$(mktemp -d)"
trap 'rm -rf "$packages"' EXIT

for project in "$here/CSharp/PackageSmoke.CSharp.csproj" "$here/FSharp/PackageSmoke.FSharp.fsproj"; do
    dotnet restore "$project" -p:AuthznVersion="$version" --packages "$packages" \
        --source "$feed" --source https://api.nuget.org/v3/index.json
    dotnet run --project "$project" -c Release --no-restore -p:AuthznVersion="$version"
done

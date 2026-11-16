#!/usr/bin/env bash
# Packs what installer/build-binaries.sh staged into the release tarball
# a router's updater installs (release.TarballName), and lists its
# checksum in SHA256SUMS -- unsigned: the CI's `release` environment
# signs it (scripts/sign-sums.sh), and nothing else ever holds the key.
#
#   installer/package-release.sh STAGE_DIR OUT_DIR
#
# The tarball is the same bytes for the same stage: entries sorted, owned
# by root, every mtime SOURCE_DATE_EPOCH (the commit's time in CI), gzip
# without a name or time. Everything in it sits under fr_os-<VERSION>/.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE="$(cd "${1:?usage: package-release.sh STAGE_DIR OUT_DIR}" && pwd)"
OUT="${2:?usage: package-release.sh STAGE_DIR OUT_DIR}"
VERSION="$(cat "$REPO_ROOT/VERSION")"
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "error: VERSION is not X.Y.Z: $VERSION" >&2
    exit 1
fi
name="fr_os-$VERSION-amd64.tar.gz"

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
tar --create --format=gnu --sort=name --owner=0 --group=0 --numeric-owner \
    --mtime="@${SOURCE_DATE_EPOCH:-0}" --transform="s,^\\.,fr_os-$VERSION," \
    -C "$STAGE" . | gzip -9 -n > "$OUT/$name"
(cd "$OUT" && sha256sum "$name" > SHA256SUMS)
cat "$OUT/SHA256SUMS"

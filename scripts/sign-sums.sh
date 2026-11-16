#!/bin/sh
# Signs a SHA256SUMS file with the release key, in CI (docs/RELEASING.md),
# as 1.x's scripts/sign-sums.sh:
#
#   SIGNING_KEY=<PEM> RELEASE_TAG=<tag or empty> scripts/sign-sums.sh DIR/SHA256SUMS
#
# Writes DIR/SHA256SUMS.sig (Ed25519, `openssl pkeyutl -rawin`), then
# checks it the way a router will: the key's public half must be one this
# very commit ships (release/keys/), and release.VerifyRelease must accept
# every file the list names (go run ./release/verify). A release signed
# with any other key would be refused by every router, so it isn't
# published.
#
# Only the jobs of .github/workflows/build-installer.yml that run in the
# `release` environment get SIGNING_KEY (the FROS_RELEASE_SIGNING_KEY
# secret). Without it a test build stays unsigned -- but a release
# (RELEASE_TAG set) never does.
set -eu

sums="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
if [ -z "${SIGNING_KEY:-}" ]; then
    if [ -n "${RELEASE_TAG:-}" ]; then
        echo "::error::release_tag is set but the FROS_RELEASE_SIGNING_KEY secret is not -- refusing to publish an unsigned release (docs/RELEASING.md)"
        exit 1
    fi
    echo "::notice::no FROS_RELEASE_SIGNING_KEY secret: $sums stays unsigned (fine for a test build, not for a release)"
    exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
umask 077
printf '%s\n' "$SIGNING_KEY" > "$work/release.key"
openssl pkeyutl -sign -rawin -inkey "$work/release.key" -in "$sums" -out "$sums.sig"
openssl pkey -in "$work/release.key" -pubout -outform DER > "$work/release.der"
rm -f "$work/release.key"
chmod 0644 "$sums.sig"

repo="$(cd "$(dirname "$0")/.." && pwd)"
shipped=""
for key in "$repo"/release/keys/*.pem; do
    openssl pkey -pubin -in "$key" -outform DER > "$work/shipped.der"
    if cmp -s "$work/release.der" "$work/shipped.der"; then
        shipped="$key"
    fi
done
if [ -z "$shipped" ]; then
    echo "::error::the signing key's public half is not in release/keys/"
    exit 1
fi
(cd "$repo" && go run ./release/verify "$sums")

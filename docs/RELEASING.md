# Releasing FR_OS

A router installs an update only if the release is signed with a key it
trusts (`release`, 1.x's `frfw.release_signing`). Each release carries:

| Asset | What it is |
|---|---|
| `FR_OS-<version>-amd64.iso` | the installer / live image |
| `fr_os-<version>-amd64.tar.gz` | the programs, the XDP object, the scripts and the units, as `installer/build-binaries.sh` stages them (`installer/package-release.sh`): what the image installs and what the updater installs |
| `SHA256SUMS` | sha256 of both |
| `SHA256SUMS.sig` | Ed25519 signature over `SHA256SUMS` |

The updater (`apply.Updater`: the Update screen through the
update-helper, `firewall-cli update apply`, and `fr-update-check.timer`
for a security release when `update.auto_install_security` is on)
downloads the tarball, `SHA256SUMS` and the signature from the release's
tag (`https://github.com/<repo>/releases/download/v<version>/`), or takes
them from its cache, `/opt/fr_os/releases/<version>/`. It checks the
signature against the public keys compiled into the version *already
installed* (`release/keys/`) and the tarball against the signed
checksum, and only then unpacks it -- regular files and directories
only, every path inside one top directory `fr_os-<version>/` -- and
checks it is an FR_OS 2 release of that version. It installs the
programs and scripts into `/usr/libexec/fr_os-releases/<version>/`, the
units and drop-ins into `/etc`, switches `/usr/libexec/fr_os` (a symlink)
to the new directory in one rename, and restarts what runs from it. The
release before stays installed beside it, and its files stay in the
cache, so a rollback (the Update screen, or `firewall-cli update
rollback`) needs no network; the cache is verified again on every use.

It installs only a version newer than the one running (ROADMAP SEC-12),
so release versions must always go up: a fix to an old line ships as a
new, higher version.

## Versions and betas

A version is `X.Y.Z`, or `X.Y.Z-beta.N` for a beta of it: `2.0.0-beta.1`
comes before `2.0.0-beta.2`, which comes before `2.0.0`, which comes
before `2.0.1-beta.1`. A beta is released exactly as a release is (the
review record `docs/reviews/v2.0.0-beta.1.md`, the tag `v2.0.0-beta.1`,
the workflow with `release_tag` = `v2.0.0-beta.1`), and signed with the
same key. Mark its GitHub release as a *pre-release*: GitHub's "latest
release", which the Update screen and the periodic check ask for, never
is one, so routers aren't offered a beta. Install it from its ISO, or on
a router that runs an older version with
`firewall-cli update apply 2.0.0-beta.1`. A router on a beta is offered
the final release once it is published.

## One-time setup: the signing key

Do this on your own machine, not in CI, and keep the private key offline.
On Linux, or in Windows PowerShell with Git's OpenSSL
(`& "C:\Program Files\Git\usr\bin\openssl.exe" ...`):

```bash
openssl genpkey -algorithm ed25519 -out fros-release-2.key
openssl pkey -in fros-release-2.key -pubout -out fros-release-2.pem
```

1. Commit `fros-release-2.pem` (the **public** key) as
   `release/keys/fros-release-2.pem`. `go test ./release/` checks every
   file there is an Ed25519 public key.
2. In GitHub: *Settings → Environments → New environment*, name
   `release`. Under *Deployment branches and tags* choose *Selected
   branches and tags* and add the tag rule `v*`. Where the plan offers
   it, also tick *Required reviewers* and add yourself.
3. In that environment: *Environment secrets → Add environment secret*,
   name `FROS_RELEASE_SIGNING_KEY`, value: the whole content of
   `fros-release-2.key` (the **private** key, including the BEGIN/END
   lines). Not a repository secret: every job of every workflow can read
   those (1.x's review v0.2.1 FR-NEW-002). Only the two signing jobs of
   the release workflow use the `release` environment, and GitHub hands
   them its secret only for a `v*` tag.
4. Store `fros-release-2.key` somewhere safe and offline, in two places,
   and delete it from the machine. Anyone who has it can publish updates
   that every router installs as root; whoever loses it can sign no
   update the routers in the field accept.

Until a public key is committed, every build refuses every update -- on
purpose.

## Before tagging: the adversarial review (J2)

Every release is reviewed by at least two different AI models before it
is tagged (security-lessons J2); one model's blind spots are rarely
another's.

1. Pick the commit you mean to release and have each model review it.
   Save each report as `docs/reviews/v<VERSION>-<MODEL>.md`.
2. Triage the reports into one record, `docs/reviews/v<VERSION>.md`,
   starting from [reviews/TEMPLATE.md](reviews/TEMPLATE.md): the
   reviewed commit, the models, and one table row per distinct finding
   with its severity and status. Check each finding against the code:
   reviews overstate and miss things.
3. Close every **critical** and **high** finding: `fixed` (with the
   commit or PR), `accepted` (with the reason), `not a bug` or
   `duplicate`. Medium and low findings may stay open as issues.
4. Merge the record to `main` with the version bump.

The release workflow enforces this: before it builds anything it runs
`go run ./release/reviewgate <VERSION>`, which refuses the release when
the record is missing, names fewer than two models, reviewed a commit
that isn't part of this release or is older than the previous release,
or still has an open critical or high finding. Run it locally first:

```bash
go run ./release/reviewgate 2.0.0
```

## Publishing a release

1. Set the version in `VERSION` (`X.Y.Z`; `installer/build-binaries.sh`
   stamps it into every Go program as `version.Version`), and merge it to
   `main` together with the review record.
2. Create the GitHub release with its tag (`vX.Y.Z`) on that commit.
3. Run the *Build installer ISO* workflow **from the tag** ("Use workflow
   from" → *Tags* → `vX.Y.Z`) with `release_tag` = `vX.Y.Z`. A release is
   built from exactly the commit its tag names: the first job refuses a
   run from a branch, one whose checkout isn't the tag's commit, or one
   whose `VERSION` isn't the tag's, then checks the review record.
4. The two jobs in the `release` environment:
   - `sign-stage` signs the `SHA256SUMS` of the release tarball the first
     job packed. The ISO is then built -- with no access to the key --
     from exactly that tarball, carries it with its signature under
     `/opt/fr_os/releases/<VERSION>/`, and is boot-tested.
   - `publish` signs the published `SHA256SUMS` of the ISO and the
     tarball and uploads the four assets to the release; it is the only
     job that may write to the repository.

   Both signatures go through `scripts/sign-sums.sh`, which checks that
   the signing key's public half is one this commit ships and that the
   router's own check (`go run ./release/verify`) accepts every file.

A run without `release_tag` -- from a branch or a pull request -- never
touches the `release` environment. It makes a key of its own for the
run, trusted by that run's image only (`release/keys/boot-test.pem`,
never committed), and signs two tarballs with it: the image's own, and
the next version's beta built from the same commit (`FROS_TEST_VERSION`,
which nothing else uses). The boot test installs the second from the
Update screen and rolls back to the first; the key is deleted before
the job ends. The ISO's own `SHA256SUMS` stays unsigned.
Every action the workflow uses is pinned to a commit
(`installer/release_test.go`).

Users can check a download with OpenSSL and the public key:

```bash
openssl pkeyutl -verify -pubin -inkey release/keys/fros-release-2.pem -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
sha256sum -c --ignore-missing SHA256SUMS
```

## Security releases

A release that fixes a vulnerability must say so, so routers can tell
(security-lessons G10/J3): put **`[security]` in the release title** (for
example `v2.0.1 [security]`), or a line `Security: yes` in its notes. The
webUI then shows a "Security update available" banner.

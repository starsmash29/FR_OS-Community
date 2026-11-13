#!/bin/sh
# Records FR_OS 1.x's XDP program (bpf/xdp_sni_filter.c at the commit in
# reference/PIN) as the reference the aya port must reproduce: compiles
# it with 1.x's own build script, has the kernel run every frame of
# reference/test_fros_xdp_cases.py through it (BPF_PROG_TEST_RUN) and
# writes testdata/reference/xdp.jsonl. Loading a program needs root,
# which reference/generate.sh refuses on purpose, so this is its own
# step; it records nothing but the XDP cases. Needs root, clang and
# libbpf (libbpf-dev). Run it from the repository root after
# generate.sh, with the same 1.x clone.
#
#   sudo reference/generate-xdp.sh [path-to-a-FR_OS-1.x-clone]
set -eu

[ "$(id -u)" = 0 ] || { echo "loading a BPF program needs root" >&2; exit 1; }
root=$(pwd)
pin=$(cat reference/PIN)
src=${1:-}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

if [ -z "$src" ]; then
	git clone --quiet --filter=blob:none https://github.com/starsmash29/FR_OS-pblk.git "$work/fr_os-1"
	src="$work/fr_os-1"
fi
git -C "$src" -c advice.detachedHead=false checkout --quiet "$pin"
git -C "$src" diff --quiet HEAD -- || { echo "the 1.x checkout has local changes" >&2; exit 1; }

out="$work/out"
(
	cd "$src"
	TZ=UTC FROS_CAPTURE_DIR="$out" FROS_XDP_REQUIRED=1 PYTHONPATH="src:$root/reference" \
		python3 -m pytest -p fros_capture "$root/reference/test_fros_xdp_cases.py" \
			-q -p no:cacheprovider >"$work/pytest.log" 2>&1 || { tail -40 "$work/pytest.log" >&2; exit 1; }
)
[ -s "$out/xdp.jsonl" ] || { tail -20 "$work/pytest.log" >&2; exit 1; }
mkdir -p testdata/reference
cp "$out/xdp.jsonl" testdata/reference/
python3 - "$out/summary.json" testdata/reference/summary.json <<'PY'
import json, sys
new = json.load(open(sys.argv[1]))
path = sys.argv[2]
summary = json.load(open(path))
summary["xdp"] = new["xdp"]
open(path, "w").write(json.dumps(summary, indent=2, sort_keys=True) + "\n")
PY
echo "xdp: $(wc -l <testdata/reference/xdp.jsonl) cases"

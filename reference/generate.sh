#!/bin/sh
# Records FR_OS 1.x's behaviour as the reference FR_OS 2 must reproduce
# (AGENTS.md, "Differential tests"): checks out the Python FR_OS at the
# commit in reference/PIN, runs its own test suite with the capture
# plugin, and writes testdata/reference/. Run it from the repository root;
# commit the result together with any change of PIN. Run it as an
# ordinary user, not root: root-only 1.x tests would add cases, and the
# recorded set should not depend on who generated it. TZ=UTC: an expiry
# with no zone is read in the machine's, so the recording says which.
#
#   reference/generate.sh [path-to-a-FR_OS-1.x-clone]
set -eu

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
	TZ=UTC FROS_CAPTURE_DIR="$out" PYTHONPATH="src:$root/reference" \
		python3 -m pytest -p fros_capture tests "$root/reference/test_fros_edge_cases.py" \
			"$root/reference/test_fros_yaml_cases.py" "$root/reference/test_fros_helper_cases.py" \
			"$root/reference/test_fros_ruleset_cases.py" "$root/reference/test_fros_render_cases.py" \
			"$root/reference/test_fros_apply_cases.py" "$root/reference/test_fros_webui_cases.py" \
			"$root/reference/test_fros_tlsfp_cases.py" "$root/reference/test_fros_appid_cases.py" \
			"$root/reference/test_fros_aiids_cases.py" "$root/reference/test_fros_iot_cases.py" \
			"$root/reference/test_fros_xdpuser_cases.py" "$root/reference/test_fros_tlsfpd_cases.py" \
			--ignore=tests/webui -q -p no:cacheprovider >"$work/pytest.log" 2>&1 || true
)
[ -s "$out/summary.json" ] || { tail -20 "$work/pytest.log" >&2; exit 1; }
mkdir -p testdata/reference
# The XDP cases need root and come from reference/generate-xdp.sh: keep
# their count.
xdp=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1])).get("xdp", 0))' testdata/reference/summary.json 2>/dev/null || echo 0)
cp "$out/config.jsonl" "$out/ruleset.jsonl" "$out/yaml.jsonl" "$out/yaml_config.jsonl" "$out/helper.jsonl" \
	"$out/render.jsonl" "$out/apply.jsonl" "$out/webui.jsonl" "$out/qr.jsonl" "$out/tlsfp.jsonl" "$out/appid.jsonl" \
	"$out/aiids.jsonl" "$out/iot.jsonl" "$out/xdpuser.jsonl" "$out/tlsfpd.jsonl" "$out/summary.json" \
	testdata/reference/
echo "$pin" >testdata/reference/PIN
python3 - "$xdp" testdata/reference/summary.json <<'PY'
import json, sys
path = sys.argv[2]
summary = json.load(open(path))
summary["xdp"] = int(sys.argv[1])
open(path, "w").write(json.dumps(summary, indent=2, sort_keys=True) + "\n")
PY
cat testdata/reference/summary.json

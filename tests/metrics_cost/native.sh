#!/usr/bin/env bash
# Run only in a fresh /tmp directory containing source.tar and an external control.patch.
set -euo pipefail

if [ "$#" -ne 1 ]; then
    printf 'usage: native.sh RUN_ROOT (containing source.tar and an external control.patch)\n' >&2
    exit 2
fi

run_root=$(cd -- "$1" && pwd)
case "$run_root" in /tmp/mcrelay-metrics-cost-*) ;; *) exit 2 ;; esac
if [ ! -s "$run_root/source.tar" ] || [ ! -s "$run_root/control.patch" ]; then
    printf 'Place source.tar and the matching archived control patch as control.patch in RUN_ROOT.\n' >&2
    exit 2
fi
exec </dev/null >"$run_root/run.log" 2>&1
trap 'run_status=$?; printf "%s\n" "$run_status" >"$run_root/status"' EXIT
date -Is
cat /etc/os-release
uname -a
gcc --version
git --version
cmake --version
python3 --version
systemd --version
findmnt -T "$run_root"
sha256sum "$run_root/source.tar" "$run_root/control.patch"
printf 'building\n' >"$run_root/phase"
mkdir "$run_root/normal" "$run_root/control" "$run_root/raw"
tar -xf "$run_root/source.tar" -C "$run_root/normal"
tar -xf "$run_root/source.tar" -C "$run_root/control"
cd "$run_root/control"
patch --batch --fuzz=0 -p1 <"$run_root/control.patch" >"$run_root/control-apply.log"

cost_flags="-Wall -Wextra -Wshadow -Wpedantic -Werror -g -fstack-usage"
for variant in normal control; do
    cmake -S "$run_root/$variant" -B "$run_root/$variant-build" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
        -DCMAKE_C_FLAGS="$cost_flags" >"$run_root/$variant-configure.log" 2>&1
    cmake --build "$run_root/$variant-build" -j"$(nproc)" >"$run_root/$variant-build.log" 2>&1
    "$run_root/$variant-build/mcrelay" version
    nm "$run_root/$variant-build/mcrelay" >"$run_root/$variant-nm.txt"
    strings "$run_root/$variant-build/mcrelay" >"$run_root/$variant-strings.txt"
done
cmake -S "$run_root/normal/tests/metrics_cost" -B "$run_root/tools-build" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS="$cost_flags -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2" \
    -DCMAKE_EXE_LINKER_FLAGS="-pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack" >"$run_root/tools-configure.log" 2>&1
cmake --build "$run_root/tools-build" -j"$(nproc)" >"$run_root/tools-build.log" 2>&1
cd "$run_root/normal"
python3 tests/metrics_cost/layouts.py --normal "$run_root/normal-build/mcrelay" --control "$run_root/control-build/mcrelay" --output "$run_root/raw/layouts.json"
python3 - "$run_root" <<'PY'
from pathlib import Path
import hashlib, json, re, subprocess, sys
root = Path(sys.argv[1])
for variant in ['normal', 'control']:
    symbols = (root / (variant + '-nm.txt')).read_text()
    strings = (root / (variant + '-strings.txt')).read_text()
    assert not re.search(r'listener_test_|MCRELAY_TEST_|__wrap_|resolver_supervisor_test_', symbols + strings)
    if variant == 'control':
        assert not re.search(r'\b(?:listener_metrics_|resolver_.*metrics_|metrics_counter_add)', symbols)
flags = {variant: [line for line in (root / (variant + '-build/CMakeFiles/mcrelay.dir/flags.make')).read_text().splitlines()
                   if line.startswith(('C_FLAGS =', 'C_DEFINES ='))] for variant in ['normal', 'control']}
assert flags['normal'] == flags['control'], flags
record = {'source_archive_sha256': hashlib.sha256((root / 'source.tar').read_bytes()).hexdigest(),
          'source_identity': (root / 'normal/cmake/archive-version.txt').read_text(),
          'control_patch_sha256': hashlib.sha256((root / 'control.patch').read_bytes()).hexdigest(),
          'binaries': {variant: hashlib.sha256((root / (variant + '-build/mcrelay')).read_bytes()).hexdigest() for variant in ['normal', 'control']}, 'flags': flags}
(root / 'raw/provenance.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record))
PY

cost_arguments=(--control "$run_root/control-build/mcrelay" --normal "$run_root/normal-build/mcrelay" --tools "$run_root/tools-build")
printf 'smoke\n' >"$run_root/phase"
python3 -u tests/metrics_cost/run.py smoke "${cost_arguments[@]}" --results "$run_root/raw/smoke" >"$run_root/smoke.log" 2>&1
printf 'suite\n' >"$run_root/phase"
python3 -u tests/metrics_cost/run.py suite "${cost_arguments[@]}" --results "$run_root/raw/suite" >"$run_root/suite.log" 2>&1
printf 'snapshots\n' >"$run_root/phase"
python3 -u tests/metrics_cost/snapshots.py --binary "$run_root/tools-build/snapshot_cost" --results "$run_root/raw/snapshots" >"$run_root/snapshots.log" 2>&1
printf 'cadence900\n' >"$run_root/phase"
python3 -u tests/metrics_cost/run.py cadence "${cost_arguments[@]}" --results "$run_root/raw/cadence" >"$run_root/cadence.log" 2>&1
printf 'analysis\n' >"$run_root/phase"
python3 tests/metrics_cost/analyze.py "$run_root/raw" >"$run_root/analysis.log" 2>&1
printf 'audit\n' >"$run_root/phase"
python3 tests/metrics_cost/audit.py "$run_root/raw" >"$run_root/audit.log" 2>&1
printf 'done\n' >"$run_root/phase"
date -Is

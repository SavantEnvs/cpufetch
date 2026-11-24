#!/usr/bin/env bash
#
# mayhem/test.sh — known-answer oracle for cpufetch (upstream ships no test suite).
# Runs the unsanitized KAT builds of the four harnesses (mayhem/out/kat_*, built by build.sh with
# plain -O1) on fixed inputs — recorded CPUID dumps and /proc + /sys files of real machines — and
# asserts the decoded fields cpufetch prints (microarchitecture, SoC, process node, cores, caches,
# frequency, colour escapes). A no-op/exit(0) program prints nothing, so every assertion fails.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}


OUT="$SRC/mayhem/out"
T="$SRC/mayhem"
passed=0; failed=0
export CPUFETCH_FUZZ_STDOUT=1   # the harness otherwise discards cpufetch's stdout

# check <name> <kat binary> <input> <extended regex expected in the ANSI-stripped stdout>...
check() {
  local name="$1" bin="$2" in="$3"; shift 3
  local out
  if [ ! -x "$bin" ] || [ ! -f "$in" ]; then
    echo "FAIL $name: missing $bin or $in"; failed=$((failed+1)); return
  fi
  out=$("$bin" "$in" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g')
  local re ok=1
  for re in "$@"; do
    if ! grep -Eq -- "$re" <<<"$out"; then echo "FAIL $name: no match for /$re/"; ok=0; fi
  done
  if [ $ok -eq 1 ]; then echo "PASS $name"; passed=$((passed+1)); else failed=$((failed+1)); fi
}
# raw variant: the regex is matched against stdout with escapes kept (colour tests)
check_raw() {
  local name="$1" bin="$2" in="$3" re="$4"
  local out=""
  # capture first: `bin | grep -q` lets grep close the pipe early, and pipefail then fails on SIGPIPE
  [ -x "$bin" ] && [ -f "$in" ] && out=$("$bin" "$in" 2>/dev/null)
  if grep -Eq -- "$re" <<<"$out"; then
    echo "PASS $name"; passed=$((passed+1))
  else
    echo "FAIL $name: no match for /$re/"; failed=$((failed+1))
  fi
}

# x86: CPUID decoding (Intel Cascade Lake under KVM)
check x86-intel-uarch "$OUT/kat_x86" "$T/fuzz_x86/testsuite/intel-kvm" \
  'Microarchitecture: +Cascade Lake' 'Technology: +14nm' 'Hypervisor: +KVM' \
  'L1d Size: +32KB' 'L2 Size: +1MB' 'L3 Size: +33MB' 'Max Frequency: +2\.800 GHz' 'AVX: +AVX,AVX2,AVX512'
check x86-intel-debug "$OUT/kat_x86" "$T/fuzz_x86/testsuite/intel-debug" \
  '^- Hypervisor: KVM' 'Max standard level: 0x0000000D' 'Max extended level: 0x80000008' 'CPUID dump: 0x00050657'
check x86-intel-raw "$OUT/kat_x86" "$T/fuzz_x86/testsuite/intel-raw" \
  '0x80000002 0x00: 0x20202020 0x20202020 0x49202020 0x6C65746E'
check x86-amd-unknown-hypervisor "$OUT/kat_x86" "$T/fuzz_x86/testsuite/amd-unknown-hv" \
  'Hypervisor: +Unknown' 'Microarchitecture: +K7'
# RISC-V: /proc/cpuinfo + device tree (StarFive VisionFive 2, Allwinner D1)
check riscv-visionfive2 "$OUT/kat_riscv" "$T/fuzz_riscv/testsuite/visionfive2" \
  'SoC: +StarFive VisionFive 2' 'Microarchitecture: +U74' 'Technology: +28nm' 'Cores: +2 cores' \
  'Max Frequency: +1\.500 GHz' 'Extensions: +rv64imafdc_zicntr_zicsr_zifencei_zihpm_zba_zbb' 'Peak Performance: +3\.00 GFLOP/s'
check riscv-allwinner-d1 "$OUT/kat_riscv" "$T/fuzz_riscv/testsuite/allwinner-d1" \
  'Technology: +22nm' 'Cores: +1 cores' '\(V\) Vector Operations'
# ARM: /proc/cpuinfo MIDR fields + device tree (Raspberry Pi 4)
check arm-rpi4 "$OUT/kat_arm" "$T/fuzz_arm/testsuite/rpi4" \
  'SoC: +Broadcom BCM2711' 'Microarchitecture: +Cortex-A72' 'Technology: +28nm' 'Cores: +4 cores' \
  'Max Frequency: +1\.500 GHz' 'Peak Performance: +24\.00 GFLOP/s'
check arm-biglittle "$OUT/kat_arm" "$T/fuzz_arm/testsuite/snapdragon-biglittle" 'Technology: +7nm' 'Cores: +4 cores'
# CLI: argv parsing (help, custom RGB colour scheme, styles)
check args-help "$OUT/kat_args" "$T/fuzz_args/testsuite/help" '^Usage: cpufetch \[OPTION\]\.\.\.'
check_raw args-custom-color "$OUT/kat_args" "$T/fuzz_args/testsuite/custom-color" '48;2;239;090;045m'
check args-default "$OUT/kat_args" "$T/fuzz_args/testsuite/default" 'Microarchitecture: +Cascade Lake'

emit_ctrf "cpufetch-kat" "$passed" "$failed" 0

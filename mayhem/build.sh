#!/usr/bin/env bash
# mayhem/build.sh — build cpufetch's fuzz targets and the KAT oracle binaries.
#
# cpufetch is one CLI binary per CPU architecture (upstream Makefile picks the backend from
# `uname -m`). The Makefile links a single executable with no hooks for a harness, so this script
# compiles the same source lists the Makefile uses, per backend, with two additions:
#   -include mayhem/harness/fuzzfs.h  routes open()/opendir()/getauxval() to the fuzz input
#   -Dmain=cpufetch_main on src/common/main.c, so the harness can drive the real main()
# and, for x86, src/x86/cpuid_asm.c (the `cpuid` instruction) is replaced by the harness's cpuid().
# Targets: fuzz_x86, fuzz_riscv, fuzz_arm, fuzz_args (+ *-standalone reproducers).
# Oracle: the same harnesses built with plain -O1 (no sanitizers) as /mayhem/out/kat_<arch>, run by test.sh.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${STANDALONE_FUZZ_MAIN:?STANDALONE_FUZZ_MAIN must point at the run-once driver (set by the base image)}"
cd "$SRC"

OUT="$SRC/mayhem/out"     # gitignored by mayhem/.gitignore
OBJ="$OUT/obj"
mkdir -p "$OBJ"

C=src/common
COMMON="$C/main.c $C/cpu.c $C/udev.c $C/printer.c $C/args.c $C/global.c $C/freq.c"
X86="$COMMON src/x86/cpuid.c src/x86/apic.c src/x86/uarch.c src/x86/freq/freq.c src/x86/freq/freq_nov.c src/x86/freq/freq_avx.c src/x86/freq/freq_avx512.c"
RISCV="$COMMON $C/soc.c src/riscv/riscv.c src/riscv/uarch.c src/riscv/soc.c src/riscv/udev.c"
ARM="$COMMON src/arm/midr.c src/arm/uarch.c $C/soc.c src/arm/soc.c $C/pci.c src/arm/udev.c src/arm/sve.c"

# compile <variant> <arch-define> <cflags> <sources...>: objects into $OBJ/<variant>/
compile() {
  local variant="$1" def="$2" flags="$3"; shift 3
  local d="$OBJ/$variant"; mkdir -p "$d"
  local pids=() f extra o
  for f in "$@"; do
    extra=""
    case "$f" in
      */main.c) extra="-Dmain=cpufetch_main" ;;
      */freq_avx.c) extra="-mavx" ;;
      */freq_avx512.c) extra="-mavx512f" ;;
    esac
    o="$d/$(echo "$f" | tr / _).o"
    # shellcheck disable=SC2086
    $CC $flags -std=c99 -D_GNU_SOURCE -pthread $def -Wno-unused-parameter \
        -I mayhem/harness/stub-include -include mayhem/harness/fuzzfs.h $extra -c "$f" -o "$o" &
    pids+=($!)
    if [ "${#pids[@]}" -ge "$MAYHEM_JOBS" ]; then wait "${pids[0]}"; pids=("${pids[@]:1}"); fi
  done
  for p in "${pids[@]}"; do wait "$p"; done
}

FUZZ_CFLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1"
KAT_CFLAGS="-O1 $COVERAGE_FLAGS"

$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.c -o "$OBJ/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/standalone_main.o"
$CC $KAT_CFLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/kat_main.o"

# target <name> <arch-define> <sources>
target() {
  local name="$1" def="$2" srcs="$3"
  local hdef="$def"; [ "$name" = fuzz_args ] && hdef="$def -DFUZZ_ARGS_ONLY"
  local bdir="$name"; [ "$name" = fuzz_args ] && bdir=fuzz_x86   # same project objects as fuzz_x86
  # shellcheck disable=SC2086
  [ "$name" = fuzz_args ] || compile "$bdir" "$def" "$FUZZ_CFLAGS" $srcs
  # shellcheck disable=SC2086
  $CC $FUZZ_CFLAGS -D_GNU_SOURCE $hdef -I mayhem/harness -c mayhem/harness/fuzz_cpufetch.c -o "$OBJ/$name.harness.o"
  $CC $FUZZ_CFLAGS $LIB_FUZZING_ENGINE -pthread "$OBJ/$name.harness.o" "$OBJ/$bdir"/*.o "$OBJ/lsan_off.o" -o "$OUT/$name"
  $CC $FUZZ_CFLAGS -pthread "$OBJ/standalone_main.o" "$OBJ/$name.harness.o" "$OBJ/$bdir"/*.o "$OBJ/lsan_off.o" -o "$OUT/$name-standalone"
  # Oracle build: the project's normal (unsanitized) code path behind the same harness.
  # shellcheck disable=SC2086
  [ "$name" = fuzz_args ] || compile "kat_$bdir" "$def" "$KAT_CFLAGS" $srcs
  # shellcheck disable=SC2086
  $CC $KAT_CFLAGS -D_GNU_SOURCE $hdef -I mayhem/harness -c mayhem/harness/fuzz_cpufetch.c -o "$OBJ/kat_$name.harness.o"
  $CC $KAT_CFLAGS -pthread "$OBJ/kat_main.o" "$OBJ/kat_$name.harness.o" "$OBJ/kat_$bdir"/*.o -o "$OUT/kat_${name#fuzz_}"
}

target fuzz_x86 -DARCH_X86 "$X86"
target fuzz_args -DARCH_X86 "$X86"
target fuzz_riscv -DARCH_RISCV "$RISCV"
target fuzz_arm -DARCH_ARM "$ARM"

ls -l "$OUT"/fuzz_x86 "$OUT"/fuzz_args "$OUT"/fuzz_riscv "$OUT"/fuzz_arm "$OUT"/kat_*

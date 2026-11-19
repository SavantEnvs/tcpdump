#!/usr/bin/env bash
#
# mayhem/build.sh — build tcpdump's fuzz targets and its functional test build.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. Uses upstream's own
# CMake build, out of tree, into three gitignored build dirs (mayhem/.gitignore):
#   mayhem/build-fuzz  tcpdump + libnetdissect.a, ASan+UBSan (halting) + SanCov, DWARF 3 (default config)
#   mayhem/build-smb   same, configured with -DENABLE_SMB=ON (the SMB printer is compiled out by default)
#   mayhem/build-test  tcpdump with the project's NORMAL flags, for mayhem/test.sh (upstream's TESTrun)
# and stages the fuzz binaries in mayhem/out/ (also gitignored):
#   mayhem/out/tcpdump, mayhem/out/tcpdump-smb      file-input CLI targets (`-r @@`)
#   mayhem/out/fuzz_mask62plen(+-standalone)        the legacy libFuzzer harness
# Re-runnable (a build dir is configured once per argument set, then rebuilt incrementally) and offline (deps are apt: libpcap,
# libssl).
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) so an explicit empty SANITIZER_FLAGS builds without sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
M="$SRC/mayhem"
OUT="$M/out"
mkdir -p "$OUT"

# SanCov on the PROJECT code (not only a harness TU), unconditionally, so the CLI targets record edges
# in Mayhem. The sancov callbacks come from the sanitizer runtime; without one (empty SANITIZER_FLAGS)
# the libFuzzer runtime's no-main variant provides them.
COV_FLAGS="-fsanitize=fuzzer-no-link"
if [ -z "$SANITIZER_FLAGS" ]; then
  COV_LIBS="$(clang -print-file-name=libclang_rt.fuzzer_no_main-x86_64.a)"
  [ -f "$COV_LIBS" ] || COV_LIBS="$(clang -print-resource-dir)/lib/linux/libclang_rt.fuzzer_no_main-x86_64.a"
  COV_LIBS="$COV_LIBS -lstdc++"
else
  COV_LIBS=""
fi

# LeakSanitizer off at build time (SPEC §6.2 item 15), linked into every fuzz binary.
LSAN_OFF="$OUT/lsan_off.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$M/lsan_off.cc" -o "$LSAN_OFF"

FUZZ_CFLAGS="$SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS -O1"
FUZZ_LDFLAGS="$SANITIZER_FLAGS $COV_FLAGS $LSAN_OFF $COV_LIBS"

# Upstream's FindPCAP drops the libpcap link libraries when an existing CMake cache is re-configured
# (the re-run then fails to link tcpdump with undefined pcap_* symbols). So configure a build dir only
# once per argument set: re-use it as-is when its recorded arguments match, otherwise start it afresh.
# The build dirs are ours (mayhem/build-*, gitignored), never upstream files.
cmake_configure() {  # <build dir> <cmake args...>
  local dir="$1"; shift
  local want; want="$(printf '%s\n' "$@")"
  if [ -f "$dir/CMakeCache.txt" ] && [ "$(cat "$dir/.mayhem-configure-args" 2>/dev/null)" = "$want" ]; then
    return 0
  fi
  rm -rf "$dir"
  cmake -S "$SRC" -B "$dir" "$@"
  printf '%s\n' "$want" > "$dir/.mayhem-configure-args"
}

configure_fuzz() {   # <build dir> <extra cmake args...>
  local dir="$1"; shift
  cmake_configure "$dir" \
    -DCMAKE_BUILD_TYPE=None \
    -DCMAKE_C_FLAGS="$FUZZ_CFLAGS" \
    -DCMAKE_EXE_LINKER_FLAGS="$FUZZ_LDFLAGS" \
    -DWITH_SMI=OFF -DWITH_CAP_NG=OFF -DWITH_CRYPTO=ON \
    "$@"
}

# 1) Sanitized + instrumented tcpdump (default configuration) and libnetdissect.a.
configure_fuzz "$M/build-fuzz" -DENABLE_SMB=OFF
cmake --build "$M/build-fuzz" -j"$MAYHEM_JOBS" --target tcpdump
grep -q '^#define HAVE_LIBCRYPTO 1' "$M/build-fuzz/config.h" || { echo "build-fuzz: libcrypto not found (-E/-M targets need it)" >&2; exit 1; }
cp -f "$M/build-fuzz/tcpdump" "$OUT/tcpdump"

# 2) Same, with the SMB printer compiled in.
configure_fuzz "$M/build-smb" -DENABLE_SMB=ON
cmake --build "$M/build-smb" -j"$MAYHEM_JOBS" --target tcpdump
grep -q '^#define ENABLE_SMB 1' "$M/build-smb/config.h" || { echo "build-smb: ENABLE_SMB not set" >&2; exit 1; }
cp -f "$M/build-smb/tcpdump" "$OUT/tcpdump-smb"

# 3) Legacy libFuzzer harness over libnetdissect (fuzzer + standalone reproducer).
NDLIB="$M/build-fuzz/libnetdissect.a"
INC="-I$SRC -I$M/build-fuzz"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE $INC "$M/fuzz_mask62plen.cpp" \
  "$NDLIB" "$LSAN_OFF" -lpcap -lcrypto -o "$OUT/fuzz_mask62plen"
$CXX $SANITIZER_FLAGS $COV_FLAGS $DEBUG_FLAGS $INC "$M/fuzz_mask62plen.cpp" "$OUT/standalone_main.o" \
  "$NDLIB" "$LSAN_OFF" $COV_LIBS -lpcap -lcrypto -o "$OUT/fuzz_mask62plen-standalone"

# 4) The functional-test build: upstream's normal flags, no sanitizers, for testprogs/TESTrun.
#    ENABLE_SMB=ON so TESTrun also covers the SMB printer's expected outputs.
cmake_configure "$M/build-test" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_EXE_LINKER_FLAGS="$COVERAGE_FLAGS" \
  -DWITH_SMI=OFF -DWITH_CAP_NG=OFF -DWITH_CRYPTO=ON -DENABLE_SMB=ON
cmake --build "$M/build-test" -j"$MAYHEM_JOBS" --target tcpdump

ls -l "$OUT"/tcpdump "$OUT"/tcpdump-smb "$OUT"/fuzz_mask62plen "$OUT"/fuzz_mask62plen-standalone "$M/build-test/tcpdump"

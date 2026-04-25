# MASQUE Fuzzing (libFuzzer)

This directory contains a standalone `libFuzzer` target for the stateless MASQUE helper APIs in `src/http3/xqc_h3_ext_masque.c`.

## Why standalone

The target builds only the MASQUE helper source plus varint utilities, so it does not require the full xquic test stack (`CUnit`, `LibEvent`) and does not need TLS libraries for linking.

## Build

Use `clang` (or `AppleClang`) with `libFuzzer` support:

```bash
cmake -S tests/fuzz -B build/fuzz -DCMAKE_C_COMPILER=clang
cmake --build build/fuzz -j
```

## Run

Use the smoke helper script (it builds the target, copies seed files to a temporary corpus, and writes crash artifacts under `/tmp`):

```bash
XQC_FUZZ_C_COMPILER=clang XQC_FUZZ_MAX_TOTAL_TIME=60 tests/fuzz/run_smoke.sh
```

Useful environment variables:

- `XQC_FUZZ_C_COMPILER` (default: `clang`)
- `XQC_FUZZ_MAX_TOTAL_TIME` (default: `60`)
- `XQC_FUZZ_BUILD_DIR` (default: `build/fuzz`)
- `XQC_FUZZ_ARTIFACT_DIR` (default: `/tmp/xqc-fuzz-artifacts`)
- `XQC_FUZZ_DICT` (default: `tests/fuzz/masque.dict`, if present)

The smoke script automatically uses `tests/fuzz/masque.dict` (libFuzzer dictionary) when the file exists.

Recommended sanitizers are already enabled in `tests/fuzz/CMakeLists.txt`:

- `fuzzer`
- `address`
- `undefined`

## Scope

The harness exercises:

- UDP datagram framing/unframing
- Capsule encode/decode
- CONNECT-IP `ADDRESS_ASSIGN` parsing and `ADDRESS_REQUEST` building
- ROUTE_ADVERTISEMENT parsing/validation
- IP packet validation
- IPv6 MTU validation

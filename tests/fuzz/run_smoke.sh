#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"

build_dir="${XQC_FUZZ_BUILD_DIR:-${repo_root}/build/fuzz}"
c_compiler="${XQC_FUZZ_C_COMPILER:-clang}"
max_total_time="${XQC_FUZZ_MAX_TOTAL_TIME:-60}"
artifact_dir="${XQC_FUZZ_ARTIFACT_DIR:-/tmp/xqc-fuzz-artifacts}"
seed_dir="${script_dir}/corpus/masque"
dict_path="${XQC_FUZZ_DICT:-${script_dir}/masque.dict}"
binary_path="${build_dir}/fuzz_masque_libfuzzer"

if [[ ! -d "${seed_dir}" ]]; then
    echo "seed corpus directory not found: ${seed_dir}" >&2
    exit 1
fi

if ! compgen -G "${seed_dir}/*.bin" > /dev/null; then
    echo "no seed files (*.bin) found in ${seed_dir}" >&2
    exit 1
fi

tmp_corpus="$(mktemp -d)"
trap 'rm -rf "${tmp_corpus}"' EXIT

mkdir -p "${artifact_dir}"
cp "${seed_dir}"/*.bin "${tmp_corpus}/"

fuzzer_args=()
if [[ -f "${dict_path}" ]]; then
    fuzzer_args+=("-dict=${dict_path}")
fi

cmake -S "${script_dir}" -B "${build_dir}" -DCMAKE_C_COMPILER="${c_compiler}"
cmake --build "${build_dir}" -j

exec "${binary_path}" \
    "${tmp_corpus}" \
    -artifact_prefix="${artifact_dir}/" \
    -max_total_time="${max_total_time}" \
    "${fuzzer_args[@]}" \
    "$@"

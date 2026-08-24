#!/usr/bin/env bash
set -euo pipefail

: "${HOME:=/home/agent-sec}"
: "${OLLAMA_HOST:=127.0.0.1:11434}"
: "${OLLAMA_KEEP_ALIVE:=-1}"
: "${OLLAMA_KV_CACHE_TYPE:=q8_0}"
: "${OLLAMA_NUM_PARALLEL:=1}"
: "${OLLAMA_NUM_CTX:=4096}"
: "${OLLAMA_MODEL:=modelscope.cn/ANOLISA/Warden-Gen-0.6B-GGUF}"
: "${OLLAMA_MODELS:=${HOME}/.ollama/models}"
: "${OLLAMA_STARTUP_TIMEOUT_SECONDS:=60}"

export HOME OLLAMA_HOST OLLAMA_KEEP_ALIVE OLLAMA_KV_CACHE_TYPE OLLAMA_NUM_PARALLEL
export OLLAMA_MODEL OLLAMA_MODELS

for numeric_variable in OLLAMA_NUM_PARALLEL OLLAMA_NUM_CTX; do
    if [[ ! "${!numeric_variable}" =~ ^[1-9][0-9]*$ ]]; then
        echo "[entrypoint] ERROR: ${numeric_variable} must be a positive integer" >&2
        exit 1
    fi
done

mkdir -p "${HOME}" "${OLLAMA_MODELS}"

server_pid=""
stop_server() {
    if [[ -n "${server_pid}" ]]; then
        kill -TERM "${server_pid}" 2>/dev/null || true
        wait "${server_pid}" 2>/dev/null || true
    fi
}
trap stop_server INT TERM EXIT

ollama serve &
server_pid="$!"

deadline=$((SECONDS + OLLAMA_STARTUP_TIMEOUT_SECONDS))
until ollama list >/dev/null 2>&1; do
    if ! kill -0 "${server_pid}" 2>/dev/null; then
        echo "[entrypoint] ERROR: ollama serve exited before becoming ready" >&2
        wait "${server_pid}"
    fi
    if (( SECONDS >= deadline )); then
        echo "[entrypoint] ERROR: ollama serve did not become ready in ${OLLAMA_STARTUP_TIMEOUT_SECONDS}s" >&2
        exit 1
    fi
    sleep 1
done

# Pull once on a new model volume; a warm persistent volume skips this step.
if ! ollama show "${OLLAMA_MODEL}" >/dev/null 2>&1; then
    echo "[entrypoint] Pulling Ollama model ${OLLAMA_MODEL}..."
    ollama pull "${OLLAMA_MODEL}"
fi

# The model's Modelfile parameter takes precedence over Ollama's global context
# setting. Re-create the local tag from its existing layers so OLLAMA_NUM_CTX
# reliably controls num_ctx without another model download.
echo "[entrypoint] Overriding num_ctx=${OLLAMA_NUM_CTX} for ${OLLAMA_MODEL}..."
override_modelfile="$(mktemp "${TMPDIR:-/tmp}/Modelfile.XXXXXX")"
printf 'FROM %s\nPARAMETER num_ctx %s\n' \
    "${OLLAMA_MODEL}" "${OLLAMA_NUM_CTX}" >"${override_modelfile}"
if ! ollama create "${OLLAMA_MODEL}" -f "${override_modelfile}"; then
    echo "[entrypoint] WARNING: failed to override num_ctx; continuing with model defaults" >&2
fi
rm -f "${override_modelfile}"

echo "[entrypoint] Loading Ollama model ${OLLAMA_MODEL}..."
ollama run "${OLLAMA_MODEL}" ""
echo "[entrypoint] Ollama model is ready: ${OLLAMA_MODEL}"

wait "${server_pid}"
status="$?"
server_pid=""
trap - INT TERM EXIT
exit "${status}"

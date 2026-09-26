#!/usr/bin/env bash
# decider setup (OpenJev backend) in its own venv, serving on port 8000.
# First run: clone, create the venv, install torch PINNED to the official
# cu126 index (the project declares torch unconstrained -> PyPI would pull
# builds incompatible with the driver, and not reproducible).
# DECIDER_T_BUCKETS/B_BUCKETS shrink the CUDA graphs grid at startup:
# the default (up to 8k tokens) OOMs on 8 GB GPUs; our states are ~200 tokens.
# The server binds loopback by default; export DECIDER_HOST/DECIDER_PORT to
# expose it deliberately (put TLS in front before you do).
set -euo pipefail
ROOT="$(dirname "$0")/.."
if [ ! -d "$ROOT/vendor/decider/.git" ]; then
    git clone https://github.com/Mapika/decider "$ROOT/vendor/decider"
fi
cd "$ROOT/vendor/decider"
if [ ! -d .venv ]; then
    uv venv .venv --python 3.12
    uv pip install --python .venv "torch==2.14.0+cu126" --index-url https://download.pytorch.org/whl/cu126
    uv pip install --python .venv -e ".[serve]"
    uv pip install --python .venv uvicorn
fi
export DECIDER_MODEL=Mapika/decider-2b
export DECIDER_T_BUCKETS=256,1024 DECIDER_B_BUCKETS=1,4
export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True
exec .venv/bin/uvicorn decider.serve:app --host "${DECIDER_HOST:-127.0.0.1}" --port "${DECIDER_PORT:-8000}"

#!/usr/bin/env bash
# Setup di reflex con wheel CUDA 12.6 (il repo pina cu130, incompatibile col driver 550.x).
# Il 4B bf16 (8,4 GB) non entra negli 8 GB della 4060 Laptop: offload parziale in RAM
# tramite la patch REFLEX_MAX_MEMORY in engine.py (7 GiB in VRAM, resto in CPU).
# Alternativa senza patch: --model Qwen/Qwen3.5-2B (sta tutto in VRAM).
set -euo pipefail
cd "$(dirname "$0")/../vendor/reflex"
export REFLEX_MAX_MEMORY='{"0": "7GiB", "cpu": "18GiB"}'
exec uv run reflex-serve --model Qwen/Qwen3.5-4B --port 8008

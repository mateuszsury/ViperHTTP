---
name: viperhttp-build-bench
description: Handle ESP-IDF integration, sdkconfig tuning, build system wiring, and benchmarking for ViperHTTP. Use when updating CMake, sdkconfig, build flags, or performance test harnesses.
---

# ViperHTTP Build and Bench

## Overview
Keep the project buildable and measurable. Own ESP-IDF integration, sdkconfig options, and benchmark harnesses that validate performance targets.

## Workflow
1. Read references/build-config.md and references/benchmarks.md.
2. Update CMake or user module wiring as needed.
3. Verify sdkconfig values for dual-core, PSRAM, and lwIP tuning.
4. Run a basic build or lint check if possible.
5. Keep benchmark scripts and expected targets up to date.

## Hard Requirements
- Dual-core must be enabled.
- Server task pinned to Core 0.
- Use performance compiler flags where supported.
- Track memory usage (heap and PSRAM) during benchmarks.

## Definition of Done
- Build configuration matches references/build-config.md.
- Benchmarks cover static, JSON, DI, Python handler, and WebSocket.
- Performance targets recorded and measured.

## References
- Read references/build-config.md for sdkconfig and build wiring.
- Read references/benchmarks.md for benchmark scenarios and targets.
- Use plan.md in repo as the source of truth for architecture.

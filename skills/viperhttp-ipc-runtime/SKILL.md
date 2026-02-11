---
name: viperhttp-ipc-runtime
description: "Design and modify the ViperHTTP cross-core runtime: FreeRTOS tasks, IPC queues, ring buffers, scheduling, and request/response message formats. Use when changing IPC boundaries, task pinning, or inter-core data flow."
---

# ViperHTTP IPC Runtime

## Overview
Own the cross-core contract between the C server (Core 0) and MicroPython (Core 1). Keep it lock-safe, bounded, and deterministic.

## Workflow
1. Read references/ipc-spec.md for queue sizes and message layout.
2. Define ownership and lifetime for each buffer.
3. Implement IPC with FreeRTOS queues and ring buffers only.
4. Make scheduling explicit (who wakes whom, and when).
5. Add debug counters or logs for dropped messages and backpressure.

## Hard Requirements
- Keep all IPC structures in internal SRAM for low latency.
- Never share mutable buffers without clear ownership.
- Avoid cross-core malloc or free; use pools or ring buffers.
- Use mp_sched_schedule for Python callbacks; do not call into MP directly from Core 0.
- Fail fast on queue full or ring buffer overflow with clear error codes.

## Definition of Done
- IPC message structs documented and versioned.
- Queue lengths and ring buffer sizes enforced.
- Backpressure behavior documented and tested.
- No deadlocks in dual-core startup or shutdown paths.

## References
- Read references/ipc-spec.md for message layout and sizes.
- Use plan.md in repo as the source of truth for architecture.

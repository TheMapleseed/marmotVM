# marmotVM

`marmotVM` is a Python package that ships a native C extension for running a custom bytecode virtual machine from Python.

## Features

- **Custom Bytecode VM**: Secure execution environment with ~80 custom opcodes
- **Multiple Execution Modes**:
  - `KERNEL`: Full kernel access (requires root privileges)
  - `USER`: User space execution (unprivileged)
  - `SANDBOX`: Fully sandboxed (no system access)
- **Network Support**: TCP/UDP socket operations (configurable)
- **GPU Support**: NVIDIA CUDA, AMD ROCm, Apple Metal
- **Environment Access**: Get/set environment variables
- **Python Bindings**: Load as Python module

## Architecture

```
+------------------+
|   Python App    |
+--------+---------+
         |
         v
+--------+---------+
| marmotVM Python |
|    Module       |
+--------+---------+
         |
         v
+--------+---------+
|   MicroVM Core  |
|   (C23 VM)      |
+--------+---------+
         |
    +----+----+
    |         |
    v         v
 +------+ +------+
 |Network| | GPU  |
 |Stack  | | Access
 +------+ +------+
```

## Install (pip)

```bash
pip install marmotVM
```

## Python usage

```python
import marmotVM

# Create VM with sandbox mode
vm = marmotVM.MicroVM(
    mode='user',
    network='tcp',
    gpu='disabled',
    auth_key='your-secret-key',
    memory_mb=64,
)

# Load bytecode
with open('program.mvm', 'rb') as f:
    vm.load(f.read())

# Execute
exit_code = vm.run()
print(f"Exit code: {exit_code}")
print(f"Cycles: {vm.get_cycles()}")
```

## Feature switches and defaults

Use this section as the source of truth for enabling new security/integrity features.

### 1) VM creation authentication (required)

`marmotVM` now requires a creation key for every VM instance.

- Environment variable: `MARMOTVM_AUTH_KEY`
- Python constructor arg: `auth_key=...`
- VM creation succeeds only when `auth_key` exactly matches `MARMOTVM_AUTH_KEY`

Example:

```bash
export MARMOTVM_AUTH_KEY="change-me-strong-secret"
```

```python
import marmotVM
vm = marmotVM.MicroVM(auth_key="change-me-strong-secret")
```

### 2) ECC packet integrity mode (disabled by default)

ECC integrity verification is opt-in and controlled at startup:

- Environment variable: `MARMOTVM_ECC`
- Enabled values: `1`, `true`, `on` (case-insensitive variants currently supported in code)
- Default when unset: disabled
- Required keyed mode env when ECC is enabled: `MARMOTVM_ECC_KEY`

When ECC is enabled, `vm.load(packet)` requires a valid packet/header checksum flow (documented below).

```bash
export MARMOTVM_ECC=1
export MARMOTVM_ECC_KEY="replace-with-strong-secret"
```

### 2b) Network broker mode (disabled by default)

Network broker mode keeps network opcodes mediated by broker-managed opaque handles.

- Environment variable: `MARMOTVM_NET_BROKER`
- Enabled values: `1`, `true`, `on`
- Allowlist variable: `MARMOTVM_NET_ALLOW`
- Allowlist format: comma-separated `host:port` entries

Example:

```bash
export MARMOTVM_NET_BROKER=1
export MARMOTVM_NET_ALLOW="api.example.com:443,10.0.0.15:9000"
```

Behavior in broker mode:

- `NET_SOCKET` returns opaque handle (not raw host fd)
- `NET_CONNECT` is blocked unless `host:port` is allowlisted
- allowlist enforcement is validated against resolved endpoint addresses at connect time
- `NET_SEND` / `NET_RECV` resolve opaque handle internally
- `NET_BIND` / `NET_LISTEN` / `NET_ACCEPT` are denied

### 2c) RAM limit / memory ceiling

You can cap VM memory so the runtime cannot over-allocate RAM.

- Process-wide env cap: `MARMOTVM_MAX_MEMORY_MB`
- Optional per-VM target: `memory_mb=` constructor arg
- Effective VM memory is the smaller of:
  - constructor `memory_mb` (if provided)
  - `MARMOTVM_MAX_MEMORY_MB` (if set)
  - internal hard max (`MICROVM_MAX_MEMORY`)

Example:

```bash
export MARMOTVM_MAX_MEMORY_MB=64
```

```python
vm = marmotVM.MicroVM(
    mode="sandbox",
    auth_key="change-me-strong-secret",
    memory_mb=32,  # <= env cap, so VM gets 32MB
)
```

### 3) Execution mode policy (constructor option)

- `mode='user'`:
  - normal user-mode runtime
  - raw bytecode loading allowed
  - host integrations follow selected network/gpu options
  - process environment is snapshotted into VM-local cache at VM creation
- `mode='sandbox'`:
  - deny-by-default host integrations enforced in runtime
  - network forced disabled
  - GPU forced disabled
  - env/time/pid operations blocked
  - raw bytecode loading blocked
- `mode='kernel'`:
  - disabled by runtime security policy in this build
  - constructor/mode-switch requests are rejected

### 3b) Syscall / kernel-interrupt policy

For hardening, guest syscall-style execution is blocked:

- `OP_SYSCALL` always returns permission denied
- kernel mode transitions are denied
- no guest path is allowed to trigger direct kernel-surface execution in this runtime build

### 4) Effective secure startup profile

For the strictest currently implemented profile:

```bash
export MARMOTVM_AUTH_KEY="change-me-strong-secret"
export MARMOTVM_ECC=1
export MARMOTVM_NET_BROKER=1
export MARMOTVM_NET_ALLOW="api.example.com:443"
export MARMOTVM_MAX_MEMORY_MB=64
```

```python
import marmotVM
vm = marmotVM.MicroVM(
    mode="sandbox",
    auth_key="change-me-strong-secret",
)
```

## Local development build (maintainers)

If you are developing the package itself (not consuming from pip):

```bash
python -m pip install --upgrade pip build
python -m build
```

Or editable install:

```bash
python -m pip install -e .
```

## Bytecode Format

Custom bytecode format with magic number:
```
Offset  Size  Field
0       4     Magic (0x4D564D23)
4       2     Version Major
6       2     Version Minor
8       4     Flags
12      4     Code Size
16      4     Data Size
20      4     Entry Point
24      N     Code
```

## Opcodes

### Data Movement
- `0x01` MOV - Register to register
- `0x02` MOVI - Immediate 32-bit
- `0x03` MOVQ - Immediate 64-bit

### Arithmetic
- `0x10` ADD - Integer add
- `0x11` SUB - Integer subtract
- `0x12` MUL - Integer multiply
- `0x13` DIV - Integer divide
- `0x14` MOD - Modulo

### Branching
- `0x50` JMP - Jump
- `0x51` JZ - Jump if zero
- `0x52` JNZ - Jump if not zero
- `0x59` CALL - Function call

### Network
- `0x80` SOCKET - Create socket
- `0x81` BIND - Bind to port
- `0x82` LISTEN - Listen
- `0x83` ACCEPT - Accept connection
- `0x84` CONNECT - Connect to host
- `0x85` SEND - Send data
- `0x86` RECV - Receive data
- `0x87` CLOSE - Close socket

### GPU
- `0x90` GPU_INIT - Initialize GPU
- `0x91` GPU_ALLOC - Allocate GPU memory
- `0x92` GPU_UPLOAD - Upload to GPU
- `0x93` GPU_DOWNLOAD - Download from GPU
- `0x94` GPU_EXEC - Execute kernel

### Environment
- `0xA0` ENV_GET - Get environment variable
- `0xA1` ENV_SET - Set environment variable
- `0xA3` GETTIME - Get current time
- `0xA4` GETPID - Get process ID

## Security

Current security model:

1. **In-process runtime**: `marmotVM` executes as a native extension inside the Python process.
2. **Sandbox mode policy**: sandbox mode now forces deny-by-default host integrations:
   - network disabled
   - GPU disabled
   - env/time/pid operations blocked
   - raw bytecode loading blocked (magic required)
3. **Kernel mode blocked**: kernel mode is disabled by runtime security policy.
4. **Creation auth gate**: VM creation requires `auth_key` that matches `MARMOTVM_AUTH_KEY`.
5. **ECC startup mode**: set `MARMOTVM_ECC=1` (or `true`/`on`) and provide `MARMOTVM_ECC_KEY` for keyed integrity checks.
6. **Brokered network policy**: when `MARMOTVM_NET_BROKER=1`, outbound connects are restricted by `MARMOTVM_NET_ALLOW`.

Important: this is a hardened interpreter policy, not full OS-level process/container isolation.

### Required environment variables

```bash
export MARMOTVM_AUTH_KEY="change-me"
```

### Optional hardening environment variables

```bash
export MARMOTVM_ECC=1
export MARMOTVM_ECC_KEY="replace-with-strong-secret"
export MARMOTVM_NET_BROKER=1
export MARMOTVM_NET_ALLOW="api.example.com:443"
export MARMOTVM_MAX_MEMORY_MB=64
```

### ECC packet behavior

When ECC is enabled, `vm.load(packet)` enforces packet integrity:

- packet must include a valid MicroVM header (magic required)
- packet must append a 16-byte authentication tag at the end:
  - first 16 bytes of `HMAC-SHA256(payload, key)` using `MARMOTVM_ECC_KEY`
- VM builds an internal ECC image (1 parity byte per 32 payload bytes)
- if ECC is enabled and `MARMOTVM_ECC_KEY` is missing, packet load is denied
- repeated tags are rejected per VM instance (basic replay window)
- tag mismatch or malformed packet causes load rejection

Inspection helpers:

```python
vm.get_ecc_enabled()
vm.get_ecc_packet_checksum()
vm.get_ecc_image_size()
```

### VM-local environment cache lifecycle

Environment handling is now VM-local for isolation:

- at VM creation, process environment is copied into a VM-local cache
- `OP_ENV_GET` reads from that VM cache (not host `getenv`)
- `OP_ENV_SET` writes to that VM cache (not host `setenv`)
- when VM is destroyed, the cache is freed
- next startup gets a fresh snapshot

### Instance isolation and threading

- broker/ECC/memory policy is stored per VM instance (`microvm_t`)
- each VM has its own lock on Linux/macOS for thread-safe runtime/state transitions

## License

GNU GPL v3.0 (GPL-3.0-only)

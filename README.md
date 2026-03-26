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
vm = marmotVM.MicroVM(mode='user', network='tcp', gpu='disabled')

# Load bytecode
with open('program.mvm', 'rb') as f:
    vm.load(f.read())

# Execute
exit_code = vm.run()
print(f"Exit code: {exit_code}")
print(f"Cycles: {vm.get_cycles()}")
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

The MicroVM provides isolation through:

1. **Memory Limits**: Bounded heap/stack (configurable)
2. **No Direct Hardware Access**: Sandboxed I/O via syscalls
3. **Execution Modes**: Kernel mode requires elevated privileges
4. **Network Isolation**: Can be disabled entirely

## License

GNU GPL v3.0 (GPL-3.0-only)

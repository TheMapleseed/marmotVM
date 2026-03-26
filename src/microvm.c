/**
 * @file microvm.c
 * @brief BigWeiner MicroVM Implementation
 * @author BigWeiner Team
 * 
 * C23 compliant implementation of the custom bytecode VM.
 * Supports network access, GPU operations, and environment variables.
 */

#define MICROVM_IMPLEMENTATION
#include "../include/microvm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Heap->stack guard bytes.
 * This keeps allocations (heap_ptr) away from the reserved "stack" region. */
#ifndef MICROVM_HEAP_GUARD_BYTES
#define MICROVM_HEAP_GUARD_BYTES (4 * 1024)
#endif

/* Extra padding reserved after each OP_ALLOC request.
 * This reduces the risk of off-by-one writes / missing terminators
 * from breaking the VM memory layout. */
#ifndef MICROVM_ALLOC_OS_BUFFER_BYTES
#define MICROVM_ALLOC_OS_BUFFER_BYTES 64
#endif

/* Copy a NUL-terminated C string from VM memory into a host buffer. */
static microvm_error_t microvm_copy_cstring_from_vm(const microvm_t *vm, size_t off, char *out, size_t out_cap) {
    if (!vm || !vm->memory || !out || out_cap == 0) return MICROVM_ERR_INVALID_STATE;
    if (off >= vm->memory_size) return MICROVM_ERR_OUT_OF_BOUNDS;

    /* out_cap must hold a terminating NUL. */
    size_t i = 0;
    while (i + 1 < out_cap) {
        size_t idx = off + i;
        if (idx >= vm->memory_size) return MICROVM_ERR_OUT_OF_BOUNDS;
        out[i] = (char)vm->memory[idx];
        if (out[i] == '\0') {
            return MICROVM_SUCCESS;
        }
        i++;
    }

    /* No NUL found before output buffer filled. */
    out[out_cap - 1] = '\0';
    return MICROVM_ERR_INVALID_BYTECODE;
}

/* Ensure PC + need <= memory_size before reading N bytes from bytecode. */
static inline microvm_error_t microvm_require_pc_bytes(microvm_t *vm, size_t need) {
    if (!vm) return MICROVM_ERR_INVALID_STATE;
    if (vm->pc + need > vm->memory_size) return MICROVM_ERR_OUT_OF_BOUNDS;
    return MICROVM_SUCCESS;
}

/* Safely apply a signed relative offset to vm->pc (pc is size_t, so avoid underflow wrap). */
static microvm_error_t microvm_relative_jump(microvm_t *vm, int8_t offset) {
    if (!vm) return MICROVM_ERR_INVALID_STATE;

    if (offset >= 0) {
        size_t uoff = (size_t)offset;
        if (uoff > vm->memory_size - vm->pc) {
            return MICROVM_ERR_OUT_OF_BOUNDS;
        }
        if (vm->pc + uoff >= vm->memory_size) {
            return MICROVM_ERR_OUT_OF_BOUNDS;
        }
        vm->pc += uoff;
    } else {
        size_t d = (size_t)(-offset);
        if (d > vm->pc) {
            return MICROVM_ERR_OUT_OF_BOUNDS;
        }
        vm->pc -= d;
    }
    return MICROVM_SUCCESS;
}

/* Optional platform-specific includes */
#ifdef MICROVM_PLATFORM_LINUX
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <fcntl.h>
#endif

#ifdef MICROVM_PLATFORM_MACOS
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <fcntl.h>
#endif

#ifdef MICROVM_PLATFORM_WINDOWS
    #pragma comment(lib, "ws2_32.lib")
#endif

/* Global state */
static bool g_microvm_initialized = false;
static const char *g_error_strings[] = {
    "Success",
    "Invalid bytecode",
    "Invalid register",
    "Stack overflow",
    "Stack underflow",
    "Memory error",
    "Division by zero",
    "Invalid opcode",
    "Network error",
    "GPU error",
    "Permission denied",
    "Timeout",
    "Not supported",
    "Out of bounds",
    "Invalid state"
};

/* Forward declarations */
static microvm_error_t microvm_execute_op(microvm_t *vm, microvm_opcode_t opcode);
static void microvm_set_error(microvm_t *vm, microvm_error_t error, const char *msg);

/* ============================================================================
 * Initialization
 * ============================================================================ */

microvm_error_t microvm_init(void) {
    if (g_microvm_initialized) {
        return MICROVM_SUCCESS;
    }
    
#ifdef MICROVM_PLATFORM_WINDOWS
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return MICROVM_ERR_NETWORK;
    }
#endif
    
    g_microvm_initialized = true;
    return MICROVM_SUCCESS;
}

const char *microvm_version(void) {
    return MICROVM_VERSION_STRING;
}

/* ============================================================================
 * VM Creation and Destruction
 * ============================================================================ */

microvm_t *microvm_create(const microvm_config_t *config) {
    microvm_t *vm = calloc(1, sizeof(microvm_t));
    if (!vm) {
        return NULL;
    }
    
    /* Set defaults if no config provided */
    if (config) {
        vm->mode = config->mode;
        vm->network_mode = config->network_mode;
        vm->gpu_mode = config->gpu_mode;
        vm->memory_size = config->memory_size > 0 ? config->memory_size : MICROVM_MAX_MEMORY;
        /* Reserve stack region and heap guard bytes to avoid heap overruns. */
        size_t stack_reserve = config->stack_size > 0 ? config->stack_size : MICROVM_MAX_STACK_SIZE;
        if (stack_reserve + MICROVM_HEAP_GUARD_BYTES >= vm->memory_size) {
            /* Clamp to keep at least some usable heap space. */
            stack_reserve = vm->memory_size / 4;
        }
        vm->stack_ptr = vm->memory_size - stack_reserve - MICROVM_HEAP_GUARD_BYTES;
    } else {
        vm->mode = MICROVM_MODE_USER;
        vm->network_mode = MICROVM_NET_ALL;
        vm->gpu_mode = MICROVM_GPU_DISABLED;
        vm->memory_size = MICROVM_MAX_MEMORY;
        vm->stack_ptr = vm->memory_size - MICROVM_MAX_STACK_SIZE - MICROVM_HEAP_GUARD_BYTES;
    }
    
    /* Allocate memory */
    vm->memory = calloc(1, vm->memory_size);
    if (!vm->memory) {
        free(vm);
        return NULL;
    }
    
    vm->heap_ptr = 0;
    vm->running = false;
    vm->halted = false;
    vm->exit_code = 0;
    vm->call_depth = 0;
    vm->instructions_executed = 0;
    vm->cycles = 0;
    
    /* Initialize registers */
    memset(&vm->regs, 0, sizeof(vm->regs));
    memset(&vm->cpu_flags, 0, sizeof(vm->cpu_flags));
    
    return vm;
}

microvm_error_t microvm_destroy(microvm_t *vm) {
    if (!vm) {
        return MICROVM_ERR_INVALID_STATE;
    }
    
    /* Free memory */
    if (vm->memory) {
        free(vm->memory);
    }
    
    /* Free environment */
    if (vm->env_vars) {
        for (size_t i = 0; i < vm->env_count; i++) {
            free(vm->env_vars[i]);
        }
        free(vm->env_vars);
    }
    
    free(vm);
    return MICROVM_SUCCESS;
}

/* ============================================================================
 * Bytecode Loading
 * ============================================================================ */

microvm_error_t microvm_load(microvm_t *vm, const uint8_t *bytecode, size_t size) {
    if (!vm || !bytecode || size == 0) {
        return MICROVM_ERR_INVALID_BYTECODE;
    }
    
    if (size > MICROVM_MAX_BYTECODE_SIZE) {
        return MICROVM_ERR_INVALID_BYTECODE;
    }
    
    if (size > vm->memory_size) {
        return MICROVM_ERR_OUT_OF_BOUNDS;
    }

    if (size > vm->stack_ptr) {
        /* No room to even start the heap (heap_ptr is at bytecode end). */
        return MICROVM_ERR_MEMORY;
    }

    /* Reset VM state for a fresh run. */
    vm->pc = 0;
    vm->running = false;
    vm->halted = false;
    vm->exit_code = 0;
    vm->call_depth = 0;
    vm->instructions_executed = 0;
    vm->cycles = 0;
    vm->heap_ptr = size; /* Keep bytecode intact; allocate after it. */

    /* Check magic number */
    if (size >= 4) {
        uint32_t magic = (bytecode[0] << 24) | (bytecode[1] << 16) | 
                        (bytecode[2] << 8) | bytecode[3];
        if (magic != MICROVM_BYTECODE_MAGIC) {
            /* Allow loading even without magic (raw bytecode) */
        }
    }
    
    /* Copy bytecode to memory (at address 0) */
    memcpy(vm->memory, bytecode, size);
    
    return MICROVM_SUCCESS;
}

/* ============================================================================
 * Execution Core
 * ============================================================================ */

microvm_error_t microvm_run(microvm_t *vm) {
    if (!vm || !vm->memory) {
        return MICROVM_ERR_INVALID_STATE;
    }
    
    if (vm->halted) {
        return MICROVM_ERR_INVALID_STATE;
    }
    
    vm->running = true;
    
    while (vm->running && !vm->halted) {
        /* Fetch opcode */
        if (vm->pc >= vm->memory_size) {
            microvm_set_error(vm, MICROVM_ERR_OUT_OF_BOUNDS, "PC out of bounds");
            vm->running = false;
            return MICROVM_ERR_OUT_OF_BOUNDS;
        }
        
        microvm_opcode_t opcode = (microvm_opcode_t)vm->memory[vm->pc++];
        
        /* Execute instruction */
        microvm_error_t result = microvm_execute_op(vm, opcode);
        
        vm->instructions_executed++;
        vm->cycles++;

        /* Hard upper bound to avoid infinite-loop DoS. */
        if (vm->instructions_executed > 1000000) {
            microvm_set_error(vm, MICROVM_ERR_TIMEOUT, "Instruction limit exceeded");
            vm->running = false;
            return MICROVM_ERR_TIMEOUT;
        }
        
        if (result != MICROVM_SUCCESS) {
            vm->running = false;
            return result;
        }
    }
    
    vm->running = false;
    return MICROVM_SUCCESS;
}

microvm_error_t microvm_stop(microvm_t *vm) {
    if (!vm) {
        return MICROVM_ERR_INVALID_STATE;
    }
    
    vm->running = false;
    vm->halted = true;
    return MICROVM_SUCCESS;
}

microvm_error_t microvm_pause(microvm_t *vm) {
    if (!vm) {
        return MICROVM_ERR_INVALID_STATE;
    }
    
    vm->running = false;
    return MICROVM_SUCCESS;
}

microvm_error_t microvm_resume(microvm_t *vm) {
    if (!vm || vm->halted) {
        return MICROVM_ERR_INVALID_STATE;
    }
    
    vm->running = true;
    return microvm_run(vm);
}

/* ============================================================================
 * Instruction Execution
 * ============================================================================ */

static inline int64_t microvm_read_int32(const uint8_t *mem, size_t offset) {
    return (int32_t)(mem[offset] << 24 | mem[offset + 1] << 16 | 
                     mem[offset + 2] << 8 | mem[offset + 3]);
}

static inline int64_t microvm_read_int64(const uint8_t *mem, size_t offset) {
    return (int64_t)(((uint64_t)mem[offset] << 56) | 
                    ((uint64_t)mem[offset + 1] << 48) |
                    ((uint64_t)mem[offset + 2] << 40) |
                    ((uint64_t)mem[offset + 3] << 32) |
                    ((uint64_t)mem[offset + 4] << 24) |
                    ((uint64_t)mem[offset + 5] << 16) |
                    ((uint64_t)mem[offset + 6] << 8) |
                    ((uint64_t)mem[offset + 7]));
}

static microvm_error_t microvm_execute_op(microvm_t *vm, microvm_opcode_t opcode) {
    uint8_t *mem = vm->memory;
    
    switch (opcode) {
        /* ===== NOP ===== */
        case OP_NOP:
            break;
            
        /* ===== HALT ===== */
        case OP_HALT: {
            if (vm->pc < vm->memory_size - 1) {
                vm->exit_code = mem[vm->pc++];
            } else {
                vm->exit_code = 0;
            }
            vm->halted = true;
            break;
        }
        
        /* ===== Data Movement ===== */
        case OP_MOV: {
            if (microvm_require_pc_bytes(vm, 2) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            uint8_t src = mem[vm->pc++];
            if (dest >= MICROVM_MAX_REGISTERS || src >= MICROVM_MAX_REGISTERS) {
                return MICROVM_ERR_INVALID_REGISTER;
            }
            vm->regs.r[dest] = vm->regs.r[src];
            vm->regs.type[dest] = vm->regs.type[src];
            break;
        }
        
        case OP_MOVI: {
            if (microvm_require_pc_bytes(vm, 1 + 4) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            int32_t imm = microvm_read_int32(mem, vm->pc);
            vm->pc += 4;
            vm->regs.r[dest] = imm;
            vm->regs.type[dest] = REG_TYPE_INT64;
            break;
        }
        
        case OP_MOVQ: {
            if (microvm_require_pc_bytes(vm, 1 + 8) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            int64_t imm = microvm_read_int64(mem, vm->pc);
            vm->pc += 8;
            vm->regs.r[dest] = imm;
            vm->regs.type[dest] = REG_TYPE_INT64;
            break;
        }
        
        case OP_RET: {
            if (vm->call_depth == 0) {
                vm->halted = true;
                return MICROVM_SUCCESS;
            }
            vm->call_depth--;
            vm->pc = vm->call_stack[vm->call_depth];
            break;
        }
        
        /* ===== Arithmetic ===== */
        case OP_ADD: {
            if (microvm_require_pc_bytes(vm, 3) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            uint8_t a = mem[vm->pc++];
            uint8_t b = mem[vm->pc++];
            vm->regs.r[dest] = vm->regs.r[a] + vm->regs.r[b];
            break;
        }
        
        case OP_SUB: {
            if (microvm_require_pc_bytes(vm, 3) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            uint8_t a = mem[vm->pc++];
            uint8_t b = mem[vm->pc++];
            vm->regs.r[dest] = vm->regs.r[a] - vm->regs.r[b];
            break;
        }
        
        case OP_MUL: {
            if (microvm_require_pc_bytes(vm, 3) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            uint8_t a = mem[vm->pc++];
            uint8_t b = mem[vm->pc++];
            vm->regs.r[dest] = vm->regs.r[a] * vm->regs.r[b];
            break;
        }
        
        case OP_DIV: {
            if (microvm_require_pc_bytes(vm, 3) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            uint8_t a = mem[vm->pc++];
            uint8_t b = mem[vm->pc++];
            if (vm->regs.r[b] == 0) {
                return MICROVM_ERR_DIVISION_BY_ZERO;
            }
            vm->regs.r[dest] = vm->regs.r[a] / vm->regs.r[b];
            break;
        }
        
        case OP_MOD: {
            if (microvm_require_pc_bytes(vm, 3) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            uint8_t a = mem[vm->pc++];
            uint8_t b = mem[vm->pc++];
            if (vm->regs.r[b] == 0) {
                return MICROVM_ERR_DIVISION_BY_ZERO;
            }
            vm->regs.r[dest] = vm->regs.r[a] % vm->regs.r[b];
            break;
        }
        
        case OP_NEG: {
            if (microvm_require_pc_bytes(vm, 2) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            uint8_t src = mem[vm->pc++];
            vm->regs.r[dest] = -vm->regs.r[src];
            break;
        }
        
        case OP_INC: {
            if (microvm_require_pc_bytes(vm, 1) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            vm->regs.r[dest]++;
            break;
        }
        
        case OP_DEC: {
            if (microvm_require_pc_bytes(vm, 1) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            vm->regs.r[dest]--;
            break;
        }
        
        /* ===== Bitwise ===== */
        case OP_AND: {
            if (microvm_require_pc_bytes(vm, 3) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            uint8_t a = mem[vm->pc++];
            uint8_t b = mem[vm->pc++];
            vm->regs.r[dest] = vm->regs.r[a] & vm->regs.r[b];
            break;
        }
        
        case OP_OR: {
            if (microvm_require_pc_bytes(vm, 3) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            uint8_t a = mem[vm->pc++];
            uint8_t b = mem[vm->pc++];
            vm->regs.r[dest] = vm->regs.r[a] | vm->regs.r[b];
            break;
        }
        
        case OP_XOR: {
            if (microvm_require_pc_bytes(vm, 3) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            uint8_t a = mem[vm->pc++];
            uint8_t b = mem[vm->pc++];
            vm->regs.r[dest] = vm->regs.r[a] ^ vm->regs.r[b];
            break;
        }
        
        case OP_NOT: {
            if (microvm_require_pc_bytes(vm, 2) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            uint8_t src = mem[vm->pc++];
            vm->regs.r[dest] = ~vm->regs.r[src];
            break;
        }
        
        case OP_SHL: {
            if (microvm_require_pc_bytes(vm, 3) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            uint8_t src = mem[vm->pc++];
            uint8_t shift = mem[vm->pc++];
            vm->regs.r[dest] = vm->regs.r[src] << shift;
            break;
        }
        
        case OP_SHR: {
            if (microvm_require_pc_bytes(vm, 3) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            uint8_t src = mem[vm->pc++];
            uint8_t shift = mem[vm->pc++];
            vm->regs.r[dest] = vm->regs.r[src] >> shift;
            break;
        }
        
        /* ===== Comparison ===== */
        case OP_CMP: {
            if (microvm_require_pc_bytes(vm, 2) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t a = mem[vm->pc++];
            uint8_t b = mem[vm->pc++];
            int64_t result = vm->regs.r[a] - vm->regs.r[b];
            
            vm->cpu_flags.zero = (result == 0);
            vm->cpu_flags.sign = (result < 0);
            vm->cpu_flags.less = (result < 0);
            vm->cpu_flags.greater = (result > 0);
            vm->cpu_flags.equal = (result == 0);
            break;
        }
        
        /* ===== Branching ===== */
        case OP_JMP: {
            if (microvm_require_pc_bytes(vm, 1) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t offset = mem[vm->pc++];
            if (microvm_relative_jump(vm, (int8_t)offset) != MICROVM_SUCCESS) {
                return MICROVM_ERR_OUT_OF_BOUNDS;
            }
            break;
        }
        
        case OP_JZ: {
            if (microvm_require_pc_bytes(vm, 1) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t offset = mem[vm->pc++];
            if (vm->cpu_flags.zero) {
                if (microvm_relative_jump(vm, (int8_t)offset) != MICROVM_SUCCESS) {
                    return MICROVM_ERR_OUT_OF_BOUNDS;
                }
            }
            break;
        }
        
        case OP_JNZ: {
            if (microvm_require_pc_bytes(vm, 1) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t offset = mem[vm->pc++];
            if (!vm->cpu_flags.zero) {
                if (microvm_relative_jump(vm, (int8_t)offset) != MICROVM_SUCCESS) {
                    return MICROVM_ERR_OUT_OF_BOUNDS;
                }
            }
            break;
        }
        
        case OP_CALL: {
            if (microvm_require_pc_bytes(vm, 1) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t offset = mem[vm->pc++];
            if (vm->call_depth >= MICROVM_MAX_CALL_DEPTH) {
                return MICROVM_ERR_STACK_OVERFLOW;
            }
            vm->call_stack[vm->call_depth++] = vm->pc;
            if (microvm_relative_jump(vm, (int8_t)offset) != MICROVM_SUCCESS) {
                return MICROVM_ERR_OUT_OF_BOUNDS;
            }
            break;
        }
        
        /* ===== Memory Operations ===== */
        case OP_LOAD: {
            if (microvm_require_pc_bytes(vm, 2) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            uint8_t addr_reg = mem[vm->pc++];
            size_t addr = (size_t)vm->regs.r[addr_reg];
            if (addr + 8 > vm->memory_size) {
                return MICROVM_ERR_OUT_OF_BOUNDS;
            }
            vm->regs.r[dest] = microvm_read_int64(mem, addr);
            break;
        }
        
        case OP_STORE: {
            if (microvm_require_pc_bytes(vm, 2) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t addr_reg = mem[vm->pc++];
            uint8_t src = mem[vm->pc++];
            size_t addr = (size_t)vm->regs.r[addr_reg];
            if (addr + 8 > vm->memory_size) {
                return MICROVM_ERR_OUT_OF_BOUNDS;
            }
            uint8_t *ptr = (uint8_t *)&vm->regs.r[src];
            for (int i = 0; i < 8; i++) {
                mem[addr + i] = ptr[i];
            }
            break;
        }
        
        case OP_ALLOC: {
            if (microvm_require_pc_bytes(vm, 2) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            uint8_t size_reg = mem[vm->pc++];
            size_t size = (size_t)vm->regs.r[size_reg];
            
            /* Allocate requested size plus an extra safety buffer. */
            if (size == 0) {
                return MICROVM_ERR_MEMORY;
            }
            if (size > SIZE_MAX - MICROVM_ALLOC_OS_BUFFER_BYTES) {
                return MICROVM_ERR_MEMORY;
            }
            size_t reserved = size + MICROVM_ALLOC_OS_BUFFER_BYTES;
            if (vm->heap_ptr + reserved > vm->stack_ptr) {
                return MICROVM_ERR_MEMORY;
            }
            
            vm->regs.r[dest] = vm->heap_ptr;
            vm->heap_ptr += reserved;
            break;
        }
        
        /* ===== Network Operations ===== */
#ifdef MICROVM_PLATFORM_LINUX
        case OP_NET_SOCKET: {
            if (vm->network_mode == MICROVM_NET_DISABLED) {
                return MICROVM_ERR_PERMISSION;
            }
            if (microvm_require_pc_bytes(vm, 1) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            int domain = vm->regs.r[0];  /* AF_INET */
            int type = vm->regs.r[1];    /* SOCK_STREAM */
            vm->regs.r[dest] = socket(domain, type, 0);
            if (vm->regs.r[dest] < 0) {
                return MICROVM_ERR_NETWORK;
            }
            break;
        }
        
        case OP_NET_BIND: {
            if (vm->network_mode == MICROVM_NET_DISABLED) {
                return MICROVM_ERR_PERMISSION;
            }
            int sockfd = vm->regs.r[0];
            int port = (int)vm->regs.r[1];
            
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons((uint16_t)port);
            addr.sin_addr.s_addr = INADDR_ANY;
            
            if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                return MICROVM_ERR_NETWORK;
            }
            break;
        }
        
        case OP_NET_LISTEN: {
            if (vm->network_mode == MICROVM_NET_DISABLED) {
                return MICROVM_ERR_PERMISSION;
            }
            int sockfd = vm->regs.r[0];
            int backlog = (int)vm->regs.r[1];
            
            if (listen(sockfd, backlog) < 0) {
                return MICROVM_ERR_NETWORK;
            }
            break;
        }
        
        case OP_NET_ACCEPT: {
            if (vm->network_mode == MICROVM_NET_DISABLED) {
                return MICROVM_ERR_PERMISSION;
            }
            if (microvm_require_pc_bytes(vm, 1) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            int sockfd = vm->regs.r[0];
            
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            vm->regs.r[dest] = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
            break;
        }
        
        case OP_NET_CONNECT: {
            if (vm->network_mode == MICROVM_NET_DISABLED) {
                return MICROVM_ERR_PERMISSION;
            }
            int sockfd = vm->regs.r[0];
            
            /* For simplicity, assumes hostname in r1, port in r2 */
            /* Full implementation would use gethostbyname */
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            /* addr would be resolved from hostname */
            
            if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                return MICROVM_ERR_NETWORK;
            }
            break;
        }
        
        case OP_NET_SEND: {
            if (vm->network_mode == MICROVM_NET_DISABLED) {
                return MICROVM_ERR_PERMISSION;
            }
            int sockfd = vm->regs.r[0];
            size_t buf_off = (size_t)vm->regs.r[1];
            size_t len = (size_t)vm->regs.r[2];
            if (buf_off >= vm->memory_size || len > vm->memory_size - buf_off) {
                return MICROVM_ERR_OUT_OF_BOUNDS;
            }
            void *buf = (void *)&vm->memory[buf_off];
            
            ssize_t sent = send(sockfd, buf, len, 0);
            if (sent < 0) {
                return MICROVM_ERR_NETWORK;
            }
            vm->regs.r[0] = sent;
            break;
        }
        
        case OP_NET_RECV: {
            if (vm->network_mode == MICROVM_NET_DISABLED) {
                return MICROVM_ERR_PERMISSION;
            }
            int sockfd = vm->regs.r[0];
            size_t buf_off = (size_t)vm->regs.r[1];
            size_t len = (size_t)vm->regs.r[2];
            if (buf_off >= vm->memory_size || len > vm->memory_size - buf_off) {
                return MICROVM_ERR_OUT_OF_BOUNDS;
            }
            void *buf = (void *)&vm->memory[buf_off];
            
            ssize_t received = recv(sockfd, buf, len, 0);
            if (received < 0) {
                return MICROVM_ERR_NETWORK;
            }
            vm->regs.r[0] = received;
            break;
        }
        
        case OP_NET_CLOSE: {
            if (vm->network_mode == MICROVM_NET_DISABLED) {
                return MICROVM_ERR_PERMISSION;
            }
            int sockfd = vm->regs.r[0];
            close(sockfd);
            break;
        }
#endif
        
        /* ===== Environment Operations ===== */
        case OP_ENV_GET: {
            if (microvm_require_pc_bytes(vm, 1) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];

            /* vm->regs.r[0] holds an offset into VM memory (not a host pointer). */
            size_t key_off = (size_t)vm->regs.r[0];
            char key_buf[256];
            microvm_error_t kerr = microvm_copy_cstring_from_vm(vm, key_off, key_buf, sizeof(key_buf));
            if (kerr != MICROVM_SUCCESS) return kerr;

            const char *value = getenv(key_buf);
            if (value) {
                /* Store string in VM memory */
                size_t len = strlen(value) + 1;
                if (vm->heap_ptr + len > vm->stack_ptr) {
                    return MICROVM_ERR_MEMORY;
                }
                memcpy(&mem[vm->heap_ptr], value, len);
                vm->regs.r[dest] = vm->heap_ptr;
                vm->heap_ptr += len;
            } else {
                vm->regs.r[dest] = 0;
            }
            break;
        }
        
        case OP_ENV_SET: {
            /* vm->regs.r[0]/r[1] hold offsets into VM memory. */
            size_t key_off = (size_t)vm->regs.r[0];
            size_t val_off = (size_t)vm->regs.r[1];
            char key_buf[256];
            char val_buf[256];
            microvm_error_t kerr = microvm_copy_cstring_from_vm(vm, key_off, key_buf, sizeof(key_buf));
            if (kerr != MICROVM_SUCCESS) return kerr;
            microvm_error_t verr = microvm_copy_cstring_from_vm(vm, val_off, val_buf, sizeof(val_buf));
            if (verr != MICROVM_SUCCESS) return verr;
            setenv(key_buf, val_buf, 1);
            break;
        }
        
        /* ===== Time Operations ===== */
        case OP_GETTIME: {
            if (microvm_require_pc_bytes(vm, 1) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            int clock_id = (int)vm->regs.r[0];
            struct timespec ts;
            if (clock_gettime(clock_id, &ts) != 0) {
                return MICROVM_ERR_NOT_SUPPORTED;
            }
            vm->regs.r[dest] = ts.tv_sec * 1000000000 + ts.tv_nsec;
            break;
        }
        
        case OP_GETPID: {
            if (microvm_require_pc_bytes(vm, 1) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
#ifdef MICROVM_PLATFORM_LINUX
            vm->regs.r[dest] = getpid();
#else
            vm->regs.r[dest] = 0;
#endif
            break;
        }
        
        /* ===== Print Operations ===== */
        case OP_PRINT: {
            if (microvm_require_pc_bytes(vm, 1) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            /* Simplified print - would need format string parsing */
            uint8_t format_type = mem[vm->pc++];
            if (format_type == 0) {
                /* Print integer */
                printf("%ld", (long)vm->regs.r[0]);
            } else if (format_type == 1) {
                /* Print string */
                size_t str_off = (size_t)vm->regs.r[0];
                char buf[1024];
                microvm_error_t serr = microvm_copy_cstring_from_vm(vm, str_off, buf, sizeof(buf));
                if (serr != MICROVM_SUCCESS) return serr;
                printf("%s", buf);
            }
            break;
        }
        
        case OP_PRINTLN: {
            if (microvm_require_pc_bytes(vm, 1) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t format_type = mem[vm->pc++];
            if (format_type == 0) {
                printf("%ld\n", (long)vm->regs.r[0]);
            } else if (format_type == 1) {
                size_t str_off = (size_t)vm->regs.r[0];
                char buf[1024];
                microvm_error_t serr = microvm_copy_cstring_from_vm(vm, str_off, buf, sizeof(buf));
                if (serr != MICROVM_SUCCESS) return serr;
                printf("%s\n", buf);
            }
            break;
        }
        
        /* ===== Unknown Opcode ===== */
        default:
            return MICROVM_ERR_INVALID_OPCODE;
    }
    
    return MICROVM_SUCCESS;
}

/* ============================================================================
 * Configuration
 * ============================================================================ */

microvm_error_t microvm_set_mode(microvm_t *vm, microvm_mode_t mode) {
    if (!vm) {
        return MICROVM_ERR_INVALID_STATE;
    }
    
    /* Check permissions for kernel mode */
    if (mode == MICROVM_MODE_KERNEL) {
        /* Would check for root privileges here */
    }
    
    vm->mode = mode;
    return MICROVM_SUCCESS;
}

microvm_error_t microvm_set_network_mode(microvm_t *vm, microvm_network_mode_t mode) {
    if (!vm) {
        return MICROVM_ERR_INVALID_STATE;
    }
    vm->network_mode = mode;
    return MICROVM_SUCCESS;
}

microvm_error_t microvm_set_gpu_mode(microvm_t *vm, microvm_gpu_mode_t mode) {
    if (!vm) {
        return MICROVM_ERR_INVALID_STATE;
    }
    vm->gpu_mode = mode;
    return MICROVM_SUCCESS;
}

/* ============================================================================
 * Native Function Registration
 * ============================================================================ */

/* Native function storage */
typedef struct native_func_entry {
    char name[64];
    microvm_native_func_t func;
    struct native_func_entry *next;
} native_func_entry_t;

static native_func_entry_t *g_native_functions = NULL;

microvm_error_t microvm_register_native(microvm_t *vm, const char *name, microvm_native_func_t func) {
    if (!vm || !name || !func) {
        return MICROVM_ERR_INVALID_STATE;
    }
    
    native_func_entry_t *entry = malloc(sizeof(native_func_entry_t));
    if (!entry) {
        return MICROVM_ERR_MEMORY;
    }
    
    strncpy(entry->name, name, sizeof(entry->name) - 1);
    entry->name[sizeof(entry->name) - 1] = '\0';
    entry->func = func;
    entry->next = g_native_functions;
    g_native_functions = entry;
    
    return MICROVM_SUCCESS;
}

/* ============================================================================
 * Error Handling
 * ============================================================================ */

static void microvm_set_error(microvm_t *vm, microvm_error_t error, const char *msg) {
    if (!vm) return;
    
    vm->last_error = error;
    
    const char *err_str = "Unknown error";
    /* microvm_error_t values are negative (except MICROVM_SUCCESS=0). */
    if (error <= MICROVM_ERR_INVALID_BYTECODE && error >= MICROVM_ERR_INVALID_STATE) {
        err_str = g_error_strings[-error];
    }
    
    if (msg) {
        snprintf(vm->error_message, sizeof(vm->error_message), 
                "%s: %s", err_str, msg);
    } else {
        strncpy(vm->error_message, err_str, sizeof(vm->error_message) - 1);
        vm->error_message[sizeof(vm->error_message) - 1] = '\0';
    }
}

const char *microvm_get_error(const microvm_t *vm) {
    if (!vm) {
        return "Invalid VM";
    }
    return vm->error_message;
}

const char *microvm_state_to_string(const microvm_t *vm) {
    if (!vm) return "Invalid";
    if (vm->halted) return "Halted";
    if (vm->running) return "Running";
    return "Idle";
}

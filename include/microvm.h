/**
 * @file microvm.h
 * @brief BigWeiner MicroVM - Secure Execution Environment
 * @author BigWeiner Team
 * @version 1.0.0
 * 
 * C23 compliant micro-VM library for secure Python module execution.
 * Supports custom bytecode execution with network, GPU, and environment access.
 * 
 * License: GPL-3.0-only
 */

#ifndef MICROVM_H
#define MICROVM_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* C23 features detection */
#if defined(__STDC_VERSION__)
    #if __STDC_VERSION__ >= 202300L
        #define MICROVM_C23 true
    #endif
#endif

/* Platform detection */
#if defined(_WIN32) || defined(_WIN64)
    #define MICROVM_PLATFORM_WINDOWS
    #include <winsock2.h>
#elif defined(__APPLE__)
    #define MICROVM_PLATFORM_MACOS
#elif defined(__linux__)
    #define MICROVM_PLATFORM_LINUX
#endif

/* Compiler detection */
#if defined(__GNUC__)
    #define MICROVM_GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#endif

/* Version info */
#define MICROVM_VERSION_MAJOR 1
#define MICROVM_VERSION_MINOR 0
#define MICROVM_VERSION_PATCH 0
#define MICROVM_VERSION_STRING "1.0.0"

/* Config flags */
#define MICROVM_FLAG_ECC_ENABLED 0x00000001u

/* Limits */
#define MICROVM_MAX_REGISTERS 256
#define MICROVM_MAX_STACK_SIZE (1024 * 1024)  /* 1MB */
#define MICROVM_MAX_MEMORY (64 * 1024 * 1024)  /* 64MB */
#define MICROVM_MAX_BYTECODE_SIZE (10 * 1024 * 1024)  /* 10MB */
#define MICROVM_MAX_THREADS 64
#define MICROVM_MAX_CALL_DEPTH 1024
#define MICROVM_MAX_BROKER_SOCKETS 64

/* Execution modes */
typedef enum microvm_mode {
    MICROVM_MODE_KERNEL,       /* Full kernel access (requires root) */
    MICROVM_MODE_USER,          /* User space only (unprivileged) */
    MICROVM_MODE_SANDBOX       /* Fully sandboxed (no system access) */
} microvm_mode_t;

/* Network modes */
typedef enum microvm_network_mode {
    MICROVM_NET_DISABLED,      /* No network access */
    MICROVM_NET_TCP,           /* TCP only */
    MICROVM_NET_UDP,           /* UDP only */
    MICROVM_NET_ALL            /* Full network access */
} microvm_network_mode_t;

/* GPU modes */
typedef enum microvm_gpu_mode {
    MICROVM_GPU_DISABLED,       /* No GPU access */
    MICROVM_GPU_NVIDIA,        /* NVIDIA CUDA */
    MICROVM_GPU_AMD,           /* AMD ROCm */
    MICROVM_GPU_METAL,          /* Apple Metal */
    MICROVM_GPU_ALL             /* All available GPUs */
} microvm_gpu_mode_t;

/* Error codes */
typedef enum microvm_error {
    MICROVM_SUCCESS = 0,
    MICROVM_ERR_INVALID_BYTECODE = -1,
    MICROVM_ERR_INVALID_REGISTER = -2,
    MICROVM_ERR_STACK_OVERFLOW = -3,
    MICROVM_ERR_STACK_UNDERFLOW = -4,
    MICROVM_ERR_MEMORY = -5,
    MICROVM_ERR_DIVISION_BY_ZERO = -6,
    MICROVM_ERR_INVALID_OPCODE = -7,
    MICROVM_ERR_NETWORK = -8,
    MICROVM_ERR_GPU = -9,
    MICROVM_ERR_PERMISSION = -10,
    MICROVM_ERR_TIMEOUT = -11,
    MICROVM_ERR_NOT_SUPPORTED = -12,
    MICROVM_ERR_OUT_OF_BOUNDS = -13,
    MICROVM_ERR_INVALID_STATE = -14
} microvm_error_t;

/* Instruction opcodes (custom bytecode) */
typedef enum microvm_opcode {
    /* Data movement */
    OP_MOV = 0x01,          /* mov rdest, rsrc */
    OP_MOVI = 0x02,         /* movi rdest, imm32 */
    OP_MOVQ = 0x03,         /* movq rdest, imm64 */
    OP_MOVF = 0x04,         /* movf rdest, float */
    OP_MOVD = 0x05,         /* movd rdest, double */
    OP_LDARG = 0x06,        /* ldarg rdest, arg_idx */
    OP_RET = 0x07,          /* ret rsrc */
    OP_RETNULL = 0x08,      /* ret null */
    
    /* Arithmetic */
    OP_ADD = 0x10,          /* add rdest, rsrc1, rsrc2 */
    OP_SUB = 0x11,          /* sub rdest, rsrc1, rsrc2 */
    OP_MUL = 0x12,          /* mul rdest, rsrc1, rsrc2 */
    OP_DIV = 0x13,          /* div rdest, rsrc1, rsrc2 */
    OP_MOD = 0x14,          /* mod rdest, rsrc1, rsrc2 */
    OP_NEG = 0x15,          /* neg rdest, rsrc */
    OP_INC = 0x16,          /* inc rdest */
    OP_DEC = 0x17,          /* dec rdest */
    
    /* Floating point arithmetic */
    OP_ADDF = 0x20,         /* addf rdest, rsrc1, rsrc2 */
    OP_SUBF = 0x21,         /* subf rdest, rsrc1, rsrc2 */
    OP_MULF = 0x22,         /* mulf rdest, rsrc1, rsrc2 */
    OP_DIVF = 0x23,         /* divf rdest, rsrc1, rsrc2 */
    
    /* Bitwise */
    OP_AND = 0x30,          /* and rdest, rsrc1, rsrc2 */
    OP_OR = 0x31,           /* or rdest, rsrc1, rsrc2 */
    OP_XOR = 0x32,          /* xor rdest, rsrc1, rsrc2 */
    OP_NOT = 0x33,          /* not rdest, rsrc */
    OP_SHL = 0x34,          /* shl rdest, rsrc, shift */
    OP_SHR = 0x35,          /* shr rdest, rsrc, shift */
    
    /* Comparison */
    OP_CMP = 0x40,          /* cmp rsrc1, rsrc2 (sets flags) */
    OP_CMPF = 0x41,         /* cmpf rsrc1, rsrc2 */
    OP_TEST = 0x42,         /* test rsrc1, rsrc2 */
    
    /* Branching */
    OP_JMP = 0x50,          /* jmp label */
    OP_JZ = 0x51,           /* jz label (jump if zero) */
    OP_JNZ = 0x52,          /* jnz label (jump if not zero) */
    OP_JE = 0x53,           /* je label (jump if equal) */
    OP_JNE = 0x54,          /* jne label */
    OP_JG = 0x55,           /* jg label (jump if greater) */
    OP_JGE = 0x56,          /* jge label */
    OP_JL = 0x57,           /* jl label (jump if less) */
    OP_JLE = 0x58,          /* jle label */
    OP_CALL = 0x59,         /* call label */
    OP_SYSCALL = 0x5A,      /* syscall number, ... */
    
    /* Memory operations */
    OP_LOAD = 0x60,         /* load rdest, [address] */
    OP_STORE = 0x61,        /* store [address], rsrc */
    OP_LOADB = 0x62,        /* loadb rdest, [address] */
    OP_STOREB = 0x63,       /* storeb [address], rsrc */
    OP_LOADW = 0x64,        /* loadw rdest, [address] */
    OP_STOREW = 0x65,       /* storew [address], rsrc */
    OP_LOADD = 0x66,        /* loadd rdest, [address] */
    OP_STORED = 0x67,       /* stored [address], rsrc */
    OP_ALLOC = 0x68,        /* alloc rdest, size */
    OP_FREE = 0x69,         /* free address */
    
    /* String/Buffer operations */
    OP_STRLEN = 0x70,       /* strlen rdest, string_ptr */
    OP_STRCMP = 0x71,       /* strcmp rdest, str1, str2 */
    OP_STRCOPY = 0x72,      /* strcpy dest, src */
    OP_MEMCPY = 0x73,       /* memcpy dest, src, size */
    OP_MEMSET = 0x74,       /* memset dest, value, size */
    
    /* Network operations */
    OP_NET_SOCKET = 0x80,  /* socket rdest, domain, type */
    OP_NET_BIND = 0x81,    /* bind sockfd, addr, port */
    OP_NET_LISTEN = 0x82,   /* listen sockfd, backlog */
    OP_NET_ACCEPT = 0x83,   /* accept rdest, sockfd */
    OP_NET_CONNECT = 0x84,  /* connect sockfd, addr, port */
    OP_NET_SEND = 0x85,     /* send sockfd, buf, len */
    OP_NET_RECV = 0x86,     /* recv sockfd, buf, len */
    OP_NET_CLOSE = 0x87,    /* close sockfd */
    OP_NET_GETHOST = 0x88,   /* gethostbyname rdest, hostname */
    
    /* GPU operations */
    OP_GPU_INIT = 0x90,     /* gpu_init rdest */
    OP_GPU_ALLOC = 0x91,    /* gpu_alloc rdest, size */
    OP_GPU_UPLOAD = 0x92,   /* gpu_upload dest, src, size */
    OP_GPU_DOWNLOAD = 0x93,  /* gpu_download dest, src, size */
    OP_GPU_EXEC = 0x94,     /* gpu_exec kernel, args... */
    OP_GPU_SYNC = 0x95,     /* gpu_sync */
    OP_GPU_FREE = 0x96,     /* gpu_free ptr */
    
    /* Environment operations */
    OP_ENV_GET = 0xA0,      /* env_get rdest, key */
    OP_ENV_SET = 0xA1,      /* env_set key, value */
    OP_ENV_DEL = 0xA2,      /* env_del key */
    OP_GETTIME = 0xA3,      /* gettime rdest, clock_id */
    OP_GETPID = 0xA4,       /* getpid rdest */
    
    /* Built-in functions */
    OP_PRINT = 0xB0,        /* print format, args... */
    OP_PRINTLN = 0xB1,      /* println format, args... */
    OP_DEBUG = 0xB2,        /* debug message */
    OP_ASSERT = 0xB3,       /* assert condition, message */
    OP_HALT = 0xBF,         /* halt exit_code */
    
    /* NOP and padding */
    OP_NOP = 0x00,
    OP_INVALID = 0xFF
} microvm_opcode_t;

/* Register types */
typedef enum microvm_reg_type {
    REG_TYPE_INT64,
    REG_TYPE_FLOAT,
    REG_TYPE_DOUBLE,
    REG_TYPE_PTR,
    REG_TYPE_STRING,
    REG_TYPE_ARRAY
} microvm_reg_type_t;

/* CPU flags (set by comparison operations) */
typedef struct microvm_flags {
    unsigned char zero : 1;
    unsigned char carry : 1;
    unsigned char sign : 1;
    unsigned char overflow : 1;
    unsigned char less : 1;
    unsigned char greater : 1;
    unsigned char equal : 1;
    unsigned char reserved : 1;
} microvm_flags_t;

/* Register file */
typedef struct microvm_registers {
    int64_t r[MICROVM_MAX_REGISTERS];        /* Integer registers */
    double f[MICROVM_MAX_REGISTERS];         /* Floating point registers */
    void *p[MICROVM_MAX_REGISTERS];           /* Pointer registers */
    microvm_reg_type_t type[MICROVM_MAX_REGISTERS];
} microvm_registers_t;

/* Call frame for function calls */
typedef struct microvm_frame {
    size_t return_address;
    size_t stack_base;
    size_t local_count;
    int64_t locals[];
} microvm_frame_t;

/* VM instance */
typedef struct microvm {
    /* Configuration */
    microvm_mode_t mode;
    microvm_network_mode_t network_mode;
    microvm_gpu_mode_t gpu_mode;
    bool allow_env_ops;
    bool allow_time_ops;
    bool allow_raw_bytecode;
    uint32_t config_flags;
    
    /* Memory */
    uint8_t *memory;
    size_t memory_size;
    size_t heap_ptr;
    size_t stack_ptr;
    
    /* Registers and flags */
    microvm_registers_t regs;
    microvm_flags_t cpu_flags;
    
    /* Execution state */
    size_t pc;                     /* Program counter */
    bool running;
    bool halted;
    int exit_code;
    
    /* Call stack */
    /* Return addresses for OP_CALL/OP_RET */
    size_t call_stack[MICROVM_MAX_CALL_DEPTH];
    size_t call_depth;
    
    /* Network state (if enabled) */
    int socket_fd;
    int broker_sockets[MICROVM_MAX_BROKER_SOCKETS];
    bool broker_slot_used[MICROVM_MAX_BROKER_SOCKETS];
    
    /* GPU state (if enabled) */
    void *gpu_context;
    
    /* Environment */
    char **env_vars;
    size_t env_count;
    
    /* Statistics */
    uint64_t instructions_executed;
    uint64_t cycles;
    
    /* Error handling */
    microvm_error_t last_error;
    char error_message[512];

    /* ECC/integrity state (enabled via MICROVM_FLAG_ECC_ENABLED). */
    uint8_t *ecc_image;
    size_t ecc_image_size;
    uint32_t ecc_packet_checksum;
} microvm_t;

/* Configuration structure */
typedef struct microvm_config {
    microvm_mode_t mode;
    microvm_network_mode_t network_mode;
    microvm_gpu_mode_t gpu_mode;
    bool allow_env_ops;
    bool allow_time_ops;
    bool allow_raw_bytecode;
    size_t memory_size;
    size_t stack_size;
    size_t max_bytecodes;
    uint32_t timeout_ms;
    bool debug_enabled;
    bool trace_enabled;
    const char *entry_point;
} microvm_config_t;

/* Bytecode header */
typedef struct microvm_header {
    uint32_t magic;            /* 0x4D564D23 ('MVM#') */
    uint16_t version_major;
    uint16_t version_minor;
    uint32_t flags;
    uint32_t code_size;
    uint32_t data_size;
    uint32_t rodata_size;
    uint32_t bss_size;
    uint32_t entry_point;
    uint32_t num_imports;
    uint32_t num_exports;
    uint32_t checksum;
} microvm_header_t;

/* Network address structure */
typedef struct microvm_sockaddr {
    char family;          /* AF_INET, AF_INET6 */
    char port[2];
    char address[14];     /* IPv4 or IPv6 */
} microvm_sockaddr_t;

/* GPU kernel definition */
typedef struct microvm_gpu_kernel {
    const char *name;
    const uint8_t *code;
    size_t code_size;
    uint32_t workgroup_size;
    uint32_t num_args;
} microvm_gpu_kernel_t;

/* Public API */

/**
 * Initialize the MicroVM library
 * @return MICROVM_SUCCESS on success, error code on failure
 */
microvm_error_t microvm_init(void);

/**
 * Create a new VM instance
 * @param config Configuration (can be NULL for defaults)
 * @return VM instance handle, or NULL on failure
 */
microvm_t *microvm_create(const microvm_config_t *config);

/**
 * Destroy a VM instance
 * @param vm VM instance handle
 * @return MICROVM_SUCCESS on success
 */
microvm_error_t microvm_destroy(microvm_t *vm);

/**
 * Load bytecode into VM
 * @param vm VM instance
 * @param bytecode Bytecode data
 * @param size Size of bytecode
 * @return MICROVM_SUCCESS on success
 */
microvm_error_t microvm_load(microvm_t *vm, const uint8_t *bytecode, size_t size);

/**
 * Execute the loaded bytecode
 * @param vm VM instance
 * @return MICROVM_SUCCESS on success, error code on failure
 */
microvm_error_t microvm_run(microvm_t *vm);

/**
 * Stop execution
 * @param vm VM instance
 * @return MICROVM_SUCCESS on success
 */
microvm_error_t microvm_stop(microvm_t *vm);

/**
 * Pause execution
 * @param vm VM instance
 * @return MICROVM_SUCCESS on success
 */
microvm_error_t microvm_pause(microvm_t *vm);

/**
 * Resume execution
 * @param vm VM instance
 * @return MICROVM_SUCCESS on success
 */
microvm_error_t microvm_resume(microvm_t *vm);

/**
 * Get error message for last error
 * @param vm VM instance
 * @return Error message string (do not free)
 */
const char *microvm_get_error(const microvm_t *vm);

/**
 * Get VM state string
 * @param vm VM instance
 * @return State string
 */
const char *microvm_state_to_string(const microvm_t *vm);

/**
 * Get library version
 * @return Version string
 */
const char *microvm_version(void);

/**
 * Set execution mode (kernel/user/sandbox)
 * @param vm VM instance
 * @param mode Execution mode
 * @return MICROVM_SUCCESS on success
 */
microvm_error_t microvm_set_mode(microvm_t *vm, microvm_mode_t mode);

/**
 * Set network access mode
 * @param vm VM instance
 * @param mode Network mode
 * @return MICROVM_SUCCESS on success
 */
microvm_error_t microvm_set_network_mode(microvm_t *vm, microvm_network_mode_t mode);

/**
 * Set GPU access mode
 * @param vm VM instance
 * @param mode GPU mode
 * @return MICROVM_SUCCESS on success
 */
microvm_error_t microvm_set_gpu_mode(microvm_t *vm, microvm_gpu_mode_t mode);

/**
 * Register a native function
 * @param vm VM instance
 * @param name Function name
 * @param func Function pointer
 * @return MICROVM_SUCCESS on success
 */
typedef int64_t (*microvm_native_func_t)(microvm_t *vm, int64_t *args);
microvm_error_t microvm_register_native(microvm_t *vm, const char *name, microvm_native_func_t func);

/* Utility macros */
#define MICROVM_MAKE_VERSION(major, minor, patch) \
    (((major) << 16) | ((minor) << 8) | (patch))

#define MICROVM_VERSION \
    MICROVM_MAKE_VERSION(MICROVM_VERSION_MAJOR, MICROVM_VERSION_MINOR, MICROVM_VERSION_PATCH)

/* Bytecode magic number */
#define MICROVM_BYTECODE_MAGIC 0x4D564D23

/* Inline helpers (C23 allows this) */
static inline bool microvm_is_halted(const microvm_t *vm) {
    return vm && vm->halted;
}

static inline bool microvm_is_running(const microvm_t *vm) {
    return vm && vm->running && !vm->halted;
}

static inline int microvm_get_exit_code(const microvm_t *vm) {
    return vm ? vm->exit_code : -1;
}

static inline size_t microvm_get_pc(const microvm_t *vm) {
    return vm ? vm->pc : 0;
}

static inline uint64_t microvm_get_cycles(const microvm_t *vm) {
    return vm ? vm->cycles : 0;
}

#endif /* MICROVM_H */

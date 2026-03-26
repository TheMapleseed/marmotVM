/**
 * @file test.c
 * @brief MicroVM test suite
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/microvm.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) void test_##name(void)
#define RUN_TEST(name) do { \
    printf("Running " #name "... "); \
    test_##name(); \
    printf("PASSED\n"); \
    tests_passed++; \
} while(0)

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("FAILED: %s\n", msg); \
        tests_failed++; \
        return; \
    } \
} while(0)

/* Test VM creation and destruction */
TEST(create_destroy) {
    microvm_init();
    microvm_t *vm = microvm_create(NULL);
    ASSERT(vm != NULL, "VM should be created");
    ASSERT(microvm_is_halted(vm) == false, "VM should not be halted initially");
    microvm_destroy(vm);
}

/* Test loading bytecode */
TEST(load_bytecode) {
    microvm_t *vm = microvm_create(NULL);
    
    /* Simple bytecode: MOVI r0, 42; HALT */
    uint8_t bytecode[] = {OP_MOVI, 0, 0, 0, 42, OP_HALT, 0};
    
    microvm_error_t err = microvm_load(vm, bytecode, sizeof(bytecode));
    ASSERT(err == MICROVM_SUCCESS, "Should load bytecode successfully");
    
    microvm_destroy(vm);
}

/* Test basic arithmetic */
TEST(arithmetic) {
    microvm_t *vm = microvm_create(NULL);
    
    /* 
     * MOVI r0, 10
     * MOVI r1, 20
     * ADD r2, r0, r1
     * HALT
     */
    uint8_t bytecode[] = {
        OP_MOVI, 0, 0, 0, 0, 10,   /* r0 = 10 (imm32 big-endian) */
        OP_MOVI, 1, 0, 0, 0, 20,   /* r1 = 20 (imm32 big-endian) */
        OP_ADD, 2, 0, 1,        /* r2 = r0 + r1 */
        OP_HALT, 0
    };
    
    microvm_load(vm, bytecode, sizeof(bytecode));
    microvm_run(vm);
    
    ASSERT(vm->regs.r[2] == 30, "Addition should be 30");
    ASSERT(microvm_get_exit_code(vm) == 0, "Exit code should be 0");
    
    microvm_destroy(vm);
}

/* Test division */
TEST(division) {
    microvm_t *vm = microvm_create(NULL);
    
    uint8_t bytecode[] = {
        OP_MOVI, 0, 0, 0, 0, 100,  /* r0 = 100 (imm32 big-endian) */
        OP_MOVI, 1, 0, 0, 0, 4,    /* r1 = 4 (imm32 big-endian) */
        OP_DIV, 2, 0, 1,        /* r2 = r0 / r1 */
        OP_HALT, 0
    };
    
    microvm_load(vm, bytecode, sizeof(bytecode));
    microvm_run(vm);
    
    ASSERT(vm->regs.r[2] == 25, "Division should be 25");
    
    microvm_destroy(vm);
}

/* Test division by zero */
TEST(division_by_zero) {
    microvm_t *vm = microvm_create(NULL);
    
    uint8_t bytecode[] = {
        OP_MOVI, 0, 0, 0, 0, 100,
        OP_MOVI, 1, 0, 0, 0, 0,
        OP_DIV, 2, 0, 1,
        OP_HALT, 0
    };
    
    microvm_load(vm, bytecode, sizeof(bytecode));
    microvm_error_t err = microvm_run(vm);
    
    ASSERT(err == MICROVM_ERR_DIVISION_BY_ZERO, "Should catch division by zero");
    
    microvm_destroy(vm);
}

/* Test conditional jump */
TEST(conditional_jump) {
    microvm_t *vm = microvm_create(NULL);
    
    /* 
     * MOVI r0, 10
     * MOVI r1, 10
     * CMP r0, r1
     * JZ skip  (should NOT jump)
     * MOVI r2, 1
     * HALT
     */
    uint8_t bytecode[] = {
        OP_MOVI, 0, 0, 0, 0, 10,
        OP_MOVI, 1, 0, 0, 0, 10,
        OP_CMP, 0, 1,
        OP_JZ, 8,              /* Skip MOVI r2,99 (6 bytes) + JMP (2 bytes) */
        OP_MOVI, 2, 0, 0, 0, 99,  /* Should NOT execute */
        OP_JMP, 6,             /* Skip MOVI r2,42 (6 bytes) */
        OP_MOVI, 2, 0, 0, 0, 42,  /* Should execute - r2 = 42 */
        OP_HALT, 0
    };
    
    microvm_load(vm, bytecode, sizeof(bytecode));
    microvm_run(vm);
    
    ASSERT(vm->regs.r[2] == 42, "Should execute correct branch");
    
    microvm_destroy(vm);
}

/* Test memory allocation */
TEST(memory_alloc) {
    microvm_t *vm = microvm_create(NULL);
    
    uint8_t bytecode[] = {
        OP_MOVI, 0, 0, 0, 0, 100,  /* Size = 100 (imm32 big-endian) */
        OP_ALLOC, 1, 0,         /* Allocate r0 bytes, store in r1 */
        OP_HALT, 0
    };
    
    microvm_load(vm, bytecode, sizeof(bytecode));
    microvm_run(vm);
    
    ASSERT(vm->regs.r[1] >= 0, "Should return valid address");
    ASSERT(vm->regs.r[1] < vm->memory_size, "Address should be in range");
    
    microvm_destroy(vm);
}

/* Test environment get */
TEST(env_get) {
    microvm_t *vm = microvm_create(NULL);
    setenv("MICROVM_TEST_VAR", "hello_world", 1);
    
    uint8_t bytecode[] = {
        OP_MOVI, 0, 0, 0, 0,    /* will store key ptr */
        OP_MOVQ, 0, 0, 0, 0,    /* placeholder */
        OP_MOVQ, 0, 0, 0, 0,
        /* Would need string in memory - simplified test */
        OP_HALT, 0
    };
    
    /* This is a placeholder - actual env test needs setup */
    microvm_destroy(vm);
}

/* Test VM state */
TEST(vm_state) {
    microvm_t *vm = microvm_create(NULL);
    
    ASSERT(strcmp(microvm_state_to_string(vm), "Idle") == 0, "Should be idle initially");
    
    vm->running = true;
    ASSERT(strcmp(microvm_state_to_string(vm), "Running") == 0, "Should be running");
    
    vm->halted = true;
    ASSERT(strcmp(microvm_state_to_string(vm), "Halted") == 0, "Should be halted");
    
    microvm_destroy(vm);
}

/* Test configuration */
TEST(config) {
    microvm_t *vm = microvm_create(NULL);
    
    microvm_set_mode(vm, MICROVM_MODE_SANDBOX);
    ASSERT(vm->mode == MICROVM_MODE_SANDBOX, "Mode should be sandbox");
    
    microvm_set_network_mode(vm, MICROVM_NET_DISABLED);
    ASSERT(vm->network_mode == MICROVM_NET_DISABLED, "Network should be disabled");
    
    microvm_set_gpu_mode(vm, MICROVM_GPU_DISABLED);
    ASSERT(vm->gpu_mode == MICROVM_GPU_DISABLED, "GPU should be disabled");
    
    microvm_destroy(vm);
}

int main(void) {
    printf("=== MicroVM Test Suite ===\n\n");
    
    microvm_init();
    
    RUN_TEST(create_destroy);
    RUN_TEST(load_bytecode);
    RUN_TEST(arithmetic);
    RUN_TEST(division);
    RUN_TEST(division_by_zero);
    RUN_TEST(conditional_jump);
    RUN_TEST(memory_alloc);
    RUN_TEST(env_get);
    RUN_TEST(vm_state);
    RUN_TEST(config);
    
    printf("\n=== Results ===\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);
    
    return tests_failed > 0 ? 1 : 0;
}

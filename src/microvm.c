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

static inline bool microvm_valid_reg(uint8_t reg) {
    return reg < MICROVM_MAX_REGISTERS;
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

static inline void microvm_lock(microvm_t *vm) {
#if defined(MICROVM_PLATFORM_LINUX) || defined(MICROVM_PLATFORM_MACOS)
    if (vm) pthread_mutex_lock(&vm->lock);
#else
    (void)vm;
#endif
}

static inline void microvm_unlock(microvm_t *vm) {
#if defined(MICROVM_PLATFORM_LINUX) || defined(MICROVM_PLATFORM_MACOS)
    if (vm) pthread_mutex_unlock(&vm->lock);
#else
    (void)vm;
#endif
}

/* Forward declarations */
static microvm_error_t microvm_execute_op(microvm_t *vm, microvm_opcode_t opcode);
static void microvm_set_error(microvm_t *vm, microvm_error_t error, const char *msg);
static microvm_error_t microvm_build_ecc_image(microvm_t *vm, const uint8_t *data, size_t len);
static void microvm_ecc_tag_payload(const microvm_t *vm, const uint8_t *data, size_t len, uint8_t out16[16]);
static bool microvm_ct_equal(const uint8_t *a, const uint8_t *b, size_t n);
static bool microvm_ecc_replay_seen(const microvm_t *vm, const uint8_t tag16[16]);
static microvm_error_t microvm_ecc_replay_add(microvm_t *vm, const uint8_t tag16[16]);
static microvm_error_t microvm_snapshot_process_env(microvm_t *vm);
static const char *microvm_cached_env_get(const microvm_t *vm, const char *key);
static microvm_error_t microvm_cached_env_set(microvm_t *vm, const char *key, const char *value);
static int microvm_broker_alloc_handle(microvm_t *vm, int fd);
static int microvm_broker_get_fd(const microvm_t *vm, int handle);
static void microvm_broker_close_all(microvm_t *vm);
static bool microvm_net_allow_match(const microvm_t *vm, const char *host, int port);
static void microvm_parse_net_rules(microvm_t *vm);
static bool microvm_sockaddr_equal(const struct sockaddr *a, const struct sockaddr *b);
static bool microvm_net_allow_match_resolved(const microvm_t *vm, const struct sockaddr *candidate, int port);
static void microvm_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
static void microvm_hmac_sha256(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    uint8_t out[32]
);

static void microvm_ecc_tag_payload(const microvm_t *vm, const uint8_t *data, size_t len, uint8_t out16[16]) {
    uint8_t mac[32];
    memset(out16, 0, 16);
    if (!vm || !vm->ecc_keyed_enabled || vm->ecc_key[0] == '\0') {
        return;
    }
    microvm_hmac_sha256(
        (const uint8_t *)vm->ecc_key,
        strlen(vm->ecc_key),
        data,
        len,
        mac
    );
    memcpy(out16, mac, 16);
}

static bool microvm_ct_equal(const uint8_t *a, const uint8_t *b, size_t n) {
    unsigned char diff = 0u;
    for (size_t i = 0; i < n; i++) {
        diff |= (unsigned char)(a[i] ^ b[i]);
    }
    return diff == 0u;
}

static bool microvm_ecc_replay_seen(const microvm_t *vm, const uint8_t tag16[16]) {
    if (!vm) return false;
    for (size_t i = 0; i < vm->ecc_seen_count; i++) {
        if (microvm_ct_equal(vm->ecc_seen_tags[i], tag16, 16)) {
            return true;
        }
    }
    return false;
}

static microvm_error_t microvm_ecc_replay_add(microvm_t *vm, const uint8_t tag16[16]) {
    if (!vm) return MICROVM_ERR_INVALID_STATE;
    if (vm->ecc_seen_count < MICROVM_MAX_ECC_REPLAY_TAGS) {
        memcpy(vm->ecc_seen_tags[vm->ecc_seen_count++], tag16, 16);
        return MICROVM_SUCCESS;
    }
    /* Sliding window: drop oldest */
    memmove(vm->ecc_seen_tags, vm->ecc_seen_tags + 1, (MICROVM_MAX_ECC_REPLAY_TAGS - 1) * 16);
    memcpy(vm->ecc_seen_tags[MICROVM_MAX_ECC_REPLAY_TAGS - 1], tag16, 16);
    return MICROVM_SUCCESS;
}

/* ---- Minimal SHA-256/HMAC implementation for keyed ECC checks ---- */
static inline uint32_t rotr32(uint32_t x, uint32_t n) { return (x >> n) | (x << (32u - n)); }
static inline uint32_t ch32(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
static inline uint32_t maj32(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static inline uint32_t bsig0(uint32_t x) { return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22); }
static inline uint32_t bsig1(uint32_t x) { return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25); }
static inline uint32_t ssig0(uint32_t x) { return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3); }
static inline uint32_t ssig1(uint32_t x) { return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10); }

static const uint32_t K256[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

static void microvm_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint32_t h[8] = {
        0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
        0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
    };

    uint64_t bit_len = (uint64_t)len * 8u;
    size_t total = len + 1 + 8;
    size_t padded = ((total + 63u) / 64u) * 64u;
    uint8_t *msg = (uint8_t *)calloc(padded, 1);
    if (!msg) {
        memset(out, 0, 32);
        return;
    }
    memcpy(msg, data, len);
    msg[len] = 0x80u;
    msg[padded - 8] = (uint8_t)(bit_len >> 56);
    msg[padded - 7] = (uint8_t)(bit_len >> 48);
    msg[padded - 6] = (uint8_t)(bit_len >> 40);
    msg[padded - 5] = (uint8_t)(bit_len >> 32);
    msg[padded - 4] = (uint8_t)(bit_len >> 24);
    msg[padded - 3] = (uint8_t)(bit_len >> 16);
    msg[padded - 2] = (uint8_t)(bit_len >> 8);
    msg[padded - 1] = (uint8_t)(bit_len);

    for (size_t off = 0; off < padded; off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++) {
            size_t j = off + (size_t)i * 4u;
            w[i] = ((uint32_t)msg[j] << 24) | ((uint32_t)msg[j + 1] << 16) |
                   ((uint32_t)msg[j + 2] << 8) | (uint32_t)msg[j + 3];
        }
        for (int i = 16; i < 64; i++) {
            w[i] = ssig1(w[i - 2]) + w[i - 7] + ssig0(w[i - 15]) + w[i - 16];
        }

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t t1 = hh + bsig1(e) + ch32(e, f, g) + K256[i] + w[i];
            uint32_t t2 = bsig0(a) + maj32(a, b, c);
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    free(msg);
    for (int i = 0; i < 8; i++) {
        out[i * 4]     = (uint8_t)(h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(h[i]);
    }
}

static void microvm_hmac_sha256(
    const uint8_t *key, size_t key_len,
    const uint8_t *data, size_t data_len,
    uint8_t out[32]
) {
    uint8_t k0[64];
    memset(k0, 0, sizeof(k0));

    if (key_len > 64) {
        microvm_sha256(key, key_len, k0);
    } else {
        memcpy(k0, key, key_len);
    }

    uint8_t ipad[64], opad[64];
    for (size_t i = 0; i < 64; i++) {
        ipad[i] = (uint8_t)(k0[i] ^ 0x36u);
        opad[i] = (uint8_t)(k0[i] ^ 0x5cu);
    }

    size_t inner_len = 64 + data_len;
    uint8_t *inner = (uint8_t *)malloc(inner_len);
    if (!inner) {
        memset(out, 0, 32);
        return;
    }
    memcpy(inner, ipad, 64);
    memcpy(inner + 64, data, data_len);
    uint8_t inner_hash[32];
    microvm_sha256(inner, inner_len, inner_hash);
    free(inner);

    uint8_t outer[64 + 32];
    memcpy(outer, opad, 64);
    memcpy(outer + 64, inner_hash, 32);
    microvm_sha256(outer, sizeof(outer), out);
}

/* One XOR parity byte for each 32-byte payload block. */
static microvm_error_t microvm_build_ecc_image(microvm_t *vm, const uint8_t *data, size_t len) {
    if (!vm) return MICROVM_ERR_INVALID_STATE;

    if (vm->ecc_image) {
        free(vm->ecc_image);
        vm->ecc_image = NULL;
        vm->ecc_image_size = 0;
    }

    if (!data || len == 0) {
        vm->ecc_packet_checksum = 0;
        return MICROVM_SUCCESS;
    }

    const size_t block_size = 32;
    size_t blocks = (len + block_size - 1) / block_size;
    vm->ecc_image = (uint8_t *)calloc(blocks, sizeof(uint8_t));
    if (!vm->ecc_image) {
        return MICROVM_ERR_MEMORY;
    }

    for (size_t b = 0; b < blocks; b++) {
        size_t start = b * block_size;
        size_t end = start + block_size;
        if (end > len) end = len;
        uint8_t parity = 0;
        for (size_t i = start; i < end; i++) {
            parity ^= data[i];
        }
        vm->ecc_image[b] = parity;
    }

    vm->ecc_image_size = blocks;
    uint8_t tag16[16];
    microvm_ecc_tag_payload(vm, data, len, tag16);
    vm->ecc_packet_checksum = ((uint32_t)tag16[0] << 24) |
                              ((uint32_t)tag16[1] << 16) |
                              ((uint32_t)tag16[2] << 8) |
                              (uint32_t)tag16[3];
    return MICROVM_SUCCESS;
}

static const char *microvm_cached_env_get(const microvm_t *vm, const char *key) {
    if (!vm || !key || !vm->env_vars) return NULL;
    size_t key_len = strlen(key);
    for (size_t i = 0; i < vm->env_count; i++) {
        const char *entry = vm->env_vars[i];
        if (!entry) continue;
        if (strncmp(entry, key, key_len) == 0 && entry[key_len] == '=') {
            return entry + key_len + 1;
        }
    }
    return NULL;
}

static microvm_error_t microvm_cached_env_set(microvm_t *vm, const char *key, const char *value) {
    if (!vm || !key || !value) return MICROVM_ERR_INVALID_STATE;
    size_t key_len = strlen(key);
    if (key_len == 0 || strchr(key, '=')) return MICROVM_ERR_INVALID_BYTECODE;

    size_t value_len = strlen(value);
    size_t needed = key_len + 1 + value_len + 1;
    char *entry = (char *)malloc(needed);
    if (!entry) return MICROVM_ERR_MEMORY;
    memcpy(entry, key, key_len);
    entry[key_len] = '=';
    memcpy(entry + key_len + 1, value, value_len);
    entry[needed - 1] = '\0';

    for (size_t i = 0; i < vm->env_count; i++) {
        const char *curr = vm->env_vars[i];
        if (!curr) continue;
        if (strncmp(curr, key, key_len) == 0 && curr[key_len] == '=') {
            free(vm->env_vars[i]);
            vm->env_vars[i] = entry;
            return MICROVM_SUCCESS;
        }
    }

    char **grown = (char **)realloc(vm->env_vars, sizeof(char *) * (vm->env_count + 1));
    if (!grown) {
        free(entry);
        return MICROVM_ERR_MEMORY;
    }
    vm->env_vars = grown;
    vm->env_vars[vm->env_count++] = entry;
    return MICROVM_SUCCESS;
}

static microvm_error_t microvm_snapshot_process_env(microvm_t *vm) {
    if (!vm) return MICROVM_ERR_INVALID_STATE;
#if defined(MICROVM_PLATFORM_LINUX) || defined(MICROVM_PLATFORM_MACOS)
    extern char **environ;
    if (!environ) return MICROVM_SUCCESS;

    size_t count = 0;
    while (environ[count]) count++;
    if (count == 0) return MICROVM_SUCCESS;

    vm->env_vars = (char **)calloc(count, sizeof(char *));
    if (!vm->env_vars) return MICROVM_ERR_MEMORY;

    for (size_t i = 0; i < count; i++) {
        size_t n = strlen(environ[i]);
        vm->env_vars[i] = (char *)malloc(n + 1);
        if (!vm->env_vars[i]) {
            for (size_t j = 0; j < i; j++) free(vm->env_vars[j]);
            free(vm->env_vars);
            vm->env_vars = NULL;
            vm->env_count = 0;
            return MICROVM_ERR_MEMORY;
        }
        memcpy(vm->env_vars[i], environ[i], n + 1);
    }
    vm->env_count = count;
#endif
    return MICROVM_SUCCESS;
}

static int microvm_broker_alloc_handle(microvm_t *vm, int fd) {
    if (!vm || fd < 0) return -1;
    for (int i = 0; i < MICROVM_MAX_BROKER_SOCKETS; i++) {
        if (!vm->broker_slot_used[i]) {
            vm->broker_slot_used[i] = true;
            vm->broker_sockets[i] = fd;
            return i + 1; /* Opaque non-zero handle */
        }
    }
    return -1;
}

static int microvm_broker_get_fd(const microvm_t *vm, int handle) {
    if (!vm || handle <= 0) return -1;
    int idx = handle - 1;
    if (idx < 0 || idx >= MICROVM_MAX_BROKER_SOCKETS) return -1;
    if (!vm->broker_slot_used[idx]) return -1;
    return vm->broker_sockets[idx];
}

static void microvm_broker_close_all(microvm_t *vm) {
    if (!vm) return;
    for (int i = 0; i < MICROVM_MAX_BROKER_SOCKETS; i++) {
        if (vm->broker_slot_used[i]) {
#if defined(MICROVM_PLATFORM_WINDOWS)
            closesocket(vm->broker_sockets[i]);
#else
            close(vm->broker_sockets[i]);
#endif
            vm->broker_slot_used[i] = false;
            vm->broker_sockets[i] = -1;
        }
    }
}

static bool microvm_net_allow_match(const microvm_t *vm, const char *host, int port) {
    if (!vm || !vm->net_broker_enabled) return true;
    if (!host || port <= 0) return false;
    for (size_t i = 0; i < vm->net_rule_count; i++) {
        if (vm->net_rules[i].port == (uint16_t)port &&
            strcmp(vm->net_rules[i].host, host) == 0) {
            return true;
        }
    }
    return false;
}

static bool microvm_sockaddr_equal(const struct sockaddr *a, const struct sockaddr *b) {
    if (!a || !b || a->sa_family != b->sa_family) return false;
    if (a->sa_family == AF_INET) {
        const struct sockaddr_in *aa = (const struct sockaddr_in *)a;
        const struct sockaddr_in *bb = (const struct sockaddr_in *)b;
        return aa->sin_addr.s_addr == bb->sin_addr.s_addr;
    }
    if (a->sa_family == AF_INET6) {
        const struct sockaddr_in6 *aa = (const struct sockaddr_in6 *)a;
        const struct sockaddr_in6 *bb = (const struct sockaddr_in6 *)b;
        return memcmp(&aa->sin6_addr, &bb->sin6_addr, sizeof(struct in6_addr)) == 0;
    }
    return false;
}

static bool microvm_net_allow_match_resolved(const microvm_t *vm, const struct sockaddr *candidate, int port) {
    if (!vm || !candidate || port <= 0) return false;
    char port_buf[16];
    snprintf(port_buf, sizeof(port_buf), "%d", port);

    for (size_t i = 0; i < vm->net_rule_count; i++) {
        if (vm->net_rules[i].port != (uint16_t)port) continue;
        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = candidate->sa_family;
        hints.ai_socktype = SOCK_STREAM;
        struct addrinfo *allow_res = NULL;
        if (getaddrinfo(vm->net_rules[i].host, port_buf, &hints, &allow_res) != 0 || !allow_res) {
            continue;
        }
        for (struct addrinfo *p = allow_res; p; p = p->ai_next) {
            if (microvm_sockaddr_equal(candidate, p->ai_addr)) {
                freeaddrinfo(allow_res);
                return true;
            }
        }
        freeaddrinfo(allow_res);
    }
    return false;
}

static void microvm_parse_net_rules(microvm_t *vm) {
    if (!vm) return;
    vm->net_rule_count = 0;
    if (vm->net_allow_raw[0] == '\0') return;

    char work[1024];
    strncpy(work, vm->net_allow_raw, sizeof(work) - 1);
    work[sizeof(work) - 1] = '\0';

    char *saveptr = NULL;
    char *tok = strtok_r(work, ",", &saveptr);
    while (tok && vm->net_rule_count < MICROVM_MAX_NET_RULES) {
        while (*tok == ' ' || *tok == '\t') tok++;
        size_t n = strlen(tok);
        while (n > 0 && (tok[n - 1] == ' ' || tok[n - 1] == '\t')) tok[--n] = '\0';
        char *colon = strrchr(tok, ':');
        if (colon && colon != tok && colon[1] != '\0') {
            *colon = '\0';
            char *endp = NULL;
            unsigned long p = strtoul(colon + 1, &endp, 10);
            if (endp && *endp == '\0' && p > 0 && p <= 65535) {
                microvm_net_rule_t *r = &vm->net_rules[vm->net_rule_count++];
                strncpy(r->host, tok, sizeof(r->host) - 1);
                r->host[sizeof(r->host) - 1] = '\0';
                r->port = (uint16_t)p;
            }
        }
        tok = strtok_r(NULL, ",", &saveptr);
    }
}

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
#if defined(MICROVM_PLATFORM_LINUX) || defined(MICROVM_PLATFORM_MACOS)
    pthread_mutexattr_t mattr;
    if (pthread_mutexattr_init(&mattr) != 0) {
        free(vm);
        return NULL;
    }
    pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_RECURSIVE);
    if (pthread_mutex_init(&vm->lock, &mattr) != 0) {
        pthread_mutexattr_destroy(&mattr);
        free(vm);
        return NULL;
    }
    pthread_mutexattr_destroy(&mattr);
#endif
    
    /* Set defaults if no config provided */
    if (config) {
        vm->mode = config->mode;
        vm->network_mode = config->network_mode;
        vm->gpu_mode = config->gpu_mode;
        vm->allow_env_ops = config->allow_env_ops;
        vm->allow_time_ops = config->allow_time_ops;
        vm->allow_raw_bytecode = config->allow_raw_bytecode;
        vm->config_flags = config->config_flags;
        vm->net_broker_enabled = config->net_broker_enabled;
        vm->memory_cap_bytes = config->memory_cap_bytes;
        vm->ecc_keyed_enabled = false;
        vm->ecc_key[0] = '\0';
        if (config->net_allow_raw) {
            strncpy(vm->net_allow_raw, config->net_allow_raw, sizeof(vm->net_allow_raw) - 1);
            vm->net_allow_raw[sizeof(vm->net_allow_raw) - 1] = '\0';
        } else {
            vm->net_allow_raw[0] = '\0';
        }
        if (config->ecc_key && config->ecc_key[0] != '\0') {
            strncpy(vm->ecc_key, config->ecc_key, sizeof(vm->ecc_key) - 1);
            vm->ecc_key[sizeof(vm->ecc_key) - 1] = '\0';
            vm->ecc_keyed_enabled = true;
        }
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
        vm->allow_env_ops = true;
        vm->allow_time_ops = true;
        vm->allow_raw_bytecode = true;
        vm->config_flags = 0;
        vm->net_broker_enabled = false;
        vm->net_allow_raw[0] = '\0';
        vm->ecc_keyed_enabled = false;
        vm->ecc_key[0] = '\0';
        vm->memory_cap_bytes = 0;
        vm->memory_size = MICROVM_MAX_MEMORY;
        vm->stack_ptr = vm->memory_size - MICROVM_MAX_STACK_SIZE - MICROVM_HEAP_GUARD_BYTES;
    }

    /* Per-instance env overrides for broker/ECC/memory policy. */
    const char *broker_env = getenv("MARMOTVM_NET_BROKER");
    if (broker_env && (
        strcmp(broker_env, "1") == 0 || strcmp(broker_env, "true") == 0 ||
        strcmp(broker_env, "TRUE") == 0 || strcmp(broker_env, "on") == 0 ||
        strcmp(broker_env, "ON") == 0)) {
        vm->net_broker_enabled = true;
    }
    const char *allow_env = getenv("MARMOTVM_NET_ALLOW");
    if (allow_env && allow_env[0] != '\0') {
        strncpy(vm->net_allow_raw, allow_env, sizeof(vm->net_allow_raw) - 1);
        vm->net_allow_raw[sizeof(vm->net_allow_raw) - 1] = '\0';
    }
    const char *ecc_env = getenv("MARMOTVM_ECC");
    if (ecc_env && (
        strcmp(ecc_env, "1") == 0 || strcmp(ecc_env, "true") == 0 ||
        strcmp(ecc_env, "TRUE") == 0 || strcmp(ecc_env, "on") == 0 ||
        strcmp(ecc_env, "ON") == 0)) {
        vm->config_flags |= MICROVM_FLAG_ECC_ENABLED;
    }
    const char *ecc_key_env = getenv("MARMOTVM_ECC_KEY");
    if (ecc_key_env && ecc_key_env[0] != '\0') {
        strncpy(vm->ecc_key, ecc_key_env, sizeof(vm->ecc_key) - 1);
        vm->ecc_key[sizeof(vm->ecc_key) - 1] = '\0';
        vm->ecc_keyed_enabled = true;
    }
    const char *mem_cap_env = getenv("MARMOTVM_MAX_MEMORY_MB");
    if (mem_cap_env && mem_cap_env[0] != '\0') {
        char *endp = NULL;
        unsigned long long mb = strtoull(mem_cap_env, &endp, 10);
        if (endp && *endp == '\0' && mb > 0) {
            unsigned long long bytes = mb * 1024ULL * 1024ULL;
            vm->memory_cap_bytes = bytes > (unsigned long long)SIZE_MAX ? SIZE_MAX : (size_t)bytes;
        }
    }

    if (vm->memory_cap_bytes > 0 && vm->memory_size > vm->memory_cap_bytes) {
        vm->memory_size = vm->memory_cap_bytes;
    }
    microvm_parse_net_rules(vm);

    /* Sandbox policy is deny-by-default for privileged host integrations. */
    if (vm->mode == MICROVM_MODE_SANDBOX) {
        vm->network_mode = MICROVM_NET_DISABLED;
        vm->gpu_mode = MICROVM_GPU_DISABLED;
        vm->allow_env_ops = false;
        vm->allow_time_ops = false;
        vm->allow_raw_bytecode = false;
    }

    /* Kernel mode must be explicitly privileged on Unix-like platforms. */
    if (vm->mode == MICROVM_MODE_KERNEL) {
        /*
         * Hard security policy:
         * kernel-mode execution is disabled in this runtime build to prevent
         * any guest-triggered kernel-surface interaction.
         */
        #if defined(MICROVM_PLATFORM_LINUX) || defined(MICROVM_PLATFORM_MACOS)
        pthread_mutex_destroy(&vm->lock);
        #endif
        free(vm);
        return NULL;
    }
    
    /* Allocate memory */
    vm->memory = calloc(1, vm->memory_size);
    if (!vm->memory) {
        #if defined(MICROVM_PLATFORM_LINUX) || defined(MICROVM_PLATFORM_MACOS)
        pthread_mutex_destroy(&vm->lock);
        #endif
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
    vm->ecc_image = NULL;
    vm->ecc_image_size = 0;
    vm->ecc_packet_checksum = 0;
    vm->ecc_seen_count = 0;
    vm->env_vars = NULL;
    vm->env_count = 0;
    for (int i = 0; i < MICROVM_MAX_BROKER_SOCKETS; i++) {
        vm->broker_sockets[i] = -1;
        vm->broker_slot_used[i] = false;
    }
    
    /* Initialize registers */
    memset(&vm->regs, 0, sizeof(vm->regs));
    memset(&vm->cpu_flags, 0, sizeof(vm->cpu_flags));

    /* Snapshot process environment into VM-local cache for this instance. */
    if (vm->allow_env_ops) {
        microvm_error_t e = microvm_snapshot_process_env(vm);
        if (e != MICROVM_SUCCESS) {
            microvm_destroy(vm);
            return NULL;
        }
    }
    
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
    microvm_broker_close_all(vm);

    if (vm->ecc_image) {
        free(vm->ecc_image);
    }
    
    /* Free environment */
    if (vm->env_vars) {
        for (size_t i = 0; i < vm->env_count; i++) {
            free(vm->env_vars[i]);
        }
        free(vm->env_vars);
    }
#if defined(MICROVM_PLATFORM_LINUX) || defined(MICROVM_PLATFORM_MACOS)
    pthread_mutex_destroy(&vm->lock);
#endif
    free(vm);
    return MICROVM_SUCCESS;
}

/* ============================================================================
 * Bytecode Loading
 * ============================================================================ */

microvm_error_t microvm_load(microvm_t *vm, const uint8_t *bytecode, size_t size) {
    #define RETURN_UNLOCK(code) do { microvm_unlock(vm); return (code); } while (0)
    if (!vm || !bytecode || size == 0) {
        return MICROVM_ERR_INVALID_BYTECODE;
    }
    microvm_lock(vm);
    
    if (size > MICROVM_MAX_BYTECODE_SIZE) {
        RETURN_UNLOCK(MICROVM_ERR_INVALID_BYTECODE);
    }
    
    if (size > vm->memory_size) {
        RETURN_UNLOCK(MICROVM_ERR_OUT_OF_BOUNDS);
    }

    if (size > vm->stack_ptr) {
        /* No room to even start the heap (heap_ptr is at bytecode end). */
        RETURN_UNLOCK(MICROVM_ERR_MEMORY);
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
    if (vm->ecc_image) {
        free(vm->ecc_image);
        vm->ecc_image = NULL;
        vm->ecc_image_size = 0;
    }
    vm->ecc_packet_checksum = 0;

    /* Check magic number */
    bool has_valid_magic = false;
    if (size >= 4) {
        uint32_t magic = (bytecode[0] << 24) | (bytecode[1] << 16) | 
                        (bytecode[2] << 8) | bytecode[3];
        if (magic != MICROVM_BYTECODE_MAGIC) {
            if (!vm->allow_raw_bytecode) {
                RETURN_UNLOCK(MICROVM_ERR_INVALID_BYTECODE);
            }
        } else {
            has_valid_magic = true;
        }
    } else if (!vm->allow_raw_bytecode) {
        RETURN_UNLOCK(MICROVM_ERR_INVALID_BYTECODE);
    }

    if ((vm->config_flags & MICROVM_FLAG_ECC_ENABLED) != 0u) {
        if (!vm->ecc_keyed_enabled || vm->ecc_key[0] == '\0') {
            RETURN_UNLOCK(MICROVM_ERR_PERMISSION);
        }
        const size_t header_size = sizeof(microvm_header_t);
        if (!has_valid_magic || size <= header_size + 16 || header_size < 48) {
            RETURN_UNLOCK(MICROVM_ERR_INVALID_BYTECODE);
        }

        const uint8_t *provided_tag = bytecode + size - 16;
        const uint8_t *payload = bytecode + header_size;
        size_t payload_size = size - header_size - 16;
        uint8_t computed_tag[16];
        microvm_ecc_tag_payload(vm, payload, payload_size, computed_tag);
        if (!microvm_ct_equal(provided_tag, computed_tag, 16)) {
            RETURN_UNLOCK(MICROVM_ERR_INVALID_BYTECODE);
        }
        if (microvm_ecc_replay_seen(vm, computed_tag)) {
            RETURN_UNLOCK(MICROVM_ERR_PERMISSION);
        }
        microvm_error_t rerr = microvm_ecc_replay_add(vm, computed_tag);
        if (rerr != MICROVM_SUCCESS) {
            RETURN_UNLOCK(rerr);
        }

        microvm_error_t eerr = microvm_build_ecc_image(vm, payload, payload_size);
        if (eerr != MICROVM_SUCCESS) {
            RETURN_UNLOCK(eerr);
        }
    }
    
    /* Copy bytecode to memory (at address 0) */
    memcpy(vm->memory, bytecode, size);
    microvm_unlock(vm);
    return MICROVM_SUCCESS;
    #undef RETURN_UNLOCK
}

/* ============================================================================
 * Execution Core
 * ============================================================================ */

microvm_error_t microvm_run(microvm_t *vm) {
    if (!vm || !vm->memory) {
        return MICROVM_ERR_INVALID_STATE;
    }
    microvm_lock(vm);
    
    if (vm->halted) {
        microvm_unlock(vm);
        return MICROVM_ERR_INVALID_STATE;
    }
    
    vm->running = true;
    
    while (vm->running && !vm->halted) {
        /* Fetch opcode */
        if (vm->pc >= vm->memory_size) {
            microvm_set_error(vm, MICROVM_ERR_OUT_OF_BOUNDS, "PC out of bounds");
            vm->running = false;
            microvm_unlock(vm);
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
            microvm_unlock(vm);
            return MICROVM_ERR_TIMEOUT;
        }
        
        if (result != MICROVM_SUCCESS) {
            vm->running = false;
            microvm_unlock(vm);
            return result;
        }
    }
    
    vm->running = false;
    microvm_unlock(vm);
    return MICROVM_SUCCESS;
}

microvm_error_t microvm_stop(microvm_t *vm) {
    if (!vm) {
        return MICROVM_ERR_INVALID_STATE;
    }
    microvm_lock(vm);
    vm->running = false;
    vm->halted = true;
    microvm_unlock(vm);
    return MICROVM_SUCCESS;
}

microvm_error_t microvm_pause(microvm_t *vm) {
    if (!vm) {
        return MICROVM_ERR_INVALID_STATE;
    }
    microvm_lock(vm);
    vm->running = false;
    microvm_unlock(vm);
    return MICROVM_SUCCESS;
}

microvm_error_t microvm_resume(microvm_t *vm) {
    if (!vm || vm->halted) {
        return MICROVM_ERR_INVALID_STATE;
    }
    microvm_lock(vm);
    vm->running = true;
    microvm_unlock(vm);
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
            if (!microvm_valid_reg(dest)) return MICROVM_ERR_INVALID_REGISTER;
            int32_t imm = microvm_read_int32(mem, vm->pc);
            vm->pc += 4;
            vm->regs.r[dest] = imm;
            vm->regs.type[dest] = REG_TYPE_INT64;
            break;
        }
        
        case OP_MOVQ: {
            if (microvm_require_pc_bytes(vm, 1 + 8) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            if (!microvm_valid_reg(dest)) return MICROVM_ERR_INVALID_REGISTER;
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
            if (!microvm_valid_reg(dest) || !microvm_valid_reg(a) || !microvm_valid_reg(b)) return MICROVM_ERR_INVALID_REGISTER;
            vm->regs.r[dest] = vm->regs.r[a] + vm->regs.r[b];
            break;
        }
        
        case OP_SUB: {
            if (microvm_require_pc_bytes(vm, 3) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            uint8_t a = mem[vm->pc++];
            uint8_t b = mem[vm->pc++];
            if (!microvm_valid_reg(dest) || !microvm_valid_reg(a) || !microvm_valid_reg(b)) return MICROVM_ERR_INVALID_REGISTER;
            vm->regs.r[dest] = vm->regs.r[a] - vm->regs.r[b];
            break;
        }
        
        case OP_MUL: {
            if (microvm_require_pc_bytes(vm, 3) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            uint8_t a = mem[vm->pc++];
            uint8_t b = mem[vm->pc++];
            if (!microvm_valid_reg(dest) || !microvm_valid_reg(a) || !microvm_valid_reg(b)) return MICROVM_ERR_INVALID_REGISTER;
            vm->regs.r[dest] = vm->regs.r[a] * vm->regs.r[b];
            break;
        }
        
        case OP_DIV: {
            if (microvm_require_pc_bytes(vm, 3) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            uint8_t a = mem[vm->pc++];
            uint8_t b = mem[vm->pc++];
            if (!microvm_valid_reg(dest) || !microvm_valid_reg(a) || !microvm_valid_reg(b)) return MICROVM_ERR_INVALID_REGISTER;
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
            if (!microvm_valid_reg(dest) || !microvm_valid_reg(a) || !microvm_valid_reg(b)) return MICROVM_ERR_INVALID_REGISTER;
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
            if (!microvm_valid_reg(dest) || !microvm_valid_reg(src)) return MICROVM_ERR_INVALID_REGISTER;
            vm->regs.r[dest] = -vm->regs.r[src];
            break;
        }
        
        case OP_INC: {
            if (microvm_require_pc_bytes(vm, 1) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            if (!microvm_valid_reg(dest)) return MICROVM_ERR_INVALID_REGISTER;
            vm->regs.r[dest]++;
            break;
        }
        
        case OP_DEC: {
            if (microvm_require_pc_bytes(vm, 1) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            if (!microvm_valid_reg(dest)) return MICROVM_ERR_INVALID_REGISTER;
            vm->regs.r[dest]--;
            break;
        }
        
        /* ===== Bitwise ===== */
        case OP_AND: {
            if (microvm_require_pc_bytes(vm, 3) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            uint8_t a = mem[vm->pc++];
            uint8_t b = mem[vm->pc++];
            if (!microvm_valid_reg(dest) || !microvm_valid_reg(a) || !microvm_valid_reg(b)) return MICROVM_ERR_INVALID_REGISTER;
            vm->regs.r[dest] = vm->regs.r[a] & vm->regs.r[b];
            break;
        }
        
        case OP_OR: {
            if (microvm_require_pc_bytes(vm, 3) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            uint8_t a = mem[vm->pc++];
            uint8_t b = mem[vm->pc++];
            if (!microvm_valid_reg(dest) || !microvm_valid_reg(a) || !microvm_valid_reg(b)) return MICROVM_ERR_INVALID_REGISTER;
            vm->regs.r[dest] = vm->regs.r[a] | vm->regs.r[b];
            break;
        }
        
        case OP_XOR: {
            if (microvm_require_pc_bytes(vm, 3) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            uint8_t a = mem[vm->pc++];
            uint8_t b = mem[vm->pc++];
            if (!microvm_valid_reg(dest) || !microvm_valid_reg(a) || !microvm_valid_reg(b)) return MICROVM_ERR_INVALID_REGISTER;
            vm->regs.r[dest] = vm->regs.r[a] ^ vm->regs.r[b];
            break;
        }
        
        case OP_NOT: {
            if (microvm_require_pc_bytes(vm, 2) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            uint8_t src = mem[vm->pc++];
            if (!microvm_valid_reg(dest) || !microvm_valid_reg(src)) return MICROVM_ERR_INVALID_REGISTER;
            vm->regs.r[dest] = ~vm->regs.r[src];
            break;
        }
        
        case OP_SHL: {
            if (microvm_require_pc_bytes(vm, 3) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            uint8_t src = mem[vm->pc++];
            uint8_t shift = mem[vm->pc++];
            if (!microvm_valid_reg(dest) || !microvm_valid_reg(src)) return MICROVM_ERR_INVALID_REGISTER;
            vm->regs.r[dest] = vm->regs.r[src] << shift;
            break;
        }
        
        case OP_SHR: {
            if (microvm_require_pc_bytes(vm, 3) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            uint8_t src = mem[vm->pc++];
            uint8_t shift = mem[vm->pc++];
            if (!microvm_valid_reg(dest) || !microvm_valid_reg(src)) return MICROVM_ERR_INVALID_REGISTER;
            vm->regs.r[dest] = vm->regs.r[src] >> shift;
            break;
        }
        
        /* ===== Comparison ===== */
        case OP_CMP: {
            if (microvm_require_pc_bytes(vm, 2) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t a = mem[vm->pc++];
            uint8_t b = mem[vm->pc++];
            if (!microvm_valid_reg(a) || !microvm_valid_reg(b)) return MICROVM_ERR_INVALID_REGISTER;
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

        case OP_SYSCALL: {
            /*
             * Syscalls are intentionally blocked in this runtime.
             * This prevents guest bytecode from triggering host/kernel actions.
             */
            return MICROVM_ERR_PERMISSION;
        }
        
        /* ===== Memory Operations ===== */
        case OP_LOAD: {
            if (microvm_require_pc_bytes(vm, 2) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            uint8_t addr_reg = mem[vm->pc++];
            if (!microvm_valid_reg(dest) || !microvm_valid_reg(addr_reg)) return MICROVM_ERR_INVALID_REGISTER;
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
            if (!microvm_valid_reg(addr_reg) || !microvm_valid_reg(src)) return MICROVM_ERR_INVALID_REGISTER;
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
            if (!microvm_valid_reg(dest) || !microvm_valid_reg(size_reg)) return MICROVM_ERR_INVALID_REGISTER;
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
#if defined(MICROVM_PLATFORM_LINUX) || defined(MICROVM_PLATFORM_MACOS)
        case OP_NET_SOCKET: {
            if (vm->network_mode == MICROVM_NET_DISABLED) {
                return MICROVM_ERR_PERMISSION;
            }
            if (microvm_require_pc_bytes(vm, 1) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            if (!microvm_valid_reg(dest)) return MICROVM_ERR_INVALID_REGISTER;
            int domain = vm->regs.r[0];  /* AF_INET */
            int type = vm->regs.r[1];    /* SOCK_STREAM */
            int fd = socket(domain, type, 0);
            if (fd < 0) {
                return MICROVM_ERR_NETWORK;
            }
            if (vm->net_broker_enabled) {
                int handle = microvm_broker_alloc_handle(vm, fd);
                if (handle < 0) {
                    close(fd);
                    return MICROVM_ERR_NETWORK;
                }
                vm->regs.r[dest] = handle;
            } else {
                vm->regs.r[dest] = fd;
            }
            break;
        }
        
        case OP_NET_BIND: {
            if (vm->network_mode == MICROVM_NET_DISABLED) {
                return MICROVM_ERR_PERMISSION;
            }
            if (vm->net_broker_enabled) {
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
            if (vm->net_broker_enabled) {
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
            if (vm->net_broker_enabled) {
                return MICROVM_ERR_PERMISSION;
            }
            if (microvm_require_pc_bytes(vm, 1) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            if (!microvm_valid_reg(dest)) return MICROVM_ERR_INVALID_REGISTER;
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
            int sock_token = (int)vm->regs.r[0];
            size_t host_off = (size_t)vm->regs.r[1];
            int port = (int)vm->regs.r[2];
            char host_buf[256];
            microvm_error_t herr = microvm_copy_cstring_from_vm(vm, host_off, host_buf, sizeof(host_buf));
            if (herr != MICROVM_SUCCESS) return herr;

            int sockfd = vm->net_broker_enabled ? microvm_broker_get_fd(vm, sock_token) : sock_token;
            if (sockfd < 0) return MICROVM_ERR_NETWORK;

            char port_buf[16];
            snprintf(port_buf, sizeof(port_buf), "%d", port);
            struct addrinfo hints;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;
            struct addrinfo *res = NULL;
            if (getaddrinfo(host_buf, port_buf, &hints, &res) != 0 || !res) {
                return MICROVM_ERR_NETWORK;
            }
            int rc = -1;
            bool tried = false;
            bool allowed_target = false;
            for (struct addrinfo *p = res; p; p = p->ai_next) {
                if (!microvm_net_allow_match(vm, host_buf, port)) continue;
                if (!microvm_net_allow_match_resolved(vm, p->ai_addr, port)) continue;
                allowed_target = true;
                tried = true;
                rc = connect(sockfd, p->ai_addr, p->ai_addrlen);
                if (rc == 0) break;
            }
            freeaddrinfo(res);
            if (!allowed_target) {
                return MICROVM_ERR_PERMISSION;
            }
            if (!tried || rc < 0) {
                return MICROVM_ERR_NETWORK;
            }
            break;
        }
        
        case OP_NET_SEND: {
            if (vm->network_mode == MICROVM_NET_DISABLED) {
                return MICROVM_ERR_PERMISSION;
            }
            int sock_token = (int)vm->regs.r[0];
            int sockfd = vm->net_broker_enabled ? microvm_broker_get_fd(vm, sock_token) : sock_token;
            if (sockfd < 0) return MICROVM_ERR_NETWORK;
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
            int sock_token = (int)vm->regs.r[0];
            int sockfd = vm->net_broker_enabled ? microvm_broker_get_fd(vm, sock_token) : sock_token;
            if (sockfd < 0) return MICROVM_ERR_NETWORK;
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
            int sock_token = (int)vm->regs.r[0];
            if (vm->net_broker_enabled) {
                int idx = sock_token - 1;
                if (idx < 0 || idx >= MICROVM_MAX_BROKER_SOCKETS || !vm->broker_slot_used[idx]) {
                    return MICROVM_ERR_NETWORK;
                }
                close(vm->broker_sockets[idx]);
                vm->broker_slot_used[idx] = false;
                vm->broker_sockets[idx] = -1;
            } else {
                int sockfd = sock_token;
                close(sockfd);
            }
            break;
        }
#endif
        
        /* ===== Environment Operations ===== */
        case OP_ENV_GET: {
            if (!vm->allow_env_ops) {
                return MICROVM_ERR_PERMISSION;
            }
            if (microvm_require_pc_bytes(vm, 1) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            if (!microvm_valid_reg(dest)) return MICROVM_ERR_INVALID_REGISTER;

            /* vm->regs.r[0] holds an offset into VM memory (not a host pointer). */
            size_t key_off = (size_t)vm->regs.r[0];
            char key_buf[256];
            microvm_error_t kerr = microvm_copy_cstring_from_vm(vm, key_off, key_buf, sizeof(key_buf));
            if (kerr != MICROVM_SUCCESS) return kerr;

            const char *value = microvm_cached_env_get(vm, key_buf);
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
            if (!vm->allow_env_ops) {
                return MICROVM_ERR_PERMISSION;
            }
            /* vm->regs.r[0]/r[1] hold offsets into VM memory. */
            size_t key_off = (size_t)vm->regs.r[0];
            size_t val_off = (size_t)vm->regs.r[1];
            char key_buf[256];
            char val_buf[256];
            microvm_error_t kerr = microvm_copy_cstring_from_vm(vm, key_off, key_buf, sizeof(key_buf));
            if (kerr != MICROVM_SUCCESS) return kerr;
            microvm_error_t verr = microvm_copy_cstring_from_vm(vm, val_off, val_buf, sizeof(val_buf));
            if (verr != MICROVM_SUCCESS) return verr;
            microvm_error_t serr = microvm_cached_env_set(vm, key_buf, val_buf);
            if (serr != MICROVM_SUCCESS) return serr;
            break;
        }
        
        /* ===== Time Operations ===== */
        case OP_GETTIME: {
            if (!vm->allow_time_ops) {
                return MICROVM_ERR_PERMISSION;
            }
            if (microvm_require_pc_bytes(vm, 1) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            if (!microvm_valid_reg(dest)) return MICROVM_ERR_INVALID_REGISTER;
            int clock_id = (int)vm->regs.r[0];
            struct timespec ts;
            if (clock_gettime(clock_id, &ts) != 0) {
                return MICROVM_ERR_NOT_SUPPORTED;
            }
            vm->regs.r[dest] = ts.tv_sec * 1000000000 + ts.tv_nsec;
            break;
        }
        
        case OP_GETPID: {
            if (!vm->allow_time_ops) {
                return MICROVM_ERR_PERMISSION;
            }
            if (microvm_require_pc_bytes(vm, 1) != MICROVM_SUCCESS) return MICROVM_ERR_OUT_OF_BOUNDS;
            uint8_t dest = mem[vm->pc++];
            if (!microvm_valid_reg(dest)) return MICROVM_ERR_INVALID_REGISTER;
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
    microvm_lock(vm);
    
    /* Check permissions for kernel mode */
    if (mode == MICROVM_MODE_KERNEL) {
        microvm_unlock(vm);
        return MICROVM_ERR_PERMISSION;
    }

    if (mode == MICROVM_MODE_SANDBOX) {
        vm->network_mode = MICROVM_NET_DISABLED;
        vm->gpu_mode = MICROVM_GPU_DISABLED;
        vm->allow_env_ops = false;
        vm->allow_time_ops = false;
        vm->allow_raw_bytecode = false;
    }

    vm->mode = mode;
    microvm_unlock(vm);
    return MICROVM_SUCCESS;
}

microvm_error_t microvm_set_network_mode(microvm_t *vm, microvm_network_mode_t mode) {
    if (!vm) {
        return MICROVM_ERR_INVALID_STATE;
    }
    microvm_lock(vm);
    if (vm->mode == MICROVM_MODE_SANDBOX && mode != MICROVM_NET_DISABLED) {
        microvm_unlock(vm);
        return MICROVM_ERR_PERMISSION;
    }
    vm->network_mode = mode;
    microvm_unlock(vm);
    return MICROVM_SUCCESS;
}

microvm_error_t microvm_set_gpu_mode(microvm_t *vm, microvm_gpu_mode_t mode) {
    if (!vm) {
        return MICROVM_ERR_INVALID_STATE;
    }
    microvm_lock(vm);
    if (vm->mode == MICROVM_MODE_SANDBOX && mode != MICROVM_GPU_DISABLED) {
        microvm_unlock(vm);
        return MICROVM_ERR_PERMISSION;
    }
    vm->gpu_mode = mode;
    microvm_unlock(vm);
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

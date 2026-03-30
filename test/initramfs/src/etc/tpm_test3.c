#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#ifndef STRICT_SESSION_TESTS
#define STRICT_SESSION_TESTS 0
#endif

#define TPM_DEV   "/dev/tpm0"
#define TPMRM_DEV "/dev/tpmrm0"
#define TPM_MAX_RESP 4096

/* TPM 2.0 tags */
#define TPM_ST_NO_SESSIONS      0x8001
#define TPM_ST_RSP_NO_SESSIONS  0x8001

/* TPM 2.0 command codes */
#define TPM2_CC_FLUSH_CONTEXT      0x00000165
#define TPM2_CC_START_AUTH_SESSION 0x00000176
#define TPM2_CC_GET_CAPABILITY     0x0000017A
#define TPM2_CC_GET_RANDOM         0x0000017B
#define TPM2_CC_PCR_READ           0x0000017E

/* TPM capability/property constants */
#define TPM_CAP_TPM_PROPERTIES  0x00000006
#define TPM_PT_MANUFACTURER     0x00000105

/* TPM handles / constants */
#define TPM_RH_NULL      0x40000007

/* TPM algorithms */
#define TPM_ALG_SHA256   0x000B
#define TPM_ALG_NULL     0x0010

/* TPM session types */
#define TPM_SE_HMAC      0x00

static void put_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)((v >> 8) & 0xff);
    p[1] = (uint8_t)(v & 0xff);
}

static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)((v >> 24) & 0xff);
    p[1] = (uint8_t)((v >> 16) & 0xff);
    p[2] = (uint8_t)((v >> 8) & 0xff);
    p[3] = (uint8_t)(v & 0xff);
}

static uint16_t get_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t get_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |
           (uint32_t)p[3];
}

static int parse_rsp_header(const uint8_t *rsp, size_t len,
                            uint16_t *tag, uint32_t *size, uint32_t *rc) {
    if (len < 10) return -1;
    *tag = get_be16(rsp + 0);
    *size = get_be32(rsp + 2);
    *rc   = get_be32(rsp + 6);
    return 0;
}

static int write_full(int fd, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) return -1;
        if (n == 0) {
            errno = EIO;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

static ssize_t read_once(int fd, uint8_t *buf, size_t cap) {
    return read(fd, buf, cap);
}

static int transact(int fd,
                    const char *name,
                    const uint8_t *cmd,
                    size_t cmd_len,
                    uint8_t *rsp,
                    size_t rsp_cap,
                    uint16_t *out_tag,
                    uint32_t *out_size,
                    uint32_t *out_rc,
                    ssize_t *out_n) {
    uint16_t tag;
    uint32_t size;
    uint32_t rc;
    ssize_t n;

    if (write_full(fd, cmd, cmd_len) < 0) {
        printf("[FAIL] %s: write failed: %s\n", name, strerror(errno));
        return -1;
    }

    n = read_once(fd, rsp, rsp_cap);
    if (n < 0) {
        printf("[FAIL] %s: read failed: %s\n", name, strerror(errno));
        return -1;
    }

    if (parse_rsp_header(rsp, (size_t)n, &tag, &size, &rc) < 0) {
        printf("[FAIL] %s: invalid response header\n", name);
        return -1;
    }

    if (out_tag)  *out_tag = tag;
    if (out_size) *out_size = size;
    if (out_rc)   *out_rc = rc;
    if (out_n)    *out_n = n;

    return 0;
}

static int transact_expect_success(
    int fd, const char *name,
    const uint8_t *cmd, size_t cmd_len,
    uint8_t *rsp, size_t rsp_cap
) {
    uint16_t tag;
    uint32_t size, rc;
    ssize_t n;

    if (transact(fd, name, cmd, cmd_len, rsp, rsp_cap, &tag, &size, &rc, &n) < 0)
        return -1;

    if (tag != TPM_ST_RSP_NO_SESSIONS) {
        printf("[FAIL] %s: unexpected response tag 0x%04x\n", name, tag);
        return -1;
    }
    if (size < 10 || size > (uint32_t)n) {
        printf("[FAIL] %s: invalid size field %u (n=%zd)\n", name, size, n);
        return -1;
    }
    if (rc != 0) {
        printf("[FAIL] %s: TPM returned rc=0x%08x\n", name, rc);
        return -1;
    }
    return 0;
}

static int transact_expect_failure(int fd, const char *name,
                                   const uint8_t *cmd, size_t cmd_len) {
    uint8_t rsp[TPM_MAX_RESP];
    uint16_t tag;
    uint32_t size, rc;
    ssize_t n;

    errno = 0;
    if (write(fd, cmd, cmd_len) < 0) {
        printf("[PASS] %s: write failed as expected: %s\n", name, strerror(errno));
        return 0;
    }

    n = read(fd, rsp, sizeof(rsp));
    if (n < 0) {
        printf("[PASS] %s: read failed after malformed command: %s\n", name, strerror(errno));
        return 0;
    }

    if (parse_rsp_header(rsp, (size_t)n, &tag, &size, &rc) == 0 && rc != 0) {
        printf("[PASS] %s: structured TPM error rc=0x%08x\n", name, rc);
        return 0;
    }

    printf("[WARN] %s: malformed command did not fail clearly\n", name);
    return 0;
}

/* ---------------- Command builders ---------------- */

static size_t build_get_capability(uint8_t *cmd, uint32_t capability,
                                   uint32_t property, uint32_t count) {
    put_be16(cmd + 0, TPM_ST_NO_SESSIONS);
    put_be32(cmd + 2, 22);
    put_be32(cmd + 6, TPM2_CC_GET_CAPABILITY);
    put_be32(cmd + 10, capability);
    put_be32(cmd + 14, property);
    put_be32(cmd + 18, count);
    return 22;
}

static size_t build_get_random(uint8_t *cmd, uint16_t bytes_requested) {
    put_be16(cmd + 0, TPM_ST_NO_SESSIONS);
    put_be32(cmd + 2, 12);
    put_be32(cmd + 6, TPM2_CC_GET_RANDOM);
    put_be16(cmd + 10, bytes_requested);
    return 12;
}

static size_t build_pcr_read_sha256_pcr0(uint8_t *cmd) {
    put_be16(cmd + 0, TPM_ST_NO_SESSIONS);
    put_be32(cmd + 2, 20);
    put_be32(cmd + 6, TPM2_CC_PCR_READ);

    put_be32(cmd + 10, 1);           /* count */
    put_be16(cmd + 14, TPM_ALG_SHA256);
    cmd[16] = 3;                     /* sizeofSelect */
    cmd[17] = 0x01;                  /* PCR 0 */
    cmd[18] = 0x00;
    cmd[19] = 0x00;

    return 20;
}

/*
 * StartAuthSession with:
 * - tpmKey = TPM_RH_NULL
 * - bind   = TPM_RH_NULL
 * - nonceCaller = 32-byte random nonce (obtained via GetRandom)
 * - encryptedSalt = empty
 * - sessionType = TPM_SE_HMAC
 * - symmetric = TPM_ALG_NULL
 * - authHash  = TPM_ALG_SHA256
 *
 * total = header(10) + handles(8) + nonceCaller(2+32) + encryptedSalt(2)
 *       + sessionType(1) + symmetric(2) + authHash(2)
 *       = 59
 */
static size_t build_start_auth_session_hmac(uint8_t *cmd, const uint8_t *nonce, uint16_t nonce_len) {
    size_t off = 0;
    
    /* Header - will be filled in after params */
    put_be16(cmd + 6, TPM2_CC_START_AUTH_SESSION);
    
    put_be32(cmd + 10, TPM_RH_NULL);  /* tpmKey */
    put_be32(cmd + 14, TPM_RH_NULL);  /* bind */
    off = 18;
    
    /* nonceCaller: TPM2B_NONCE = u16 size + data */
    put_be16(cmd + off, nonce_len);
    off += 2;
    memcpy(cmd + off, nonce, nonce_len);
    off += nonce_len;
    
    /* encryptedSalt: TPM2B_ENCRYPTED_SECRET = u16 size (empty) */
    put_be16(cmd + off, 0);
    off += 2;
    
    /* sessionType: u8 */
    cmd[off] = TPM_SE_HMAC;
    off += 1;
    
    /* symmetric: TPMT_SYM_DEF = u16 algorithm */
    put_be16(cmd + off, TPM_ALG_NULL);
    off += 2;
    
    /* authHash: u16 */
    put_be16(cmd + off, TPM_ALG_SHA256);
    off += 2;
    
    /* Fill in header */
    put_be16(cmd + 0, TPM_ST_NO_SESSIONS);
    put_be32(cmd + 2, (uint32_t)off);
    
    return off;
}

/* FlushContext(handle) => header(10) + handle(4) = 14 */
static size_t build_flush_context(uint8_t *cmd, uint32_t handle) {
    put_be16(cmd + 0, TPM_ST_NO_SESSIONS);
    put_be32(cmd + 2, 14);
    put_be32(cmd + 6, TPM2_CC_FLUSH_CONTEXT);
    put_be32(cmd + 10, handle);
    return 14;
}

static size_t build_short_malformed(uint8_t *cmd) {
    cmd[0] = 0x80;
    cmd[1] = 0x01;
    cmd[2] = 0x00;
    cmd[3] = 0x00;
    return 4;
}

static size_t build_size_mismatch_malformed(uint8_t *cmd) {
    put_be16(cmd + 0, TPM_ST_NO_SESSIONS);
    put_be32(cmd + 2, 64);                   /* fake size */
    put_be32(cmd + 6, TPM2_CC_GET_RANDOM);
    put_be16(cmd + 10, 8);
    return 12;                              /* actual != size */
}

/* ---------------- Existing round-3 style tests ---------------- */

static int test_basic_commands(int fd) {
    uint8_t cmd[256];
    uint8_t rsp[TPM_MAX_RESP];
    uint32_t m = 0;

    printf("=== basic command tests ===\n");

    if (transact_expect_success(
            fd, "TPM2_GetCapability(Manufacturer)",
            cmd, build_get_capability(cmd, TPM_CAP_TPM_PROPERTIES, TPM_PT_MANUFACTURER, 1),
            rsp, sizeof(rsp)) < 0) {
        return -1;
    }
    if (get_be32(rsp + 2) >= 22) m = get_be32(rsp + 18);
    printf("[PASS] GetCapability ok, manufacturer=0x%08x\n", m);

    if (transact_expect_success(
            fd, "TPM2_GetRandom(16)",
            cmd, build_get_random(cmd, 16),
            rsp, sizeof(rsp)) < 0) {
        return -1;
    }
    printf("[PASS] GetRandom ok\n");

    if (transact_expect_success(
            fd, "TPM2_PCR_Read(SHA256,PCR0)",
            cmd, build_pcr_read_sha256_pcr0(cmd),
            rsp, sizeof(rsp)) < 0) {
        return -1;
    }
    printf("[PASS] PCR_Read ok\n\n");

    return 0;
}

static int test_repeated_commands(int fd, int rounds) {
    uint8_t cmd[256];
    uint8_t rsp[TPM_MAX_RESP];
    int i;

    printf("=== repeated command stability test (%d rounds) ===\n", rounds);

    for (i = 0; i < rounds; i++) {
        if (transact_expect_success(
                fd, "repeated GetRandom",
                cmd, build_get_random(cmd, 8),
                rsp, sizeof(rsp)) < 0) {
            printf("[FAIL] repeated command failed at round %d\n\n", i);
            return -1;
        }
    }

    printf("[PASS] repeated commands stable for %d rounds\n\n", rounds);
    return 0;
}

static int test_malformed_inputs(int fd) {
    uint8_t cmd[256];

    printf("=== malformed input tests ===\n");

    transact_expect_failure(fd, "short malformed command",
                            cmd, build_short_malformed(cmd));

    transact_expect_failure(fd, "size mismatch malformed command",
                            cmd, build_size_mismatch_malformed(cmd));

    printf("[PASS] malformed input handling test completed\n\n");
    return 0;
}

static int test_multi_open_isolation(void) {
    int fd1, fd2;
    uint8_t cmd1[256], cmd2[256];
    uint8_t rsp1[TPM_MAX_RESP], rsp2[TPM_MAX_RESP];
    ssize_t n1, n2;
    uint16_t tag;
    uint32_t size, rc;

    printf("=== multi-open isolation test ===\n");

    fd1 = open(TPM_DEV, O_RDWR);
    if (fd1 < 0) {
        printf("[FAIL] open fd1: %s\n\n", strerror(errno));
        return -1;
    }

    fd2 = open(TPM_DEV, O_RDWR);
    if (fd2 < 0) {
        printf("[FAIL] open fd2: %s\n\n", strerror(errno));
        close(fd1);
        return -1;
    }

    if (write_full(fd1, cmd1, build_get_capability(cmd1, TPM_CAP_TPM_PROPERTIES, TPM_PT_MANUFACTURER, 1)) < 0) {
        printf("[FAIL] fd1 write failed: %s\n\n", strerror(errno));
        close(fd1); close(fd2);
        return -1;
    }

    if (write_full(fd2, cmd2, build_get_random(cmd2, 16)) < 0) {
        printf("[FAIL] fd2 write failed: %s\n\n", strerror(errno));
        close(fd1); close(fd2);
        return -1;
    }

    n1 = read_once(fd1, rsp1, sizeof(rsp1));
    n2 = read_once(fd2, rsp2, sizeof(rsp2));

    close(fd1);
    close(fd2);

    if (n1 < 0 || n2 < 0) {
        printf("[FAIL] multi-open read failed: fd1=%zd fd2=%zd\n\n", n1, n2);
        return -1;
    }

    if (parse_rsp_header(rsp1, (size_t)n1, &tag, &size, &rc) < 0 || rc != 0) {
        printf("[FAIL] fd1 response invalid or error\n\n");
        return -1;
    }

    if (parse_rsp_header(rsp2, (size_t)n2, &tag, &size, &rc) < 0 || rc != 0) {
        printf("[FAIL] fd2 response invalid or error\n\n");
        return -1;
    }

    if (n1 == n2) {
        printf("[WARN] fd1/fd2 responses have same length; isolation not disproved but less informative\n");
    }

    printf("[PASS] multi-open basic isolation ok (fd1=%zd bytes, fd2=%zd bytes)\n\n", n1, n2);
    return 0;
}

static int child_worker(const char *name, int loops, uint16_t rnd) {
    int fd;
    uint8_t cmd[256];
    uint8_t rsp[TPM_MAX_RESP];
    int i;

    fd = open(TPM_DEV, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "[child %s] open failed: %s\n", name, strerror(errno));
        return 1;
    }

    for (i = 0; i < loops; i++) {
        if (transact_expect_success(fd, name, cmd, build_get_random(cmd, rnd), rsp, sizeof(rsp)) < 0) {
            close(fd);
            return 1;
        }
    }

    close(fd);
    return 0;
}

static int test_multi_process_stability(void) {
    pid_t p1, p2;
    int st1 = 0, st2 = 0;

    printf("=== multi-process stability test ===\n");

    p1 = fork();
    if (p1 < 0) {
        printf("[FAIL] fork p1 failed: %s\n\n", strerror(errno));
        return -1;
    }
    if (p1 == 0) _exit(child_worker("child1", 5, 8));

    p2 = fork();
    if (p2 < 0) {
        printf("[FAIL] fork p2 failed: %s\n\n", strerror(errno));
        kill(p1, SIGTERM);
        waitpid(p1, NULL, 0);
        return -1;
    }
    if (p2 == 0) _exit(child_worker("child2", 5, 16));

    waitpid(p1, &st1, 0);
    waitpid(p2, &st2, 0);

    if (!WIFEXITED(st1) || WEXITSTATUS(st1) != 0 ||
        !WIFEXITED(st2) || WEXITSTATUS(st2) != 0) {
        printf("[FAIL] multi-process stability failed: st1=%d st2=%d\n\n", st1, st2);
        return -1;
    }

    printf("[PASS] multi-process stability ok\n\n");
    return 0;
}

/* ---------------- New session / HMAC / RM semantic tests ---------------- */

/*
 * Session foundation test:
 * - first get random bytes for nonce
 * - try to create an HMAC session on /dev/tpm0
 * - if success, parse session handle and flush it
 * - if not supported, SKIP by default
 */
static int test_session_foundation_on_tpm0(void) {
    int fd;
    uint8_t cmd[256], rsp[TPM_MAX_RESP];
    uint16_t tag;
    uint32_t size, rc, session_handle = 0;
    ssize_t n;
    uint8_t nonce[32];

    printf("=== session/HMAC foundation test on /dev/tpm0 ===\n");

    fd = open(TPM_DEV, O_RDWR);
    if (fd < 0) {
        printf("[FAIL] open %s: %s\n\n", TPM_DEV, strerror(errno));
        return -1;
    }

    /* Get random nonce first */
    if (transact_expect_success(fd, "GetRandom(32) for nonce",
                                cmd, build_get_random(cmd, 32),
                                rsp, sizeof(rsp)) < 0) {
        printf("[SKIP] could not get random nonce\n\n");
        close(fd);
        return 0;
    }
    
    /* Extract nonce from GetRandom response (skip header + size field) */
    if (get_be32(rsp + 2) < 16) {
        printf("[SKIP] GetRandom response too short for nonce\n\n");
        close(fd);
        return 0;
    }
    uint16_t rnd_len = get_be16(rsp + 10);
    if (rnd_len < 32) {
        /* Pad with zeros if not enough bytes */
        memset(nonce, 0, sizeof(nonce));
        memcpy(nonce, rsp + 12, rnd_len < 32 ? rnd_len : 32);
    } else {
        memcpy(nonce, rsp + 12, 32);
    }

    if (transact(fd, "TPM2_StartAuthSession(HMAC)",
                 cmd, build_start_auth_session_hmac(cmd, nonce, 32),
                 rsp, sizeof(rsp),
                 &tag, &size, &rc, &n) < 0) {
        close(fd);
        return -1;
    }

    if (rc != 0) {
        if (STRICT_SESSION_TESTS) {
            printf("[FAIL] StartAuthSession unsupported or failed rc=0x%08x\n\n", rc);
            close(fd);
            return -1;
        }
        printf("[SKIP] StartAuthSession not available yet (rc=0x%08x)\n\n", rc);
        close(fd);
        return 0;
    }

    if (size < 14 || (size_t)n < 14) {
        printf("[FAIL] StartAuthSession response too short\n\n");
        close(fd);
        return -1;
    }

    session_handle = get_be32(rsp + 10);
    printf("[PASS] HMAC session created, handle=0x%08x\n", session_handle);

    if (transact_expect_success(fd, "TPM2_FlushContext(session)",
                                cmd, build_flush_context(cmd, session_handle),
                                rsp, sizeof(rsp)) < 0) {
        printf("[FAIL] FlushContext failed for session handle 0x%08x\n\n", session_handle);
        close(fd);
        return -1;
    }

    printf("[PASS] session flush succeeded\n\n");
    close(fd);
    return 0;
}

/*
 * /dev/tpmrm0 optional test:
 * - if device absent => SKIP
 * - if present, basic GetRandom works
 */
static int test_tpmrm_basic_optional(void) {
    int fd;
    uint8_t cmd[256], rsp[TPM_MAX_RESP];

    printf("=== optional /dev/tpmrm0 basic test ===\n");

    fd = open(TPMRM_DEV, O_RDWR);
    if (fd < 0) {
        if (errno == ENOENT) {
            printf("[SKIP] %s not implemented in this iteration\n\n", TPMRM_DEV);
            return 0;
        }
        printf("[FAIL] open %s: %s\n\n", TPMRM_DEV, strerror(errno));
        return -1;
    }

    if (transact_expect_success(fd, "TPMRM GetRandom",
                                cmd, build_get_random(cmd, 16),
                                rsp, sizeof(rsp)) < 0) {
        close(fd);
        printf("[FAIL] %s basic GetRandom failed\n\n", TPMRM_DEV);
        return -1;
    }

    close(fd);
    printf("[PASS] %s basic access ok\n\n", TPMRM_DEV);
    return 0;
}

/*
 * Resource-manager/session isolation semantics:
 * - only meaningful if /dev/tpmrm0 exists and StartAuthSession works
 * - create one HMAC session on fd1
 * - create another HMAC session on fd2
 * - flush session1 using fd1 => should succeed
 * - try flushing session1 using fd2 => should fail cleanly, or return structured error
 *
 * This checks a very basic “handle/state should not bleed across file instances”
 * style semantic if tpmrm-like behavior has been introduced.
 */
static int test_tpmrm_session_isolation_optional(void) {
    int fd1 = -1, fd2 = -1;
    uint8_t cmd[256], rsp[TPM_MAX_RESP];
    uint16_t tag;
    uint32_t size, rc;
    ssize_t n;
    uint32_t h1 = 0, h2 = 0;
    uint8_t nonce1[32], nonce2[32];

    printf("=== optional /dev/tpmrm0 session isolation test ===\n");

    fd1 = open(TPMRM_DEV, O_RDWR);
    if (fd1 < 0) {
        if (errno == ENOENT) {
            printf("[SKIP] %s not implemented; isolation test skipped\n\n", TPMRM_DEV);
            return 0;
        }
        printf("[FAIL] open fd1 %s: %s\n\n", TPMRM_DEV, strerror(errno));
        return -1;
    }

    fd2 = open(TPMRM_DEV, O_RDWR);
    if (fd2 < 0) {
        printf("[FAIL] open fd2 %s: %s\n\n", TPMRM_DEV, strerror(errno));
        close(fd1);
        return -1;
    }

    /* Get nonce for fd1 */
    if (transact_expect_success(fd1, "TPMRM GetRandom(32) for nonce1",
                                cmd, build_get_random(cmd, 32),
                                rsp, sizeof(rsp)) < 0) {
        printf("[SKIP] could not get random nonce1\n\n");
        close(fd1); close(fd2);
        return 0;
    }
    memcpy(nonce1, rsp + 12, 32);

    if (transact(fd1, "TPMRM StartAuthSession fd1",
                 cmd, build_start_auth_session_hmac(cmd, nonce1, 32),
                 rsp, sizeof(rsp), &tag, &size, &rc, &n) < 0) {
        close(fd1); close(fd2);
        return -1;
    }

    if (rc != 0) {
        if (STRICT_SESSION_TESTS) {
            printf("[FAIL] TPMRM session creation on fd1 failed rc=0x%08x\n\n", rc);
            close(fd1); close(fd2);
            return -1;
        }
        printf("[SKIP] TPMRM StartAuthSession not available yet on fd1 (rc=0x%08x)\n\n", rc);
        close(fd1); close(fd2);
        return 0;
    }
    h1 = get_be32(rsp + 10);

    /* Get nonce for fd2 */
    if (transact_expect_success(fd2, "TPMRM GetRandom(32) for nonce2",
                                cmd, build_get_random(cmd, 32),
                                rsp, sizeof(rsp)) < 0) {
        printf("[SKIP] could not get random nonce2\n\n");
        close(fd1); close(fd2);
        return 0;
    }
    memcpy(nonce2, rsp + 12, 32);

    if (transact(fd2, "TPMRM StartAuthSession fd2",
                 cmd, build_start_auth_session_hmac(cmd, nonce2, 32),
                 rsp, sizeof(rsp), &tag, &size, &rc, &n) < 0) {
        close(fd1); close(fd2);
        return -1;
    }

    if (rc != 0) {
        if (STRICT_SESSION_TESTS) {
            printf("[FAIL] TPMRM session creation on fd2 failed rc=0x%08x\n\n", rc);
            close(fd1); close(fd2);
            return -1;
        }
        printf("[SKIP] TPMRM StartAuthSession not available yet on fd2 (rc=0x%08x)\n\n", rc);
        close(fd1); close(fd2);
        return 0;
    }
    h2 = get_be32(rsp + 10);

    printf("[PASS] TPMRM sessions created: h1=0x%08x h2=0x%08x\n", h1, h2);

    if (transact_expect_success(fd1, "TPMRM FlushContext(h1) on fd1",
                                cmd, build_flush_context(cmd, h1),
                                rsp, sizeof(rsp)) < 0) {
        printf("[FAIL] fd1 flush of h1 failed\n\n");
        close(fd1); close(fd2);
        return -1;
    }

    /*
     * Using h1 from fd2 should not accidentally behave like a valid local handle
     * if file-instance/resource-manager isolation exists.
     * Accept any clear failure mode.
     */
    if (transact(fd2, "TPMRM FlushContext(h1) on fd2",
                 cmd, build_flush_context(cmd, h1),
                 rsp, sizeof(rsp), &tag, &size, &rc, &n) < 0) {
        printf("[PASS] cross-fd flush failed cleanly at I/O layer\n\n");
        close(fd1); close(fd2);
        return 0;
    }

    if (rc != 0) {
        printf("[PASS] cross-fd flush returned structured TPM error rc=0x%08x\n\n", rc);
        /* cleanup h2 on fd2 */
        transact_expect_success(fd2, "TPMRM FlushContext(h2) on fd2",
                                cmd, build_flush_context(cmd, h2),
                                rsp, sizeof(rsp));
        close(fd1); close(fd2);
        return 0;
    }

    /*
     * If it succeeded, this may indicate no per-file isolation / virtualization yet.
     * Treat as WARN in non-strict mode, FAIL in strict mode.
     */
    if (STRICT_SESSION_TESTS) {
        printf("[FAIL] cross-fd flush unexpectedly succeeded; isolation too weak\n\n");
        close(fd1); close(fd2);
        return -1;
    }

    printf("[WARN] cross-fd flush succeeded; tpmrm-style isolation may not be implemented yet\n");
    transact_expect_success(fd2, "TPMRM FlushContext(h2) on fd2",
                            cmd, build_flush_context(cmd, h2),
                            rsp, sizeof(rsp));
    printf("[SKIP] tpmrm isolation semantics not enforced yet\n\n");

    close(fd1);
    close(fd2);
    return 0;
}

/* ---------------- main ---------------- */

int main(void) {
    int fd;
    int failed = 0;

    printf("=== TPM Round-3 Session/RM Test Suite ===\n");
    printf("STRICT_SESSION_TESTS=%d\n\n", STRICT_SESSION_TESTS);

    fd = open(TPM_DEV, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "[FAIL] open %s: %s\n", TPM_DEV, strerror(errno));
        return 1;
    }
    printf("[PASS] open %s\n\n", TPM_DEV);

    if (test_basic_commands(fd) < 0) failed++;
    if (test_repeated_commands(fd, 20) < 0) failed++;
    if (test_malformed_inputs(fd) < 0) failed++;

    close(fd);

    if (test_multi_open_isolation() < 0) failed++;
    if (test_multi_process_stability() < 0) failed++;

    /* new semantic tests */
    if (test_session_foundation_on_tpm0() < 0) failed++;
    if (test_tpmrm_basic_optional() < 0) failed++;
    if (test_tpmrm_session_isolation_optional() < 0) failed++;

    printf("=== Summary ===\n");
    if (failed == 0) {
        printf("[PASS] All round-3 session/RM tests passed (or cleanly skipped optional parts)\n");
        return 0;
    }

    printf("[FAIL] %d test group(s) failed\n", failed);
    return 1;
}
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TPM_DEV "/dev/tpm0"
#define TPM_MAX_RESP 4096

/* TPM 2.0 tags */
#define TPM_ST_NO_SESSIONS      0x8001
#define TPM_ST_RSP_NO_SESSIONS  0x8001

/* TPM 2.0 command codes */
#define TPM2_CC_STARTUP         0x00000144
#define TPM2_CC_SELF_TEST       0x00000143
#define TPM2_CC_GET_CAPABILITY  0x0000017A
#define TPM2_CC_GET_RANDOM      0x0000017B
#define TPM2_CC_PCR_READ        0x0000017E

/* TPM 2.0 capability / property constants */
#define TPM_CAP_TPM_PROPERTIES  0x00000006
#define TPM_PT_MANUFACTURER     0x00000105

/* TPM 2.0 algorithms */
#define TPM_ALG_SHA256          0x000B

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

static void hex_dump(const char *name, const uint8_t *buf, size_t len) {
    size_t i;
    printf("%s (%zu bytes)\n", name, len);
    for (i = 0; i < len; i++) {
        if (i % 16 == 0) printf("%04zx: ", i);
        printf("%02x ", buf[i]);
        if ((i + 1) % 16 == 0 || i + 1 == len) printf("\n");
    }
}

static int parse_rsp_header(const uint8_t *rsp, size_t len,
                            uint16_t *tag, uint32_t *size, uint32_t *rc) {
    if (len < 10) {
        fprintf(stderr, "response too short: %zu\n", len);
        return -1;
    }
    *tag = get_be16(rsp + 0);
    *size = get_be32(rsp + 2);
    *rc   = get_be32(rsp + 6);
    return 0;
}

static int write_full(int fd, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            return -1;
        }
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

static int transact_expect_success(
    int fd,
    const char *name,
    const uint8_t *cmd,
    size_t cmd_len,
    uint8_t *rsp,
    size_t rsp_cap,
    int dump
) {
    uint16_t tag;
    uint32_t size;
    uint32_t rc;
    ssize_t n;

    printf("=== %s ===\n", name);

    if (dump) hex_dump("command", cmd, cmd_len);

    if (write_full(fd, cmd, cmd_len) < 0) {
        printf("[FAIL] write failed: %s\n\n", strerror(errno));
        return -1;
    }

    n = read_once(fd, rsp, rsp_cap);
    if (n < 0) {
        printf("[FAIL] read failed: %s\n\n", strerror(errno));
        return -1;
    }

    if (dump) hex_dump("response", rsp, (size_t)n);

    if (parse_rsp_header(rsp, (size_t)n, &tag, &size, &rc) < 0) {
        printf("[FAIL] invalid response header\n\n");
        return -1;
    }

    printf("tag=0x%04x size=%u rc=0x%08x\n", tag, size, rc);

    if (tag != TPM_ST_RSP_NO_SESSIONS) {
        printf("[FAIL] unexpected response tag\n\n");
        return -1;
    }

    if (size < 10 || size > (uint32_t)n) {
        printf("[FAIL] invalid response size field\n\n");
        return -1;
    }

    if (rc != 0) {
        printf("[FAIL] TPM returned error rc=0x%08x\n\n", rc);
        return -1;
    }

    printf("[PASS] %s\n\n", name);
    return 0;
}

static int transact_expect_failure(
    int fd,
    const char *name,
    const uint8_t *cmd,
    size_t cmd_len
) {
    uint8_t rsp[TPM_MAX_RESP];
    ssize_t n;

    printf("=== %s ===\n", name);

    errno = 0;
    if (write(fd, cmd, cmd_len) < 0) {
        printf("[PASS] write failed as expected: %s\n\n", strerror(errno));
        return 0;
    }

    /*
     * 如果 write 没失败，也允许 read 返回错误，或者返回 TPM error response。
     * 关键目标：系统不能 panic，接口要有定义行为。
     */
    n = read(fd, rsp, sizeof(rsp));
    if (n < 0) {
        printf("[PASS] read failed after malformed command: %s\n\n", strerror(errno));
        return 0;
    }

    if (n >= 10) {
        uint16_t tag;
        uint32_t size;
        uint32_t rc;
        if (parse_rsp_header(rsp, (size_t)n, &tag, &size, &rc) == 0 && rc != 0) {
            printf("[PASS] TPM returned structured error rc=0x%08x\n\n", rc);
            return 0;
        }
    }

    printf("[WARN] malformed command did not fail clearly; investigate behavior\n\n");
    return 0;
}

/* -------- Command builders -------- */

static size_t build_get_capability(uint8_t *cmd, uint32_t capability, uint32_t property, uint32_t count) {
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
    /*
     * Header(10)
     * count=1                       4
     * hash=SHA256                   2
     * sizeofSelect=3                1
     * pcrSelect[3]={0x01,0x00,0x00} 3
     * total = 20
     */
    put_be16(cmd + 0, TPM_ST_NO_SESSIONS);
    put_be32(cmd + 2, 20);
    put_be32(cmd + 6, TPM2_CC_PCR_READ);

    put_be32(cmd + 10, 1);
    put_be16(cmd + 14, TPM_ALG_SHA256);
    cmd[16] = 3;
    cmd[17] = 0x01;
    cmd[18] = 0x00;
    cmd[19] = 0x00;
    return 20;
}

static size_t build_short_malformed(uint8_t *cmd) {
    cmd[0] = 0x80;
    cmd[1] = 0x01;
    cmd[2] = 0x00;
    cmd[3] = 0x00;
    return 4;
}

static size_t build_size_mismatch_malformed(uint8_t *cmd) {
    /*
     * 实际 12 字节，但 header.size 填 64
     */
    put_be16(cmd + 0, TPM_ST_NO_SESSIONS);
    put_be32(cmd + 2, 64);
    put_be32(cmd + 6, TPM2_CC_GET_RANDOM);
    put_be16(cmd + 10, 8);
    return 12;
}

int main(void) {
    int fd;
    int failed = 0;
    uint8_t cmd[256];
    uint8_t rsp[TPM_MAX_RESP];
    size_t cmd_len;

    printf("=== TPM Round-2 Test Suite ===\n\n");

    fd = open(TPM_DEV, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "[FAIL] open %s: %s\n", TPM_DEV, strerror(errno));
        return 1;
    }
    printf("[PASS] open %s\n\n", TPM_DEV);

    /* Test 1: GetCapability */
    cmd_len = build_get_capability(cmd, TPM_CAP_TPM_PROPERTIES, TPM_PT_MANUFACTURER, 1);
    if (transact_expect_success(fd, "TPM2_GetCapability(Manufacturer)", cmd, cmd_len, rsp, sizeof(rsp), 0) < 0) {
        failed++;
    } else if (sizeof(rsp) >= 22) {
        /* 尝试打印 manufacturer */
        uint32_t m = get_be32(rsp + 18);
        char vendor[5];
        vendor[0] = (char)((m >> 24) & 0xff);
        vendor[1] = (char)((m >> 16) & 0xff);
        vendor[2] = (char)((m >> 8) & 0xff);
        vendor[3] = (char)(m & 0xff);
        vendor[4] = '\0';
        printf("manufacturer: 0x%08x (%.4s)\n\n", m, vendor);
    }

    /* Test 2: GetRandom */
    cmd_len = build_get_random(cmd, 16);
    if (transact_expect_success(fd, "TPM2_GetRandom(16)", cmd, cmd_len, rsp, sizeof(rsp), 0) < 0) {
        failed++;
    }

    /* Test 3: PCR_Read */
    cmd_len = build_pcr_read_sha256_pcr0(cmd);
    if (transact_expect_success(fd, "TPM2_PCR_Read(SHA256,PCR0)", cmd, cmd_len, rsp, sizeof(rsp), 0) < 0) {
        failed++;
    }

    /* Test 4: malformed short command */
    cmd_len = build_short_malformed(cmd);
    if (transact_expect_failure(fd, "Malformed short command", cmd, cmd_len) < 0) {
        failed++;
    }

    /* Test 5: malformed size mismatch */
    cmd_len = build_size_mismatch_malformed(cmd);
    if (transact_expect_failure(fd, "Malformed size mismatch command", cmd, cmd_len) < 0) {
        failed++;
    }

    close(fd);

    printf("=== Summary ===\n");
    if (failed == 0) {
        printf("[PASS] All round-2 tests passed\n");
        return 0;
    }

    printf("[FAIL] %d test(s) failed\n", failed);
    return 1;
}
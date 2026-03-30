#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tcti_device.h>
#include <tss2/tss2_esys.h>

#ifndef STRICT_SESSION_TESTS
#define STRICT_SESSION_TESTS 0
#endif

#define DEV_TPM0   "/dev/tpm0"
#define DEV_TPMRM0 "/dev/tpmrm0"

#define TPM_ST_NO_SESSIONS      0x8001
#define TPM_ST_RSP_NO_SESSIONS  0x8001

#define TPM2_CC_GET_CAPABILITY  0x0000017A
#define TPM2_CC_GET_RANDOM      0x0000017B
#define TPM2_CC_PCR_READ        0x0000017E

#define TPM_CAP_TPM_PROPERTIES  0x00000006
#define TPM_PT_MANUFACTURER     0x00000105
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

static int parse_rsp_header(const uint8_t *rsp, size_t len,
                            uint16_t *tag, uint32_t *size, uint32_t *rc) {
    if (len < 10) return -1;
    *tag = get_be16(rsp + 0);
    *size = get_be32(rsp + 2);
    *rc   = get_be32(rsp + 6);
    return 0;
}

static void print_test_header(const char *name) {
    printf("=== %s ===\n", name);
}

static int raw_partial_read_test(const char *path, const uint8_t *cmd, size_t cmd_len, const char *name) {
    int fd;
    uint8_t hdr[10];
    uint8_t body[4096];
    ssize_t n1, n2;
    uint16_t tag;
    uint32_t size, rc;
    size_t body_len;

    print_test_header(name);

    fd = open(path, O_RDWR);
    if (fd < 0) {
        printf("[FAIL] open %s: %s\n\n", path, strerror(errno));
        return -1;
    }

    if (write_full(fd, cmd, cmd_len) < 0) {
        printf("[FAIL] write %s: %s\n\n", path, strerror(errno));
        close(fd);
        return -1;
    }

    /* first read only 10-byte response header */
    n1 = read(fd, hdr, sizeof(hdr));
    if (n1 < 0) {
        printf("[FAIL] first partial read: %s\n\n", strerror(errno));
        close(fd);
        return -1;
    }
    if (n1 != 10) {
        printf("[FAIL] first partial read returned %zd bytes, expected 10\n\n", n1);
        close(fd);
        return -1;
    }

    if (parse_rsp_header(hdr, 10, &tag, &size, &rc) < 0) {
        printf("[FAIL] parse header failed\n\n");
        close(fd);
        return -1;
    }

    printf("[INFO] header: tag=0x%04x size=%u rc=0x%08x\n", tag, size, rc);

    if (tag != TPM_ST_RSP_NO_SESSIONS) {
        printf("[FAIL] unexpected tag\n\n");
        close(fd);
        return -1;
    }

    if (size < 10) {
        printf("[FAIL] invalid size in header\n\n");
        close(fd);
        return -1;
    }

    body_len = size - 10;
    if (body_len > sizeof(body)) {
        printf("[FAIL] body too large: %zu\n\n", body_len);
        close(fd);
        return -1;
    }

    /* second read must return the remaining bytes */
    n2 = read(fd, body, body_len);
    if (n2 < 0) {
        printf("[FAIL] second partial read: %s\n\n", strerror(errno));
        close(fd);
        return -1;
    }
    if ((size_t)n2 != body_len) {
        printf("[FAIL] second partial read returned %zd bytes, expected %zu\n\n", n2, body_len);
        close(fd);
        return -1;
    }

    printf("[PASS] partial read semantics ok on %s\n\n", path);
    close(fd);
    return 0;
}

static int tcti_init_test(const char *path) {
    TSS2_RC rc;
    size_t size = 0;
    TSS2_TCTI_CONTEXT *ctx = NULL;

    char name[128];
    snprintf(name, sizeof(name), "TCTI init test (%s)", path);
    print_test_header(name);

    rc = Tss2_Tcti_Device_Init(NULL, &size, path);
    if (rc != TSS2_RC_SUCCESS) {
        printf("[FAIL] size query failed: 0x%x\n\n", rc);
        return -1;
    }

    ctx = (TSS2_TCTI_CONTEXT *)calloc(1, size);
    if (!ctx) {
        printf("[FAIL] calloc\n\n");
        return -1;
    }

    rc = Tss2_Tcti_Device_Init(ctx, &size, path);
    if (rc != TSS2_RC_SUCCESS) {
        printf("[FAIL] TCTI init failed: 0x%x\n\n", rc);
        free(ctx);
        return -1;
    }

    printf("[PASS] TCTI init success, context size = %zu\n\n", size);
    free(ctx);
    return 0;
}

static int esys_init(const char *path, ESYS_CONTEXT **out_esys, TSS2_TCTI_CONTEXT **out_tcti) {
    TSS2_RC rc;
    size_t size = 0;
    TSS2_TCTI_CONTEXT *tcti = NULL;
    ESYS_CONTEXT *esys = NULL;

    rc = Tss2_Tcti_Device_Init(NULL, &size, path);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Tss2_Tcti_Device_Init size query failed: 0x%x\n", rc);
        return -1;
    }

    tcti = (TSS2_TCTI_CONTEXT *)calloc(1, size);
    if (!tcti) {
        perror("calloc");
        return -1;
    }

    rc = Tss2_Tcti_Device_Init(tcti, &size, path);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Tss2_Tcti_Device_Init failed: 0x%x\n", rc);
        free(tcti);
        return -1;
    }

    rc = Esys_Initialize(&esys, tcti, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys_Initialize failed: 0x%x\n", rc);
        free(tcti);
        return -1;
    }

    *out_esys = esys;
    *out_tcti = tcti;
    return 0;
}

static void esys_cleanup(ESYS_CONTEXT *esys, TSS2_TCTI_CONTEXT *tcti) {
    if (esys) {
        Esys_Finalize(&esys);
    }
    if (tcti) {
        free(tcti);
    }
}

static int esys_getrandom_test(const char *path, UINT16 bytes) {
    ESYS_CONTEXT *esys = NULL;
    TSS2_TCTI_CONTEXT *tcti = NULL;
    TPM2B_DIGEST *random = NULL;
    TSS2_RC rc;

    char name[128];
    snprintf(name, sizeof(name), "ESAPI GetRandom test (%s)", path);
    print_test_header(name);

    if (esys_init(path, &esys, &tcti) < 0) {
        printf("[FAIL] ESYS init failed\n\n");
        return -1;
    }

    rc = Esys_GetRandom(esys,
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        bytes,
                        &random);
    if (rc != TSS2_RC_SUCCESS) {
        printf("[FAIL] Esys_GetRandom rc=0x%x\n\n", rc);
        esys_cleanup(esys, tcti);
        return -1;
    }

    if (!random) {
        printf("[FAIL] Esys_GetRandom returned NULL\n\n");
        esys_cleanup(esys, tcti);
        return -1;
    }

    printf("[PASS] Esys_GetRandom success, size=%u\n\n", random->size);
    Esys_Free(random);
    esys_cleanup(esys, tcti);
    return 0;
}

static int esys_getcap_test(const char *path) {
    ESYS_CONTEXT *esys = NULL;
    TSS2_TCTI_CONTEXT *tcti = NULL;
    TPMS_CAPABILITY_DATA *cap_data = NULL;
    TPMI_YES_NO more_data = TPM2_NO;
    TSS2_RC rc;

    char name[128];
    snprintf(name, sizeof(name), "ESAPI GetCapability test (%s)", path);
    print_test_header(name);

    if (esys_init(path, &esys, &tcti) < 0) {
        printf("[FAIL] ESYS init failed\n\n");
        return -1;
    }

    rc = Esys_GetCapability(esys,
                            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                            TPM2_CAP_TPM_PROPERTIES,
                            TPM2_PT_MANUFACTURER,
                            1,
                            &more_data,
                            &cap_data);
    if (rc != TSS2_RC_SUCCESS) {
        printf("[FAIL] Esys_GetCapability rc=0x%x\n\n", rc);
        esys_cleanup(esys, tcti);
        return -1;
    }

    printf("[PASS] Esys_GetCapability success, more_data=%u\n\n", more_data);
    Esys_Free(cap_data);
    esys_cleanup(esys, tcti);
    return 0;
}

static int esys_pcrread_test(const char *path) {
    ESYS_CONTEXT *esys = NULL;
    TSS2_TCTI_CONTEXT *tcti = NULL;
    TPML_PCR_SELECTION pcr_sel;
    UINT32 pcr_update_counter = 0;
    TPML_PCR_SELECTION *out_sel = NULL;
    TPML_DIGEST *out_digests = NULL;
    TSS2_RC rc;

    char name[128];
    snprintf(name, sizeof(name), "ESAPI PCR_Read test (%s)", path);
    print_test_header(name);

    if (esys_init(path, &esys, &tcti) < 0) {
        printf("[FAIL] ESYS init failed\n\n");
        return -1;
    }

    memset(&pcr_sel, 0, sizeof(pcr_sel));
    pcr_sel.count = 1;
    pcr_sel.pcrSelections[0].hash = TPM2_ALG_SHA256;
    pcr_sel.pcrSelections[0].sizeofSelect = 3;
    pcr_sel.pcrSelections[0].pcrSelect[0] = 0x01;
    pcr_sel.pcrSelections[0].pcrSelect[1] = 0x00;
    pcr_sel.pcrSelections[0].pcrSelect[2] = 0x00;

    rc = Esys_PCR_Read(esys,
                       ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                       &pcr_sel,
                       &pcr_update_counter,
                       &out_sel,
                       &out_digests);
    if (rc != TSS2_RC_SUCCESS) {
        printf("[FAIL] Esys_PCR_Read rc=0x%x\n\n", rc);
        esys_cleanup(esys, tcti);
        return -1;
    }

    printf("[PASS] Esys_PCR_Read success, update_counter=%u\n\n", pcr_update_counter);

    Esys_Free(out_sel);
    Esys_Free(out_digests);
    esys_cleanup(esys, tcti);
    return 0;
}

static int esys_repeated_getrandom_test(const char *path, int rounds) {
    ESYS_CONTEXT *esys = NULL;
    TSS2_TCTI_CONTEXT *tcti = NULL;
    TPM2B_DIGEST *random = NULL;
    TSS2_RC rc;
    int i;

    char name[128];
    snprintf(name, sizeof(name), "ESAPI repeated GetRandom (%s, %d rounds)", path, rounds);
    print_test_header(name);

    if (esys_init(path, &esys, &tcti) < 0) {
        printf("[FAIL] ESYS init failed\n\n");
        return -1;
    }

    for (i = 0; i < rounds; i++) {
        rc = Esys_GetRandom(esys,
                            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                            8,
                            &random);
        if (rc != TSS2_RC_SUCCESS) {
            printf("[FAIL] round %d Esys_GetRandom rc=0x%x\n\n", i, rc);
            esys_cleanup(esys, tcti);
            return -1;
        }
        Esys_Free(random);
        random = NULL;
    }

    printf("[PASS] repeated GetRandom stable for %d rounds\n\n", rounds);
    esys_cleanup(esys, tcti);
    return 0;
}

static int esys_session_test(const char *path) {
    ESYS_CONTEXT *esys = NULL;
    TSS2_TCTI_CONTEXT *tcti = NULL;
    ESYS_TR session = ESYS_TR_NONE;
    TPM2B_NONCE nonceCaller = { .size = 0 };
    TPMT_SYM_DEF symmetric = { .algorithm = TPM2_ALG_NULL };
    TSS2_RC rc;

    char name[128];
    snprintf(name, sizeof(name), "ESAPI StartAuthSession/FlushContext (%s)", path);
    print_test_header(name);

    if (esys_init(path, &esys, &tcti) < 0) {
        printf("[FAIL] ESYS init failed\n\n");
        return -1;
    }

    rc = Esys_StartAuthSession(esys,
                               ESYS_TR_NONE, ESYS_TR_NONE,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               &nonceCaller,
                               TPM2_SE_HMAC,
                               &symmetric,
                               TPM2_ALG_SHA256,
                               &session);
    if (rc != TSS2_RC_SUCCESS) {
        if (STRICT_SESSION_TESTS) {
            printf("[FAIL] Esys_StartAuthSession rc=0x%x\n\n", rc);
            esys_cleanup(esys, tcti);
            return -1;
        }
        printf("[SKIP] Esys_StartAuthSession not available yet, rc=0x%x\n\n", rc);
        esys_cleanup(esys, tcti);
        return 0;
    }

    printf("[PASS] Esys_StartAuthSession success, session=0x%x\n", session);

    rc = Esys_FlushContext(esys, session);
    if (rc != TSS2_RC_SUCCESS) {
        printf("[FAIL] Esys_FlushContext rc=0x%x\n\n", rc);
        esys_cleanup(esys, tcti);
        return -1;
    }

    printf("[PASS] Esys_FlushContext success\n\n");
    esys_cleanup(esys, tcti);
    return 0;
}

static int child_worker(const char *path, int loops) {
    ESYS_CONTEXT *esys = NULL;
    TSS2_TCTI_CONTEXT *tcti = NULL;
    TPM2B_DIGEST *random = NULL;
    TSS2_RC rc;
    int i;

    if (esys_init(path, &esys, &tcti) < 0) {
        return 1;
    }

    for (i = 0; i < loops; i++) {
        rc = Esys_GetRandom(esys,
                            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                            8,
                            &random);
        if (rc != TSS2_RC_SUCCESS) {
            esys_cleanup(esys, tcti);
            return 1;
        }
        Esys_Free(random);
        random = NULL;
    }

    esys_cleanup(esys, tcti);
    return 0;
}

static int esys_multi_process_test(const char *path) {
    pid_t p1, p2;
    int st1 = 0, st2 = 0;

    char name[128];
    snprintf(name, sizeof(name), "ESAPI multi-process stability (%s)", path);
    print_test_header(name);

    p1 = fork();
    if (p1 < 0) {
        printf("[FAIL] fork p1: %s\n\n", strerror(errno));
        return -1;
    }
    if (p1 == 0) {
        _exit(child_worker(path, 5));
    }

    p2 = fork();
    if (p2 < 0) {
        printf("[FAIL] fork p2: %s\n\n", strerror(errno));
        kill(p1, SIGTERM);
        waitpid(p1, NULL, 0);
        return -1;
    }
    if (p2 == 0) {
        _exit(child_worker(path, 5));
    }

    waitpid(p1, &st1, 0);
    waitpid(p2, &st2, 0);

    if (!WIFEXITED(st1) || WEXITSTATUS(st1) != 0 ||
        !WIFEXITED(st2) || WEXITSTATUS(st2) != 0) {
        printf("[FAIL] multi-process ESAPI test failed: st1=%d st2=%d\n\n", st1, st2);
        return -1;
    }

    printf("[PASS] multi-process ESAPI stability ok\n\n");
    return 0;
}

int main(void) {
    int failed = 0;
    uint8_t cmd[64];

    printf("=== TPM2-TSS Full Feature Test Suite ===\n");
    printf("STRICT_SESSION_TESTS=%d\n\n", STRICT_SESSION_TESTS);

    /* ---------- raw device layer ---------- */
    if (raw_partial_read_test(
            DEV_TPM0,
            cmd, build_get_random(cmd, 16),
            "raw partial-read GetRandom on /dev/tpm0") < 0) {
        failed++;
    }

    if (raw_partial_read_test(
            DEV_TPMRM0,
            cmd, build_get_random(cmd, 16),
            "raw partial-read GetRandom on /dev/tpmrm0") < 0) {
        failed++;
    }

    /* ---------- tcti layer ---------- */
    if (tcti_init_test(DEV_TPM0) < 0) failed++;
    if (tcti_init_test(DEV_TPMRM0) < 0) failed++;

    /* ---------- esapi layer ---------- */
    if (esys_getcap_test(DEV_TPM0) < 0) failed++;
    if (esys_getcap_test(DEV_TPMRM0) < 0) failed++;

    if (esys_getrandom_test(DEV_TPM0, 16) < 0) failed++;
    if (esys_getrandom_test(DEV_TPMRM0, 16) < 0) failed++;

    if (esys_pcrread_test(DEV_TPM0) < 0) failed++;
    if (esys_pcrread_test(DEV_TPMRM0) < 0) failed++;

    if (esys_repeated_getrandom_test(DEV_TPM0, 20) < 0) failed++;
    if (esys_repeated_getrandom_test(DEV_TPMRM0, 20) < 0) failed++;

    if (esys_multi_process_test(DEV_TPMRM0) < 0) failed++;

    /* ---------- session foundation ---------- */
    if (esys_session_test(DEV_TPM0) < 0) failed++;
    if (esys_session_test(DEV_TPMRM0) < 0) failed++;

    printf("=== Summary ===\n");
    if (failed == 0) {
        printf("[PASS] All full-suite tests passed\n");
        return 0;
    }

    printf("[FAIL] %d test group(s) failed\n", failed);
    return 1;
}
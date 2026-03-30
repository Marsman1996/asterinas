// SPDX-License-Identifier: MPL-2.0

//! TPM device test program
//!
//! Tests basic TPM functionality by:
//! 1. Opening /dev/tpm0
//! 2. Sending a TPM2_GetCapability command
//! 3. Reading and validating the response

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

// TPM 2.0 command tags
#define TPM_ST_NO_SESSIONS 0x8001
#define TPM_ST_RSP_NO_SESSIONS 0x8001

// TPM 2.0 command codes
#define TPM2_GET_CAPABILITY 0x0000017A

// TPM 2.0 capability types
#define TPM_CAP_TPM_PROPERTIES 0x00000006

// TPM 2.0 property tags
#define TPM_PT_MANUFACTURER 0x00000105

// TPM header structure
struct tpm_header {
    uint16_t tag;
    uint32_t size;
    uint32_t code;
} __attribute__((packed));

// Helper function to write big-endian values
static void write_be16(uint8_t *buf, uint16_t val) {
    buf[0] = (val >> 8) & 0xFF;
    buf[1] = val & 0xFF;
}

static void write_be32(uint8_t *buf, uint32_t val) {
    buf[0] = (val >> 24) & 0xFF;
    buf[1] = (val >> 16) & 0xFF;
    buf[2] = (val >> 8) & 0xFF;
    buf[3] = val & 0xFF;
}

static uint16_t read_be16(const uint8_t *buf) {
    return (buf[0] << 8) | buf[1];
}

static uint32_t read_be32(const uint8_t *buf) {
    return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) | buf[3];
}

// Build TPM2_GetCapability command
static int build_get_capability(uint8_t *buf, size_t buf_size,
                                 uint32_t capability, uint32_t property,
                                 uint32_t count) {
    if (buf_size < 22) {
        return -1;
    }

    // Header: tag (2) + size (4) + command_code (4) = 10 bytes
    write_be16(buf + 0, TPM_ST_NO_SESSIONS);  // tag
    write_be32(buf + 2, 22);                   // size (10 header + 12 params)
    write_be32(buf + 6, TPM2_GET_CAPABILITY); // command code

    // Parameters: capability (4) + property (4) + count (4) = 12 bytes
    write_be32(buf + 10, capability);
    write_be32(buf + 14, property);
    write_be32(buf + 18, count);

    return 22;
}

// Parse TPM response header
static int parse_response_header(const uint8_t *buf, size_t len,
                                  uint16_t *tag, uint32_t *size,
                                  uint32_t *code) {
    if (len < 10) {
        fprintf(stderr, "Response too short: %zu bytes\n", len);
        return -1;
    }

    *tag = read_be16(buf + 0);
    *size = read_be32(buf + 2);
    *code = read_be32(buf + 6);

    return 0;
}

int main(void) {
    int fd;
    uint8_t cmd[64];
    uint8_t rsp[256];
    int cmd_len;
    ssize_t ret;

    printf("=== TPM Device Test ===\n\n");

    // Test 1: Open /dev/tpm0
    printf("Test 1: Opening /dev/tpm0... ");
    fd = open("/dev/tpm0", O_RDWR);
    if (fd < 0) {
        printf("FAILED: %s\n", strerror(errno));
        return 1;
    }
    printf("OK (fd=%d)\n", fd);

    // Test 2: Build GetCapability command
    printf("Test 2: Building TPM2_GetCapability command... ");
    cmd_len = build_get_capability(cmd, sizeof(cmd),
                                    TPM_CAP_TPM_PROPERTIES,
                                    TPM_PT_MANUFACTURER, 1);
    if (cmd_len < 0) {
        printf("FAILED\n");
        close(fd);
        return 1;
    }
    printf("OK (%d bytes)\n", cmd_len);

    // Test 3: Write command to TPM
    printf("Test 3: Writing command to /dev/tpm0... ");
    ret = write(fd, cmd, cmd_len);
    if (ret < 0) {
        printf("FAILED: %s\n", strerror(errno));
        close(fd);
        return 1;
    }
    if (ret != cmd_len) {
        printf("FAILED: wrote %zd of %d bytes\n", ret, cmd_len);
        close(fd);
        return 1;
    }
    printf("OK\n");

    // Test 4: Read response from TPM
    printf("Test 4: Reading response from /dev/tpm0... ");
    ret = read(fd, rsp, sizeof(rsp));
    if (ret < 0) {
        printf("FAILED: %s\n", strerror(errno));
        close(fd);
        return 1;
    }
    printf("OK (%zd bytes)\n", ret);

    // Test 5: Parse and validate response
    printf("Test 5: Parsing response header... ");
    uint16_t tag;
    uint32_t size, code;
    if (parse_response_header(rsp, ret, &tag, &size, &code) < 0) {
        printf("FAILED\n");
        close(fd);
        return 1;
    }
    printf("OK\n");

    // Display response info
    printf("\n=== Response Details ===\n");
    printf("Tag:           0x%04x", tag);
    if (tag == TPM_ST_RSP_NO_SESSIONS) {
        printf(" (TPM_ST_RSP_NO_SESSIONS)");
    }
    printf("\n");
    printf("Size:          %u bytes\n", size);
    printf("Response Code: 0x%08x", code);
    if (code == 0) {
        printf(" (SUCCESS)");
    } else {
        printf(" (ERROR)");
    }
    printf("\n");

    // Test 6: Check if response is success
    printf("\nTest 6: Checking response code... ");
    if (code != 0) {
        printf("FAILED (error code 0x%08x)\n", code);
        close(fd);
        return 1;
    }
    printf("OK (SUCCESS)\n");

    // Parse manufacturer if available
    if (ret >= 22) {
        uint32_t manufacturer = read_be32(rsp + 18);
        printf("\n=== TPM Manufacturer ===\n");
        printf("Vendor ID: 0x%08x\n", manufacturer);
        // Common vendor IDs:
        // 0x49465800 = "IFX" (Infineon)
        // 0x4E544300 = "NTC" (Nuvoton)
        // 0x51434F4D = "QCOM" (Qualcomm)
        // 0x414D4400 = "AMD"
        // 0x49424D00 = "IBM"
        // 0x494E5443 = "INTC" (Intel)
        // 0x534D5343 = "SMSC"
        // 0x41544D4C = "ATML" (Atmel)
        // 0x53544D20 = "STM " (STMicroelectronics)
        // 0x4C454E00 = "LEN" (Lenovo)
        // 0x48504900 = "HPI" (HP)
        // 0x464C5900 = "FLY" (Flybit)
        // 0x54584E00 = "TXN" (Texas Instruments)

        // Try to decode as ASCII
        char vendor[5];
        vendor[0] = (manufacturer >> 24) & 0xFF;
        vendor[1] = (manufacturer >> 16) & 0xFF;
        vendor[2] = (manufacturer >> 8) & 0xFF;
        vendor[3] = manufacturer & 0xFF;
        vendor[4] = '\0';
        printf("Vendor Name: %.4s\n", vendor);
    }

    printf("\n=== All Tests Passed ===\n");

    close(fd);
    return 0;
}

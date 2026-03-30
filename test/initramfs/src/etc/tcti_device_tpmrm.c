#include <stdio.h>
#include <stdlib.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tcti_device.h>

int main(void) {
    TSS2_RC rc;
    size_t size = 0;
    TSS2_TCTI_CONTEXT *ctx = NULL;

    rc = Tss2_Tcti_Device_Init(NULL, &size, "/dev/tpmrm0");
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Tss2_Tcti_Device_Init(size query) failed: 0x%x\n", rc);
        return 1;
    }

    ctx = (TSS2_TCTI_CONTEXT *)calloc(1, size);
    if (!ctx) {
        perror("calloc");
        return 1;
    }

    rc = Tss2_Tcti_Device_Init(ctx, &size, "/dev/tpmrm0");
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Tss2_Tcti_Device_Init failed: 0x%x\n", rc);
        free(ctx);
        return 1;
    }

    printf("TCTI device init success, context size = %zu\n", size);

    free(ctx);
    return 0;
}
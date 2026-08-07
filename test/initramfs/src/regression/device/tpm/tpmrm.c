// SPDX-License-Identifier: MPL-2.0

/* Synchronous Linux-6.17 TPM2 resource-manager regression tests. */

#include "tpm_test_common.h"

FN_SETUP(check_tpm_availability)
{
    tpm_require_device(TPM_DEVICE);
    tpm_require_device(TPMRM_DEVICE);
}
END_SETUP()

FN_TEST(tpmrm_device_is_character_device)
{
    struct stat stat_buf;

    /* /dev/tpmrm0 uses dynamically allocated dev_t; do not hard-code 10:1. */
    TEST_RES(stat(TPMRM_DEVICE, &stat_buf), S_ISCHR(stat_buf.st_mode));
}
END_TEST()

FN_TEST(tpmrm_allows_multiple_independent_opens)
{
    int fd1 = TEST_SUCC(open(TPMRM_DEVICE, O_RDWR));
    int fd2 = TEST_SUCC(open(TPMRM_DEVICE, O_RDWR));

    TEST_SUCC(close(fd2));
    TEST_SUCC(close(fd1));
}
END_TEST()

FN_TEST(tpmrm_cc_table_accepts_known_and_synthesizes_unknown_error)
{
    uint8_t response[256] = { 0 };
    ssize_t len;
    uint32_t rc;
    int fd = TEST_SUCC(open(TPMRM_DEVICE, O_RDWR));

    len = TEST_RES(tpm_transact_sync(
                       fd,
                       tpm_get_random_command,
                       sizeof(tpm_get_random_command),
                       response,
                       sizeof(response)),
                   _ret >= TPM_HEADER_SIZE + 2);
    if (len >= TPM_HEADER_SIZE + 2)
        TEST_RES(tpm_read_be32(response + 6), _ret == 0);

    memset(response, 0, sizeof(response));
    len = TEST_RES(tpm_transact_sync(
                       fd,
                       tpm_unknown_command,
                       sizeof(tpm_unknown_command),
                       response,
                       sizeof(response)),
                   _ret == TPM_HEADER_SIZE);

    if (len == TPM_HEADER_SIZE) {
        rc = tpm_read_be32(response + 6);
        TEST_RES(rc, _ret != 0);
        TEST_RES(rc & 0xffffU, _ret == TPM2_RC_COMMAND_CODE);
    }

    TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(tpmrm_isolates_sessions_between_spaces)
{
    uint8_t response[512] = { 0 };
    uint8_t flush_command[14];
    uint32_t session_handle = 0;
    ssize_t len;
    int owner_fd = TEST_SUCC(open(TPMRM_DEVICE, O_RDWR));
    int other_fd = TEST_SUCC(open(TPMRM_DEVICE, O_RDWR));

    len = TEST_RES(tpm_transact_sync(
                       owner_fd,
                       tpm_start_auth_session_command,
                       sizeof(tpm_start_auth_session_command),
                       response,
                       sizeof(response)),
                   _ret >= TPM_HEADER_SIZE + 4);

    if (len >= TPM_HEADER_SIZE + 4) {
        TEST_RES(tpm_read_be32(response + 6), _ret == 0);
        session_handle = tpm_read_be32(response + TPM_HEADER_SIZE);
        TEST_RES(session_handle >> 24,
                 _ret == 0x02 || _ret == 0x03);
    }

    if (len >= TPM_HEADER_SIZE + 4) {
        tpm_build_flush_context_command(flush_command, session_handle);

        memset(response, 0, sizeof(response));
        len = TEST_RES(tpm_transact_sync(
                           other_fd,
                           flush_command,
                           sizeof(flush_command),
                           response,
                           sizeof(response)),
                       _ret >= TPM_HEADER_SIZE);
        if (len >= TPM_HEADER_SIZE)
            TEST_RES(tpm_read_be32(response + 6), _ret != 0);

        memset(response, 0, sizeof(response));
        len = TEST_RES(tpm_transact_sync(
                           owner_fd,
                           flush_command,
                           sizeof(flush_command),
                           response,
                           sizeof(response)),
                       _ret == TPM_HEADER_SIZE);
        if (len == TPM_HEADER_SIZE)
            TEST_RES(tpm_read_be32(response + 6), _ret == 0);
    }

    TEST_SUCC(close(other_fd));
    TEST_SUCC(close(owner_fd));
}
END_TEST()

FN_TEST(tpmrm_close_discards_session_space)
{
    uint8_t response[512] = { 0 };
    uint8_t flush_command[14];
    uint32_t session_handle = 0;
    ssize_t len;
    int fd = TEST_SUCC(open(TPMRM_DEVICE, O_RDWR));

    len = TEST_RES(tpm_transact_sync(
                       fd,
                       tpm_start_auth_session_command,
                       sizeof(tpm_start_auth_session_command),
                       response,
                       sizeof(response)),
                   _ret >= TPM_HEADER_SIZE + 4);

    if (len >= TPM_HEADER_SIZE + 4) {
        TEST_RES(tpm_read_be32(response + 6), _ret == 0);
        session_handle = tpm_read_be32(response + TPM_HEADER_SIZE);
    }

    TEST_SUCC(close(fd));

    if (len < TPM_HEADER_SIZE + 4)
        return;

    /* tpmrm_release() calls tpm2_del_space(). */
    fd = TEST_SUCC(open(TPM_DEVICE, O_RDWR));
    tpm_build_flush_context_command(flush_command, session_handle);

    len = TEST_RES(tpm_transact_sync(
                       fd,
                       flush_command,
                       sizeof(flush_command),
                       response,
                       sizeof(response)),
                   _ret >= TPM_HEADER_SIZE);
    if (len >= TPM_HEADER_SIZE)
        TEST_RES(tpm_read_be32(response + 6), _ret != 0);

    TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(tpmrm_virtualizes_objects_and_filters_capabilities)
{
    uint8_t response[1024] = { 0 };
    uint8_t flush_command[14];
    uint32_t object_handle = 0;
    uint32_t owner_count = 0;
    ssize_t len;
    bool found = false;
    int owner_fd = TEST_SUCC(open(TPMRM_DEVICE, O_RDWR));
    int other_fd = TEST_SUCC(open(TPMRM_DEVICE, O_RDWR));

    len = TEST_RES(tpm_transact_sync(
                       owner_fd,
                       tpm_hash_sequence_start_command,
                       sizeof(tpm_hash_sequence_start_command),
                       response,
                       sizeof(response)),
                   _ret >= TPM_HEADER_SIZE + 4);

    if (len >= TPM_HEADER_SIZE + 4) {
        TEST_RES(tpm_read_be32(response + 6), _ret == 0);
        object_handle = tpm_read_be32(response + TPM_HEADER_SIZE);
        TEST_RES(object_handle >> 24, _ret == 0x80);
    }

    if (len >= TPM_HEADER_SIZE + 4) {
        memset(response, 0, sizeof(response));
        len = TEST_RES(tpm_transact_sync(
                           owner_fd,
                           tpm_get_transient_handles_command,
                           sizeof(tpm_get_transient_handles_command),
                           response,
                           sizeof(response)),
                       _ret >= 19);
    }

    if (len >= 19) {
        TEST_RES(tpm_read_be32(response + 6), _ret == 0);
        owner_count = tpm_read_be32(response + 15);
        TEST_RES(owner_count,
                 _ret >= 1 &&
                     _ret <= (uint32_t)(((size_t)len - 19) / 4));

        if (owner_count <= (uint32_t)(((size_t)len - 19) / 4)) {
            for (uint32_t i = 0; i < owner_count; i++)
                found |= tpm_read_be32(response + 19 + i * 4) ==
                         object_handle;
            TEST_RES(found, _ret == true);
        }
    }

    memset(response, 0, sizeof(response));
    len = TEST_RES(tpm_transact_sync(
                       other_fd,
                       tpm_get_transient_handles_command,
                       sizeof(tpm_get_transient_handles_command),
                       response,
                       sizeof(response)),
                   _ret >= 19);

    if (len >= 19) {
        TEST_RES(tpm_read_be32(response + 6), _ret == 0);
        TEST_RES(tpm_read_be32(response + 15), _ret == 0);
    }

    if (object_handle != 0) {
        tpm_build_flush_context_command(flush_command, object_handle);

        /* Foreign transient virtual handle is rejected in tpm2_map_command(). */
        TEST_ERRNO(write(other_fd, flush_command, sizeof(flush_command)),
                   EINVAL);

        memset(response, 0, sizeof(response));
        len = TEST_RES(tpm_transact_sync(
                           owner_fd,
                           flush_command,
                           sizeof(flush_command),
                           response,
                           sizeof(response)),
                       _ret == TPM_HEADER_SIZE);
        if (len == TPM_HEADER_SIZE)
            TEST_RES(tpm_read_be32(response + 6), _ret == 0);
    }

    TEST_SUCC(close(other_fd));
    TEST_SUCC(close(owner_fd));
}
END_TEST()

FN_TEST(tpmrm_limits_transient_objects_to_three_slots_per_space)
{
    enum { NR_OBJECTS = 3 };
    uint8_t response[1024] = { 0 };
    uint8_t flush_command[14];
    uint32_t handles[NR_OBJECTS] = { 0 };
    size_t created = 0;
    int fd = TEST_SUCC(open(TPMRM_DEVICE, O_RDWR));

    for (size_t i = 0; i < NR_OBJECTS; i++) {
        ssize_t len;

        memset(response, 0, sizeof(response));
        len = TEST_RES(tpm_transact_sync(
                           fd,
                           tpm_hash_sequence_start_command,
                           sizeof(tpm_hash_sequence_start_command),
                           response,
                           sizeof(response)),
                       _ret >= TPM_HEADER_SIZE + 4);

        if (len < TPM_HEADER_SIZE + 4)
            break;

        TEST_RES(tpm_read_be32(response + 6), _ret == 0);
        handles[i] = tpm_read_be32(response + TPM_HEADER_SIZE);
        TEST_RES(handles[i] >> 24, _ret == 0x80);
        created++;
    }

    if (created == NR_OBJECTS) {
        /* Linux struct tpm_space has context_tbl[3]. */
        TEST_ERRNO(write(fd,
                         tpm_hash_sequence_start_command,
                         sizeof(tpm_hash_sequence_start_command)),
                   ENOMEM);
    }

    for (size_t i = 0; i < created; i++) {
        ssize_t len;

        tpm_build_flush_context_command(flush_command, handles[i]);
        memset(response, 0, sizeof(response));

        len = TEST_RES(tpm_transact_sync(
                           fd,
                           flush_command,
                           sizeof(flush_command),
                           response,
                           sizeof(response)),
                       _ret == TPM_HEADER_SIZE);

        if (len == TPM_HEADER_SIZE)
            TEST_RES(tpm_read_be32(response + 6), _ret == 0);
    }

    TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(tpmrm_limits_sessions_to_three_slots_per_space)
{
    enum { NR_SESSIONS = 3 };
    uint8_t response[1024] = { 0 };
    uint8_t flush_command[14];
    uint32_t handles[NR_SESSIONS] = { 0 };
    size_t created = 0;
    int fd = TEST_SUCC(open(TPMRM_DEVICE, O_RDWR));

    for (size_t i = 0; i < NR_SESSIONS; i++) {
        ssize_t len;

        memset(response, 0, sizeof(response));
        len = TEST_RES(tpm_transact_sync(
                           fd,
                           tpm_start_auth_session_command,
                           sizeof(tpm_start_auth_session_command),
                           response,
                           sizeof(response)),
                       _ret >= TPM_HEADER_SIZE + 4);

        if (len < TPM_HEADER_SIZE + 4)
            break;

        TEST_RES(tpm_read_be32(response + 6), _ret == 0);
        handles[i] = tpm_read_be32(response + TPM_HEADER_SIZE);
        TEST_RES(handles[i] >> 24,
                 _ret == 0x02 || _ret == 0x03);
        created++;
    }

    if (created == NR_SESSIONS) {
        /* Linux struct tpm_space has session_tbl[3]. */
        TEST_ERRNO(write(fd,
                         tpm_start_auth_session_command,
                         sizeof(tpm_start_auth_session_command)),
                   ENOMEM);
    }

    for (size_t i = 0; i < created; i++) {
        ssize_t len;

        tpm_build_flush_context_command(flush_command, handles[i]);
        memset(response, 0, sizeof(response));

        len = TEST_RES(tpm_transact_sync(
                           fd,
                           flush_command,
                           sizeof(flush_command),
                           response,
                           sizeof(response)),
                       _ret == TPM_HEADER_SIZE);

        if (len == TPM_HEADER_SIZE)
            TEST_RES(tpm_read_be32(response + 6), _ret == 0);
    }

    TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(tpmrm_saves_and_restores_objects_across_spaces)
{
    enum { NR_SPACES = 4 };
    int fds[NR_SPACES];
    uint32_t handles[NR_SPACES] = { 0 };
    uint8_t response[1024] = { 0 };
    uint8_t flush_command[14];
    size_t opened = 0;
    size_t created = 0;

    for (size_t i = 0; i < NR_SPACES; i++) {
        fds[i] = TEST_SUCC(open(TPMRM_DEVICE, O_RDWR));
        if (fds[i] >= 0)
            opened++;
    }

    for (size_t i = 0; i < opened; i++) {
        ssize_t len;

        memset(response, 0, sizeof(response));
        len = TEST_RES(tpm_transact_sync(
                           fds[i],
                           tpm_hash_sequence_start_command,
                           sizeof(tpm_hash_sequence_start_command),
                           response,
                           sizeof(response)),
                       _ret >= TPM_HEADER_SIZE + 4);

        if (len < TPM_HEADER_SIZE + 4)
            break;

        TEST_RES(tpm_read_be32(response + 6), _ret == 0);
        handles[i] = tpm_read_be32(response + TPM_HEADER_SIZE);
        TEST_RES(handles[i] >> 24, _ret == 0x80);
        created++;
    }

    /* Re-enter each space; RM must ContextLoad its saved object. */
    for (size_t i = 0; i < created; i++) {
        ssize_t len;

        tpm_build_flush_context_command(flush_command, handles[i]);
        memset(response, 0, sizeof(response));

        len = TEST_RES(tpm_transact_sync(
                           fds[i],
                           flush_command,
                           sizeof(flush_command),
                           response,
                           sizeof(response)),
                       _ret == TPM_HEADER_SIZE);

        if (len == TPM_HEADER_SIZE)
            TEST_RES(tpm_read_be32(response + 6), _ret == 0);
    }

    for (size_t i = 0; i < opened; i++)
        TEST_SUCC(close(fds[i]));
}
END_TEST()

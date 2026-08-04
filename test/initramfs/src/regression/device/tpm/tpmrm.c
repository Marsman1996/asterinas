// SPDX-License-Identifier: MPL-2.0

/* TPM resource-manager integration tests. */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../common/test.h"

#define TPM_DEVICE "/dev/tpm0"
#define TPMRM_DEVICE "/dev/tpmrm0"
#define TPM_MAJOR 10
#define TPM_MINOR 0
#define TPMRM_MINOR 1
#define TPM_HEADER_SIZE 10
#define TPM_MAX_COMMAND_SIZE (64 * 1024)
#define TPM_ST_NO_SESSIONS 0x8001U
#define TPM_RANDOM_BYTES 32

static const uint8_t hash_sequence_start_command[] = {
	0x80, 0x01, /* TPM_ST_NO_SESSIONS */
	0x00, 0x00, 0x00, 0x0e, /* command size */
	0x00, 0x00, 0x01, 0x86, /* TPM2_HashSequenceStart */
	0x00, 0x00, /* empty auth */
	0x00, 0x0b, /* TPM_ALG_SHA256 */
};

static const uint8_t get_transient_handles_command[] = {
	0x80, 0x01, /* TPM_ST_NO_SESSIONS */
	0x00, 0x00, 0x00, 0x16, /* command size */
	0x00, 0x00, 0x01, 0x7a, /* TPM2_GetCapability */
	0x00, 0x00, 0x00, 0x01, /* TPM_CAP_HANDLES */
	0x80, 0x00, 0x00, 0x00, /* first transient handle */
	0x00, 0x00, 0x00, 0x40, /* maximum count */
};

static const uint8_t start_auth_session_command[] = {
	0x80, 0x01, /* TPM_ST_NO_SESSIONS */
	0x00, 0x00, 0x00, 0x2b, /* command size */
	0x00, 0x00, 0x01, 0x76, /* TPM2_StartAuthSession */
	0x40, 0x00, 0x00, 0x07, /* tpmKey: TPM_RH_NULL */
	0x40, 0x00, 0x00, 0x07, /* bind: TPM_RH_NULL */
	0x00, 0x10, /* nonceCaller size */
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x00, /* empty encryptedSalt */
	0x00, /* TPM_SE_HMAC */
	0x00, 0x10, /* symmetric: TPM_ALG_NULL */
	0x00, 0x0b, /* authHash: TPM_ALG_SHA256 */
};

static uint32_t read_be32(const uint8_t *bytes)
{
	return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
	       ((uint32_t)bytes[2] << 8) | bytes[3];
}

static void build_command_header(uint8_t *command, size_t size, uint32_t code)
{
	command[0] = 0x80;
	command[1] = 0x01;
	command[2] = size >> 24;
	command[3] = size >> 16;
	command[4] = size >> 8;
	command[5] = size;
	command[6] = code >> 24;
	command[7] = code >> 16;
	command[8] = code >> 8;
	command[9] = code;
}

static void build_flush_context_command(uint8_t *command, uint32_t handle)
{
	static const uint8_t header[] = {
		0x80, 0x01, /* TPM_ST_NO_SESSIONS */
		0x00, 0x00, 0x00, 0x0e, /* command size */
		0x00, 0x00, 0x01, 0x65, /* TPM2_FlushContext */
	};

	memcpy(command, header, sizeof(header));
	command[10] = handle >> 24;
	command[11] = handle >> 16;
	command[12] = handle >> 8;
	command[13] = handle;
}

static void exit_if_tpm_is_unavailable(void)
{
	if (access(TPM_DEVICE, F_OK) == 0 && access(TPMRM_DEVICE, F_OK) == 0)
		return;

	if (errno == ENOENT || errno == ENODEV || errno == ENXIO) {
		fprintf(stderr,
			"TPM tests skipped: TPM devices are unavailable\n");
		exit(EXIT_SUCCESS);
	}

	perror("failed to inspect TPM devices");
	exit(EXIT_FAILURE);
}

FN_SETUP(check_tpm_availability)
{
	exit_if_tpm_is_unavailable();
}
END_SETUP()

FN_TEST(tpmrm_isolates_sessions_between_spaces)
{
	uint8_t flush_command[14];
	uint8_t response[256];
	uint32_t session_handle;
	int owner_fd = TEST_SUCC(open(TPMRM_DEVICE, O_RDWR | O_NONBLOCK));
	int other_fd = TEST_SUCC(open(TPMRM_DEVICE, O_RDWR | O_NONBLOCK));

	TEST_RES(write(owner_fd, start_auth_session_command,
		       sizeof(start_auth_session_command)),
		 _ret == sizeof(start_auth_session_command));
	TEST_RES(read(owner_fd, response, sizeof(response)),
		 _ret >= TPM_HEADER_SIZE + sizeof(uint32_t));
	TEST_RES(read_be32(response + 6), _ret == 0);
	session_handle = read_be32(response + TPM_HEADER_SIZE);
	TEST_RES(session_handle >> 24, _ret == 0x02 || _ret == 0x03);

	build_flush_context_command(flush_command, session_handle);
	TEST_RES(write(other_fd, flush_command, sizeof(flush_command)),
		 _ret == sizeof(flush_command));
	TEST_RES(read(other_fd, response, sizeof(response)),
		 _ret >= TPM_HEADER_SIZE);
	TEST_RES(read_be32(response + 6), _ret != 0);

	TEST_RES(write(owner_fd, flush_command, sizeof(flush_command)),
		 _ret == sizeof(flush_command));
	TEST_RES(read(owner_fd, response, sizeof(response)),
		 _ret == TPM_HEADER_SIZE);
	TEST_RES(read_be32(response + 6), _ret == 0);
	TEST_ERRNO(write(owner_fd, flush_command, sizeof(flush_command)), EIO);

	TEST_SUCC(close(other_fd));
	TEST_SUCC(close(owner_fd));
}
END_TEST()

FN_TEST(tpmrm_close_discards_session_space)
{
	uint8_t flush_command[14];
	uint8_t response[256];
	uint32_t session_handle;
	int fd = TEST_SUCC(open(TPMRM_DEVICE, O_RDWR | O_NONBLOCK));

	TEST_RES(write(fd, start_auth_session_command,
		       sizeof(start_auth_session_command)),
		 _ret == sizeof(start_auth_session_command));
	TEST_RES(read(fd, response, sizeof(response)),
		 _ret >= TPM_HEADER_SIZE + sizeof(uint32_t));
	TEST_RES(read_be32(response + 6), _ret == 0);
	session_handle = read_be32(response + TPM_HEADER_SIZE);
	TEST_SUCC(close(fd));

	fd = TEST_SUCC(open(TPM_DEVICE, O_RDWR | O_NONBLOCK));
	build_flush_context_command(flush_command, session_handle);
	TEST_RES(write(fd, flush_command, sizeof(flush_command)),
		 _ret == sizeof(flush_command));
	TEST_RES(read(fd, response, sizeof(response)), _ret >= TPM_HEADER_SIZE);
	TEST_RES(read_be32(response + 6), _ret != 0);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(tpm_session_context_round_trip_and_repeated_flush)
{
	uint8_t response[1024];
	uint8_t command[1024];
	uint8_t flush_command[14];
	uint32_t session_handle;
	ssize_t response_len;
	int fd = TEST_SUCC(open(TPM_DEVICE, O_RDWR | O_NONBLOCK));

	TEST_RES(write(fd, start_auth_session_command,
		       sizeof(start_auth_session_command)),
		 _ret == sizeof(start_auth_session_command));
	TEST_RES(read(fd, response, sizeof(response)), _ret >= 14);
	session_handle = read_be32(response + TPM_HEADER_SIZE);

	build_command_header(command, 14, 0x00000162);
	command[10] = session_handle >> 24;
	command[11] = session_handle >> 16;
	command[12] = session_handle >> 8;
	command[13] = session_handle;
	TEST_RES(write(fd, command, 14), _ret == 14);
	response_len = TEST_RES(read(fd, response, sizeof(response)),
				_ret > TPM_HEADER_SIZE);
	TEST_RES(read_be32(response + 6), _ret == 0);

	build_command_header(command, response_len, 0x00000161);
	memmove(command + TPM_HEADER_SIZE, response + TPM_HEADER_SIZE,
		response_len - TPM_HEADER_SIZE);
	TEST_RES(write(fd, command, response_len), _ret == response_len);
	TEST_RES(read(fd, response, sizeof(response)), _ret >= 14);
	TEST_RES(read_be32(response + 6), _ret == 0);
	session_handle = read_be32(response + TPM_HEADER_SIZE);

	build_flush_context_command(flush_command, session_handle);
	TEST_RES(write(fd, flush_command, sizeof(flush_command)),
		 _ret == sizeof(flush_command));
	TEST_RES(read(fd, response, sizeof(response)), _ret == TPM_HEADER_SIZE);
	TEST_RES(read_be32(response + 6), _ret == 0);
	TEST_RES(write(fd, flush_command, sizeof(flush_command)),
		 _ret == sizeof(flush_command));
	TEST_RES(read(fd, response, sizeof(response)), _ret >= TPM_HEADER_SIZE);
	TEST_RES(read_be32(response + 6), _ret != 0);
	TEST_SUCC(close(fd));
}
END_TEST()

FN_TEST(tpmrm_virtualizes_objects_and_filters_capabilities)
{
	uint8_t response[1024];
	uint8_t flush_command[14];
	uint32_t object_handle;
	int owner_fd = TEST_SUCC(open(TPMRM_DEVICE, O_RDWR | O_NONBLOCK));
	int other_fd = TEST_SUCC(open(TPMRM_DEVICE, O_RDWR | O_NONBLOCK));

	TEST_RES(write(owner_fd, hash_sequence_start_command,
		       sizeof(hash_sequence_start_command)),
		 _ret == sizeof(hash_sequence_start_command));
	TEST_RES(read(owner_fd, response, sizeof(response)), _ret >= 14);
	TEST_RES(read_be32(response + 6), _ret == 0);
	object_handle = read_be32(response + TPM_HEADER_SIZE);
	TEST_RES(object_handle >> 24, _ret == 0x80);

	TEST_RES(write(owner_fd, get_transient_handles_command,
		       sizeof(get_transient_handles_command)),
		 _ret == sizeof(get_transient_handles_command));
	TEST_RES(read(owner_fd, response, sizeof(response)), _ret >= 19);
	TEST_RES(read_be32(response + 6), _ret == 0);
	uint32_t owner_count = read_be32(response + 15);
	TEST_RES(owner_count, _ret >= 1);
	bool found = false;
	for (uint32_t i = 0; i < owner_count; i++)
		found |= read_be32(response + 19 + i * 4) == object_handle;
	TEST_RES(found, _ret == 1);

	TEST_RES(write(other_fd, get_transient_handles_command,
		       sizeof(get_transient_handles_command)),
		 _ret == sizeof(get_transient_handles_command));
	TEST_RES(read(other_fd, response, sizeof(response)), _ret >= 19);
	TEST_RES(read_be32(response + 6), _ret == 0);
	TEST_RES(read_be32(response + 15), _ret == 0);

	build_flush_context_command(flush_command, object_handle);
	TEST_RES(write(other_fd, flush_command, sizeof(flush_command)),
		 _ret == sizeof(flush_command));
	TEST_RES(read(other_fd, response, sizeof(response)),
		 _ret >= TPM_HEADER_SIZE);
	TEST_RES(read_be32(response + 6), _ret != 0);

	TEST_RES(write(owner_fd, flush_command, sizeof(flush_command)),
		 _ret == sizeof(flush_command));
	TEST_RES(read(owner_fd, response, sizeof(response)),
		 _ret == TPM_HEADER_SIZE);
	TEST_RES(read_be32(response + 6), _ret == 0);

	TEST_SUCC(close(other_fd));
	TEST_SUCC(close(owner_fd));
}
END_TEST()

FN_TEST(tpmrm_handles_multiple_saved_resources)
{
	enum { NR_OBJECTS = 8 };
	uint32_t handles[NR_OBJECTS];
	uint8_t response[512];
	uint8_t flush_command[14];
	int fd = TEST_SUCC(open(TPMRM_DEVICE, O_RDWR | O_NONBLOCK));

	for (size_t i = 0; i < NR_OBJECTS; i++) {
		TEST_RES(write(fd, hash_sequence_start_command,
			       sizeof(hash_sequence_start_command)),
			 _ret == sizeof(hash_sequence_start_command));
		TEST_RES(read(fd, response, sizeof(response)), _ret >= 14);
		TEST_RES(read_be32(response + 6), _ret == 0);
		handles[i] = read_be32(response + TPM_HEADER_SIZE);
	}

	for (size_t i = 0; i < NR_OBJECTS; i++) {
		build_flush_context_command(flush_command, handles[i]);
		TEST_RES(write(fd, flush_command, sizeof(flush_command)),
			 _ret == sizeof(flush_command));
		TEST_RES(read(fd, response, sizeof(response)),
			 _ret == TPM_HEADER_SIZE);
		TEST_RES(read_be32(response + 6), _ret == 0);
	}
	TEST_SUCC(close(fd));
}
END_TEST()

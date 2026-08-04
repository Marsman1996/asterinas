// SPDX-License-Identifier: MPL-2.0

/* TPM 2.0 protocol regression tests through the character devices. */

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

struct tpm_device {
	const char *path;
	unsigned int minor;
};

static const struct tpm_device tpm_devices[] = {
	{ TPM_DEVICE, TPM_MINOR },
	{ TPMRM_DEVICE, TPMRM_MINOR },
};

static const uint8_t get_random_command[] = {
	0x80, 0x01, /* TPM_ST_NO_SESSIONS */
	0x00, 0x00,
	0x00, 0x0c, /* command size */
	0x00, 0x00,
	0x01, 0x7b, /* TPM2_GetRandom */
	0x00, TPM_RANDOM_BYTES, /* requested bytes */
};

static const uint8_t get_capability_command[] = {
	0x80, 0x01, /* TPM_ST_NO_SESSIONS */
	0x00, 0x00, 0x00, 0x16, /* command size */
	0x00, 0x00, 0x01, 0x7a, /* TPM2_GetCapability */
	0x00, 0x00, 0x00, 0x06, /* TPM_CAP_TPM_PROPERTIES */
	0x00, 0x00, 0x01, 0x05, /* TPM_PT_MANUFACTURER */
	0x00, 0x00, 0x00, 0x01, /* property count */
};

static const uint8_t pcr_read_command[] = {
	0x80, 0x01, /* TPM_ST_NO_SESSIONS */
	0x00, 0x00, 0x00, 0x14, /* command size */
	0x00, 0x00, 0x01, 0x7e, /* TPM2_PCR_Read */
	0x00, 0x00, 0x00, 0x01, /* selection count */
	0x00, 0x0b, /* TPM_ALG_SHA256 */
	0x03, 0x01, 0x00, 0x00, /* PCR 0 selection */
};

static const uint8_t unknown_command[] = {
	0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0xff, 0xff, 0xff, 0xff,
};

static const uint8_t invalid_size_command[] = {
	0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x7b,
};

static uint16_t read_be16(const uint8_t *bytes)
{
	return ((uint16_t)bytes[0] << 8) | bytes[1];
}

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

static void build_get_random_command(uint8_t *command, uint16_t size)
{
	build_command_header(command, 12, 0x0000017b);
	command[10] = size >> 8;
	command[11] = size;
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

FN_TEST(tpm_get_random_and_partial_reads)
{
	for (size_t i = 0; i < sizeof(tpm_devices) / sizeof(tpm_devices[0]);
	     i++) {
		uint8_t response[256];
		struct pollfd pfd;
		ssize_t first_len;
		ssize_t rest_len;
		size_t response_len;
		uint16_t random_len;
		int fd = TEST_SUCC(
			open(tpm_devices[i].path, O_RDWR | O_NONBLOCK));

		TEST_RES(write(fd, get_random_command,
			       sizeof(get_random_command)),
			 _ret == sizeof(get_random_command));

		pfd = (struct pollfd){
			.fd = fd,
			.events = POLLIN | POLLOUT,
		};
		TEST_RES(poll(&pfd, 1, 0),
			 _ret == 1 && pfd.revents == (POLLIN | POLLOUT));

		first_len = TEST_RES(read(fd, response, 5), _ret == 5);
		TEST_ERRNO(write(fd, get_random_command,
				 sizeof(get_random_command)),
			   EBUSY);

		rest_len = TEST_RES(read(fd, response + first_len,
					 sizeof(response) - first_len),
				    _ret > 0);
		response_len = first_len + rest_len;
		random_len = read_be16(response + TPM_HEADER_SIZE);

		TEST_RES(read_be16(response), _ret == TPM_ST_NO_SESSIONS);
		TEST_RES(read_be32(response + 2), _ret == response_len);
		TEST_RES(read_be32(response + 6), _ret == 0);
		TEST_RES(random_len, _ret <= TPM_RANDOM_BYTES);
		TEST_RES(response_len, _ret == TPM_HEADER_SIZE +
						       sizeof(uint16_t) +
						       random_len);

		TEST_ERRNO(read(fd, response, sizeof(response)), EAGAIN);
		pfd.revents = 0;
		TEST_RES(poll(&pfd, 1, 0), _ret == 1 && pfd.revents == POLLOUT);

		TEST_SUCC(close(fd));
	}
}
END_TEST()

FN_TEST(tpm_gets_capability_and_reads_pcr)
{
	for (size_t i = 0; i < sizeof(tpm_devices) / sizeof(tpm_devices[0]);
	     i++) {
		uint8_t response[256];
		ssize_t response_len;
		int fd = TEST_SUCC(
			open(tpm_devices[i].path, O_RDWR | O_NONBLOCK));

		TEST_RES(write(fd, get_capability_command,
			       sizeof(get_capability_command)),
			 _ret == sizeof(get_capability_command));
		response_len = TEST_RES(read(fd, response, sizeof(response)),
					_ret >= TPM_HEADER_SIZE + 17);
		TEST_RES(read_be32(response + 2), _ret == response_len);
		TEST_RES(read_be32(response + 6), _ret == 0);
		TEST_RES(read_be32(response + 11), _ret == 0x00000006);
		TEST_RES(read_be32(response + 15), _ret >= 1);
		TEST_RES(read_be32(response + 19), _ret == 0x00000105);
		TEST_RES(read_be32(response + 23), _ret != 0);

		TEST_RES(write(fd, pcr_read_command, sizeof(pcr_read_command)),
			 _ret == sizeof(pcr_read_command));
		response_len = TEST_RES(read(fd, response, sizeof(response)),
					_ret > TPM_HEADER_SIZE);
		TEST_RES(read_be32(response + 2), _ret == response_len);
		TEST_RES(read_be32(response + 6), _ret == 0);

		TEST_SUCC(close(fd));
	}
}
END_TEST()

FN_TEST(tpm_preserves_error_responses_and_recovers)
{
	for (size_t i = 0; i < sizeof(tpm_devices) / sizeof(tpm_devices[0]);
	     i++) {
		uint8_t response[256];
		int fd = TEST_SUCC(
			open(tpm_devices[i].path, O_RDWR | O_NONBLOCK));

		TEST_RES(write(fd, unknown_command, sizeof(unknown_command)),
			 _ret == sizeof(unknown_command));
		TEST_RES(read(fd, response, sizeof(response)),
			 _ret >= TPM_HEADER_SIZE);
		TEST_RES(read_be32(response + 6), _ret != 0);

		TEST_ERRNO(write(fd, invalid_size_command,
				 sizeof(invalid_size_command)),
			   EIO);
		TEST_RES(write(fd, get_random_command,
			       sizeof(get_random_command)),
			 _ret == sizeof(get_random_command));
		TEST_RES(read(fd, response, sizeof(response)),
			 _ret >= TPM_HEADER_SIZE + sizeof(uint16_t));
		TEST_RES(read_be32(response + 6), _ret == 0);
		TEST_SUCC(close(fd));
	}
}
END_TEST()

FN_TEST(tpm_random_lengths_and_data_sanity)
{
	static const uint16_t sizes[] = { 1, 32, 64 };

	for (size_t i = 0; i < sizeof(tpm_devices) / sizeof(tpm_devices[0]);
	     i++) {
		int fd = TEST_SUCC(
			open(tpm_devices[i].path, O_RDWR | O_NONBLOCK));

		for (size_t j = 0; j < sizeof(sizes) / sizeof(sizes[0]); j++) {
			uint8_t command[12];
			uint8_t response[128] = { 0 };

			build_get_random_command(command, sizes[j]);
			TEST_RES(write(fd, command, sizeof(command)),
				 _ret == sizeof(command));
			TEST_RES(read(fd, response, sizeof(response)),
				 _ret >= TPM_HEADER_SIZE + sizeof(uint16_t));
			uint16_t returned =
				read_be16(response + TPM_HEADER_SIZE);
			TEST_RES(returned, _ret > 0 && _ret <= sizes[j]);
		}
		TEST_SUCC(close(fd));
	}
}
END_TEST()

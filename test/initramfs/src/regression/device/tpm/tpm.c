// // SPDX-License-Identifier: MPL-2.0

// /* Regression tests for the TPM character devices. */

// #include <errno.h>
// #include <fcntl.h>
// #include <pthread.h>
// #include <poll.h>
// #include <signal.h>
// #include <stdbool.h>
// #include <stdint.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <sys/ioctl.h>
// #include <sys/stat.h>
// #include <sys/sysmacros.h>
// #include <sys/wait.h>
// #include <unistd.h>

// #include "../../common/test.h"

// #define TPM_DEVICE "/dev/tpm0"
// #define TPMRM_DEVICE "/dev/tpmrm0"
// #define TPM_MAJOR 10
// #define TPM_MINOR 0
// #define TPMRM_MINOR 1
// #define TPM_HEADER_SIZE 10
// #define TPM_MAX_COMMAND_SIZE (64 * 1024)
// #define TPM_ST_NO_SESSIONS 0x8001U
// #define TPM_RANDOM_BYTES 32

// struct tpm_device {
// 	const char *path;
// 	unsigned int minor;
// };

// static const struct tpm_device tpm_devices[] = {
// 	{ TPM_DEVICE, TPM_MINOR },
// 	{ TPMRM_DEVICE, TPMRM_MINOR },
// };

// static const uint8_t get_random_command[] = {
// 	0x80, 0x01, /* TPM_ST_NO_SESSIONS */
// 	0x00, 0x00,
// 	0x00, 0x0c, /* command size */
// 	0x00, 0x00,
// 	0x01, 0x7b, /* TPM2_GetRandom */
// 	0x00, TPM_RANDOM_BYTES, /* requested bytes */
// };

// static const uint8_t invalid_tag_command[] = {
// 	0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x7b,
// };

// static const uint8_t invalid_size_command[] = {
// 	0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x7b,
// };

// static const uint8_t start_auth_session_command[] = {
// 	0x80, 0x01, /* TPM_ST_NO_SESSIONS */
// 	0x00, 0x00, 0x00, 0x2b, /* command size */
// 	0x00, 0x00, 0x01, 0x76, /* TPM2_StartAuthSession */
// 	0x40, 0x00, 0x00, 0x07, /* tpmKey: TPM_RH_NULL */
// 	0x40, 0x00, 0x00, 0x07, /* bind: TPM_RH_NULL */
// 	0x00, 0x10, /* nonceCaller size */
// 	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
// 	0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x00, /* empty encryptedSalt */
// 	0x00, /* TPM_SE_HMAC */
// 	0x00, 0x10, /* symmetric: TPM_ALG_NULL */
// 	0x00, 0x0b, /* authHash: TPM_ALG_SHA256 */
// };

// static uint32_t read_be32(const uint8_t *bytes)
// {
// 	return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
// 	       ((uint32_t)bytes[2] << 8) | bytes[3];
// }

// static void build_flush_context_command(uint8_t *command, uint32_t handle)
// {
// 	static const uint8_t header[] = {
// 		0x80, 0x01, /* TPM_ST_NO_SESSIONS */
// 		0x00, 0x00, 0x00, 0x0e, /* command size */
// 		0x00, 0x00, 0x01, 0x65, /* TPM2_FlushContext */
// 	};

// 	memcpy(command, header, sizeof(header));
// 	command[10] = handle >> 24;
// 	command[11] = handle >> 16;
// 	command[12] = handle >> 8;
// 	command[13] = handle;
// }

// struct blocking_read_args {
// 	int fd;
// 	ssize_t result;
// 	uint8_t response[256];
// };

// struct shared_writer_args {
// 	int fd;
// 	ssize_t result;
// 	int error;
// };

// static void *blocking_read_thread(void *arg)
// {
// 	struct blocking_read_args *args = arg;

// 	args->result = read(args->fd, args->response, sizeof(args->response));
// 	return NULL;
// }

// static void *shared_writer_thread(void *arg)
// {
// 	struct shared_writer_args *args = arg;

// 	errno = 0;
// 	args->result =
// 		write(args->fd, get_random_command, sizeof(get_random_command));
// 	args->error = errno;
// 	return NULL;
// }

// static void tpm_signal_handler(int signal)
// {
// 	(void)signal;
// }

// static void exit_if_tpm_is_unavailable(void)
// {
// 	if (access(TPM_DEVICE, F_OK) == 0 && access(TPMRM_DEVICE, F_OK) == 0)
// 		return;

// 	if (errno == ENOENT || errno == ENODEV || errno == ENXIO) {
// 		fprintf(stderr,
// 			"TPM tests skipped: TPM devices are unavailable\n");
// 		exit(EXIT_SUCCESS);
// 	}

// 	perror("failed to inspect TPM devices");
// 	exit(EXIT_FAILURE);
// }

// FN_SETUP(check_tpm_availability)
// {
// 	exit_if_tpm_is_unavailable();
// }
// END_SETUP()

// FN_TEST(tpm_device_identity_and_mode)
// {
// 	for (size_t i = 0; i < sizeof(tpm_devices) / sizeof(tpm_devices[0]);
// 	     i++) {
// 		const struct tpm_device *device = &tpm_devices[i];
// 		struct stat stat_buf;

// 		TEST_RES(stat(device->path, &stat_buf),
// 			 S_ISCHR(stat_buf.st_mode) &&
// 				 stat_buf.st_rdev ==
// 					 makedev(TPM_MAJOR, device->minor) &&
// 				 (stat_buf.st_mode & 0777) == 0600);
// 	}
// }
// END_TEST()

// FN_TEST(tpm_idle_file_semantics)
// {
// 	for (size_t i = 0; i < sizeof(tpm_devices) / sizeof(tpm_devices[0]);
// 	     i++) {
// 		uint8_t byte;
// 		struct pollfd pfd;
// 		int fd = TEST_SUCC(
// 			open(tpm_devices[i].path, O_RDWR | O_NONBLOCK));

// 		pfd = (struct pollfd){
// 			.fd = fd,
// 			.events = POLLIN | POLLOUT,
// 		};
// 		TEST_RES(poll(&pfd, 1, 0), _ret == 1 && pfd.revents == POLLOUT);
// 		TEST_RES(read(fd, &byte, 0), _ret == 0);
// 		TEST_ERRNO(read(fd, &byte, 1), EAGAIN);
// 		TEST_ERRNO(lseek(fd, 0, SEEK_SET), ESPIPE);

// 		TEST_SUCC(close(fd));
// 	}
// }
// END_TEST()

// FN_TEST(tpm_rejects_invalid_command_sizes)
// {
// 	uint8_t short_command[TPM_HEADER_SIZE - 1] = { 0 };
// 	uint8_t *large_command =
// 		TEST_RES(calloc(1, TPM_MAX_COMMAND_SIZE + 1), _ret != NULL);

// 	for (size_t i = 0; i < sizeof(tpm_devices) / sizeof(tpm_devices[0]);
// 	     i++) {
// 		int fd = TEST_SUCC(
// 			open(tpm_devices[i].path, O_RDWR | O_NONBLOCK));

// 		TEST_ERRNO(write(fd, short_command, sizeof(short_command)),
// 			   EINVAL);
// 		TEST_ERRNO(write(fd, large_command, TPM_MAX_COMMAND_SIZE + 1),
// 			   EMSGSIZE);

// 		TEST_SUCC(close(fd));
// 	}

// 	free(large_command);
// }
// END_TEST()

// FN_TEST(tpm_file_descriptors_have_independent_responses)
// {
// 	for (size_t i = 0; i < sizeof(tpm_devices) / sizeof(tpm_devices[0]);
// 	     i++) {
// 		uint8_t response[2][256];
// 		int fds[2];

// 		fds[0] = TEST_SUCC(
// 			open(tpm_devices[i].path, O_RDWR | O_NONBLOCK));
// 		fds[1] = TEST_SUCC(
// 			open(tpm_devices[i].path, O_RDWR | O_NONBLOCK));

// 		for (size_t j = 0; j < 2; j++) {
// 			TEST_RES(write(fds[j], get_random_command,
// 				       sizeof(get_random_command)),
// 				 _ret == sizeof(get_random_command));
// 		}
// 		for (size_t j = 0; j < 2; j++) {
// 			TEST_RES(read(fds[j], response[j], sizeof(response[j])),
// 				 _ret >= TPM_HEADER_SIZE + sizeof(uint16_t));
// 			TEST_RES(read_be32(response[j] + 6), _ret == 0);
// 			TEST_SUCC(close(fds[j]));
// 		}
// 	}
// }
// END_TEST()

// FN_TEST(tpm_access_modes_are_enforced)
// {
// 	uint8_t byte = 0;

// 	for (size_t i = 0; i < sizeof(tpm_devices) / sizeof(tpm_devices[0]);
// 	     i++) {
// 		int fd = TEST_SUCC(open(tpm_devices[i].path, O_RDONLY));

// 		TEST_ERRNO(write(fd, get_random_command,
// 				 sizeof(get_random_command)),
// 			   EBADF);
// 		TEST_SUCC(close(fd));

// 		fd = TEST_SUCC(open(tpm_devices[i].path, O_WRONLY));
// 		TEST_ERRNO(read(fd, &byte, sizeof(byte)), EBADF);
// 		TEST_SUCC(close(fd));
// 	}
// }
// END_TEST()

// FN_TEST(tpm_rejects_malformed_headers)
// {
// 	for (size_t i = 0; i < sizeof(tpm_devices) / sizeof(tpm_devices[0]);
// 	     i++) {
// 		int fd = TEST_SUCC(
// 			open(tpm_devices[i].path, O_RDWR | O_NONBLOCK));

// 		TEST_ERRNO(write(fd, invalid_tag_command,
// 				 sizeof(invalid_tag_command)),
// 			   EIO);
// 		TEST_ERRNO(write(fd, invalid_size_command,
// 				 sizeof(invalid_size_command)),
// 			   EIO);
// 		TEST_SUCC(close(fd));
// 	}
// }
// END_TEST()

// FN_TEST(tpm_blocking_read_wakes_for_response)
// {
// 	for (size_t i = 0; i < sizeof(tpm_devices) / sizeof(tpm_devices[0]);
// 	     i++) {
// 		struct blocking_read_args args = { 0 };
// 		pthread_t thread;

// 		args.fd = TEST_SUCC(open(tpm_devices[i].path, O_RDWR));
// 		TEST_RES(pthread_create(&thread, NULL, blocking_read_thread,
// 					&args),
// 			 _ret == 0);
// 		TEST_SUCC(usleep(10000));
// 		TEST_RES(write(args.fd, get_random_command,
// 			       sizeof(get_random_command)),
// 			 _ret == sizeof(get_random_command));
// 		TEST_RES(pthread_join(thread, NULL), _ret == 0);
// 		TEST_RES(args.result,
// 			 _ret >= TPM_HEADER_SIZE + sizeof(uint16_t));
// 		TEST_RES(read_be32(args.response + 6), _ret == 0);
// 		TEST_SUCC(close(args.fd));
// 	}
// }
// END_TEST()

// FN_TEST(tpm_supports_dup_and_dynamic_nonblocking)
// {
// 	for (size_t i = 0; i < sizeof(tpm_devices) / sizeof(tpm_devices[0]);
// 	     i++) {
// 		uint8_t response[256];
// 		int fd = TEST_SUCC(open(tpm_devices[i].path, O_RDWR));
// 		int dup_fd = TEST_SUCC(dup(fd));

// 		TEST_SUCC(fcntl(fd, F_SETFL, O_NONBLOCK));
// 		TEST_ERRNO(read(dup_fd, response, sizeof(response)), EAGAIN);
// 		TEST_RES(write(fd, get_random_command,
// 			       sizeof(get_random_command)),
// 			 _ret == sizeof(get_random_command));
// 		TEST_RES(read(dup_fd, response, 5), _ret == 5);
// 		TEST_ERRNO(write(fd, get_random_command,
// 				 sizeof(get_random_command)),
// 			   EBUSY);
// 		TEST_RES(read(fd, response, sizeof(response)), _ret > 0);

// 		TEST_SUCC(close(dup_fd));
// 		TEST_SUCC(close(fd));
// 	}
// }
// END_TEST()

// FN_TEST(tpm_handles_zero_length_ioctl_and_bad_addresses)
// {
// 	void *bad_address = (void *)(uintptr_t)-1;

// 	for (size_t i = 0; i < sizeof(tpm_devices) / sizeof(tpm_devices[0]);
// 	     i++) {
// 		uint8_t response[256];
// 		int fd = TEST_SUCC(
// 			open(tpm_devices[i].path, O_RDWR | O_NONBLOCK));

// 		TEST_ERRNO(write(fd, get_random_command, 0), EINVAL);
// 		TEST_ERRNO(ioctl(fd, 0, NULL), ENOTTY);
// 		TEST_ERRNO(write(fd, bad_address, TPM_HEADER_SIZE), EFAULT);
// 		TEST_ERRNO(read(fd, bad_address, 1), EAGAIN);
// 		TEST_RES(write(fd, get_random_command,
// 			       sizeof(get_random_command)),
// 			 _ret == sizeof(get_random_command));
// 		TEST_ERRNO(read(fd, bad_address, 1), EFAULT);
// 		TEST_ERRNO(write(fd, get_random_command,
// 				 sizeof(get_random_command)),
// 			   EBUSY);
// 		TEST_RES(read(fd, response, sizeof(response)), _ret > 0);
// 		TEST_SUCC(close(fd));
// 	}
// }
// END_TEST()

// FN_TEST(tpm_same_file_serializes_writers)
// {
// 	for (size_t i = 0; i < sizeof(tpm_devices) / sizeof(tpm_devices[0]);
// 	     i++) {
// 		struct shared_writer_args args[2];
// 		pthread_t threads[2];
// 		uint8_t response[256];
// 		int fd = TEST_SUCC(
// 			open(tpm_devices[i].path, O_RDWR | O_NONBLOCK));

// 		for (size_t j = 0; j < 2; j++) {
// 			args[j] = (struct shared_writer_args){ .fd = fd };
// 			TEST_RES(pthread_create(&threads[j], NULL,
// 						shared_writer_thread, &args[j]),
// 				 _ret == 0);
// 		}
// 		for (size_t j = 0; j < 2; j++)
// 			TEST_RES(pthread_join(threads[j], NULL), _ret == 0);
// 		TEST_RES((args[0].result == sizeof(get_random_command)) +
// 				 (args[1].result == sizeof(get_random_command)),
// 			 _ret == 1);
// 		TEST_RES((args[0].result == -1 && args[0].error == EBUSY) +
// 				 (args[1].result == -1 &&
// 				  args[1].error == EBUSY),
// 			 _ret == 1);
// 		TEST_RES(read(fd, response, sizeof(response)), _ret > 0);
// 		TEST_SUCC(close(fd));
// 	}
// }
// END_TEST()

// FN_TEST(tpm_blocking_read_is_interruptible)
// {
// 	for (size_t i = 0; i < sizeof(tpm_devices) / sizeof(tpm_devices[0]);
// 	     i++) {
// 		int ready[2];
// 		int fd = TEST_SUCC(open(tpm_devices[i].path, O_RDWR));
// 		TEST_SUCC(pipe(ready));
// 		pid_t child = TEST_SUCC(fork());

// 		if (child == 0) {
// 			uint8_t response[32];
// 			struct sigaction action = {
// 				.sa_handler = tpm_signal_handler,
// 			};

// 			close(ready[0]);
// 			sigemptyset(&action.sa_mask);
// 			sigaction(SIGUSR1, &action, NULL);
// 			if (write(ready[1], "R", 1) != 1)
// 				_exit(EXIT_FAILURE);
// 			errno = 0;
// 			ssize_t result = read(fd, response, sizeof(response));
// 			_exit(result == -1 && errno == EINTR ? EXIT_SUCCESS :
// 							       EXIT_FAILURE);
// 		}

// 		TEST_SUCC(close(ready[1]));
// 		char byte;
// 		TEST_RES(read(ready[0], &byte, 1), _ret == 1);
// 		TEST_SUCC(kill(child, SIGUSR1));
// 		int status;
// 		TEST_RES(waitpid(child, &status, 0),
// 			 _ret == child && WIFEXITED(status) &&
// 				 WEXITSTATUS(status) == EXIT_SUCCESS);
// 		TEST_SUCC(close(ready[0]));
// 		TEST_SUCC(close(fd));
// 	}
// }
// END_TEST()

// FN_TEST(tpm_process_exit_cleans_sessions)
// {
// 	int handles[2];
// 	TEST_SUCC(pipe(handles));
// 	pid_t child = TEST_SUCC(fork());

// 	if (child == 0) {
// 		uint8_t response[256];
// 		close(handles[0]);
// 		int fd = open(TPM_DEVICE, O_RDWR | O_NONBLOCK);
// 		if (fd < 0 ||
// 		    write(fd, start_auth_session_command,
// 			  sizeof(start_auth_session_command)) !=
// 			    sizeof(start_auth_session_command) ||
// 		    read(fd, response, sizeof(response)) < 14)
// 			_exit(EXIT_FAILURE);
// 		uint32_t handle = read_be32(response + TPM_HEADER_SIZE);
// 		if (write(handles[1], &handle, sizeof(handle)) !=
// 		    sizeof(handle))
// 			_exit(EXIT_FAILURE);
// 		_exit(EXIT_SUCCESS);
// 	}

// 	TEST_SUCC(close(handles[1]));
// 	uint32_t handle;
// 	TEST_RES(read(handles[0], &handle, sizeof(handle)),
// 		 _ret == sizeof(handle));
// 	int status;
// 	TEST_RES(waitpid(child, &status, 0),
// 		 _ret == child && WIFEXITED(status) &&
// 			 WEXITSTATUS(status) == EXIT_SUCCESS);
// 	TEST_SUCC(close(handles[0]));

// 	uint8_t flush_command[14];
// 	uint8_t response[256];
// 	int fd = TEST_SUCC(open(TPM_DEVICE, O_RDWR | O_NONBLOCK));
// 	build_flush_context_command(flush_command, handle);
// 	TEST_RES(write(fd, flush_command, sizeof(flush_command)),
// 		 _ret == sizeof(flush_command));
// 	TEST_RES(read(fd, response, sizeof(response)), _ret >= TPM_HEADER_SIZE);
// 	TEST_RES(read_be32(response + 6), _ret != 0);
// 	TEST_SUCC(close(fd));
// }
// END_TEST()




// SPDX-License-Identifier: MPL-2.0

/* Regression tests for the raw TPM character device /dev/tpm0. */

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
#define TPM_MAJOR 10
#define TPM_MINOR 224
#define TPM_HEADER_SIZE 10
#define TPM_MAX_COMMAND_SIZE (64 * 1024)
#define TPM_ST_NO_SESSIONS 0x8001U
#define TPM_RANDOM_BYTES 32

static const uint8_t get_random_command[] = {
	0x80, 0x01, /* TPM_ST_NO_SESSIONS */
	0x00, 0x00,
	0x00, 0x0c, /* command size */
	0x00, 0x00,
	0x01, 0x7b, /* TPM2_GetRandom */
	0x00, TPM_RANDOM_BYTES, /* requested bytes */
};

static const uint8_t invalid_tag_command[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x7b,
};

static const uint8_t invalid_size_command[] = {
	0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x7b,
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

struct blocking_read_args {
	int fd;
	ssize_t result;
	uint8_t response[256];
};

struct shared_writer_args {
	int fd;
	ssize_t result;
	int error;
};

static void *blocking_read_thread(void *arg)
{
	struct blocking_read_args *args = arg;

	args->result = read(args->fd, args->response, sizeof(args->response));
	return NULL;
}

static void *shared_writer_thread(void *arg)
{
	struct shared_writer_args *args = arg;

	errno = 0;
	args->result =
		write(args->fd, get_random_command, sizeof(get_random_command));
	args->error = errno;
	return NULL;
}

static void tpm_signal_handler(int signal)
{
	(void)signal;
}

static void exit_if_tpm_is_unavailable(void)
{
	if (access(TPM_DEVICE, F_OK) == 0)
		return;

	if (errno == ENOENT || errno == ENODEV || errno == ENXIO) {
		fprintf(stderr,
			"TPM tests skipped: /dev/tpm0 is unavailable\n");
		exit(EXIT_SUCCESS);
	}

	perror("failed to inspect /dev/tpm0");
	exit(EXIT_FAILURE);
}

FN_SETUP(check_tpm_availability)
{
	exit_if_tpm_is_unavailable();
}
END_SETUP()

FN_TEST(tpm_device_identity_and_mode)
{
	{
		struct stat stat_buf;

		TEST_RES(stat(TPM_DEVICE, &stat_buf),
			 S_ISCHR(stat_buf.st_mode) &&
				 stat_buf.st_rdev ==
					 makedev(TPM_MAJOR, TPM_MINOR) &&
				 (stat_buf.st_mode & 0777) == 0600);
	}
}
END_TEST()

FN_TEST(tpm_idle_file_semantics)
{
	{
		uint8_t byte;
		struct pollfd pfd;
		int fd = TEST_SUCC(
			open(TPM_DEVICE, O_RDWR | O_NONBLOCK));

		pfd = (struct pollfd){
			.fd = fd,
			.events = POLLIN | POLLOUT,
		};
		TEST_RES(poll(&pfd, 1, 0), _ret == 1 && pfd.revents == POLLOUT);
		TEST_RES(read(fd, &byte, 0), _ret == 0);
		TEST_ERRNO(read(fd, &byte, 1), EAGAIN);
		TEST_ERRNO(lseek(fd, 0, SEEK_SET), ESPIPE);

		TEST_SUCC(close(fd));
	}
}
END_TEST()

FN_TEST(tpm_rejects_invalid_command_sizes)
{
	uint8_t short_command[TPM_HEADER_SIZE - 1] = { 0 };
	uint8_t *large_command =
		TEST_RES(calloc(1, TPM_MAX_COMMAND_SIZE + 1), _ret != NULL);

	{
		int fd = TEST_SUCC(
			open(TPM_DEVICE, O_RDWR | O_NONBLOCK));

		TEST_ERRNO(write(fd, short_command, sizeof(short_command)),
			   EINVAL);
		TEST_ERRNO(write(fd, large_command, TPM_MAX_COMMAND_SIZE + 1),
			   EMSGSIZE);

		TEST_SUCC(close(fd));
	}

	free(large_command);
}
END_TEST()

FN_TEST(tpm_file_descriptors_have_independent_responses)
{
	{
		uint8_t response[2][256];
		int fds[2];

		fds[0] = TEST_SUCC(
			open(TPM_DEVICE, O_RDWR | O_NONBLOCK));
		fds[1] = TEST_SUCC(
			open(TPM_DEVICE, O_RDWR | O_NONBLOCK));

		for (size_t j = 0; j < 2; j++) {
			TEST_RES(write(fds[j], get_random_command,
				       sizeof(get_random_command)),
				 _ret == sizeof(get_random_command));
		}
		for (size_t j = 0; j < 2; j++) {
			TEST_RES(read(fds[j], response[j], sizeof(response[j])),
				 _ret >= TPM_HEADER_SIZE + sizeof(uint16_t));
			TEST_RES(read_be32(response[j] + 6), _ret == 0);
			TEST_SUCC(close(fds[j]));
		}
	}
}
END_TEST()

FN_TEST(tpm_access_modes_are_enforced)
{
	uint8_t byte = 0;

	{
		int fd = TEST_SUCC(open(TPM_DEVICE, O_RDONLY));

		TEST_ERRNO(write(fd, get_random_command,
				 sizeof(get_random_command)),
			   EBADF);
		TEST_SUCC(close(fd));

		fd = TEST_SUCC(open(TPM_DEVICE, O_WRONLY));
		TEST_ERRNO(read(fd, &byte, sizeof(byte)), EBADF);
		TEST_SUCC(close(fd));
	}
}
END_TEST()

FN_TEST(tpm_rejects_malformed_headers)
{
	{
		int fd = TEST_SUCC(
			open(TPM_DEVICE, O_RDWR | O_NONBLOCK));

		TEST_ERRNO(write(fd, invalid_tag_command,
				 sizeof(invalid_tag_command)),
			   EIO);
		TEST_ERRNO(write(fd, invalid_size_command,
				 sizeof(invalid_size_command)),
			   EIO);
		TEST_SUCC(close(fd));
	}
}
END_TEST()

FN_TEST(tpm_blocking_read_wakes_for_response)
{
	{
		struct blocking_read_args args = { 0 };
		pthread_t thread;

		args.fd = TEST_SUCC(open(TPM_DEVICE, O_RDWR));
		TEST_RES(pthread_create(&thread, NULL, blocking_read_thread,
					&args),
			 _ret == 0);
		TEST_SUCC(usleep(10000));
		TEST_RES(write(args.fd, get_random_command,
			       sizeof(get_random_command)),
			 _ret == sizeof(get_random_command));
		TEST_RES(pthread_join(thread, NULL), _ret == 0);
		TEST_RES(args.result,
			 _ret >= TPM_HEADER_SIZE + sizeof(uint16_t));
		TEST_RES(read_be32(args.response + 6), _ret == 0);
		TEST_SUCC(close(args.fd));
	}
}
END_TEST()

FN_TEST(tpm_supports_dup_and_dynamic_nonblocking)
{
	{
		uint8_t response[256];
		int fd = TEST_SUCC(open(TPM_DEVICE, O_RDWR));
		int dup_fd = TEST_SUCC(dup(fd));

		TEST_SUCC(fcntl(fd, F_SETFL, O_NONBLOCK));
		TEST_ERRNO(read(dup_fd, response, sizeof(response)), EAGAIN);
		TEST_RES(write(fd, get_random_command,
			       sizeof(get_random_command)),
			 _ret == sizeof(get_random_command));
		TEST_RES(read(dup_fd, response, 5), _ret == 5);
		TEST_ERRNO(write(fd, get_random_command,
				 sizeof(get_random_command)),
			   EBUSY);
		TEST_RES(read(fd, response, sizeof(response)), _ret > 0);

		TEST_SUCC(close(dup_fd));
		TEST_SUCC(close(fd));
	}
}
END_TEST()

FN_TEST(tpm_handles_zero_length_ioctl_and_bad_addresses)
{
	void *bad_address = (void *)(uintptr_t)-1;

	{
		uint8_t response[256];
		int fd = TEST_SUCC(
			open(TPM_DEVICE, O_RDWR | O_NONBLOCK));

		TEST_ERRNO(write(fd, get_random_command, 0), EINVAL);
		TEST_ERRNO(ioctl(fd, 0, NULL), ENOTTY);
		TEST_ERRNO(write(fd, bad_address, TPM_HEADER_SIZE), EFAULT);
		TEST_ERRNO(read(fd, bad_address, 1), EAGAIN);
		TEST_RES(write(fd, get_random_command,
			       sizeof(get_random_command)),
			 _ret == sizeof(get_random_command));
		TEST_ERRNO(read(fd, bad_address, 1), EFAULT);
		TEST_ERRNO(write(fd, get_random_command,
				 sizeof(get_random_command)),
			   EBUSY);
		TEST_RES(read(fd, response, sizeof(response)), _ret > 0);
		TEST_SUCC(close(fd));
	}
}
END_TEST()

FN_TEST(tpm_same_file_serializes_writers)
{
	{
		struct shared_writer_args args[2];
		pthread_t threads[2];
		uint8_t response[256];
		int fd = TEST_SUCC(
			open(TPM_DEVICE, O_RDWR | O_NONBLOCK));

		for (size_t j = 0; j < 2; j++) {
			args[j] = (struct shared_writer_args){ .fd = fd };
			TEST_RES(pthread_create(&threads[j], NULL,
						shared_writer_thread, &args[j]),
				 _ret == 0);
		}
		for (size_t j = 0; j < 2; j++)
			TEST_RES(pthread_join(threads[j], NULL), _ret == 0);
		TEST_RES((args[0].result == sizeof(get_random_command)) +
				 (args[1].result == sizeof(get_random_command)),
			 _ret == 1);
		TEST_RES((args[0].result == -1 && args[0].error == EBUSY) +
				 (args[1].result == -1 &&
				  args[1].error == EBUSY),
			 _ret == 1);
		TEST_RES(read(fd, response, sizeof(response)), _ret > 0);
		TEST_SUCC(close(fd));
	}
}
END_TEST()

FN_TEST(tpm_blocking_read_is_interruptible)
{
	{
		int ready[2];
		int fd = TEST_SUCC(open(TPM_DEVICE, O_RDWR));
		TEST_SUCC(pipe(ready));
		pid_t child = TEST_SUCC(fork());

		if (child == 0) {
			uint8_t response[32];
			struct sigaction action = {
				.sa_handler = tpm_signal_handler,
			};

			close(ready[0]);
			sigemptyset(&action.sa_mask);
			sigaction(SIGUSR1, &action, NULL);
			if (write(ready[1], "R", 1) != 1)
				_exit(EXIT_FAILURE);
			errno = 0;
			ssize_t result = read(fd, response, sizeof(response));
			_exit(result == -1 && errno == EINTR ? EXIT_SUCCESS :
							       EXIT_FAILURE);
		}

		TEST_SUCC(close(ready[1]));
		char byte;
		TEST_RES(read(ready[0], &byte, 1), _ret == 1);
		TEST_SUCC(kill(child, SIGUSR1));
		int status;
		TEST_RES(waitpid(child, &status, 0),
			 _ret == child && WIFEXITED(status) &&
				 WEXITSTATUS(status) == EXIT_SUCCESS);
		TEST_SUCC(close(ready[0]));
		TEST_SUCC(close(fd));
	}
}
END_TEST()

FN_TEST(tpm_process_exit_cleans_sessions)
{
	int handles[2];
	TEST_SUCC(pipe(handles));
	pid_t child = TEST_SUCC(fork());

	if (child == 0) {
		uint8_t response[256];
		close(handles[0]);
		int fd = open(TPM_DEVICE, O_RDWR | O_NONBLOCK);
		if (fd < 0 ||
		    write(fd, start_auth_session_command,
			  sizeof(start_auth_session_command)) !=
			    sizeof(start_auth_session_command) ||
		    read(fd, response, sizeof(response)) < 14)
			_exit(EXIT_FAILURE);
		uint32_t handle = read_be32(response + TPM_HEADER_SIZE);
		if (write(handles[1], &handle, sizeof(handle)) !=
		    sizeof(handle))
			_exit(EXIT_FAILURE);
		_exit(EXIT_SUCCESS);
	}

	TEST_SUCC(close(handles[1]));
	uint32_t handle;
	TEST_RES(read(handles[0], &handle, sizeof(handle)),
		 _ret == sizeof(handle));
	int status;
	TEST_RES(waitpid(child, &status, 0),
		 _ret == child && WIFEXITED(status) &&
			 WEXITSTATUS(status) == EXIT_SUCCESS);
	TEST_SUCC(close(handles[0]));

	uint8_t flush_command[14];
	uint8_t response[256];
	int fd = TEST_SUCC(open(TPM_DEVICE, O_RDWR | O_NONBLOCK));
	build_flush_context_command(flush_command, handle);
	TEST_RES(write(fd, flush_command, sizeof(flush_command)),
		 _ret == sizeof(flush_command));
	TEST_RES(read(fd, response, sizeof(response)), _ret >= TPM_HEADER_SIZE);
	TEST_RES(read_be32(response + 6), _ret != 0);
	TEST_SUCC(close(fd));
}
END_TEST()
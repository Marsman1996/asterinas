// SPDX-License-Identifier: MPL-2.0
/*
 * TPM character-device lifecycle regression tests.
 *
 * Purpose:
 *   Exercise the /dev/tpm0 and /dev/tpmrm0 lifecycle paths affected by
 *   async command work, response timers, timeout work, partial reads,
 *   accepted new writes, and close/reopen synchronization.
 *
 * This file is intentionally standalone so the same binary can be run on
 * Linux and Asterinas for differential regression testing.
 *
 * Build:
 *   cc -O2 -Wall -Wextra -pthread tpm_lifecycle_regression.c -o tpm_lifecycle_regression
 *
 * Run:
 *   ./tpm_lifecycle_regression
 *   ./tpm_lifecycle_regression --loops 500
 *   ./tpm_lifecycle_regression --slow
 *
 * Notes:
 *   --slow adds the 120-second response-expiration test and therefore takes
 *   more than two minutes.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define TPM_DEVICE "/dev/tpm0"
#define TPMRM_DEVICE "/dev/tpmrm0"

#define TPM_HEADER_SIZE 10
#define RESPONSE_BUF_SIZE 4096

static const uint8_t get_random_command[] = {
	0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x7b, 0x00, 0x20,
};

static const uint8_t hash_sequence_start_command[] = {
	0x80, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x00,
	0x00, 0x01, 0x86, 0x00, 0x00, 0x00, 0x0b,
};

static unsigned int tests_passed;
static unsigned int tests_failed;
static unsigned int tests_skipped;

static uint32_t read_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void pass(const char *name)
{
	tests_passed++;
	printf("[PASS] %s\n", name);
}

static void fail_errno(const char *name, const char *what)
{
	int e = errno;
	tests_failed++;
	fprintf(stderr, "[FAIL] %s: %s: errno=%d (%s)\n", name, what, e,
		strerror(e));
}

static void fail_msg(const char *name, const char *msg)
{
	tests_failed++;
	fprintf(stderr, "[FAIL] %s: %s\n", name, msg);
}

static void skip(const char *name, const char *msg)
{
	tests_skipped++;
	printf("[SKIP] %s: %s\n", name, msg);
}

static int device_exists(const char *path)
{
	return access(path, F_OK) == 0;
}

static int wait_for_events(int fd, short events, int timeout_ms,
			   short *revents_out)
{
	struct pollfd pfd = {
		.fd = fd,
		.events = events,
		.revents = 0,
	};

	int ret;
	do {
		ret = poll(&pfd, 1, timeout_ms);
	} while (ret < 0 && errno == EINTR);

	if (revents_out)
		*revents_out = pfd.revents;

	return ret;
}

static int wait_readable(int fd, int timeout_ms)
{
	short revents = 0;
	int ret = wait_for_events(fd, POLLIN, timeout_ms, &revents);

	if (ret <= 0)
		return ret;

	if (!(revents & POLLIN)) {
		errno = EIO;
		return -1;
	}

	return 1;
}

static int validate_success_response(const uint8_t *buf, ssize_t len)
{
	if (len < TPM_HEADER_SIZE)
		return -1;

	if (read_be32(buf + 2) != (uint32_t)len)
		return -1;

	if (read_be32(buf + 6) != 0)
		return -1;

	return 0;
}

static ssize_t read_response(int fd, uint8_t *buf, size_t cap, int timeout_ms)
{
	if (wait_readable(fd, timeout_ms) != 1)
		return -1;

	ssize_t n;
	do {
		n = read(fd, buf, cap);
	} while (n < 0 && errno == EINTR);

	return n;
}

static int write_command(int fd, const void *buf, size_t len)
{
	ssize_t n;
	do {
		n = write(fd, buf, len);
	} while (n < 0 && errno == EINTR);

	if (n < 0)
		return -1;

	if ((size_t)n != len) {
		errno = EIO;
		return -1;
	}

	return 0;
}

/* A write after a partial read must retire the old response timer safely. */
static void test_partial_read_then_new_write(const char *path, const char *name)
{
	uint8_t first[5];
	uint8_t second[RESPONSE_BUF_SIZE];

	if (!device_exists(path)) {
		skip(name, "device is unavailable");
		return;
	}

	int fd = open(path, O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		fail_errno(name, "open");
		return;
	}

	if (write_command(fd, get_random_command, sizeof(get_random_command)) <
	    0) {
		fail_errno(name, "first write");
		close(fd);
		return;
	}

	if (wait_readable(fd, 10000) != 1) {
		fail_errno(name, "waiting for first response");
		close(fd);
		return;
	}

	ssize_t n;
	do {
		n = read(fd, first, sizeof(first));
	} while (n < 0 && errno == EINTR);

	if (n != (ssize_t)sizeof(first)) {
		if (n < 0)
			fail_errno(name, "partial read");
		else
			fail_msg(name, "partial read did not return 5 bytes");
		close(fd);
		return;
	}

	if (write_command(fd, get_random_command, sizeof(get_random_command)) <
	    0) {
		fail_errno(name, "write after partial read");
		close(fd);
		return;
	}

	ssize_t second_len = read_response(fd, second, sizeof(second), 10000);
	if (second_len < 0) {
		fail_errno(name, "reading new response");
		close(fd);
		return;
	}

	if (validate_success_response(second, second_len) < 0) {
		fail_msg(
			name,
			"new response is malformed or has a nonzero TPM return code");
		close(fd);
		return;
	}

	close(fd);
	pass(name);
}

/* Repeatedly widen the race between unfinished async work and close/reopen. */
static void test_raw_async_close_reopen(unsigned int loops)
{
	const char *name = "tpm0 async close -> immediate reopen";

	if (!device_exists(TPM_DEVICE)) {
		skip(name, "device is unavailable");
		return;
	}

	for (unsigned int i = 0; i < loops; i++) {
		int fd = open(TPM_DEVICE, O_RDWR | O_NONBLOCK);
		if (fd < 0) {
			fail_errno(name, "initial open");
			return;
		}

		if (write_command(fd, get_random_command,
				  sizeof(get_random_command)) < 0) {
			fail_errno(name, "async GetRandom write");
			close(fd);
			return;
		}

		if (close(fd) < 0) {
			fail_errno(name, "close after async write");
			return;
		}

		fd = open(TPM_DEVICE, O_RDWR | O_NONBLOCK);
		if (fd < 0) {
			fprintf(stderr,
				"[FAIL] %s: iteration=%u immediate reopen: errno=%d (%s)\n",
				name, i, errno, strerror(errno));
			tests_failed++;
			return;
		}

		if (close(fd) < 0) {
			fail_errno(name, "close reopened fd");
			return;
		}
	}

	pass(name);
}

/* RM close must drain async work and clean its resource space before return. */
static void test_rm_async_close_resource_stress(unsigned int loops)
{
	const char *name = "tpmrm0 async resource close stress";

	if (!device_exists(TPMRM_DEVICE)) {
		skip(name, "device is unavailable");
		return;
	}

	for (unsigned int i = 0; i < loops; i++) {
		int fd = open(TPMRM_DEVICE, O_RDWR | O_NONBLOCK);
		if (fd < 0) {
			fail_errno(name, "open");
			return;
		}

		if (write_command(fd, hash_sequence_start_command,
				  sizeof(hash_sequence_start_command)) < 0) {
			fprintf(stderr,
				"[FAIL] %s: iteration=%u HashSequenceStart write: errno=%d (%s)\n",
				name, i, errno, strerror(errno));
			tests_failed++;
			close(fd);
			return;
		}

		if (close(fd) < 0) {
			fail_errno(
				name,
				"close after async resource-creating command");
			return;
		}
	}

	int fd = open(TPMRM_DEVICE, O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		fail_errno(name, "final open");
		return;
	}

	if (write_command(fd, get_random_command, sizeof(get_random_command)) <
	    0) {
		fail_errno(name, "final GetRandom write");
		close(fd);
		return;
	}

	uint8_t response[RESPONSE_BUF_SIZE];
	ssize_t n = read_response(fd, response, sizeof(response), 10000);
	if (n < 0) {
		fail_errno(name, "final GetRandom read");
		close(fd);
		return;
	}

	if (validate_success_response(response, n) < 0) {
		fail_msg(name, "final tpmrm0 response is invalid");
		close(fd);
		return;
	}

	close(fd);
	pass(name);
}

/* Write immediately after a full read; stale timeout work must not clear it. */
static void test_full_read_then_immediate_write(const char *path,
						const char *name,
						unsigned int loops)
{
	if (!device_exists(path)) {
		skip(name, "device is unavailable");
		return;
	}

	int fd = open(path, O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		fail_errno(name, "open");
		return;
	}

	for (unsigned int i = 0; i < loops; i++) {
		uint8_t response[RESPONSE_BUF_SIZE];

		if (write_command(fd, get_random_command,
				  sizeof(get_random_command)) < 0) {
			fprintf(stderr,
				"[FAIL] %s: iteration=%u write: errno=%d (%s)\n",
				name, i, errno, strerror(errno));
			tests_failed++;
			close(fd);
			return;
		}

		ssize_t n =
			read_response(fd, response, sizeof(response), 10000);
		if (n < 0) {
			fprintf(stderr,
				"[FAIL] %s: iteration=%u read: errno=%d (%s)\n",
				name, i, errno, strerror(errno));
			tests_failed++;
			close(fd);
			return;
		}

		if (validate_success_response(response, n) < 0) {
			fprintf(stderr,
				"[FAIL] %s: iteration=%u invalid TPM response\n",
				name, i);
			tests_failed++;
			close(fd);
			return;
		}
	}

	close(fd);
	pass(name);
}

/* Optional slow test: wait for response expiry, then verify writability. */
static void test_response_timeout_slow(const char *path, const char *name)
{
	if (!device_exists(path)) {
		skip(name, "device is unavailable");
		return;
	}

	int fd = open(path, O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		fail_errno(name, "open");
		return;
	}

	if (write_command(fd, get_random_command, sizeof(get_random_command)) <
	    0) {
		fail_errno(name, "write");
		close(fd);
		return;
	}

	if (wait_readable(fd, 10000) != 1) {
		fail_errno(name, "waiting for response before timeout");
		close(fd);
		return;
	}

	struct timespec req = {
		.tv_sec = 122,
		.tv_nsec = 0,
	};

	while (nanosleep(&req, &req) < 0 && errno == EINTR)
		;

	short revents = 0;
	int ret = wait_for_events(fd, POLLIN | POLLOUT, 0, &revents);
	if (ret < 0) {
		fail_errno(name, "poll after 122 seconds");
		close(fd);
		return;
	}

	if (revents & POLLIN) {
		fail_msg(
			name,
			"response is still readable after the 120-second expiration window");
		close(fd);
		return;
	}

	if (!(revents & POLLOUT)) {
		fail_msg(name,
			 "device is not writable after response expiration");
		close(fd);
		return;
	}

	if (write_command(fd, get_random_command, sizeof(get_random_command)) <
	    0) {
		fail_errno(name, "write after response timeout");
		close(fd);
		return;
	}

	uint8_t response[RESPONSE_BUF_SIZE];
	ssize_t n = read_response(fd, response, sizeof(response), 10000);
	if (n < 0) {
		fail_errno(name, "read after response timeout");
		close(fd);
		return;
	}

	if (validate_success_response(response, n) < 0) {
		fail_msg(name, "response after timeout is invalid");
		close(fd);
		return;
	}

	close(fd);
	pass(name);
}

static unsigned int parse_loops(int argc, char **argv)
{
	for (int i = 1; i + 1 < argc; i++) {
		if (strcmp(argv[i], "--loops") == 0) {
			char *end = NULL;
			unsigned long value = strtoul(argv[i + 1], &end, 10);
			if (end && *end == '\0' && value > 0 && value <= 100000)
				return (unsigned int)value;
		}
	}

	return 200;
}

static int has_arg(int argc, char **argv, const char *arg)
{
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], arg) == 0)
			return 1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	unsigned int loops = parse_loops(argc, argv);
	int slow = has_arg(argc, argv, "--slow");

	printf("TPM lifecycle regression tests\n");
	printf("stress loops: %u\n", loops);
	printf("slow timeout tests: %s\n\n", slow ? "enabled" : "disabled");

	test_partial_read_then_new_write(
		TPM_DEVICE, "tpm0 partial read -> new write -> new response");

	test_partial_read_then_new_write(
		TPMRM_DEVICE,
		"tpmrm0 partial read -> new write -> new response");

	test_raw_async_close_reopen(loops);
	test_rm_async_close_resource_stress(loops);

	test_full_read_then_immediate_write(
		TPM_DEVICE, "tpm0 full read -> immediate next command", loops);

	test_full_read_then_immediate_write(
		TPMRM_DEVICE, "tpmrm0 full read -> immediate next command",
		loops);

	if (slow) {
		test_response_timeout_slow(
			TPM_DEVICE, "tpm0 120-second response expiration");

		test_response_timeout_slow(
			TPMRM_DEVICE, "tpmrm0 120-second response expiration");
	}

	printf("\nSummary: %u passed, %u failed, %u skipped\n", tests_passed,
	       tests_failed, tests_skipped);

	return tests_failed ? EXIT_FAILURE : EXIT_SUCCESS;
}

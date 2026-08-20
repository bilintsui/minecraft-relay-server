/*
 * hosts.c: Tests for the local static host-name table
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* section: headers (project) */
#include "hosts.h"

/* section: defines */
/* assertion */
#define CHECK(condition, message) \
	do { \
		if (!(condition)) { \
			fprintf(stderr, "%s (errno=%d)\n", message, errno); \
			goto cleanup; \
		} \
	} while (0)

/* section: functions (local) */
static bool hosts_address_equal(const net_addr *address, sa_family_t family, const char *expected) {
	if (address == NULL || address->family != family || expected == NULL) {
		return false;
	}
	uint8_t expected_address[16] = { 0 };
	if (inet_pton(family, expected, expected_address) != 1) {
		return false;
	}
	size_t address_size = family == AF_INET ? sizeof(uint32_t) : sizeof(uint8_t) * 16;
	return memcmp(&address->addr, expected_address, address_size) == 0;
}

static bool hosts_test_arguments(void) {
	int test_result = false;
	hosts_address_result result = { 0 };
	hosts_table *table = NULL;
	size_t malformed_line_count = 0;
	CHECK(hosts_table_load(NULL, &table, &malformed_line_count) == HOSTS_LOAD_BAD_ARGUMENT && table == NULL, "NULL hosts filename was accepted");
	CHECK(hosts_table_load("", &table, &malformed_line_count) == HOSTS_LOAD_BAD_ARGUMENT && table == NULL, "empty hosts filename was accepted");
	CHECK(hosts_table_lookup(NULL, "localhost", &result) == HOSTS_LOOKUP_BAD_ARGUMENT, "NULL hosts table was accepted");
	hosts_address_result_destroy(NULL);
	hosts_table_destroy(NULL);
	test_result = true;

cleanup:
	hosts_address_result_destroy(&result);
	hosts_table_destroy(table);
	return test_result;
}

static bool hosts_test_file_error(const char *missing_filename) {
	int test_result = false;
	hosts_address_result result = { 0 };
	hosts_table *table = NULL;
	size_t malformed_line_count = 1;
	CHECK(hosts_table_load(missing_filename, &table, &malformed_line_count) == HOSTS_LOAD_FILE_ERROR && table != NULL, "missing hosts file did not retain the fallback table");
	CHECK(malformed_line_count == 0, "missing hosts file reported malformed lines");
	CHECK(hosts_table_lookup(table, "localhost", &result) == HOSTS_LOOKUP_OK, "fallback localhost lookup failed");
	CHECK(result.address_count == 2 && hosts_address_equal(&result.addresses[0], AF_INET, "127.0.0.1") && hosts_address_equal(&result.addresses[1], AF_INET6, "::1"),
		"fallback localhost addresses are invalid");
	test_result = true;

cleanup:
	hosts_address_result_destroy(&result);
	hosts_table_destroy(table);
	return test_result;
}

static bool hosts_test_records(const char *filename) {
	int test_result = false;
	hosts_address_result result = { 0 };
	hosts_table *table = NULL;
	size_t malformed_line_count = 0;
	CHECK(hosts_table_load(filename, &table, &malformed_line_count) == HOSTS_LOAD_OK && table != NULL, "hosts fixture could not be loaded");
	CHECK(malformed_line_count == 3, "hosts fixture returned the wrong malformed line count");
	CHECK(hosts_table_lookup(table, "EXAMPLE.COM.", &result) == HOSTS_LOOKUP_OK, "canonical hosts name was not normalized");
	CHECK(result.address_count == 2 && hosts_address_equal(&result.addresses[0], AF_INET, "192.0.2.10") && hosts_address_equal(&result.addresses[1], AF_INET6, "2001:db8::10"),
		"canonical hosts lookup did not preserve file order");
	hosts_address_result_destroy(&result);
	CHECK(hosts_table_lookup(table, "alias.example", &result) == HOSTS_LOOKUP_OK && result.address_count == 1 && hosts_address_equal(&result.addresses[0], AF_INET, "192.0.2.10"),
		"hosts alias lookup failed");
	hosts_address_result_destroy(&result);
	CHECK(hosts_table_lookup(table, "localhost.", &result) == HOSTS_LOOKUP_OK, "localhost lookup failed");
	CHECK(result.address_count == 2 && hosts_address_equal(&result.addresses[0], AF_INET, "127.0.1.1") && hosts_address_equal(&result.addresses[1], AF_INET6, "::1"),
		"localhost fallback did not preserve the file record and add the missing family");
	hosts_address_result_destroy(&result);
	CHECK(hosts_table_lookup(table, "remote-alias", &result) == HOSTS_LOOKUP_OK && result.address_count == 1 && hosts_address_equal(&result.addresses[0], AF_INET, "192.0.2.99"),
		"a rejected non-loopback localhost alias discarded another valid alias");
	hosts_address_result_destroy(&result);
	CHECK(hosts_table_lookup(table, "missing.example", &result) == HOSTS_LOOKUP_NOT_FOUND && result.address_count == 0, "missing hosts name returned an address");
	test_result = true;

cleanup:
	hosts_address_result_destroy(&result);
	hosts_table_destroy(table);
	return test_result;
}

static int hosts_write_fixture(const char *filename) {
	static const char fixture[] =
		"# local static hosts fixture\n"
		"192.0.2.10 Example.COM alias.example.\n"
		"2001:db8::10 example.com\n"
		"192.0.2.10 example.com\n"
		"127.0.1.1 LOCALHOST localhost-alias\n"
		"192.0.2.99 localhost remote-alias\n"
		"invalid-address invalid.example\n"
		"192.0.2.11\n";
	int fd = open(filename, O_CREAT | O_EXCL | O_WRONLY, 0600);
	if (fd == -1) {
		return -1;
	}
	ssize_t fixture_size = (ssize_t)(sizeof(fixture) - 1);
	ssize_t written = write(fd, fixture, (size_t)fixture_size);
	int saved_errno = errno;
	if (close(fd) == -1 && written == fixture_size) {
		return -1;
	}
	errno = saved_errno;
	return written == fixture_size ? 0 : -1;
}

/* section: functions (entry point) */
int main(void) {
	int test_result = EXIT_FAILURE;
	char directory[] = "/tmp/mcrelay-hosts-XXXXXX";
	char filename[256] = { 0 };
	char missing_filename[256] = { 0 };
	CHECK(mkdtemp(directory) != NULL, "cannot create hosts test directory");
	CHECK(snprintf(filename, sizeof(filename), "%s/hosts", directory) > 0, "cannot create hosts fixture path");
	CHECK(snprintf(missing_filename, sizeof(missing_filename), "%s/missing", directory) > 0, "cannot create missing hosts path");
	CHECK(hosts_write_fixture(filename) == 0, "cannot write hosts fixture");
	CHECK(hosts_test_arguments(), "hosts argument tests failed");
	CHECK(hosts_test_file_error(missing_filename), "hosts file-error tests failed");
	CHECK(hosts_test_records(filename), "hosts record tests failed");
	test_result = EXIT_SUCCESS;

cleanup:
	if (filename[0] != '\0') {
		unlink(filename);
	}
	rmdir(directory);
	return test_result;
}

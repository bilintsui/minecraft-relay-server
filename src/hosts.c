/*
 * hosts.c: Local static host-name table
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* section: headers (self) */
#include "hosts.h"

/* section: defines */
/* input limits */
#define HOSTS_LINE_SIZE	8192
#define HOSTS_NAME_SIZE	256
#define HOSTS_RECORD_LIMIT	16384

/* section: types */
typedef struct {
	net_addr address;
	char name[HOSTS_NAME_SIZE];
} hosts_record;
typedef enum {
	HOSTS_RECORD_ADD_OK,
	HOSTS_RECORD_ADD_LIMIT,
	HOSTS_RECORD_ADD_MEMORY
} hosts_record_add_status;
struct hosts_table {
	size_t record_capacity;
	size_t record_count;
	hosts_record *records;
};

/* section: functions (local) */
static bool hosts_address_equal(const net_addr *left, const net_addr *right) {
	if (left->family != right->family) {
		return false;
	}
	if (left->family == AF_INET) {
		return left->addr.v4 == right->addr.v4;
	}
	return left->family == AF_INET6 && memcmp(left->addr.v6, right->addr.v6, sizeof(left->addr.v6)) == 0;
}

static bool hosts_address_is_loopback(const net_addr *address) {
	if (address->family == AF_INET) {
		const uint8_t *bytes = (const uint8_t *)&address->addr.v4;
		return bytes[0] == 127;
	}
	if (address->family == AF_INET6) {
		static const uint8_t loopback[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
		return memcmp(address->addr.v6, loopback, sizeof(loopback)) == 0;
	}
	return false;
}

static bool hosts_name_normalize(const char *source, char *target, size_t target_size) {
	if (source == NULL || target == NULL || target_size == 0) {
		return false;
	}
	size_t source_size = strlen(source);
	if (source_size > 0 && source[source_size - 1] == '.') {
		source_size--;
	}
	if (source_size == 0 || source_size >= target_size || (source_size > 0 && source[source_size - 1] == '.')) {
		return false;
	}
	for (size_t source_index = 0; source_index < source_size; source_index++) {
		unsigned char source_character = (unsigned char)source[source_index];
		if (isspace(source_character) || source_character == '#') {
			return false;
		}
		target[source_index] = source_character >= 'A' && source_character <= 'Z' ? (char)(source_character - 'A' + 'a') : (char)source_character;
	}
	target[source_size] = '\0';
	return true;
}

static hosts_record_add_status hosts_record_add(hosts_table *table, const char *name, const net_addr *address) {
	for (size_t record_index = 0; record_index < table->record_count; record_index++) {
		if (strcmp(table->records[record_index].name, name) == 0 && hosts_address_equal(&table->records[record_index].address, address)) {
			return HOSTS_RECORD_ADD_OK;
		}
	}
	if (table->record_count == HOSTS_RECORD_LIMIT) {
		return HOSTS_RECORD_ADD_LIMIT;
	}
	if (table->record_count == table->record_capacity) {
		size_t record_capacity = table->record_capacity == 0 ? 16 : table->record_capacity * 2;
		if (record_capacity > HOSTS_RECORD_LIMIT) {
			record_capacity = HOSTS_RECORD_LIMIT;
		}
		hosts_record *records = realloc(table->records, record_capacity * sizeof(*records));
		if (records == NULL) {
			return HOSTS_RECORD_ADD_MEMORY;
		}
		table->record_capacity = record_capacity;
		table->records = records;
	}
	hosts_record *record = &table->records[table->record_count++];
	record->address = *address;
	snprintf(record->name, sizeof(record->name), "%s", name);
	return HOSTS_RECORD_ADD_OK;
}

static bool hosts_result_empty(const hosts_address_result *result) {
	return result->addresses == NULL && result->address_count == 0;
}

static hosts_record_add_status hosts_table_fallback_add(hosts_table *table) {
	bool have_ipv4 = false;
	bool have_ipv6 = false;
	for (size_t record_index = 0; record_index < table->record_count; record_index++) {
		const hosts_record *record = &table->records[record_index];
		if (strcmp(record->name, "localhost") != 0 || !hosts_address_is_loopback(&record->address)) {
			continue;
		}
		have_ipv4 = have_ipv4 || record->address.family == AF_INET;
		have_ipv6 = have_ipv6 || record->address.family == AF_INET6;
	}
	if (!have_ipv4) {
		net_addr address = net_addr_parse("127.0.0.1");
		hosts_record_add_status status = hosts_record_add(table, "localhost", &address);
		if (status != HOSTS_RECORD_ADD_OK) {
			return status;
		}
	}
	if (!have_ipv6) {
		net_addr address = net_addr_parse("::1");
		return hosts_record_add(table, "localhost", &address);
	}
	return HOSTS_RECORD_ADD_OK;
}

static hosts_record_add_status hosts_table_parse_line(hosts_table *table, char *line, size_t *malformed_line_count) {
	char *comment = strchr(line, '#');
	if (comment != NULL) {
		*comment = '\0';
	}
	char *cursor = line;
	while (isspace((unsigned char)*cursor)) {
		cursor++;
	}
	if (*cursor == '\0') {
		return HOSTS_RECORD_ADD_OK;
	}
	char *address_text = cursor;
	while (*cursor != '\0' && !isspace((unsigned char)*cursor)) {
		cursor++;
	}
	if (*cursor != '\0') {
		*cursor = '\0';
		cursor++;
	}
	net_addr address = net_addr_parse(address_text);
	if (address.family == 0) {
		(*malformed_line_count)++;
		return HOSTS_RECORD_ADD_OK;
	}
	bool line_malformed = false;
	bool name_found = false;
	while (*cursor != '\0') {
		while (isspace((unsigned char)*cursor)) {
			cursor++;
		}
		if (*cursor == '\0') {
			break;
		}
		char *name_text = cursor;
		while (*cursor != '\0' && !isspace((unsigned char)*cursor)) {
			cursor++;
		}
		if (*cursor != '\0') {
			*cursor = '\0';
			cursor++;
		}
		name_found = true;
		char name[HOSTS_NAME_SIZE];
		if (!hosts_name_normalize(name_text, name, sizeof(name))) {
			line_malformed = true;
			continue;
		}
		if (strcmp(name, "localhost") == 0 && !hosts_address_is_loopback(&address)) {
			line_malformed = true;
			continue;
		}
		hosts_record_add_status status = hosts_record_add(table, name, &address);
		if (status != HOSTS_RECORD_ADD_OK) {
			return status;
		}
	}
	if (!name_found || line_malformed) {
		(*malformed_line_count)++;
	}
	return HOSTS_RECORD_ADD_OK;
}

static hosts_load_status hosts_table_read(FILE *file, hosts_table *table, size_t *malformed_line_count) {
	char line[HOSTS_LINE_SIZE];
	while (fgets(line, sizeof(line), file) != NULL) {
		if (strchr(line, '\n') == NULL && !feof(file)) {
			int next_character = fgetc(file);
			if (next_character != EOF) {
				while (next_character != '\n' && next_character != EOF) {
					next_character = fgetc(file);
				}
				(*malformed_line_count)++;
				continue;
			}
		}
		if (ferror(file)) {
			return HOSTS_LOAD_FILE_ERROR;
		}
		hosts_record_add_status status = hosts_table_parse_line(table, line, malformed_line_count);
		if (status == HOSTS_RECORD_ADD_LIMIT) {
			return HOSTS_LOAD_LIMIT;
		}
		if (status == HOSTS_RECORD_ADD_MEMORY) {
			return HOSTS_LOAD_MEMORY;
		}
	}
	return ferror(file) ? HOSTS_LOAD_FILE_ERROR : HOSTS_LOAD_OK;
}

/* section: functions (exported) */
void hosts_address_result_destroy(hosts_address_result *result) {
	if (result == NULL) {
		return;
	}
	free(result->addresses);
	memset(result, 0, sizeof(*result));
}

bool hosts_table_clone(const hosts_table *source, hosts_table **result) {
	if (source == NULL || result == NULL || *result != NULL || source->record_count > source->record_capacity || source->record_capacity > HOSTS_RECORD_LIMIT
		|| (source->records == NULL) != (source->record_capacity == 0)) {
		errno = EINVAL;
		return false;
	}
	hosts_table *candidate = calloc(1, sizeof(*candidate));
	if (candidate == NULL) {
		errno = ENOMEM;
		return false;
	}
	if (source->record_count > 0) {
		candidate->records = malloc(source->record_count * sizeof(*candidate->records));
		if (candidate->records == NULL) {
			hosts_table_destroy(candidate);
			errno = ENOMEM;
			return false;
		}
		memcpy(candidate->records, source->records, source->record_count * sizeof(*candidate->records));
		candidate->record_capacity = source->record_count;
		candidate->record_count = source->record_count;
	}
	*result = candidate;
	errno = 0;
	return true;
}

void hosts_table_destroy(hosts_table *table) {
	if (table == NULL) {
		return;
	}
	free(table->records);
	free(table);
}

hosts_load_status hosts_table_load(const char *filename, hosts_table **result, size_t *malformed_line_count) {
	if (filename == NULL || filename[0] == '\0' || result == NULL || *result != NULL || malformed_line_count == NULL) {
		return HOSTS_LOAD_BAD_ARGUMENT;
	}
	*malformed_line_count = 0;
	hosts_table *table = calloc(1, sizeof(*table));
	if (table == NULL) {
		return HOSTS_LOAD_MEMORY;
	}
	hosts_load_status status = HOSTS_LOAD_OK;
	FILE *file = fopen(filename, "r");
	if (file == NULL) {
		status = HOSTS_LOAD_FILE_ERROR;
	} else {
		status = hosts_table_read(file, table, malformed_line_count);
		if (fclose(file) != 0 && status == HOSTS_LOAD_OK) {
			status = HOSTS_LOAD_FILE_ERROR;
		}
	}
	if (status == HOSTS_LOAD_FILE_ERROR) {
		free(table->records);
		memset(table, 0, sizeof(*table));
		*malformed_line_count = 0;
	} else if (status != HOSTS_LOAD_OK) {
		hosts_table_destroy(table);
		return status;
	}
	hosts_record_add_status fallback_status = hosts_table_fallback_add(table);
	if (fallback_status != HOSTS_RECORD_ADD_OK) {
		hosts_table_destroy(table);
		return fallback_status == HOSTS_RECORD_ADD_LIMIT ? HOSTS_LOAD_LIMIT : HOSTS_LOAD_MEMORY;
	}
	*result = table;
	return status;
}

hosts_lookup_status hosts_table_lookup(const hosts_table *table, const char *hostname, hosts_address_result *result) {
	if (table == NULL || hostname == NULL || result == NULL || !hosts_result_empty(result)) {
		return HOSTS_LOOKUP_BAD_ARGUMENT;
	}
	char name[HOSTS_NAME_SIZE];
	if (!hosts_name_normalize(hostname, name, sizeof(name))) {
		return HOSTS_LOOKUP_BAD_ARGUMENT;
	}
	for (size_t record_index = 0; record_index < table->record_count; record_index++) {
		if (strcmp(table->records[record_index].name, name) != 0) {
			continue;
		}
		bool duplicate = false;
		for (size_t address_index = 0; address_index < result->address_count; address_index++) {
			if (hosts_address_equal(&result->addresses[address_index], &table->records[record_index].address)) {
				duplicate = true;
				break;
			}
		}
		if (duplicate) {
			continue;
		}
		net_addr *addresses = realloc(result->addresses, (result->address_count + 1) * sizeof(*addresses));
		if (addresses == NULL) {
			hosts_address_result_destroy(result);
			return HOSTS_LOOKUP_MEMORY;
		}
		result->addresses = addresses;
		result->addresses[result->address_count++] = table->records[record_index].address;
	}
	return result->address_count == 0 ? HOSTS_LOOKUP_NOT_FOUND : HOSTS_LOOKUP_OK;
}

/*
 * resolver/util.c: Shared resolver utility functions
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* section: headers (self) */
#include "util.h"

/* section: functions (exported) */
bool resolver_name_encloses(const char *zone, const char *name) {
	if (zone == NULL || name == NULL) {
		return false;
	}
	if (strcmp(zone, ".") == 0) {
		return true;
	}
	size_t name_length = strlen(name);
	size_t zone_length = strlen(zone);
	return (name_length == zone_length && strcmp(name, zone) == 0)
		|| (name_length > zone_length && name[name_length - zone_length - 1] == '.' && strcmp(name + name_length - zone_length, zone) == 0);
}

bool resolver_name_normalize(const char *source, char target[NS_MAXDNAME]) {
	if (source == NULL || target == NULL) {
		return false;
	}
	size_t source_length = 0;
	while (source_length < NS_MAXDNAME && source[source_length] != '\0') {
		source_length++;
	}
	if (source_length == 0 || source_length == NS_MAXDNAME) {
		return false;
	}
	bool terminal_root_removed = source_length > 1 && source[source_length - 1] == '.';
	if (terminal_root_removed) {
		source_length--;
	}
	if (terminal_root_removed && source[source_length - 1] == '.') {
		return false;
	}
	for (size_t index = 0; index < source_length; index++) {
		unsigned char character = (unsigned char)source[index];
		if (character >= 'A' && character <= 'Z') {
			character = (unsigned char)(character - 'A' + 'a');
		}
		target[index] = (char)character;
	}
	target[source_length] = '\0';
	return true;
}

bool resolver_size_add(size_t *target, size_t value) {
	if (*target > SIZE_MAX - value) {
		return false;
	}
	*target += value;
	return true;
}

bool resolver_size_multiply(size_t left, size_t right, size_t *result) {
	if (left != 0 && right > SIZE_MAX / left) {
		return false;
	}
	*result = left * right;
	return true;
}

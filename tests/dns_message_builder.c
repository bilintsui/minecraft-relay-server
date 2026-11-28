/*
 * dns_message_builder.c: Shared DNS response fixtures for address and SRV tests
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/nameser.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* section: headers (self) */
#include "dns_message_builder.h"

/* section: functions (local) */
static bool dns_builder_bytes_write(dns_message_builder *builder, const void *source, size_t size) {
	if (builder == NULL || source == NULL || size > sizeof(builder->data) - builder->size) {
		return false;
	}
	memcpy(builder->data + builder->size, source, size);
	builder->size += size;
	return true;
}

static bool dns_builder_name_write(dns_message_builder *builder, const char *name, size_t *name_offset) {
	if (builder == NULL || name == NULL) {
		return false;
	}
	if (name_offset != NULL) {
		*name_offset = builder->size;
	}
	if (strcmp(name, ".") == 0) {
		const uint8_t root = 0;
		return dns_builder_bytes_write(builder, &root, sizeof(root));
	}
	const char *label = name;
	while (*label != '\0') {
		const char *separator = strchr(label, '.');
		size_t label_size = separator == NULL ? strlen(label) : (size_t)(separator - label);
		if (label_size == 0) {
			if (separator != NULL && separator[1] == '\0') {
				break;
			}
			return false;
		}
		if (label_size > 63) {
			return false;
		}
		uint8_t wire_size = (uint8_t)label_size;
		if (!dns_builder_bytes_write(builder, &wire_size, sizeof(wire_size)) || !dns_builder_bytes_write(builder, label, label_size)) {
			return false;
		}
		if (separator == NULL) {
			break;
		}
		label = separator + 1;
	}
	const uint8_t root = 0;
	return dns_builder_bytes_write(builder, &root, sizeof(root));
}

static bool dns_builder_pointer_write(dns_message_builder *builder, size_t offset) {
	if (builder == NULL || offset > 0x3FFF) {
		return false;
	}
	uint8_t pointer[2] = { (uint8_t)(0xC0 | (offset >> 8)), (uint8_t)offset };
	return dns_builder_bytes_write(builder, pointer, sizeof(pointer));
}

/* section: functions (exported) */
bool dns_builder_authority_add(dns_message_builder *builder, const char *owner, size_t owner_pointer, uint16_t type, uint16_t record_class, uint32_t ttl, const void *rdata, size_t rdata_size) {
	if (!dns_builder_record_add(builder, owner, owner_pointer, type, record_class, ttl, rdata, rdata_size, NULL)) {
		return false;
	}
	builder->answer_count--;
	builder->data[6] = (uint8_t)(builder->answer_count >> 8);
	builder->data[7] = (uint8_t)builder->answer_count;
	builder->authority_count++;
	builder->data[8] = (uint8_t)(builder->authority_count >> 8);
	builder->data[9] = (uint8_t)builder->authority_count;
	return true;
}

bool dns_builder_record_add(dns_message_builder *builder, const char *owner, size_t owner_pointer, uint16_t type, uint16_t record_class, uint32_t ttl, const void *rdata, size_t rdata_size,
	size_t *rdata_offset) {
	if (builder == NULL || rdata_size > UINT16_MAX || (rdata == NULL && rdata_size != 0)) {
		return false;
	}
	if (owner_pointer == DNS_TEST_NO_POINTER) {
		if (!dns_builder_name_write(builder, owner, NULL)) {
			return false;
		}
	} else if (!dns_builder_pointer_write(builder, owner_pointer)) {
		return false;
	}
	uint8_t metadata[10];
	metadata[0] = (uint8_t)(type >> 8);
	metadata[1] = (uint8_t)type;
	metadata[2] = (uint8_t)(record_class >> 8);
	metadata[3] = (uint8_t)record_class;
	metadata[4] = (uint8_t)(ttl >> 24);
	metadata[5] = (uint8_t)(ttl >> 16);
	metadata[6] = (uint8_t)(ttl >> 8);
	metadata[7] = (uint8_t)ttl;
	metadata[8] = (uint8_t)(rdata_size >> 8);
	metadata[9] = (uint8_t)rdata_size;
	if (!dns_builder_bytes_write(builder, metadata, sizeof(metadata))) {
		return false;
	}
	if (rdata_offset != NULL) {
		*rdata_offset = builder->size;
	}
	if (rdata_size != 0 && !dns_builder_bytes_write(builder, rdata, rdata_size)) {
		return false;
	}
	builder->answer_count++;
	builder->data[6] = (uint8_t)(builder->answer_count >> 8);
	builder->data[7] = (uint8_t)builder->answer_count;
	return true;
}

bool dns_builder_response_start(dns_message_builder *builder, const char *question_name, uint16_t question_type) {
	if (builder == NULL || question_name == NULL) {
		return false;
	}
	memset(builder, 0, sizeof(*builder));
	builder->size = NS_HFIXEDSZ;
	builder->data[0] = (uint8_t)(DNS_TEST_QUERY_ID >> 8);
	builder->data[1] = (uint8_t)DNS_TEST_QUERY_ID;
	builder->data[2] = 0x81;
	builder->data[3] = 0x80;
	builder->data[5] = 1;
	if (!dns_builder_name_write(builder, question_name, &builder->question_name_offset)) {
		return false;
	}
	builder->question_type_offset = builder->size;
	uint8_t question_tail[4] = { (uint8_t)(question_type >> 8), (uint8_t)question_type, 0, ns_c_in };
	if (!dns_builder_bytes_write(builder, question_tail, sizeof(question_tail))) {
		return false;
	}
	builder->question_class_offset = builder->question_type_offset + 2;
	if (snprintf(builder->question_name, sizeof(builder->question_name), "%s", question_name) < 0) {
		return false;
	}
	return true;
}

bool dns_builder_wire_name_create(const char *name, uint8_t *target, size_t target_size, size_t *result_size) {
	if (name == NULL || target == NULL || result_size == NULL) {
		return false;
	}
	dns_message_builder builder;
	memset(&builder, 0, sizeof(builder));
	if (!dns_builder_name_write(&builder, name, NULL) || builder.size > target_size) {
		return false;
	}
	memcpy(target, builder.data, builder.size);
	*result_size = builder.size;
	return true;
}

bool dns_builder_wire_soa_create(const char *mname, const char *rname, uint32_t minimum, uint8_t *target, size_t target_size, size_t *result_size) {
	if (mname == NULL || rname == NULL || target == NULL || result_size == NULL) {
		return false;
	}
	dns_message_builder builder;
	memset(&builder, 0, sizeof(builder));
	if (!dns_builder_name_write(&builder, mname, NULL) || !dns_builder_name_write(&builder, rname, NULL)) {
		return false;
	}
	const uint32_t values[5] = { 1, 2, 3, 4, minimum };
	for (size_t value_index = 0; value_index < sizeof(values) / sizeof(values[0]); value_index++) {
		uint8_t wire_value[4] = {
			(uint8_t)(values[value_index] >> 24),
			(uint8_t)(values[value_index] >> 16),
			(uint8_t)(values[value_index] >> 8),
			(uint8_t)values[value_index]
		};
		if (!dns_builder_bytes_write(&builder, wire_value, sizeof(wire_value))) {
			return false;
		}
	}
	if (builder.size > target_size) {
		return false;
	}
	memcpy(target, builder.data, builder.size);
	*result_size = builder.size;
	return true;
}

/*
 * dns_message_builder.h: Shared DNS response fixtures for address and SRV tests
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef MCRELAY_TEST_DNS_MESSAGE_BUILDER_H

#define MCRELAY_TEST_DNS_MESSAGE_BUILDER_H

/* section: headers (library) */
#include <arpa/nameser.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* section: defines */
/* DNS message */
#define DNS_TEST_MESSAGE_CAPACITY	32768
#define DNS_TEST_NO_POINTER	SIZE_MAX

/* DNS query */
#define DNS_TEST_QUERY_SIZE	4
#define DNS_TEST_QUERY_TOKEN_FIRST	0x4D
#define DNS_TEST_QUERY_TOKEN_SECOND	0x52
#define DNS_TEST_QUERY_ID	((DNS_TEST_QUERY_TOKEN_FIRST << 8) | DNS_TEST_QUERY_TOKEN_SECOND)

/* section: types */
typedef struct {
	size_t answer_count;
	size_t authority_count;
	uint8_t data[DNS_TEST_MESSAGE_CAPACITY];
	size_t question_class_offset;
	size_t question_name_offset;
	size_t question_type_offset;
	char question_name[NS_MAXDNAME];
	size_t size;
} dns_message_builder;

/* section: functions (exported) */
bool dns_builder_authority_add(dns_message_builder *builder, const char *owner, size_t owner_pointer, uint16_t type, uint16_t record_class, uint32_t ttl, const void *rdata, size_t rdata_size);
bool dns_builder_record_add(dns_message_builder *builder, const char *owner, size_t owner_pointer, uint16_t type, uint16_t record_class, uint32_t ttl, const void *rdata, size_t rdata_size,
	size_t *rdata_offset);
bool dns_builder_response_start(dns_message_builder *builder, const char *question_name, uint16_t question_type);
bool dns_builder_wire_name_create(const char *name, uint8_t *target, size_t target_size, size_t *result_size);
bool dns_builder_wire_soa_create(const char *mname, const char *rname, uint32_t minimum, uint8_t *target, size_t target_size, size_t *result_size);

#endif

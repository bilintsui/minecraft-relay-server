/*
 * resolver/dns.c: DNS response parsing
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/nameser.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

/* section: headers (project) */
#include "util.h"

/* section: headers (self) */
#include "dns.h"

/* section: types */
typedef struct {
	net_addr address;
	char owner[NS_MAXDNAME];
	uint32_t ttl;
} dns_address_candidate;
typedef enum {
	DNS_NEGATIVE_PARSE_OK,
	DNS_NEGATIVE_PARSE_LIMIT,
	DNS_NEGATIVE_PARSE_MALFORMED
} dns_negative_parse_status;
typedef enum {
	DNS_QUERY_EXACT_OK,
	DNS_QUERY_EXACT_MEMORY,
	DNS_QUERY_EXACT_MALFORMED,
	DNS_QUERY_EXACT_PERMANENT_ERROR,
	DNS_QUERY_EXACT_TEMPORARY_ERROR
} dns_query_exact_status;
typedef struct {
	char owner[NS_MAXDNAME];
	in_port_t port;
	uint16_t priority;
	char target[NS_MAXDNAME];
	uint32_t ttl;
	uint16_t weight;
} dns_srv_candidate;

/* section: functions (local) */
static bool dns_address_result_empty(const dns_address_result *result) {
	return result->addresses == NULL && result->address_count == 0 && result->cnames == NULL && result->cname_count == 0 && result->canonical_name[0] == '\0'
		&& result->negative.effective_ttl == 0 && result->negative.minimum == 0 && result->negative.owner[0] == '\0' && result->negative.record_ttl == 0 && !result->negative.valid
		&& result->question_name[0] == '\0' && result->rcode == 0;
}

static uint32_t dns_cname_ttl_min(const dns_cname_record *cnames, size_t cname_count) {
	uint32_t result = UINT32_MAX;
	for (size_t cname_index = 0; cname_index < cname_count; cname_index++) {
		if (cnames[cname_index].ttl < result) {
			result = cnames[cname_index].ttl;
		}
	}
	return result;
}

static bool dns_name_equal(const char *left, const char *right) {
	if (left == NULL || right == NULL) {
		return false;
	}
	size_t left_length = strlen(left);
	size_t right_length = strlen(right);
	if (left_length > 1 && left[left_length - 1] == '.') {
		left_length--;
	}
	if (right_length > 1 && right[right_length - 1] == '.') {
		right_length--;
	}
	if (left_length != right_length) {
		return false;
	}
	for (size_t index = 0; index < left_length; index++) {
		unsigned char left_character = (unsigned char)left[index];
		unsigned char right_character = (unsigned char)right[index];
		if (left_character >= 'A' && left_character <= 'Z') {
			left_character = (unsigned char)(left_character - 'A' + 'a');
		}
		if (right_character >= 'A' && right_character <= 'Z') {
			right_character = (unsigned char)(right_character - 'A' + 'a');
		}
		if (left_character != right_character) {
			return false;
		}
	}
	return true;
}

static bool dns_name_normalize(const char *source, char *target, size_t target_size) {
	if (source == NULL || target == NULL || target_size == 0) {
		return false;
	}
	size_t source_length = strlen(source);
	if (source_length > 1 && source[source_length - 1] == '.') {
		source_length--;
	}
	if (source_length >= target_size) {
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

static bool dns_name_record_parse(const ns_msg *response, const ns_rr *answer, dns_cname_record *record) {
	const unsigned char *message_begin = ns_msg_base(*response);
	const unsigned char *message_end = ns_msg_end(*response);
	const unsigned char *rdata = ns_rr_rdata(*answer);
	size_t rdata_size = ns_rr_rdlen(*answer);
	if (rdata < message_begin || rdata > message_end || rdata_size > (size_t)(message_end - rdata)) {
		return false;
	}
	char target[NS_MAXDNAME];
	int consumed = ns_name_uncompress(message_begin, message_end, rdata, target, sizeof(target));
	if (consumed <= 0 || (size_t)consumed != rdata_size) {
		return false;
	}
	memset(record, 0, sizeof(*record));
	record->ttl = ns_rr_ttl(*answer);
	return dns_name_normalize(ns_rr_name(*answer), record->owner, sizeof(record->owner)) && dns_name_normalize(target, record->target, sizeof(record->target));
}

static dns_address_lookup_status dns_lookup_chain_append(dns_address_result *target, dns_address_result *source, uint32_t *chain_ttl) {
	if (target->question_name[0] == '\0') {
		memcpy(target->question_name, source->question_name, sizeof(target->question_name));
		memcpy(target->canonical_name, source->question_name, sizeof(target->canonical_name));
	} else if (!dns_name_equal(target->canonical_name, source->question_name)) {
		return DNS_ADDRESS_LOOKUP_MALFORMED;
	}
	if (source->cname_count > DNS_CNAME_DEPTH_LIMIT - target->cname_count) {
		return DNS_ADDRESS_LOOKUP_LIMIT;
	}
	if (source->cname_count > 0 && target->cnames == NULL) {
		target->cnames = calloc(DNS_CNAME_DEPTH_LIMIT, sizeof(*target->cnames));
		if (target->cnames == NULL) {
			return DNS_ADDRESS_LOOKUP_MEMORY;
		}
	}
	for (size_t source_index = 0; source_index < source->cname_count; source_index++) {
		for (size_t target_index = 0; target_index < target->cname_count; target_index++) {
			if (dns_name_equal(target->cnames[target_index].owner, source->cnames[source_index].target)) {
				return DNS_ADDRESS_LOOKUP_MALFORMED;
			}
		}
		target->cnames[target->cname_count++] = source->cnames[source_index];
		if (source->cnames[source_index].ttl < *chain_ttl) {
			*chain_ttl = source->cnames[source_index].ttl;
		}
	}
	memcpy(target->canonical_name, source->canonical_name, sizeof(target->canonical_name));
	target->rcode = source->rcode;
	return DNS_ADDRESS_LOOKUP_OK;
}

static dns_address_lookup_status dns_lookup_parse_status(dns_address_parse_status parse_status, uint8_t rcode) {
	switch (parse_status) {
		case DNS_ADDRESS_PARSE_OK:
		case DNS_ADDRESS_PARSE_ALIAS_ONLY:
			return DNS_ADDRESS_LOOKUP_OK;
		case DNS_ADDRESS_PARSE_NODATA:
			return DNS_ADDRESS_LOOKUP_NODATA;
		case DNS_ADDRESS_PARSE_NXDOMAIN:
			return DNS_ADDRESS_LOOKUP_NOT_FOUND;
		case DNS_ADDRESS_PARSE_RCODE_ERROR:
			return rcode == ns_r_servfail ? DNS_ADDRESS_LOOKUP_TEMPORARY_ERROR : DNS_ADDRESS_LOOKUP_PERMANENT_ERROR;
		case DNS_ADDRESS_PARSE_TRUNCATED:
			return DNS_ADDRESS_LOOKUP_TRUNCATED;
		case DNS_ADDRESS_PARSE_BAD_ARGUMENT:
			return DNS_ADDRESS_LOOKUP_BAD_ARGUMENT;
		case DNS_ADDRESS_PARSE_LIMIT:
			return DNS_ADDRESS_LOOKUP_LIMIT;
		case DNS_ADDRESS_PARSE_MALFORMED:
			return DNS_ADDRESS_LOOKUP_MALFORMED;
		case DNS_ADDRESS_PARSE_MEMORY:
			return DNS_ADDRESS_LOOKUP_MEMORY;
	}
	return DNS_ADDRESS_LOOKUP_MALFORMED;
}

static bool dns_lookup_status_keeps_result(dns_address_lookup_status status) {
	return status == DNS_ADDRESS_LOOKUP_OK || status == DNS_ADDRESS_LOOKUP_NODATA || status == DNS_ADDRESS_LOOKUP_NOT_FOUND || status == DNS_ADDRESS_LOOKUP_PERMANENT_ERROR
		|| status == DNS_ADDRESS_LOOKUP_TEMPORARY_ERROR;
}

static bool dns_negative_record_parse(const ns_msg *response, const ns_rr *authority, dns_negative_record *record) {
	const unsigned char *message_begin = ns_msg_base(*response);
	const unsigned char *message_end = ns_msg_end(*response);
	const unsigned char *rdata = ns_rr_rdata(*authority);
	size_t rdata_size = ns_rr_rdlen(*authority);
	if (rdata < message_begin || rdata > message_end || rdata_size > (size_t)(message_end - rdata)) {
		return false;
	}
	const unsigned char *rdata_end = rdata + rdata_size;
	const unsigned char *cursor = rdata;
	char name[NS_MAXDNAME];
	for (size_t name_index = 0; name_index < 2; name_index++) {
		int consumed = ns_name_uncompress(message_begin, message_end, cursor, name, sizeof(name));
		if (consumed <= 0 || (size_t)consumed > (size_t)(rdata_end - cursor)) {
			return false;
		}
		cursor += consumed;
	}
	if ((size_t)(rdata_end - cursor) != sizeof(uint32_t) * 5) {
		return false;
	}
	uint32_t values[5];
	for (size_t value_index = 0; value_index < sizeof(values) / sizeof(values[0]); value_index++) {
		uint32_t value;
		memcpy(&value, cursor + value_index * sizeof(value), sizeof(value));
		values[value_index] = ntohl(value);
	}
	memset(record, 0, sizeof(*record));
	record->minimum = values[4];
	record->record_ttl = ns_rr_ttl(*authority);
	record->effective_ttl = record->minimum < record->record_ttl ? record->minimum : record->record_ttl;
	record->valid = true;
	return dns_name_normalize(ns_rr_name(*authority), record->owner, sizeof(record->owner));
}

static dns_negative_parse_status dns_negative_response_parse(ns_msg *response, const char *canonical_name, const dns_cname_record *cnames, size_t cname_count,
	dns_negative_record *result) {
	int authority_count = ns_msg_count(*response, ns_s_ns);
	if (authority_count > DNS_AUTHORITY_RECORD_LIMIT) {
		return DNS_NEGATIVE_PARSE_LIMIT;
	}
	for (int authority_index = 0; authority_index < authority_count; authority_index++) {
		ns_rr authority;
		if (ns_parserr(response, ns_s_ns, authority_index, &authority) != 0) {
			return DNS_NEGATIVE_PARSE_MALFORMED;
		}
		if (ns_rr_class(authority) != ns_c_in || ns_rr_type(authority) != ns_t_soa) {
			continue;
		}
		dns_negative_record candidate;
		if (!dns_negative_record_parse(response, &authority, &candidate)) {
			return DNS_NEGATIVE_PARSE_MALFORMED;
		}
		if (!resolver_name_encloses(candidate.owner, canonical_name)) {
			continue;
		}
		if (!result->valid || strlen(candidate.owner) > strlen(result->owner)) {
			*result = candidate;
		} else if (strcmp(candidate.owner, result->owner) == 0) {
			if (candidate.minimum < result->minimum) {
				result->minimum = candidate.minimum;
			}
			if (candidate.record_ttl < result->record_ttl) {
				result->record_ttl = candidate.record_ttl;
			}
			result->effective_ttl = result->minimum < result->record_ttl ? result->minimum : result->record_ttl;
		}
	}
	if (result->valid) {
		uint32_t cname_ttl = dns_cname_ttl_min(cnames, cname_count);
		if (cname_ttl < result->effective_ttl) {
			result->effective_ttl = cname_ttl;
		}
	}
	return DNS_NEGATIVE_PARSE_OK;
}

static dns_query_exact_status dns_query_exact(res_state resolver, const char *name, int type, unsigned char *response, int response_capacity, int *response_size) {
	unsigned char query[NS_MAXMSG];
	int query_size = res_nmkquery(resolver, ns_o_query, name, ns_c_in, type, NULL, 0, NULL, query, (int)sizeof(query));
	if (query_size <= 0 || query_size > (int)sizeof(query)) {
		return DNS_QUERY_EXACT_PERMANENT_ERROR;
	}
	int result;
	/* glibc res_nsend() leaves res_h_errno untouched on transport failures (verified on 2.35); classify by errno instead. */
	errno = 0;
	result = res_nsend(resolver, query, query_size, response, response_capacity);
	int failure_errno = errno;
	if (result <= 0) {
		switch (failure_errno) {
			case ENOMEM:
				return DNS_QUERY_EXACT_MEMORY;
			case EMSGSIZE:
				return DNS_QUERY_EXACT_MALFORMED;
			case ESRCH:
			case EINVAL:
			case EAFNOSUPPORT:
			case EPROTONOSUPPORT:
			case EACCES:
			case EPERM:
				return DNS_QUERY_EXACT_PERMANENT_ERROR;
			default:
				/* Network and resource errors, plus an undocumented errno == 0 failure, are retried conservatively. */
				return DNS_QUERY_EXACT_TEMPORARY_ERROR;
		}
	}
	*response_size = result;
	return DNS_QUERY_EXACT_OK;
}

static bool dns_resolver_init(res_state resolver) {
	if (res_ninit(resolver) != 0) {
		return false;
	}
	if (resolver->retry > DNS_QUERY_ATTEMPT_LIMIT) {
		resolver->retry = DNS_QUERY_ATTEMPT_LIMIT;
	}
	if (resolver->retrans > DNS_QUERY_RETRANSMIT_TIMEOUT_SEC) {
		resolver->retrans = DNS_QUERY_RETRANSMIT_TIMEOUT_SEC;
	}
	return true;
}

static dns_address_parse_status dns_response_addresses_collect(ns_msg *response, sa_family_t family, dns_address_candidate *addresses, size_t *address_count, dns_cname_record *cnames,
	size_t *cname_count) {
	const unsigned char *message_begin = ns_msg_base(*response);
	const unsigned char *message_end = ns_msg_end(*response);
	ns_type address_type = family == AF_INET ? ns_t_a : ns_t_aaaa;
	size_t address_size = family == AF_INET ? sizeof(uint32_t) : sizeof(uint8_t) * 16;
	int answer_count = ns_msg_count(*response, ns_s_an);
	for (int answer_index = 0; answer_index < answer_count; answer_index++) {
		ns_rr answer;
		if (ns_parserr(response, ns_s_an, answer_index, &answer) != 0) {
			return DNS_ADDRESS_PARSE_MALFORMED;
		}
		if (ns_rr_class(answer) != ns_c_in) {
			continue;
		}
		if (ns_rr_type(answer) == address_type) {
			if (ns_rr_rdlen(answer) != address_size || ns_rr_rdata(answer) < message_begin || ns_rr_rdata(answer) > message_end || address_size > (size_t)(message_end - ns_rr_rdata(answer))) {
				return DNS_ADDRESS_PARSE_MALFORMED;
			}
			dns_address_candidate *candidate = &addresses[(*address_count)++];
			memset(candidate, 0, sizeof(*candidate));
			candidate->address.family = family;
			memcpy(&candidate->address.addr, ns_rr_rdata(answer), address_size);
			candidate->ttl = ns_rr_ttl(answer);
			if (!dns_name_normalize(ns_rr_name(answer), candidate->owner, sizeof(candidate->owner))) {
				return DNS_ADDRESS_PARSE_MALFORMED;
			}
		} else if (ns_rr_type(answer) == ns_t_cname) {
			dns_cname_record *candidate = &cnames[(*cname_count)++];
			if (!dns_name_record_parse(response, &answer, candidate)) {
				return DNS_ADDRESS_PARSE_MALFORMED;
			}
		}
	}
	return DNS_ADDRESS_PARSE_OK;
}

static dns_address_parse_status dns_response_chain_build(const dns_address_candidate *addresses, size_t address_count, const dns_cname_record *cnames, size_t cname_count, dns_address_result *result) {
	char current_name[NS_MAXDNAME];
	memcpy(current_name, result->question_name, sizeof(current_name));
	uint32_t chain_ttl = UINT32_MAX;
	if (cname_count > 0) {
		result->cnames = calloc(DNS_CNAME_DEPTH_LIMIT, sizeof(*result->cnames));
		if (result->cnames == NULL) {
			return DNS_ADDRESS_PARSE_MEMORY;
		}
	}
	while (true) {
		const dns_cname_record *matching_cname = NULL;
		uint32_t matching_ttl = UINT32_MAX;
		bool matching_address = false;
		for (size_t address_index = 0; address_index < address_count; address_index++) {
			if (dns_name_equal(addresses[address_index].owner, current_name)) {
				matching_address = true;
				break;
			}
		}
		for (size_t cname_index = 0; cname_index < cname_count; cname_index++) {
			if (!dns_name_equal(cnames[cname_index].owner, current_name)) {
				continue;
			}
			if (matching_cname != NULL && !dns_name_equal(matching_cname->target, cnames[cname_index].target)) {
				return DNS_ADDRESS_PARSE_MALFORMED;
			}
			if (matching_cname == NULL) {
				matching_cname = &cnames[cname_index];
			}
			if (cnames[cname_index].ttl < matching_ttl) {
				matching_ttl = cnames[cname_index].ttl;
			}
		}
		if (matching_cname == NULL) {
			break;
		}
		if (matching_address || result->cname_count == DNS_CNAME_DEPTH_LIMIT) {
			return matching_address ? DNS_ADDRESS_PARSE_MALFORMED : DNS_ADDRESS_PARSE_LIMIT;
		}
		for (size_t chain_index = 0; chain_index < result->cname_count; chain_index++) {
			if (dns_name_equal(result->cnames[chain_index].owner, matching_cname->target)) {
				return DNS_ADDRESS_PARSE_MALFORMED;
			}
		}
		dns_cname_record *chain_record = &result->cnames[result->cname_count++];
		memcpy(chain_record, matching_cname, sizeof(*chain_record));
		chain_record->ttl = matching_ttl;
		if (matching_ttl < chain_ttl) {
			chain_ttl = matching_ttl;
		}
		memcpy(current_name, matching_cname->target, sizeof(current_name));
	}
	memcpy(result->canonical_name, current_name, sizeof(result->canonical_name));
	size_t matching_address_count = 0;
	for (size_t address_index = 0; address_index < address_count; address_index++) {
		if (dns_name_equal(addresses[address_index].owner, current_name)) {
			matching_address_count++;
		}
	}
	if (matching_address_count == 0) {
		return result->cname_count == 0 ? DNS_ADDRESS_PARSE_NODATA : DNS_ADDRESS_PARSE_ALIAS_ONLY;
	}
	result->addresses = calloc(matching_address_count, sizeof(*result->addresses));
	if (result->addresses == NULL) {
		return DNS_ADDRESS_PARSE_MEMORY;
	}
	for (size_t address_index = 0; address_index < address_count; address_index++) {
		if (!dns_name_equal(addresses[address_index].owner, current_name)) {
			continue;
		}
		dns_address_record *record = &result->addresses[result->address_count++];
		record->address = addresses[address_index].address;
		record->record_ttl = addresses[address_index].ttl;
		record->effective_ttl = chain_ttl < record->record_ttl ? chain_ttl : record->record_ttl;
	}
	return DNS_ADDRESS_PARSE_OK;
}

static dns_srv_lookup_status dns_srv_lookup_chain_append(dns_srv_result *target, dns_srv_result *source, uint32_t *chain_ttl) {
	if (target->question_name[0] == '\0') {
		memcpy(target->question_name, source->question_name, sizeof(target->question_name));
		memcpy(target->canonical_name, source->question_name, sizeof(target->canonical_name));
	} else if (!dns_name_equal(target->canonical_name, source->question_name)) {
		return DNS_SRV_LOOKUP_MALFORMED;
	}
	if (source->cname_count > DNS_CNAME_DEPTH_LIMIT - target->cname_count) {
		return DNS_SRV_LOOKUP_LIMIT;
	}
	if (source->cname_count > 0 && target->cnames == NULL) {
		target->cnames = calloc(DNS_CNAME_DEPTH_LIMIT, sizeof(*target->cnames));
		if (target->cnames == NULL) {
			return DNS_SRV_LOOKUP_MEMORY;
		}
	}
	for (size_t source_index = 0; source_index < source->cname_count; source_index++) {
		for (size_t target_index = 0; target_index < target->cname_count; target_index++) {
			if (dns_name_equal(target->cnames[target_index].owner, source->cnames[source_index].target)) {
				return DNS_SRV_LOOKUP_MALFORMED;
			}
		}
		target->cnames[target->cname_count++] = source->cnames[source_index];
		if (source->cnames[source_index].ttl < *chain_ttl) {
			*chain_ttl = source->cnames[source_index].ttl;
		}
	}
	memcpy(target->canonical_name, source->canonical_name, sizeof(target->canonical_name));
	target->rcode = source->rcode;
	return DNS_SRV_LOOKUP_OK;
}

static dns_srv_lookup_status dns_srv_lookup_parse_status(dns_srv_parse_status parse_status, uint8_t rcode) {
	switch (parse_status) {
		case DNS_SRV_PARSE_OK:
		case DNS_SRV_PARSE_ALIAS_ONLY:
			return DNS_SRV_LOOKUP_OK;
		case DNS_SRV_PARSE_NODATA:
			return DNS_SRV_LOOKUP_NODATA;
		case DNS_SRV_PARSE_NXDOMAIN:
			return DNS_SRV_LOOKUP_NOT_FOUND;
		case DNS_SRV_PARSE_RCODE_ERROR:
			return rcode == ns_r_servfail ? DNS_SRV_LOOKUP_TEMPORARY_ERROR : DNS_SRV_LOOKUP_PERMANENT_ERROR;
		case DNS_SRV_PARSE_TRUNCATED:
			return DNS_SRV_LOOKUP_TRUNCATED;
		case DNS_SRV_PARSE_BAD_ARGUMENT:
			return DNS_SRV_LOOKUP_BAD_ARGUMENT;
		case DNS_SRV_PARSE_LIMIT:
			return DNS_SRV_LOOKUP_LIMIT;
		case DNS_SRV_PARSE_MALFORMED:
			return DNS_SRV_LOOKUP_MALFORMED;
		case DNS_SRV_PARSE_MEMORY:
			return DNS_SRV_LOOKUP_MEMORY;
	}
	return DNS_SRV_LOOKUP_MALFORMED;
}

static bool dns_srv_lookup_status_keeps_result(dns_srv_lookup_status status) {
	return status == DNS_SRV_LOOKUP_OK || status == DNS_SRV_LOOKUP_NODATA || status == DNS_SRV_LOOKUP_NOT_FOUND || status == DNS_SRV_LOOKUP_PERMANENT_ERROR
		|| status == DNS_SRV_LOOKUP_TEMPORARY_ERROR;
}

static dns_srv_parse_status dns_srv_response_chain_build(const dns_srv_candidate *records, size_t record_count, const dns_cname_record *cnames, size_t cname_count, dns_srv_result *result) {
	char current_name[NS_MAXDNAME];
	memcpy(current_name, result->question_name, sizeof(current_name));
	uint32_t chain_ttl = UINT32_MAX;
	if (cname_count > 0) {
		result->cnames = calloc(DNS_CNAME_DEPTH_LIMIT, sizeof(*result->cnames));
		if (result->cnames == NULL) {
			return DNS_SRV_PARSE_MEMORY;
		}
	}
	while (true) {
		const dns_cname_record *matching_cname = NULL;
		uint32_t matching_ttl = UINT32_MAX;
		bool matching_record = false;
		for (size_t record_index = 0; record_index < record_count; record_index++) {
			if (dns_name_equal(records[record_index].owner, current_name)) {
				matching_record = true;
				break;
			}
		}
		for (size_t cname_index = 0; cname_index < cname_count; cname_index++) {
			if (!dns_name_equal(cnames[cname_index].owner, current_name)) {
				continue;
			}
			if (matching_cname != NULL && !dns_name_equal(matching_cname->target, cnames[cname_index].target)) {
				return DNS_SRV_PARSE_MALFORMED;
			}
			if (matching_cname == NULL) {
				matching_cname = &cnames[cname_index];
			}
			if (cnames[cname_index].ttl < matching_ttl) {
				matching_ttl = cnames[cname_index].ttl;
			}
		}
		if (matching_cname == NULL) {
			break;
		}
		if (matching_record || result->cname_count == DNS_CNAME_DEPTH_LIMIT) {
			return matching_record ? DNS_SRV_PARSE_MALFORMED : DNS_SRV_PARSE_LIMIT;
		}
		for (size_t chain_index = 0; chain_index < result->cname_count; chain_index++) {
			if (dns_name_equal(result->cnames[chain_index].owner, matching_cname->target)) {
				return DNS_SRV_PARSE_MALFORMED;
			}
		}
		dns_cname_record *chain_record = &result->cnames[result->cname_count++];
		memcpy(chain_record, matching_cname, sizeof(*chain_record));
		chain_record->ttl = matching_ttl;
		if (matching_ttl < chain_ttl) {
			chain_ttl = matching_ttl;
		}
		memcpy(current_name, matching_cname->target, sizeof(current_name));
	}
	memcpy(result->canonical_name, current_name, sizeof(result->canonical_name));
	size_t matching_record_count = 0;
	for (size_t record_index = 0; record_index < record_count; record_index++) {
		if (dns_name_equal(records[record_index].owner, current_name)) {
			matching_record_count++;
		}
	}
	if (matching_record_count == 0) {
		return result->cname_count == 0 ? DNS_SRV_PARSE_NODATA : DNS_SRV_PARSE_ALIAS_ONLY;
	}
	result->records = calloc(matching_record_count, sizeof(*result->records));
	if (result->records == NULL) {
		return DNS_SRV_PARSE_MEMORY;
	}
	for (size_t record_index = 0; record_index < record_count; record_index++) {
		if (!dns_name_equal(records[record_index].owner, current_name)) {
			continue;
		}
		dns_srv_record *record = &result->records[result->record_count++];
		record->priority = records[record_index].priority;
		record->weight = records[record_index].weight;
		record->port = records[record_index].port;
		memcpy(record->target, records[record_index].target, sizeof(record->target));
		record->record_ttl = records[record_index].ttl;
		record->effective_ttl = chain_ttl < record->record_ttl ? chain_ttl : record->record_ttl;
	}
	return DNS_SRV_PARSE_OK;
}

static dns_srv_parse_status dns_srv_response_records_collect(ns_msg *response, dns_srv_candidate *records, size_t *record_count, dns_cname_record *cnames, size_t *cname_count) {
	const unsigned char *message_begin = ns_msg_base(*response);
	const unsigned char *message_end = ns_msg_end(*response);
	int answer_count = ns_msg_count(*response, ns_s_an);
	for (int answer_index = 0; answer_index < answer_count; answer_index++) {
		ns_rr answer;
		if (ns_parserr(response, ns_s_an, answer_index, &answer) != 0) {
			return DNS_SRV_PARSE_MALFORMED;
		}
		if (ns_rr_class(answer) != ns_c_in) {
			continue;
		}
		if (ns_rr_type(answer) == ns_t_srv) {
			const unsigned char *rdata = ns_rr_rdata(answer);
			size_t rdata_size = ns_rr_rdlen(answer);
			if (rdata < message_begin || rdata > message_end || rdata_size < 7 || rdata_size > (size_t)(message_end - rdata)) {
				return DNS_SRV_PARSE_MALFORMED;
			}
			char target[NS_MAXDNAME];
			int consumed = ns_name_uncompress(message_begin, message_end, rdata + 6, target, sizeof(target));
			if (consumed <= 0 || (size_t)consumed != rdata_size - 6) {
				return DNS_SRV_PARSE_MALFORMED;
			}
			dns_srv_candidate *candidate = &records[(*record_count)++];
			memset(candidate, 0, sizeof(*candidate));
			uint16_t value;
			memcpy(&value, rdata, sizeof(value));
			candidate->priority = ntohs(value);
			memcpy(&value, rdata + 2, sizeof(value));
			candidate->weight = ntohs(value);
			memcpy(&value, rdata + 4, sizeof(value));
			candidate->port = ntohs(value);
			candidate->ttl = ns_rr_ttl(answer);
			if (!dns_name_normalize(ns_rr_name(answer), candidate->owner, sizeof(candidate->owner)) || !dns_name_normalize(target, candidate->target, sizeof(candidate->target))) {
				return DNS_SRV_PARSE_MALFORMED;
			}
		} else if (ns_rr_type(answer) == ns_t_cname) {
			dns_cname_record *candidate = &cnames[(*cname_count)++];
			if (!dns_name_record_parse(response, &answer, candidate)) {
				return DNS_SRV_PARSE_MALFORMED;
			}
		}
	}
	return DNS_SRV_PARSE_OK;
}

static bool dns_srv_result_empty(const dns_srv_result *result) {
	return result->canonical_name[0] == '\0' && result->cnames == NULL && result->cname_count == 0 && result->negative.effective_ttl == 0 && result->negative.minimum == 0
		&& result->negative.owner[0] == '\0' && result->negative.record_ttl == 0 && !result->negative.valid && result->question_name[0] == '\0' && result->rcode == 0 && result->records == NULL
		&& result->record_count == 0;
}

/* section: functions (exported) */
dns_address_lookup_status dns_address_lookup(const char *hostname, sa_family_t family, dns_address_result *result) {
	if (hostname == NULL || hostname[0] == '\0' || strlen(hostname) >= NS_MAXDNAME || (family != AF_INET && family != AF_INET6) || result == NULL || !dns_address_result_empty(result)) {
		return DNS_ADDRESS_LOOKUP_BAD_ARGUMENT;
	}
	struct __res_state resolver;
	memset(&resolver, 0, sizeof(resolver));
	if (!dns_resolver_init(&resolver)) {
		return DNS_ADDRESS_LOOKUP_PERMANENT_ERROR;
	}
	unsigned char *response = malloc(NS_MAXMSG);
	if (response == NULL) {
		res_nclose(&resolver);
		return DNS_ADDRESS_LOOKUP_MEMORY;
	}
	dns_address_result aggregate = { 0 };
	char query_name[NS_MAXDNAME];
	memcpy(query_name, hostname, strlen(hostname) + 1);
	uint32_t chain_ttl = UINT32_MAX;
	dns_address_lookup_status lookup_status = DNS_ADDRESS_LOOKUP_PERMANENT_ERROR;
	while (true) {
		int query_type = family == AF_INET ? ns_t_a : ns_t_aaaa;
		int response_size = 0;
		dns_query_exact_status query_status = dns_query_exact(&resolver, query_name, query_type, response, NS_MAXMSG, &response_size);
		if (query_status != DNS_QUERY_EXACT_OK) {
			switch (query_status) {
				case DNS_QUERY_EXACT_MEMORY:
					lookup_status = DNS_ADDRESS_LOOKUP_MEMORY;
					break;
				case DNS_QUERY_EXACT_MALFORMED:
					lookup_status = DNS_ADDRESS_LOOKUP_MALFORMED;
					break;
				case DNS_QUERY_EXACT_PERMANENT_ERROR:
					lookup_status = DNS_ADDRESS_LOOKUP_PERMANENT_ERROR;
					break;
				case DNS_QUERY_EXACT_TEMPORARY_ERROR:
				default:
					lookup_status = DNS_ADDRESS_LOOKUP_TEMPORARY_ERROR;
					break;
			}
			break;
		}
		if (response_size > NS_MAXMSG) {
			lookup_status = DNS_ADDRESS_LOOKUP_TRUNCATED;
			break;
		}
		dns_address_result partial = { 0 };
		dns_address_parse_status parse_status = dns_address_response_parse(response, (size_t)response_size, family, &partial);
		if (partial.question_name[0] != '\0' && !dns_name_equal(partial.question_name, query_name)) {
			dns_address_result_destroy(&partial);
			lookup_status = DNS_ADDRESS_LOOKUP_MALFORMED;
			break;
		}
		lookup_status = dns_lookup_parse_status(parse_status, partial.rcode);
		if (parse_status == DNS_ADDRESS_PARSE_NODATA || parse_status == DNS_ADDRESS_PARSE_NXDOMAIN) {
			dns_address_lookup_status terminal_status = lookup_status;
			lookup_status = dns_lookup_chain_append(&aggregate, &partial, &chain_ttl);
			if (lookup_status == DNS_ADDRESS_LOOKUP_OK) {
				aggregate.negative = partial.negative;
				if (aggregate.negative.valid && chain_ttl < aggregate.negative.effective_ttl) {
					aggregate.negative.effective_ttl = chain_ttl;
				}
				lookup_status = terminal_status;
			}
			dns_address_result_destroy(&partial);
			break;
		}
		if (parse_status != DNS_ADDRESS_PARSE_OK && parse_status != DNS_ADDRESS_PARSE_ALIAS_ONLY) {
			if (dns_lookup_status_keeps_result(lookup_status)) {
				if (aggregate.question_name[0] == '\0') {
					aggregate = partial;
					memset(&partial, 0, sizeof(partial));
				} else {
					aggregate.rcode = partial.rcode;
				}
			}
			dns_address_result_destroy(&partial);
			break;
		}
		lookup_status = dns_lookup_chain_append(&aggregate, &partial, &chain_ttl);
		if (lookup_status != DNS_ADDRESS_LOOKUP_OK) {
			dns_address_result_destroy(&partial);
			break;
		}
		if (parse_status == DNS_ADDRESS_PARSE_OK) {
			/* Move the address array into the aggregate before destroying the partial result. */
			aggregate.addresses = partial.addresses;
			aggregate.address_count = partial.address_count;
			partial.addresses = NULL;
			partial.address_count = 0;
			for (size_t address_index = 0; address_index < aggregate.address_count; address_index++) {
				if (chain_ttl < aggregate.addresses[address_index].effective_ttl) {
					aggregate.addresses[address_index].effective_ttl = chain_ttl;
				}
			}
			dns_address_result_destroy(&partial);
			break;
		}
		memcpy(query_name, aggregate.canonical_name, sizeof(query_name));
		dns_address_result_destroy(&partial);
	}
	free(response);
	res_nclose(&resolver);
	if (dns_lookup_status_keeps_result(lookup_status)) {
		*result = aggregate;
	} else {
		dns_address_result_destroy(&aggregate);
	}
	return lookup_status;
}

dns_address_parse_status dns_address_response_parse(const void *message, size_t message_size, sa_family_t family, dns_address_result *result) {
	if (message == NULL || message_size > INT_MAX || (family != AF_INET && family != AF_INET6) || result == NULL || !dns_address_result_empty(result)) {
		return DNS_ADDRESS_PARSE_BAD_ARGUMENT;
	}
	ns_msg response;
	if (ns_initparse(message, (int)message_size, &response) != 0) {
		return DNS_ADDRESS_PARSE_MALFORMED;
	}
	if (!ns_msg_getflag(response, ns_f_qr) || ns_msg_getflag(response, ns_f_opcode) != ns_o_query || ns_msg_count(response, ns_s_qd) != 1) {
		return DNS_ADDRESS_PARSE_MALFORMED;
	}
	if (ns_msg_getflag(response, ns_f_tc)) {
		return DNS_ADDRESS_PARSE_TRUNCATED;
	}
	ns_rr question;
	ns_type question_type = family == AF_INET ? ns_t_a : ns_t_aaaa;
	if (ns_parserr(&response, ns_s_qd, 0, &question) != 0 || ns_rr_class(question) != ns_c_in || ns_rr_type(question) != question_type
		|| !dns_name_normalize(ns_rr_name(question), result->question_name, sizeof(result->question_name))) {
		memset(result, 0, sizeof(*result));
		return DNS_ADDRESS_PARSE_MALFORMED;
	}
	result->rcode = (uint8_t)ns_msg_getflag(response, ns_f_rcode);
	if (result->rcode != ns_r_noerror && result->rcode != ns_r_nxdomain) {
		return DNS_ADDRESS_PARSE_RCODE_ERROR;
	}
	int answer_count = ns_msg_count(response, ns_s_an);
	if (answer_count > DNS_ADDRESS_RECORD_LIMIT) {
		memset(result, 0, sizeof(*result));
		return DNS_ADDRESS_PARSE_LIMIT;
	}
	dns_address_candidate *addresses = NULL;
	dns_cname_record *cnames = NULL;
	if (answer_count > 0) {
		addresses = calloc((size_t)answer_count, sizeof(*addresses));
		cnames = calloc((size_t)answer_count, sizeof(*cnames));
		if (addresses == NULL || cnames == NULL) {
			free(addresses);
			free(cnames);
			memset(result, 0, sizeof(*result));
			return DNS_ADDRESS_PARSE_MEMORY;
		}
	}
	size_t address_count = 0;
	size_t cname_count = 0;
	dns_address_parse_status status = dns_response_addresses_collect(&response, family, addresses, &address_count, cnames, &cname_count);
	if (status == DNS_ADDRESS_PARSE_OK) {
		status = dns_response_chain_build(addresses, address_count, cnames, cname_count, result);
	}
	free(addresses);
	free(cnames);
	if (result->rcode == ns_r_nxdomain) {
		if (status == DNS_ADDRESS_PARSE_OK) {
			status = DNS_ADDRESS_PARSE_MALFORMED;
		} else if (status == DNS_ADDRESS_PARSE_ALIAS_ONLY || status == DNS_ADDRESS_PARSE_NODATA) {
			dns_negative_parse_status negative_status = dns_negative_response_parse(&response, result->canonical_name, result->cnames, result->cname_count, &result->negative);
			status = negative_status == DNS_NEGATIVE_PARSE_OK ? DNS_ADDRESS_PARSE_NXDOMAIN
				: (negative_status == DNS_NEGATIVE_PARSE_LIMIT ? DNS_ADDRESS_PARSE_LIMIT : DNS_ADDRESS_PARSE_MALFORMED);
		}
	} else if (status == DNS_ADDRESS_PARSE_NODATA) {
		dns_negative_parse_status negative_status = dns_negative_response_parse(&response, result->canonical_name, result->cnames, result->cname_count, &result->negative);
		status = negative_status == DNS_NEGATIVE_PARSE_OK ? status : (negative_status == DNS_NEGATIVE_PARSE_LIMIT ? DNS_ADDRESS_PARSE_LIMIT : DNS_ADDRESS_PARSE_MALFORMED);
	}
	if (status != DNS_ADDRESS_PARSE_OK && status != DNS_ADDRESS_PARSE_ALIAS_ONLY && status != DNS_ADDRESS_PARSE_NODATA && status != DNS_ADDRESS_PARSE_NXDOMAIN) {
		dns_address_result_destroy(result);
	}
	return status;
}

void dns_address_result_destroy(dns_address_result *result) {
	if (result == NULL) {
		return;
	}
	free(result->addresses);
	free(result->cnames);
	memset(result, 0, sizeof(*result));
}

dns_srv_lookup_status dns_srv_lookup(const char *query_name, dns_srv_result *result) {
	if (query_name == NULL || query_name[0] == '\0' || strlen(query_name) >= NS_MAXDNAME || result == NULL || !dns_srv_result_empty(result)) {
		return DNS_SRV_LOOKUP_BAD_ARGUMENT;
	}
	struct __res_state resolver;
	memset(&resolver, 0, sizeof(resolver));
	if (!dns_resolver_init(&resolver)) {
		return DNS_SRV_LOOKUP_PERMANENT_ERROR;
	}
	unsigned char *response = malloc(NS_MAXMSG);
	if (response == NULL) {
		res_nclose(&resolver);
		return DNS_SRV_LOOKUP_MEMORY;
	}
	dns_srv_result aggregate = { 0 };
	char current_name[NS_MAXDNAME];
	memcpy(current_name, query_name, strlen(query_name) + 1);
	uint32_t chain_ttl = UINT32_MAX;
	dns_srv_lookup_status lookup_status = DNS_SRV_LOOKUP_PERMANENT_ERROR;
	while (true) {
		int response_size = 0;
		dns_query_exact_status query_status = dns_query_exact(&resolver, current_name, ns_t_srv, response, NS_MAXMSG, &response_size);
		if (query_status != DNS_QUERY_EXACT_OK) {
			switch (query_status) {
				case DNS_QUERY_EXACT_MEMORY:
					lookup_status = DNS_SRV_LOOKUP_MEMORY;
					break;
				case DNS_QUERY_EXACT_MALFORMED:
					lookup_status = DNS_SRV_LOOKUP_MALFORMED;
					break;
				case DNS_QUERY_EXACT_PERMANENT_ERROR:
					lookup_status = DNS_SRV_LOOKUP_PERMANENT_ERROR;
					break;
				case DNS_QUERY_EXACT_TEMPORARY_ERROR:
				default:
					lookup_status = DNS_SRV_LOOKUP_TEMPORARY_ERROR;
					break;
			}
			break;
		}
		if (response_size > NS_MAXMSG) {
			lookup_status = DNS_SRV_LOOKUP_TRUNCATED;
			break;
		}
		dns_srv_result partial = { 0 };
		dns_srv_parse_status parse_status = dns_srv_response_parse(response, (size_t)response_size, &partial);
		if (partial.question_name[0] != '\0' && !dns_name_equal(partial.question_name, current_name)) {
			dns_srv_result_destroy(&partial);
			lookup_status = DNS_SRV_LOOKUP_MALFORMED;
			break;
		}
		lookup_status = dns_srv_lookup_parse_status(parse_status, partial.rcode);
		if (parse_status == DNS_SRV_PARSE_NODATA || parse_status == DNS_SRV_PARSE_NXDOMAIN) {
			dns_srv_lookup_status terminal_status = lookup_status;
			lookup_status = dns_srv_lookup_chain_append(&aggregate, &partial, &chain_ttl);
			if (lookup_status == DNS_SRV_LOOKUP_OK) {
				aggregate.negative = partial.negative;
				if (aggregate.negative.valid && chain_ttl < aggregate.negative.effective_ttl) {
					aggregate.negative.effective_ttl = chain_ttl;
				}
				lookup_status = terminal_status;
			}
			dns_srv_result_destroy(&partial);
			break;
		}
		if (parse_status != DNS_SRV_PARSE_OK && parse_status != DNS_SRV_PARSE_ALIAS_ONLY) {
			if (dns_srv_lookup_status_keeps_result(lookup_status)) {
				if (aggregate.question_name[0] == '\0') {
					aggregate = partial;
					memset(&partial, 0, sizeof(partial));
				} else {
					aggregate.rcode = partial.rcode;
				}
			}
			dns_srv_result_destroy(&partial);
			break;
		}
		lookup_status = dns_srv_lookup_chain_append(&aggregate, &partial, &chain_ttl);
		if (lookup_status != DNS_SRV_LOOKUP_OK) {
			dns_srv_result_destroy(&partial);
			break;
		}
		if (parse_status == DNS_SRV_PARSE_OK) {
			/* Move the SRV record array into the aggregate before destroying the partial result. */
			aggregate.records = partial.records;
			aggregate.record_count = partial.record_count;
			partial.records = NULL;
			partial.record_count = 0;
			for (size_t record_index = 0; record_index < aggregate.record_count; record_index++) {
				if (chain_ttl < aggregate.records[record_index].effective_ttl) {
					aggregate.records[record_index].effective_ttl = chain_ttl;
				}
			}
			dns_srv_result_destroy(&partial);
			break;
		}
		memcpy(current_name, aggregate.canonical_name, sizeof(current_name));
		dns_srv_result_destroy(&partial);
	}
	free(response);
	res_nclose(&resolver);
	if (dns_srv_lookup_status_keeps_result(lookup_status)) {
		*result = aggregate;
	} else {
		dns_srv_result_destroy(&aggregate);
	}
	return lookup_status;
}

dns_srv_parse_status dns_srv_response_parse(const void *message, size_t message_size, dns_srv_result *result) {
	if (message == NULL || message_size > INT_MAX || result == NULL || !dns_srv_result_empty(result)) {
		return DNS_SRV_PARSE_BAD_ARGUMENT;
	}
	ns_msg response;
	if (ns_initparse(message, (int)message_size, &response) != 0) {
		return DNS_SRV_PARSE_MALFORMED;
	}
	if (!ns_msg_getflag(response, ns_f_qr) || ns_msg_getflag(response, ns_f_opcode) != ns_o_query || ns_msg_count(response, ns_s_qd) != 1) {
		return DNS_SRV_PARSE_MALFORMED;
	}
	if (ns_msg_getflag(response, ns_f_tc)) {
		return DNS_SRV_PARSE_TRUNCATED;
	}
	ns_rr question;
	if (ns_parserr(&response, ns_s_qd, 0, &question) != 0 || ns_rr_class(question) != ns_c_in || ns_rr_type(question) != ns_t_srv
		|| !dns_name_normalize(ns_rr_name(question), result->question_name, sizeof(result->question_name))) {
		memset(result, 0, sizeof(*result));
		return DNS_SRV_PARSE_MALFORMED;
	}
	result->rcode = (uint8_t)ns_msg_getflag(response, ns_f_rcode);
	if (result->rcode != ns_r_noerror && result->rcode != ns_r_nxdomain) {
		return DNS_SRV_PARSE_RCODE_ERROR;
	}
	int answer_count = ns_msg_count(response, ns_s_an);
	if (answer_count > DNS_SRV_RECORD_LIMIT) {
		memset(result, 0, sizeof(*result));
		return DNS_SRV_PARSE_LIMIT;
	}
	dns_cname_record *cnames = NULL;
	dns_srv_candidate *records = NULL;
	if (answer_count > 0) {
		cnames = calloc((size_t)answer_count, sizeof(*cnames));
		records = calloc((size_t)answer_count, sizeof(*records));
		if (cnames == NULL || records == NULL) {
			free(cnames);
			free(records);
			memset(result, 0, sizeof(*result));
			return DNS_SRV_PARSE_MEMORY;
		}
	}
	size_t cname_count = 0;
	size_t record_count = 0;
	dns_srv_parse_status status = dns_srv_response_records_collect(&response, records, &record_count, cnames, &cname_count);
	if (status == DNS_SRV_PARSE_OK) {
		status = dns_srv_response_chain_build(records, record_count, cnames, cname_count, result);
	}
	free(cnames);
	free(records);
	if (result->rcode == ns_r_nxdomain) {
		if (status == DNS_SRV_PARSE_OK) {
			status = DNS_SRV_PARSE_MALFORMED;
		} else if (status == DNS_SRV_PARSE_ALIAS_ONLY || status == DNS_SRV_PARSE_NODATA) {
			dns_negative_parse_status negative_status = dns_negative_response_parse(&response, result->canonical_name, result->cnames, result->cname_count, &result->negative);
			status = negative_status == DNS_NEGATIVE_PARSE_OK ? DNS_SRV_PARSE_NXDOMAIN
				: (negative_status == DNS_NEGATIVE_PARSE_LIMIT ? DNS_SRV_PARSE_LIMIT : DNS_SRV_PARSE_MALFORMED);
		}
	} else if (status == DNS_SRV_PARSE_NODATA) {
		dns_negative_parse_status negative_status = dns_negative_response_parse(&response, result->canonical_name, result->cnames, result->cname_count, &result->negative);
		status = negative_status == DNS_NEGATIVE_PARSE_OK ? status : (negative_status == DNS_NEGATIVE_PARSE_LIMIT ? DNS_SRV_PARSE_LIMIT : DNS_SRV_PARSE_MALFORMED);
	}
	if (status != DNS_SRV_PARSE_OK && status != DNS_SRV_PARSE_ALIAS_ONLY && status != DNS_SRV_PARSE_NODATA && status != DNS_SRV_PARSE_NXDOMAIN) {
		dns_srv_result_destroy(result);
	}
	return status;
}

void dns_srv_result_destroy(dns_srv_result *result) {
	if (result == NULL) {
		return;
	}
	free(result->cnames);
	free(result->records);
	memset(result, 0, sizeof(*result));
}

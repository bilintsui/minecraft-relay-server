/*
 * resolver/dns.c: Shared DNS query transport, names and negative responses
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/nameser.h>
#include <errno.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* section: headers (project) */
#include "util.h"

/* section: headers (self) */
#include "dns_internal.h"

/* section: functions (local) */
static bool dns_cname_chain_push(dns_cname_record *chain, size_t *count, const dns_cname_record *record, uint32_t ttl, uint32_t *chain_ttl) {
	for (size_t index = 0; index < *count; index++) {
		if (dns_name_equal(chain[index].owner, record->target)) {
			return false;
		}
	}
	dns_cname_record *next = &chain[(*count)++];
	*next = *record;
	next->ttl = ttl;
	if (ttl < *chain_ttl) {
		*chain_ttl = ttl;
	}
	return true;
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

/* section: functions (exported) */
dns_cname_chain_status dns_cname_chain_extend(dns_cname_record **chain, size_t *chain_count, const dns_cname_record *records, size_t record_count, uint32_t *chain_ttl) {
	if (record_count > DNS_CNAME_DEPTH_LIMIT - *chain_count) {
		return DNS_CNAME_CHAIN_LIMIT;
	}
	if (record_count > 0 && *chain == NULL) {
		*chain = calloc(DNS_CNAME_DEPTH_LIMIT, sizeof(**chain));
		if (*chain == NULL) {
			return DNS_CNAME_CHAIN_MEMORY;
		}
	}
	for (size_t index = 0; index < record_count; index++) {
		if (!dns_cname_chain_push(*chain, chain_count, &records[index], records[index].ttl, chain_ttl)) {
			return DNS_CNAME_CHAIN_MALFORMED;
		}
	}
	return DNS_CNAME_CHAIN_OK;
}

dns_cname_chain_status dns_cname_chain_step(const dns_cname_record *candidates, size_t candidate_count, bool has_answer, char current_name[NS_MAXDNAME],
	dns_cname_record *chain, size_t *chain_count, uint32_t *chain_ttl) {
	const dns_cname_record *match = NULL;
	uint32_t ttl = UINT32_MAX;
	for (size_t index = 0; index < candidate_count; index++) {
		const dns_cname_record *candidate = &candidates[index];
		if (!dns_name_equal(candidate->owner, current_name)) {
			continue;
		}
		if (match != NULL && !dns_name_equal(match->target, candidate->target)) {
			return DNS_CNAME_CHAIN_MALFORMED;
		}
		if (match == NULL) {
			match = candidate;
		}
		if (candidate->ttl < ttl) {
			ttl = candidate->ttl;
		}
	}
	if (match == NULL) {
		return DNS_CNAME_CHAIN_END;
	}
	if (has_answer) {
		return DNS_CNAME_CHAIN_MALFORMED;
	}
	if (*chain_count == DNS_CNAME_DEPTH_LIMIT) {
		return DNS_CNAME_CHAIN_LIMIT;
	}
	if (!dns_cname_chain_push(chain, chain_count, match, ttl, chain_ttl)) {
		return DNS_CNAME_CHAIN_MALFORMED;
	}
	memcpy(current_name, match->target, sizeof(match->target));
	return DNS_CNAME_CHAIN_OK;
}

bool dns_name_equal(const char *left, const char *right) {
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

bool dns_name_normalize(const char *source, char *target, size_t target_size) {
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

bool dns_name_record_parse(const ns_msg *response, const ns_rr *answer, dns_cname_record *record) {
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

dns_negative_parse_status dns_negative_response_parse(ns_msg *response, const char *canonical_name, const dns_cname_record *cnames, size_t cname_count, dns_negative_record *result) {
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
		if (result->valid && strcmp(candidate.owner, result->owner) == 0) {
			if (candidate.minimum < result->minimum) {
				result->minimum = candidate.minimum;
			}
			if (candidate.record_ttl < result->record_ttl) {
				result->record_ttl = candidate.record_ttl;
			}
			result->effective_ttl = result->minimum < result->record_ttl ? result->minimum : result->record_ttl;
		} else if (!result->valid || resolver_name_encloses(result->owner, candidate.owner)) {
			*result = candidate;
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

dns_query_exact_status dns_query_exact(res_state resolver, const char *name, int type, unsigned char *response, int response_capacity, int *response_size, uint16_t *query_id) {
	/* Single-question QUERY without EDNS0: 12-byte header + 255-byte maximum name + type and class fit NS_PACKETSZ. */
	unsigned char query[NS_PACKETSZ];
	int query_size = res_nmkquery(resolver, ns_o_query, name, ns_c_in, type, NULL, 0, NULL, query, (int)sizeof(query));
	if (query_size <= 0 || query_size > (int)sizeof(query)) {
		return DNS_QUERY_EXACT_PERMANENT_ERROR;
	}
	/* The TXID is fixed by res_nmkquery() and left untouched by res_nsend(); responses must carry exactly it. */
	*query_id = ns_get16(query);
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

bool dns_resolver_init(res_state resolver) {
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

/*
 * resolver/dns_address.c: A and AAAA lookups and response parsing
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/nameser.h>
#include <limits.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

/* section: headers (project) */
#include "dns_internal.h"

/* section: headers (self) */
#include "dns.h"

/* section: types */
typedef struct {
	net_addr address;
	char owner[NS_MAXDNAME];
	uint32_t ttl;
} dns_address_candidate;

/* section: functions (local) */
static bool dns_address_result_empty(const dns_address_result *result) {
	return result->addresses == NULL && result->address_count == 0 && result->cnames == NULL && result->cname_count == 0 && result->canonical_name[0] == '\0'
		&& result->negative.effective_ttl == 0 && result->negative.minimum == 0 && result->negative.owner[0] == '\0' && result->negative.record_ttl == 0 && !result->negative.valid
		&& result->question_name[0] == '\0' && result->rcode == 0;
}

static dns_address_lookup_status dns_lookup_chain_append(dns_address_result *target, dns_address_result *source, uint32_t *chain_ttl) {
	if (target->question_name[0] == '\0') {
		memcpy(target->question_name, source->question_name, sizeof(target->question_name));
		memcpy(target->canonical_name, source->question_name, sizeof(target->canonical_name));
	} else if (!dns_name_equal(target->canonical_name, source->question_name)) {
		return DNS_ADDRESS_LOOKUP_MALFORMED;
	}
	dns_cname_chain_status status = dns_cname_chain_extend(&target->cnames, &target->cname_count, source->cnames, source->cname_count, chain_ttl);
	if (status == DNS_CNAME_CHAIN_LIMIT) {
		return DNS_ADDRESS_LOOKUP_LIMIT;
	}
	if (status == DNS_CNAME_CHAIN_MEMORY) {
		return DNS_ADDRESS_LOOKUP_MEMORY;
	}
	if (status != DNS_CNAME_CHAIN_OK) {
		return DNS_ADDRESS_LOOKUP_MALFORMED;
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

static dns_address_parse_status dns_response_addresses_collect(ns_msg *response, sa_family_t family, dns_address_candidate *addresses, size_t *address_count, dns_cname_record *cnames, size_t *cname_count) {
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
		bool matching_address = false;
		for (size_t address_index = 0; address_index < address_count; address_index++) {
			if (dns_name_equal(addresses[address_index].owner, current_name)) {
				matching_address = true;
				break;
			}
		}
		dns_cname_chain_status status = dns_cname_chain_step(cnames, cname_count, matching_address, current_name, result->cnames, &result->cname_count, &chain_ttl);
		if (status == DNS_CNAME_CHAIN_END) {
			break;
		}
		if (status != DNS_CNAME_CHAIN_OK) {
			return status == DNS_CNAME_CHAIN_LIMIT ? DNS_ADDRESS_PARSE_LIMIT : DNS_ADDRESS_PARSE_MALFORMED;
		}
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
		uint16_t query_id = 0;
		dns_query_exact_status query_status = dns_query_exact(&resolver, query_name, query_type, response, NS_MAXMSG, &response_size, &query_id);
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
		dns_address_parse_status parse_status = dns_address_response_parse(response, (size_t)response_size, query_name, query_id, family, &partial);
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

dns_address_parse_status dns_address_response_parse(const void *message, size_t message_size, const char *expected_name, uint16_t expected_id, sa_family_t family, dns_address_result *result) {
	if (message == NULL || message_size > INT_MAX || expected_name == NULL || (family != AF_INET && family != AF_INET6) || result == NULL || !dns_address_result_empty(result)) {
		return DNS_ADDRESS_PARSE_BAD_ARGUMENT;
	}
	ns_msg response;
	if (ns_initparse(message, (int)message_size, &response) != 0) {
		return DNS_ADDRESS_PARSE_MALFORMED;
	}
	if (ns_msg_id(response) != expected_id) {
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
	if (!dns_name_equal(result->question_name, expected_name)) {
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

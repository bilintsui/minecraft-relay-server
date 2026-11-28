/*
 * resolver/dns_srv.c: SRV lookups and response parsing
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

/* section: headers (project) */
#include "dns_internal.h"

/* section: headers (self) */
#include "dns.h"

/* section: types */
typedef struct {
	char owner[NS_MAXDNAME];
	in_port_t port;
	uint16_t priority;
	char target[NS_MAXDNAME];
	uint32_t ttl;
	uint16_t weight;
} dns_srv_candidate;

/* section: functions (local) */
static dns_srv_lookup_status dns_srv_lookup_chain_append(dns_srv_result *target, dns_srv_result *source, uint32_t *chain_ttl) {
	if (target->question_name[0] == '\0') {
		memcpy(target->question_name, source->question_name, sizeof(target->question_name));
		memcpy(target->canonical_name, source->question_name, sizeof(target->canonical_name));
	} else if (!dns_name_equal(target->canonical_name, source->question_name)) {
		return DNS_SRV_LOOKUP_MALFORMED;
	}
	dns_cname_chain_status status = dns_cname_chain_extend(&target->cnames, &target->cname_count, source->cnames, source->cname_count, chain_ttl);
	if (status == DNS_CNAME_CHAIN_LIMIT) {
		return DNS_SRV_LOOKUP_LIMIT;
	}
	if (status == DNS_CNAME_CHAIN_MEMORY) {
		return DNS_SRV_LOOKUP_MEMORY;
	}
	if (status != DNS_CNAME_CHAIN_OK) {
		return DNS_SRV_LOOKUP_MALFORMED;
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
	return status == DNS_SRV_LOOKUP_OK || status == DNS_SRV_LOOKUP_NODATA || status == DNS_SRV_LOOKUP_NOT_FOUND || status == DNS_SRV_LOOKUP_PERMANENT_ERROR || status == DNS_SRV_LOOKUP_TEMPORARY_ERROR;
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
		bool matching_record = false;
		for (size_t record_index = 0; record_index < record_count; record_index++) {
			if (dns_name_equal(records[record_index].owner, current_name)) {
				matching_record = true;
				break;
			}
		}
		dns_cname_chain_status status = dns_cname_chain_step(cnames, cname_count, matching_record, current_name, result->cnames, &result->cname_count, &chain_ttl);
		if (status == DNS_CNAME_CHAIN_END) {
			break;
		}
		if (status != DNS_CNAME_CHAIN_OK) {
			return status == DNS_CNAME_CHAIN_LIMIT ? DNS_SRV_PARSE_LIMIT : DNS_SRV_PARSE_MALFORMED;
		}
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
		uint16_t query_id = 0;
		dns_query_exact_status query_status = dns_query_exact(&resolver, current_name, ns_t_srv, response, NS_MAXMSG, &response_size, &query_id);
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
		dns_srv_parse_status parse_status = dns_srv_response_parse(response, (size_t)response_size, current_name, query_id, &partial);
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

dns_srv_parse_status dns_srv_response_parse(const void *message, size_t message_size, const char *expected_name, uint16_t expected_id, dns_srv_result *result) {
	if (message == NULL || message_size > INT_MAX || expected_name == NULL || result == NULL || !dns_srv_result_empty(result)) {
		return DNS_SRV_PARSE_BAD_ARGUMENT;
	}
	ns_msg response;
	if (ns_initparse(message, (int)message_size, &response) != 0) {
		return DNS_SRV_PARSE_MALFORMED;
	}
	if (ns_msg_id(response) != expected_id) {
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
	if (!dns_name_equal(result->question_name, expected_name)) {
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
			status = negative_status == DNS_NEGATIVE_PARSE_OK ? DNS_SRV_PARSE_NXDOMAIN : (negative_status == DNS_NEGATIVE_PARSE_LIMIT ? DNS_SRV_PARSE_LIMIT : DNS_SRV_PARSE_MALFORMED);
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

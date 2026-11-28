/*
 * resolver/dns_internal.h: Shared DNS query and response helpers
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_RESOLVER_DNS_INTERNAL_H_INCLUDED_

#define _MRS_RESOLVER_DNS_INTERNAL_H_INCLUDED_

/* section: headers (library) */
#include <arpa/nameser.h>
#include <resolv.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* section: headers (project) */
#include "dns.h"

/* section: types */
typedef enum {
	DNS_CNAME_CHAIN_OK,
	DNS_CNAME_CHAIN_END,
	DNS_CNAME_CHAIN_LIMIT,
	DNS_CNAME_CHAIN_MALFORMED,
	DNS_CNAME_CHAIN_MEMORY
} dns_cname_chain_status;
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

/* section: functions (exported) */
/* Append aliases from the next response of an exact-name lookup. */
dns_cname_chain_status dns_cname_chain_extend(dns_cname_record **chain, size_t *chain_count, const dns_cname_record *records, size_t record_count, uint32_t *chain_ttl);
/* Follow one alias, or return END if the current name has none. A nonempty candidate list requires DNS_CNAME_DEPTH_LIMIT slots in chain. */
dns_cname_chain_status dns_cname_chain_step(const dns_cname_record *candidates, size_t candidate_count, bool has_answer, char current_name[NS_MAXDNAME],
	dns_cname_record *chain, size_t *chain_count, uint32_t *chain_ttl);
bool dns_name_equal(const char *left, const char *right);
bool dns_name_normalize(const char *source, char *target, size_t target_size);
bool dns_name_record_parse(const ns_msg *response, const ns_rr *answer, dns_cname_record *record);
dns_negative_parse_status dns_negative_response_parse(ns_msg *response, const char *canonical_name, const dns_cname_record *cnames, size_t cname_count, dns_negative_record *result);
dns_query_exact_status dns_query_exact(res_state resolver, const char *name, int type, unsigned char *response, int response_capacity, int *response_size, uint16_t *query_id);
bool dns_resolver_init(res_state resolver);

#endif

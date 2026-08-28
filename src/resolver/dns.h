/*
 * resolver/dns.h: Header file of resolver/dns.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_RESOLVER_DNS_H_INCLUDED_

#define _MRS_RESOLVER_DNS_H_INCLUDED_

/* section: headers (library) */
#include <arpa/nameser.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

/* section: headers (project) */
#include "../network.h"

/* section: defines */
/* limit */
#define DNS_ADDRESS_RECORD_LIMIT	128
#define DNS_AUTHORITY_RECORD_LIMIT	128
#define DNS_CNAME_DEPTH_LIMIT	16
#define DNS_SRV_RECORD_LIMIT	128

/* resolver
 * These values cap one res_nsend() call, not a complete multi-query CNAME lookup.
 */
#ifndef DNS_QUERY_ATTEMPT_LIMIT
#define DNS_QUERY_ATTEMPT_LIMIT	1
#endif
#ifndef DNS_QUERY_RETRANSMIT_TIMEOUT_SEC
#define DNS_QUERY_RETRANSMIT_TIMEOUT_SEC	2
#endif

/* section: types */
typedef enum {
	DNS_ADDRESS_LOOKUP_OK,
	DNS_ADDRESS_LOOKUP_BAD_ARGUMENT,
	DNS_ADDRESS_LOOKUP_LIMIT,
	DNS_ADDRESS_LOOKUP_MALFORMED,
	DNS_ADDRESS_LOOKUP_MEMORY,
	DNS_ADDRESS_LOOKUP_NODATA,
	DNS_ADDRESS_LOOKUP_NOT_FOUND,
	DNS_ADDRESS_LOOKUP_PERMANENT_ERROR,
	DNS_ADDRESS_LOOKUP_TEMPORARY_ERROR,
	DNS_ADDRESS_LOOKUP_TRUNCATED
} dns_address_lookup_status;
typedef enum {
	DNS_ADDRESS_PARSE_OK,
	DNS_ADDRESS_PARSE_ALIAS_ONLY,
	DNS_ADDRESS_PARSE_NODATA,
	DNS_ADDRESS_PARSE_NXDOMAIN,
	DNS_ADDRESS_PARSE_RCODE_ERROR,
	DNS_ADDRESS_PARSE_TRUNCATED,
	DNS_ADDRESS_PARSE_BAD_ARGUMENT,
	DNS_ADDRESS_PARSE_LIMIT,
	DNS_ADDRESS_PARSE_MALFORMED,
	DNS_ADDRESS_PARSE_MEMORY
} dns_address_parse_status;
typedef struct {
	net_addr address;
	uint32_t effective_ttl;
	uint32_t record_ttl;
} dns_address_record;
typedef struct {
	char owner[NS_MAXDNAME];
	char target[NS_MAXDNAME];
	uint32_t ttl;
} dns_cname_record;
typedef struct {
	uint32_t effective_ttl;
	uint32_t minimum;
	char owner[NS_MAXDNAME];
	uint32_t record_ttl;
	bool valid;
} dns_negative_record;
typedef struct {
	dns_address_record *addresses;
	size_t address_count;
	char canonical_name[NS_MAXDNAME];
	dns_cname_record *cnames;
	size_t cname_count;
	dns_negative_record negative;
	char question_name[NS_MAXDNAME];
	uint8_t rcode;
} dns_address_result;
typedef enum {
	DNS_SRV_LOOKUP_OK,
	DNS_SRV_LOOKUP_BAD_ARGUMENT,
	DNS_SRV_LOOKUP_LIMIT,
	DNS_SRV_LOOKUP_MALFORMED,
	DNS_SRV_LOOKUP_MEMORY,
	DNS_SRV_LOOKUP_NODATA,
	DNS_SRV_LOOKUP_NOT_FOUND,
	DNS_SRV_LOOKUP_PERMANENT_ERROR,
	DNS_SRV_LOOKUP_TEMPORARY_ERROR,
	DNS_SRV_LOOKUP_TRUNCATED
} dns_srv_lookup_status;
typedef enum {
	DNS_SRV_PARSE_OK,
	DNS_SRV_PARSE_ALIAS_ONLY,
	DNS_SRV_PARSE_NODATA,
	DNS_SRV_PARSE_NXDOMAIN,
	DNS_SRV_PARSE_RCODE_ERROR,
	DNS_SRV_PARSE_TRUNCATED,
	DNS_SRV_PARSE_BAD_ARGUMENT,
	DNS_SRV_PARSE_LIMIT,
	DNS_SRV_PARSE_MALFORMED,
	DNS_SRV_PARSE_MEMORY
} dns_srv_parse_status;
typedef struct {
	uint16_t priority;
	uint16_t weight;
	in_port_t port;
	char target[NS_MAXDNAME];
	uint32_t record_ttl;
	uint32_t effective_ttl;
} dns_srv_record;
typedef struct {
	char canonical_name[NS_MAXDNAME];
	dns_cname_record *cnames;
	size_t cname_count;
	dns_negative_record negative;
	char question_name[NS_MAXDNAME];
	uint8_t rcode;
	dns_srv_record *records;
	size_t record_count;
} dns_srv_result;

/* section: functions (exported) */
/* Results passed to these functions must be zero-initialized or previously destroyed. */
/* DNS lookup names are exact QNAMEs; these functions do not apply search domains or replace the system NSS resolver. */
dns_address_lookup_status dns_address_lookup(const char *hostname, sa_family_t family, dns_address_result *result);
/* Parses a response only when its TXID matches expected_id and its question name matches expected_name (case-insensitive, one trailing root dot ignored). */
dns_address_parse_status dns_address_response_parse(const void *message, size_t message_size, const char *expected_name, uint16_t expected_id, sa_family_t family,
	dns_address_result *result);
void dns_address_result_destroy(dns_address_result *result);
dns_srv_lookup_status dns_srv_lookup(const char *query_name, dns_srv_result *result);
/* Parses a response only when its TXID matches expected_id and its question name matches expected_name (case-insensitive, one trailing root dot ignored). */
dns_srv_parse_status dns_srv_response_parse(const void *message, size_t message_size, const char *expected_name, uint16_t expected_id, dns_srv_result *result);
void dns_srv_result_destroy(dns_srv_result *result);

#endif

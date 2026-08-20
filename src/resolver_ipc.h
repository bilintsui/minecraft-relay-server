/*
 * resolver_ipc.h: Resolver helper IPC packet codec
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_RESOLVER_IPC_H_INCLUDED_

#define _MRS_RESOLVER_IPC_H_INCLUDED_

/* section: headers (library) */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* section: headers (project) */
#include "dns.h"

/* section: defines */
/* protocol */
#define RESOLVER_IPC_PACKET_BYTE_LIMIT	4096
#define RESOLVER_IPC_PROTOCOL_VERSION	1

/*
 * Wire integers use big-endian fixed-width encoding; the in-memory declarations below are never copied directly to the wire.
 * A request occupies one packet. A response is BEGIN, zero or more CNAME packets, zero or more ADDRESS or SRV packets, then END.
 * Every packet carries the protocol version, packet kind, exact packet size, and a nonzero query ID in its common header.
 */

/* section: types */
typedef enum {
	RESOLVER_IPC_ADDRESS_IPV4 = 1,
	RESOLVER_IPC_ADDRESS_IPV6 = 2
} resolver_ipc_address_family;
typedef enum {
	RESOLVER_IPC_CODEC_OK,
	RESOLVER_IPC_CODEC_BAD_ARGUMENT,
	RESOLVER_IPC_CODEC_LIMIT,
	RESOLVER_IPC_CODEC_MALFORMED,
	RESOLVER_IPC_CODEC_UNSUPPORTED
} resolver_ipc_codec_status;
typedef enum {
	RESOLVER_IPC_LOOKUP_OK = 1,
	RESOLVER_IPC_LOOKUP_BAD_ARGUMENT = 2,
	RESOLVER_IPC_LOOKUP_LIMIT = 3,
	RESOLVER_IPC_LOOKUP_MALFORMED = 4,
	RESOLVER_IPC_LOOKUP_MEMORY = 5,
	RESOLVER_IPC_LOOKUP_NODATA = 6,
	RESOLVER_IPC_LOOKUP_NOT_FOUND = 7,
	RESOLVER_IPC_LOOKUP_PERMANENT_ERROR = 8,
	RESOLVER_IPC_LOOKUP_TEMPORARY_ERROR = 9,
	RESOLVER_IPC_LOOKUP_TRUNCATED = 10
} resolver_ipc_lookup_status;
typedef enum {
	RESOLVER_IPC_PACKET_REQUEST = 1,
	RESOLVER_IPC_PACKET_RESPONSE_BEGIN = 2,
	RESOLVER_IPC_PACKET_RESPONSE_CNAME = 3,
	RESOLVER_IPC_PACKET_RESPONSE_ADDRESS = 4,
	RESOLVER_IPC_PACKET_RESPONSE_SRV = 5,
	RESOLVER_IPC_PACKET_RESPONSE_END = 6
} resolver_ipc_packet_kind;
typedef struct {
	resolver_ipc_packet_kind kind;
	uint64_t query_id;
} resolver_ipc_packet_header;
typedef struct {
	char query_name[NS_MAXDNAME];
	uint16_t query_class;
	uint64_t query_id;
	uint16_t query_type;
} resolver_ipc_request;
typedef struct {
	uint16_t index;
	uint64_t query_id;
	dns_address_record record;
} resolver_ipc_response_address;
typedef struct {
	char canonical_name[NS_MAXDNAME];
	size_t cname_count;
	struct timespec completed_at;
	dns_negative_record negative;
	char question_name[NS_MAXDNAME];
	uint16_t query_class;
	uint64_t query_id;
	uint16_t query_type;
	uint8_t rcode;
	size_t record_count;
	resolver_ipc_lookup_status status;
} resolver_ipc_response_begin;
typedef struct {
	dns_cname_record record;
	uint16_t index;
	uint64_t query_id;
} resolver_ipc_response_cname;
typedef struct {
	size_t cname_count;
	uint64_t query_id;
	size_t record_count;
} resolver_ipc_response_end;
typedef struct {
	uint16_t index;
	uint64_t query_id;
	dns_srv_record record;
} resolver_ipc_response_srv;

/* section: functions (exported) */
bool resolver_ipc_lookup_status_from_address(dns_address_lookup_status source, resolver_ipc_lookup_status *result);
bool resolver_ipc_lookup_status_from_srv(dns_srv_lookup_status source, resolver_ipc_lookup_status *result);
bool resolver_ipc_lookup_status_to_address(resolver_ipc_lookup_status source, dns_address_lookup_status *result);
bool resolver_ipc_lookup_status_to_srv(resolver_ipc_lookup_status source, dns_srv_lookup_status *result);
resolver_ipc_codec_status resolver_ipc_packet_inspect(const void *packet, size_t packet_size, resolver_ipc_packet_header *result);
resolver_ipc_codec_status resolver_ipc_request_decode(const void *packet, size_t packet_size, resolver_ipc_request *result);
resolver_ipc_codec_status resolver_ipc_request_encode(const resolver_ipc_request *request, void *packet, size_t packet_capacity, size_t *packet_size);
resolver_ipc_codec_status resolver_ipc_response_address_decode(const void *packet, size_t packet_size, resolver_ipc_response_address *result);
resolver_ipc_codec_status resolver_ipc_response_address_encode(const resolver_ipc_response_address *response, void *packet, size_t packet_capacity, size_t *packet_size);
resolver_ipc_codec_status resolver_ipc_response_begin_decode(const void *packet, size_t packet_size, resolver_ipc_response_begin *result);
resolver_ipc_codec_status resolver_ipc_response_begin_encode(const resolver_ipc_response_begin *response, void *packet, size_t packet_capacity, size_t *packet_size);
resolver_ipc_codec_status resolver_ipc_response_cname_decode(const void *packet, size_t packet_size, resolver_ipc_response_cname *result);
resolver_ipc_codec_status resolver_ipc_response_cname_encode(const resolver_ipc_response_cname *response, void *packet, size_t packet_capacity, size_t *packet_size);
resolver_ipc_codec_status resolver_ipc_response_end_decode(const void *packet, size_t packet_size, resolver_ipc_response_end *result);
resolver_ipc_codec_status resolver_ipc_response_end_encode(const resolver_ipc_response_end *response, void *packet, size_t packet_capacity, size_t *packet_size);
resolver_ipc_codec_status resolver_ipc_response_srv_decode(const void *packet, size_t packet_size, resolver_ipc_response_srv *result);
resolver_ipc_codec_status resolver_ipc_response_srv_encode(const resolver_ipc_response_srv *response, void *packet, size_t packet_capacity, size_t *packet_size);

#endif

/*
 * resolver/ipc_assembly.c: Listener-side resolver IPC response assembly
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/nameser.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

/* section: headers (project) */
#include "cache.h"
#include "dns.h"
#include "ipc.h"
#include "util.h"

/* section: headers (self) */
#include "ipc_assembly.h"

/* section: types */
typedef enum {
	RESOLVER_IPC_ASSEMBLY_STATE_BEGIN,
	RESOLVER_IPC_ASSEMBLY_STATE_CNAME,
	RESOLVER_IPC_ASSEMBLY_STATE_RECORD,
	RESOLVER_IPC_ASSEMBLY_STATE_END,
	RESOLVER_IPC_ASSEMBLY_STATE_COMPLETE,
	RESOLVER_IPC_ASSEMBLY_STATE_FAILED,
	RESOLVER_IPC_ASSEMBLY_STATE_TAKEN
} resolver_ipc_assembly_state;
struct resolver_ipc_assembly {
	resolver_ipc_assembly_budget *budget;
	uint32_t chain_ttl;
	size_t declared_cname_count;
	size_t declared_record_count;
	size_t dynamic_bytes;
	char expected_name[NS_MAXDNAME];
	resolver_ipc_assembly *next;
	resolver_ipc_assembly_payload payload;
	resolver_ipc_assembly *previous;
	uint16_t query_class;
	uint64_t query_id;
	uint16_t query_type;
	size_t received_cname_count;
	size_t received_record_count;
	resolver_ipc_assembly_state state;
	resolver_ipc_lookup_status status;
	struct timespec completed_at;
};
struct resolver_ipc_assembly_budget {
	resolver_ipc_assembly *assemblies;
	size_t owned_bytes;
};

/* section: functions (local) */
static void resolver_ipc_assembly_data_clear(resolver_ipc_assembly *assembly) {
	if (assembly->query_type == ns_t_srv) {
		dns_srv_result_destroy(&assembly->payload.srv);
	} else {
		dns_address_result_destroy(&assembly->payload.address);
	}
	if (assembly->budget->owned_bytes >= assembly->dynamic_bytes) {
		assembly->budget->owned_bytes -= assembly->dynamic_bytes;
	} else {
		assembly->budget->owned_bytes = 0;
	}
	assembly->dynamic_bytes = 0;
}

static bool resolver_ipc_assembly_name_normalized(const char *name) {
	char normalized[NS_MAXDNAME];
	return resolver_name_normalize(name, normalized) && strcmp(name, normalized) == 0;
}

static bool resolver_ipc_assembly_result_empty(const resolver_ipc_assembly_result *result) {
	return result != NULL && result->budget == NULL && result->completed_at.tv_sec == 0 && result->completed_at.tv_nsec == 0 && result->dynamic_bytes == 0 && result->query_id == 0
		&& result->query_type == 0 && result->status == 0;
}

static uint32_t resolver_ipc_assembly_ttl_expected(uint32_t record_ttl, uint32_t chain_ttl) {
	return record_ttl < chain_ttl ? record_ttl : chain_ttl;
}

static resolver_ipc_assembly_status resolver_ipc_assembly_arrays_allocate(resolver_ipc_assembly *assembly, size_t cname_count, size_t record_count) {
	if (!resolver_cache_result_fits(assembly->query_type, cname_count, record_count)) {
		return RESOLVER_IPC_ASSEMBLY_LIMIT;
	}
	size_t cname_bytes = 0;
	size_t record_bytes;
	size_t record_size = assembly->query_type == ns_t_srv ? sizeof(dns_srv_record) : sizeof(dns_address_record);
	if ((cname_count > 0 && !resolver_size_multiply(DNS_CNAME_DEPTH_LIMIT, sizeof(dns_cname_record), &cname_bytes))
		|| !resolver_size_multiply(record_count, record_size, &record_bytes)) {
		return RESOLVER_IPC_ASSEMBLY_LIMIT;
	}
	size_t allocation_size = cname_bytes;
	if (!resolver_size_add(&allocation_size, record_bytes) || allocation_size > (size_t)RESOLVER_REPLY_ASSEMBLY_BYTE_LIMIT
		|| assembly->budget->owned_bytes > (size_t)RESOLVER_REPLY_ASSEMBLY_BYTE_LIMIT - allocation_size) {
		return RESOLVER_IPC_ASSEMBLY_LIMIT;
	}
	dns_cname_record *cnames = cname_count == 0 ? NULL : calloc(DNS_CNAME_DEPTH_LIMIT, sizeof(*cnames));
	void *records = record_count == 0 ? NULL : calloc(record_count, record_size);
	if ((cname_count > 0 && cnames == NULL) || (record_count > 0 && records == NULL)) {
		free(cnames);
		free(records);
		return RESOLVER_IPC_ASSEMBLY_MEMORY;
	}
	if (assembly->query_type == ns_t_srv) {
		assembly->payload.srv.cnames = cnames;
		assembly->payload.srv.records = records;
	} else {
		assembly->payload.address.addresses = records;
		assembly->payload.address.cnames = cnames;
	}
	assembly->budget->owned_bytes += allocation_size;
	assembly->dynamic_bytes = allocation_size;
	return RESOLVER_IPC_ASSEMBLY_OK;
}

static bool resolver_ipc_assembly_begin_check(const resolver_ipc_assembly *assembly, const resolver_ipc_response_begin *begin) {
	if (begin->query_id != assembly->query_id || begin->query_class != assembly->query_class || begin->query_type != assembly->query_type) {
		return false;
	}
	bool positive = begin->status == RESOLVER_IPC_LOOKUP_OK;
	bool negative = begin->status == RESOLVER_IPC_LOOKUP_NODATA || begin->status == RESOLVER_IPC_LOOKUP_NOT_FOUND;
	bool resolver_error = begin->status == RESOLVER_IPC_LOOKUP_PERMANENT_ERROR || begin->status == RESOLVER_IPC_LOOKUP_TEMPORARY_ERROR;
	if (positive || negative) {
		if (negative && begin->question_name[0] == '\0') {
			return begin->canonical_name[0] == '\0' && begin->cname_count == 0 && begin->record_count == 0 && !begin->negative.valid && begin->rcode == 0;
		}
		if (!resolver_ipc_assembly_name_normalized(begin->question_name) || strcmp(begin->question_name, assembly->expected_name) != 0
			|| !resolver_ipc_assembly_name_normalized(begin->canonical_name)) {
			return false;
		}
		if (begin->status == RESOLVER_IPC_LOOKUP_OK) {
			return begin->rcode == ns_r_noerror && begin->record_count > 0 && !begin->negative.valid;
		}
		return begin->record_count == 0 && ((begin->status == RESOLVER_IPC_LOOKUP_NODATA && begin->rcode == ns_r_noerror)
			|| (begin->status == RESOLVER_IPC_LOOKUP_NOT_FOUND && (begin->rcode == ns_r_nxdomain || (begin->rcode == 0 && !begin->negative.valid))));
	}
	if (resolver_error) {
		if (begin->record_count != 0 || begin->negative.valid) {
			return false;
		}
		if ((begin->status == RESOLVER_IPC_LOOKUP_TEMPORARY_ERROR && begin->rcode != 0 && begin->rcode != ns_r_servfail)
			|| (begin->status == RESOLVER_IPC_LOOKUP_PERMANENT_ERROR && (begin->rcode == ns_r_nxdomain || begin->rcode == ns_r_servfail))) {
			return false;
		}
		if (begin->question_name[0] == '\0') {
			return begin->canonical_name[0] == '\0' && begin->cname_count == 0 && begin->rcode == 0;
		}
		return resolver_ipc_assembly_name_normalized(begin->question_name) && strcmp(begin->question_name, assembly->expected_name) == 0
			&& (begin->cname_count > 0 ? resolver_ipc_assembly_name_normalized(begin->canonical_name) : begin->canonical_name[0] == '\0');
	}
	return begin->cname_count == 0 && begin->record_count == 0 && !begin->negative.valid && begin->question_name[0] == '\0' && begin->canonical_name[0] == '\0'
		&& begin->rcode == 0;
}

static resolver_ipc_assembly_status resolver_ipc_assembly_begin_consume(resolver_ipc_assembly *assembly, const void *packet, size_t packet_size) {
	resolver_ipc_response_begin begin;
	if (resolver_ipc_response_begin_decode(packet, packet_size, &begin) != RESOLVER_IPC_CODEC_OK || !resolver_ipc_assembly_begin_check(assembly, &begin)) {
		return RESOLVER_IPC_ASSEMBLY_PROTOCOL;
	}
	resolver_ipc_assembly_status status = resolver_ipc_assembly_arrays_allocate(assembly, begin.cname_count, begin.record_count);
	if (status != RESOLVER_IPC_ASSEMBLY_OK) {
		return status;
	}
	assembly->chain_ttl = UINT32_MAX;
	assembly->completed_at = begin.completed_at;
	assembly->declared_cname_count = begin.cname_count;
	assembly->declared_record_count = begin.record_count;
	assembly->status = begin.status;
	if (assembly->query_type == ns_t_srv) {
		memcpy(assembly->payload.srv.canonical_name, begin.canonical_name, sizeof(assembly->payload.srv.canonical_name));
		assembly->payload.srv.negative = begin.negative;
		memcpy(assembly->payload.srv.question_name, begin.question_name, sizeof(assembly->payload.srv.question_name));
		assembly->payload.srv.rcode = begin.rcode;
	} else {
		memcpy(assembly->payload.address.canonical_name, begin.canonical_name, sizeof(assembly->payload.address.canonical_name));
		assembly->payload.address.negative = begin.negative;
		memcpy(assembly->payload.address.question_name, begin.question_name, sizeof(assembly->payload.address.question_name));
		assembly->payload.address.rcode = begin.rcode;
	}
	assembly->state = begin.cname_count > 0 ? RESOLVER_IPC_ASSEMBLY_STATE_CNAME
		: (begin.record_count > 0 ? RESOLVER_IPC_ASSEMBLY_STATE_RECORD : RESOLVER_IPC_ASSEMBLY_STATE_END);
	return RESOLVER_IPC_ASSEMBLY_OK;
}

static resolver_ipc_assembly_status resolver_ipc_assembly_cname_consume(resolver_ipc_assembly *assembly, const void *packet, size_t packet_size) {
	resolver_ipc_response_cname response;
	if (resolver_ipc_response_cname_decode(packet, packet_size, &response) != RESOLVER_IPC_CODEC_OK || response.query_id != assembly->query_id
		|| response.index != assembly->received_cname_count || !resolver_ipc_assembly_name_normalized(response.record.owner)
		|| !resolver_ipc_assembly_name_normalized(response.record.target)) {
		return RESOLVER_IPC_ASSEMBLY_PROTOCOL;
	}
	const char *expected_owner;
	if (assembly->received_cname_count == 0) {
		expected_owner = assembly->query_type == ns_t_srv ? assembly->payload.srv.question_name : assembly->payload.address.question_name;
	} else {
		dns_cname_record *cnames = assembly->query_type == ns_t_srv ? assembly->payload.srv.cnames : assembly->payload.address.cnames;
		expected_owner = cnames[assembly->received_cname_count - 1].target;
	}
	if (strcmp(response.record.owner, expected_owner) != 0) {
		return RESOLVER_IPC_ASSEMBLY_PROTOCOL;
	}
	dns_cname_record *cnames = assembly->query_type == ns_t_srv ? assembly->payload.srv.cnames : assembly->payload.address.cnames;
	for (size_t index = 0; index < assembly->received_cname_count; index++) {
		if (strcmp(response.record.target, cnames[index].owner) == 0) {
			return RESOLVER_IPC_ASSEMBLY_PROTOCOL;
		}
	}
	if (strcmp(response.record.target, response.record.owner) == 0) {
		return RESOLVER_IPC_ASSEMBLY_PROTOCOL;
	}
	cnames[assembly->received_cname_count++] = response.record;
	if (response.record.ttl < assembly->chain_ttl) {
		assembly->chain_ttl = response.record.ttl;
	}
	if (assembly->received_cname_count == assembly->declared_cname_count) {
		assembly->state = assembly->declared_record_count > 0 ? RESOLVER_IPC_ASSEMBLY_STATE_RECORD : RESOLVER_IPC_ASSEMBLY_STATE_END;
	}
	return RESOLVER_IPC_ASSEMBLY_OK;
}

static bool resolver_ipc_assembly_complete_check(const resolver_ipc_assembly *assembly) {
	const char *canonical_name = assembly->query_type == ns_t_srv ? assembly->payload.srv.canonical_name : assembly->payload.address.canonical_name;
	const char *question_name = assembly->query_type == ns_t_srv ? assembly->payload.srv.question_name : assembly->payload.address.question_name;
	dns_cname_record *cnames = assembly->query_type == ns_t_srv ? assembly->payload.srv.cnames : assembly->payload.address.cnames;
	bool resolver_error = assembly->status == RESOLVER_IPC_LOOKUP_PERMANENT_ERROR || assembly->status == RESOLVER_IPC_LOOKUP_TEMPORARY_ERROR;
	if (assembly->declared_cname_count > 0) {
		if (strcmp(canonical_name, cnames[assembly->declared_cname_count - 1].target) != 0) {
			return false;
		}
	} else if (!resolver_error && strcmp(canonical_name, question_name) != 0) {
		return false;
	}
	const dns_negative_record *negative = assembly->query_type == ns_t_srv ? &assembly->payload.srv.negative : &assembly->payload.address.negative;
	if (!negative->valid) {
		return true;
	}
	uint32_t expected_ttl = negative->minimum < negative->record_ttl ? negative->minimum : negative->record_ttl;
	expected_ttl = resolver_ipc_assembly_ttl_expected(expected_ttl, assembly->chain_ttl);
	return resolver_ipc_assembly_name_normalized(negative->owner) && resolver_name_encloses(negative->owner, canonical_name)
		&& negative->effective_ttl == expected_ttl;
}

static resolver_ipc_assembly_status resolver_ipc_assembly_end_consume(resolver_ipc_assembly *assembly, const void *packet, size_t packet_size) {
	resolver_ipc_response_end response;
	if (resolver_ipc_response_end_decode(packet, packet_size, &response) != RESOLVER_IPC_CODEC_OK || response.query_id != assembly->query_id
		|| response.cname_count != assembly->declared_cname_count || response.record_count != assembly->declared_record_count
		|| assembly->received_cname_count != assembly->declared_cname_count || assembly->received_record_count != assembly->declared_record_count
		|| !resolver_ipc_assembly_complete_check(assembly)) {
		return RESOLVER_IPC_ASSEMBLY_PROTOCOL;
	}
	if (assembly->query_type == ns_t_srv) {
		assembly->payload.srv.cname_count = assembly->declared_cname_count;
		assembly->payload.srv.record_count = assembly->declared_record_count;
	} else {
		assembly->payload.address.address_count = assembly->declared_record_count;
		assembly->payload.address.cname_count = assembly->declared_cname_count;
	}
	assembly->state = RESOLVER_IPC_ASSEMBLY_STATE_COMPLETE;
	return RESOLVER_IPC_ASSEMBLY_COMPLETE;
}

static resolver_ipc_assembly_status resolver_ipc_assembly_fail(resolver_ipc_assembly *assembly, resolver_ipc_assembly_status status) {
	resolver_ipc_assembly_data_clear(assembly);
	assembly->state = RESOLVER_IPC_ASSEMBLY_STATE_FAILED;
	return status;
}

static void resolver_ipc_assembly_record_commit(resolver_ipc_assembly *assembly, void *records, size_t record_size, const void *record) {
	memcpy((uint8_t *)records + assembly->received_record_count * record_size, record, record_size);
	assembly->received_record_count++;
	if (assembly->received_record_count == assembly->declared_record_count) {
		assembly->state = RESOLVER_IPC_ASSEMBLY_STATE_END;
	}
}

static resolver_ipc_assembly_status resolver_ipc_assembly_record_address_consume(resolver_ipc_assembly *assembly, const void *packet, size_t packet_size) {
	resolver_ipc_response_address response;
	sa_family_t expected_family = assembly->query_type == ns_t_a ? AF_INET : AF_INET6;
	if (resolver_ipc_response_address_decode(packet, packet_size, &response) != RESOLVER_IPC_CODEC_OK || response.query_id != assembly->query_id
		|| response.index != assembly->received_record_count || response.record.address.family != expected_family
		|| response.record.effective_ttl != resolver_ipc_assembly_ttl_expected(response.record.record_ttl, assembly->chain_ttl)) {
		return RESOLVER_IPC_ASSEMBLY_PROTOCOL;
	}
	resolver_ipc_assembly_record_commit(assembly, assembly->payload.address.addresses, sizeof(response.record), &response.record);
	return RESOLVER_IPC_ASSEMBLY_OK;
}

static resolver_ipc_assembly_status resolver_ipc_assembly_record_srv_consume(resolver_ipc_assembly *assembly, const void *packet, size_t packet_size) {
	resolver_ipc_response_srv response;
	if (resolver_ipc_response_srv_decode(packet, packet_size, &response) != RESOLVER_IPC_CODEC_OK || response.query_id != assembly->query_id
		|| response.index != assembly->received_record_count || !resolver_ipc_assembly_name_normalized(response.record.target)
		|| response.record.effective_ttl != resolver_ipc_assembly_ttl_expected(response.record.record_ttl, assembly->chain_ttl)) {
		return RESOLVER_IPC_ASSEMBLY_PROTOCOL;
	}
	resolver_ipc_assembly_record_commit(assembly, assembly->payload.srv.records, sizeof(response.record), &response.record);
	return RESOLVER_IPC_ASSEMBLY_OK;
}

/* section: functions (exported) */
resolver_ipc_assembly_budget *resolver_ipc_assembly_budget_create(void) {
	if (sizeof(resolver_ipc_assembly_budget) > (size_t)RESOLVER_REPLY_ASSEMBLY_BYTE_LIMIT) {
		return NULL;
	}
	resolver_ipc_assembly_budget *budget = calloc(1, sizeof(*budget));
	if (budget != NULL) {
		budget->owned_bytes = sizeof(*budget);
	}
	return budget;
}

void resolver_ipc_assembly_budget_destroy(resolver_ipc_assembly_budget *budget) {
	if (budget == NULL) {
		return;
	}
	while (budget->assemblies != NULL) {
		resolver_ipc_assembly_destroy(budget->assemblies);
	}
	free(budget);
}

size_t resolver_ipc_assembly_budget_owned_bytes(const resolver_ipc_assembly_budget *budget) {
	return budget == NULL ? 0 : budget->owned_bytes;
}

resolver_ipc_assembly_status resolver_ipc_assembly_create(resolver_ipc_assembly_budget *budget, const char *query_name, uint16_t query_class, uint16_t query_type, uint64_t query_id,
	resolver_ipc_assembly **result) {
	if (result != NULL) {
		*result = NULL;
	}
	char normalized_name[NS_MAXDNAME];
	if (budget == NULL || result == NULL || query_class != ns_c_in || (query_type != ns_t_a && query_type != ns_t_aaaa && query_type != ns_t_srv) || query_id == 0
		|| !resolver_name_normalize(query_name, normalized_name)) {
		return RESOLVER_IPC_ASSEMBLY_BAD_ARGUMENT;
	}
	if (sizeof(resolver_ipc_assembly) > (size_t)RESOLVER_REPLY_ASSEMBLY_BYTE_LIMIT
		|| budget->owned_bytes > (size_t)RESOLVER_REPLY_ASSEMBLY_BYTE_LIMIT - sizeof(resolver_ipc_assembly)) {
		return RESOLVER_IPC_ASSEMBLY_LIMIT;
	}
	resolver_ipc_assembly *assembly = calloc(1, sizeof(*assembly));
	if (assembly == NULL) {
		return RESOLVER_IPC_ASSEMBLY_MEMORY;
	}
	assembly->budget = budget;
	memcpy(assembly->expected_name, normalized_name, sizeof(assembly->expected_name));
	assembly->next = budget->assemblies;
	if (assembly->next != NULL) {
		assembly->next->previous = assembly;
	}
	assembly->query_class = query_class;
	assembly->query_id = query_id;
	assembly->query_type = query_type;
	assembly->state = RESOLVER_IPC_ASSEMBLY_STATE_BEGIN;
	budget->assemblies = assembly;
	budget->owned_bytes += sizeof(*assembly);
	*result = assembly;
	return RESOLVER_IPC_ASSEMBLY_OK;
}

void resolver_ipc_assembly_destroy(resolver_ipc_assembly *assembly) {
	if (assembly == NULL) {
		return;
	}
	resolver_ipc_assembly_budget *budget = assembly->budget;
	resolver_ipc_assembly_data_clear(assembly);
	if (assembly->previous == NULL) {
		budget->assemblies = assembly->next;
	} else {
		assembly->previous->next = assembly->next;
	}
	if (assembly->next != NULL) {
		assembly->next->previous = assembly->previous;
	}
	if (budget->owned_bytes >= sizeof(*assembly)) {
		budget->owned_bytes -= sizeof(*assembly);
	} else {
		budget->owned_bytes = 0;
	}
	free(assembly);
}

resolver_ipc_assembly_status resolver_ipc_assembly_packet_consume(resolver_ipc_assembly *assembly, const void *packet, size_t packet_size) {
	if (assembly == NULL || packet == NULL) {
		return RESOLVER_IPC_ASSEMBLY_BAD_ARGUMENT;
	}
	if (assembly->state == RESOLVER_IPC_ASSEMBLY_STATE_COMPLETE || assembly->state == RESOLVER_IPC_ASSEMBLY_STATE_FAILED || assembly->state == RESOLVER_IPC_ASSEMBLY_STATE_TAKEN) {
		return resolver_ipc_assembly_fail(assembly, RESOLVER_IPC_ASSEMBLY_PROTOCOL);
	}
	resolver_ipc_packet_header header;
	if (resolver_ipc_packet_inspect(packet, packet_size, &header) != RESOLVER_IPC_CODEC_OK || header.query_id != assembly->query_id) {
		return resolver_ipc_assembly_fail(assembly, RESOLVER_IPC_ASSEMBLY_PROTOCOL);
	}
	resolver_ipc_assembly_status status;
	switch (assembly->state) {
		case RESOLVER_IPC_ASSEMBLY_STATE_BEGIN:
			status = header.kind == RESOLVER_IPC_PACKET_RESPONSE_BEGIN ? resolver_ipc_assembly_begin_consume(assembly, packet, packet_size) : RESOLVER_IPC_ASSEMBLY_PROTOCOL;
			break;
		case RESOLVER_IPC_ASSEMBLY_STATE_CNAME:
			status = header.kind == RESOLVER_IPC_PACKET_RESPONSE_CNAME ? resolver_ipc_assembly_cname_consume(assembly, packet, packet_size) : RESOLVER_IPC_ASSEMBLY_PROTOCOL;
			break;
		case RESOLVER_IPC_ASSEMBLY_STATE_RECORD:
			if (assembly->query_type == ns_t_srv) {
				status = header.kind == RESOLVER_IPC_PACKET_RESPONSE_SRV ? resolver_ipc_assembly_record_srv_consume(assembly, packet, packet_size) : RESOLVER_IPC_ASSEMBLY_PROTOCOL;
			} else {
				status = header.kind == RESOLVER_IPC_PACKET_RESPONSE_ADDRESS ? resolver_ipc_assembly_record_address_consume(assembly, packet, packet_size)
					: RESOLVER_IPC_ASSEMBLY_PROTOCOL;
			}
			break;
		case RESOLVER_IPC_ASSEMBLY_STATE_END:
			status = header.kind == RESOLVER_IPC_PACKET_RESPONSE_END ? resolver_ipc_assembly_end_consume(assembly, packet, packet_size) : RESOLVER_IPC_ASSEMBLY_PROTOCOL;
			break;
		case RESOLVER_IPC_ASSEMBLY_STATE_COMPLETE:
		case RESOLVER_IPC_ASSEMBLY_STATE_FAILED:
		case RESOLVER_IPC_ASSEMBLY_STATE_TAKEN:
		default:
			status = RESOLVER_IPC_ASSEMBLY_PROTOCOL;
			break;
	}
	return status == RESOLVER_IPC_ASSEMBLY_OK || status == RESOLVER_IPC_ASSEMBLY_COMPLETE ? status : resolver_ipc_assembly_fail(assembly, status);
}

void resolver_ipc_assembly_result_destroy(resolver_ipc_assembly_result *result) {
	if (result == NULL) {
		return;
	}
	if (result->query_type == ns_t_srv) {
		dns_srv_result_destroy(&result->payload.srv);
	} else if (result->query_type == ns_t_a || result->query_type == ns_t_aaaa) {
		dns_address_result_destroy(&result->payload.address);
	}
	if (result->budget != NULL) {
		if (result->budget->owned_bytes >= result->dynamic_bytes) {
			result->budget->owned_bytes -= result->dynamic_bytes;
		} else {
			result->budget->owned_bytes = 0;
		}
	}
	memset(result, 0, sizeof(*result));
}

bool resolver_ipc_assembly_result_take(resolver_ipc_assembly *assembly, resolver_ipc_assembly_result *result) {
	if (assembly == NULL || !resolver_ipc_assembly_result_empty(result) || assembly->state != RESOLVER_IPC_ASSEMBLY_STATE_COMPLETE) {
		return false;
	}
	result->budget = assembly->budget;
	result->completed_at = assembly->completed_at;
	result->dynamic_bytes = assembly->dynamic_bytes;
	result->payload = assembly->payload;
	result->query_id = assembly->query_id;
	result->query_type = assembly->query_type;
	result->status = assembly->status;
	memset(&assembly->payload, 0, sizeof(assembly->payload));
	assembly->dynamic_bytes = 0;
	assembly->state = RESOLVER_IPC_ASSEMBLY_STATE_TAKEN;
	return true;
}

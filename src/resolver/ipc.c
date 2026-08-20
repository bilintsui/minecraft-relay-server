/*
 * resolver/ipc.c: Resolver helper IPC packet codec
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <arpa/nameser.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/* section: headers (self) */
#include "ipc.h"

/* section: defines */
/* packet */
#define RESOLVER_IPC_HEADER_SIZE	20
#define RESOLVER_IPC_MAGIC	UINT32_C(0x4D525350)

/* section: types */
typedef struct {
	const uint8_t *data;
	size_t offset;
	size_t size;
} resolver_ipc_reader;
typedef struct {
	uint8_t *data;
	size_t offset;
	size_t size;
} resolver_ipc_writer;

/* section: functions (local) */
static bool resolver_ipc_address_family_decode(uint16_t encoded, sa_family_t *result) {
	if (result == NULL) {
		return false;
	}
	switch (encoded) {
		case RESOLVER_IPC_ADDRESS_IPV4:
			*result = AF_INET;
			return true;
		case RESOLVER_IPC_ADDRESS_IPV6:
			*result = AF_INET6;
			return true;
	}
	return false;
}

static bool resolver_ipc_address_family_encode(sa_family_t family, uint16_t *result) {
	if (result == NULL) {
		return false;
	}
	switch (family) {
		case AF_INET:
			*result = RESOLVER_IPC_ADDRESS_IPV4;
			return true;
		case AF_INET6:
			*result = RESOLVER_IPC_ADDRESS_IPV6;
			return true;
	}
	return false;
}

static bool resolver_ipc_lookup_status_valid(resolver_ipc_lookup_status status) {
	switch (status) {
		case RESOLVER_IPC_LOOKUP_OK:
		case RESOLVER_IPC_LOOKUP_BAD_ARGUMENT:
		case RESOLVER_IPC_LOOKUP_LIMIT:
		case RESOLVER_IPC_LOOKUP_MALFORMED:
		case RESOLVER_IPC_LOOKUP_MEMORY:
		case RESOLVER_IPC_LOOKUP_NODATA:
		case RESOLVER_IPC_LOOKUP_NOT_FOUND:
		case RESOLVER_IPC_LOOKUP_PERMANENT_ERROR:
		case RESOLVER_IPC_LOOKUP_TEMPORARY_ERROR:
		case RESOLVER_IPC_LOOKUP_TRUNCATED:
			return true;
	}
	return false;
}

static bool resolver_ipc_name_size(const char *name, bool allow_empty, size_t *result) {
	if (name == NULL || result == NULL) {
		return false;
	}
	size_t size = 0;
	while (size < NS_MAXDNAME && name[size] != '\0') {
		size++;
	}
	if (size == NS_MAXDNAME || (!allow_empty && size == 0)) {
		return false;
	}
	*result = size;
	return true;
}

static bool resolver_ipc_negative_valid(const dns_negative_record *negative) {
	if (negative == NULL) {
		return false;
	}
	if (!negative->valid) {
		return negative->effective_ttl == 0 && negative->minimum == 0 && negative->owner[0] == '\0' && negative->record_ttl == 0;
	}
	size_t owner_size;
	return resolver_ipc_name_size(negative->owner, false, &owner_size) && negative->effective_ttl <= negative->minimum && negative->effective_ttl <= negative->record_ttl;
}

static bool resolver_ipc_packet_kind_decode(uint16_t encoded, resolver_ipc_packet_kind *result) {
	if (result == NULL) {
		return false;
	}
	switch (encoded) {
		case RESOLVER_IPC_PACKET_REQUEST:
		case RESOLVER_IPC_PACKET_RESPONSE_BEGIN:
		case RESOLVER_IPC_PACKET_RESPONSE_CNAME:
		case RESOLVER_IPC_PACKET_RESPONSE_ADDRESS:
		case RESOLVER_IPC_PACKET_RESPONSE_SRV:
		case RESOLVER_IPC_PACKET_RESPONSE_END:
			*result = (resolver_ipc_packet_kind)encoded;
			return true;
	}
	return false;
}

static bool resolver_ipc_packet_kind_encode(resolver_ipc_packet_kind kind, uint16_t *result) {
	if (result == NULL) {
		return false;
	}
	switch (kind) {
		case RESOLVER_IPC_PACKET_REQUEST:
		case RESOLVER_IPC_PACKET_RESPONSE_BEGIN:
		case RESOLVER_IPC_PACKET_RESPONSE_CNAME:
		case RESOLVER_IPC_PACKET_RESPONSE_ADDRESS:
		case RESOLVER_IPC_PACKET_RESPONSE_SRV:
		case RESOLVER_IPC_PACKET_RESPONSE_END:
			*result = (uint16_t)kind;
			return true;
	}
	return false;
}

static bool resolver_ipc_query_type_valid(uint16_t query_type) {
	return query_type == ns_t_a || query_type == ns_t_aaaa || query_type == ns_t_srv;
}

static const uint8_t *resolver_ipc_reader_take(resolver_ipc_reader *reader, size_t size) {
	if (reader == NULL || reader->offset > reader->size || size > reader->size - reader->offset) {
		return NULL;
	}
	const uint8_t *result = reader->data + reader->offset;
	reader->offset += size;
	return result;
}

static bool resolver_ipc_reader_name(resolver_ipc_reader *reader, uint16_t size, bool allow_empty, char result[NS_MAXDNAME]) {
	if (result == NULL || size >= NS_MAXDNAME || (!allow_empty && size == 0)) {
		return false;
	}
	const uint8_t *source = resolver_ipc_reader_take(reader, size);
	if (source == NULL || memchr(source, '\0', size) != NULL) {
		return false;
	}
	memcpy(result, source, size);
	result[size] = '\0';
	return true;
}

static bool resolver_ipc_reader_u8(resolver_ipc_reader *reader, uint8_t *result) {
	const uint8_t *source = resolver_ipc_reader_take(reader, sizeof(*source));
	if (source == NULL || result == NULL) {
		return false;
	}
	*result = source[0];
	return true;
}

static bool resolver_ipc_reader_u16(resolver_ipc_reader *reader, uint16_t *result) {
	const uint8_t *source = resolver_ipc_reader_take(reader, sizeof(uint16_t));
	if (source == NULL || result == NULL) {
		return false;
	}
	*result = (uint16_t)((uint16_t)source[0] << 8) | source[1];
	return true;
}

static bool resolver_ipc_reader_u32(resolver_ipc_reader *reader, uint32_t *result) {
	const uint8_t *source = resolver_ipc_reader_take(reader, sizeof(uint32_t));
	if (source == NULL || result == NULL) {
		return false;
	}
	*result = (uint32_t)source[0] << 24 | (uint32_t)source[1] << 16 | (uint32_t)source[2] << 8 | source[3];
	return true;
}

static bool resolver_ipc_reader_u64(resolver_ipc_reader *reader, uint64_t *result) {
	const uint8_t *source = resolver_ipc_reader_take(reader, sizeof(uint64_t));
	if (source == NULL || result == NULL) {
		return false;
	}
	uint64_t value = 0;
	for (size_t index = 0; index < sizeof(uint64_t); index++) {
		value = value << 8 | source[index];
	}
	*result = value;
	return true;
}

static bool resolver_ipc_status_decode(uint16_t encoded, resolver_ipc_lookup_status *result) {
	resolver_ipc_lookup_status status = (resolver_ipc_lookup_status)encoded;
	if (result == NULL || !resolver_ipc_lookup_status_valid(status)) {
		return false;
	}
	*result = status;
	return true;
}

static bool resolver_ipc_status_encode(resolver_ipc_lookup_status status, uint16_t *result) {
	if (result == NULL || !resolver_ipc_lookup_status_valid(status)) {
		return false;
	}
	*result = (uint16_t)status;
	return true;
}

static bool resolver_ipc_time_decode(uint64_t seconds, uint32_t nanoseconds, struct timespec *result) {
	if (result == NULL || nanoseconds >= 1000000000U) {
		return false;
	}
	time_t converted_seconds = (time_t)seconds;
	if (converted_seconds < 0 || (uint64_t)converted_seconds != seconds) {
		return false;
	}
	result->tv_sec = converted_seconds;
	result->tv_nsec = (long)nanoseconds;
	return true;
}

static bool resolver_ipc_time_encode(const struct timespec *source, uint64_t *seconds, uint32_t *nanoseconds) {
	if (source == NULL || seconds == NULL || nanoseconds == NULL || source->tv_sec < 0 || source->tv_nsec < 0 || source->tv_nsec >= 1000000000L) {
		return false;
	}
	uint64_t converted_seconds = (uint64_t)source->tv_sec;
	if ((time_t)converted_seconds != source->tv_sec) {
		return false;
	}
	*seconds = converted_seconds;
	*nanoseconds = (uint32_t)source->tv_nsec;
	return true;
}

static uint8_t *resolver_ipc_writer_take(resolver_ipc_writer *writer, size_t size) {
	if (writer == NULL || writer->offset > writer->size || size > writer->size - writer->offset) {
		return NULL;
	}
	uint8_t *result = writer->data + writer->offset;
	writer->offset += size;
	return result;
}

static bool resolver_ipc_writer_bytes(resolver_ipc_writer *writer, const void *source, size_t size) {
	uint8_t *target = resolver_ipc_writer_take(writer, size);
	if (target == NULL || (source == NULL && size != 0)) {
		return false;
	}
	if (size != 0) {
		memcpy(target, source, size);
	}
	return true;
}

static bool resolver_ipc_writer_u8(resolver_ipc_writer *writer, uint8_t value) {
	uint8_t *target = resolver_ipc_writer_take(writer, sizeof(value));
	if (target == NULL) {
		return false;
	}
	target[0] = value;
	return true;
}

static bool resolver_ipc_writer_u16(resolver_ipc_writer *writer, uint16_t value) {
	uint8_t *target = resolver_ipc_writer_take(writer, sizeof(value));
	if (target == NULL) {
		return false;
	}
	target[0] = (uint8_t)(value >> 8);
	target[1] = (uint8_t)value;
	return true;
}

static bool resolver_ipc_writer_u32(resolver_ipc_writer *writer, uint32_t value) {
	uint8_t *target = resolver_ipc_writer_take(writer, sizeof(value));
	if (target == NULL) {
		return false;
	}
	target[0] = (uint8_t)(value >> 24);
	target[1] = (uint8_t)(value >> 16);
	target[2] = (uint8_t)(value >> 8);
	target[3] = (uint8_t)value;
	return true;
}

static bool resolver_ipc_writer_u64(resolver_ipc_writer *writer, uint64_t value) {
	uint8_t *target = resolver_ipc_writer_take(writer, sizeof(value));
	if (target == NULL) {
		return false;
	}
	for (size_t index = 0; index < sizeof(value); index++) {
		target[sizeof(value) - index - 1] = (uint8_t)value;
		value >>= 8;
	}
	return true;
}

static resolver_ipc_codec_status resolver_ipc_header_decode(const void *packet, size_t packet_size, resolver_ipc_packet_kind expected_kind, resolver_ipc_reader *reader,
	resolver_ipc_packet_header *result) {
	if (packet == NULL || reader == NULL || result == NULL) {
		return RESOLVER_IPC_CODEC_BAD_ARGUMENT;
	}
	memset(result, 0, sizeof(*result));
	if (packet_size > RESOLVER_IPC_PACKET_BYTE_LIMIT) {
		return RESOLVER_IPC_CODEC_LIMIT;
	}
	if (packet_size < RESOLVER_IPC_HEADER_SIZE) {
		return RESOLVER_IPC_CODEC_MALFORMED;
	}
	reader->data = packet;
	reader->offset = 0;
	reader->size = packet_size;
	uint32_t magic;
	uint16_t version;
	uint16_t encoded_kind;
	uint16_t encoded_size;
	uint16_t reserved;
	if (!resolver_ipc_reader_u32(reader, &magic) || !resolver_ipc_reader_u16(reader, &version) || !resolver_ipc_reader_u16(reader, &encoded_kind)
		|| !resolver_ipc_reader_u16(reader, &encoded_size) || !resolver_ipc_reader_u16(reader, &reserved) || !resolver_ipc_reader_u64(reader, &result->query_id)) {
		return RESOLVER_IPC_CODEC_MALFORMED;
	}
	if (magic != RESOLVER_IPC_MAGIC || encoded_size != packet_size || reserved != 0 || result->query_id == 0) {
		return RESOLVER_IPC_CODEC_MALFORMED;
	}
	if (version != RESOLVER_IPC_PROTOCOL_VERSION) {
		return RESOLVER_IPC_CODEC_UNSUPPORTED;
	}
	if (!resolver_ipc_packet_kind_decode(encoded_kind, &result->kind)) {
		return RESOLVER_IPC_CODEC_UNSUPPORTED;
	}
	if (expected_kind != 0 && result->kind != expected_kind) {
		return RESOLVER_IPC_CODEC_MALFORMED;
	}
	return RESOLVER_IPC_CODEC_OK;
}

static resolver_ipc_codec_status resolver_ipc_header_encode(resolver_ipc_packet_kind kind, uint64_t query_id, void *packet, size_t packet_capacity, size_t packet_size,
	resolver_ipc_writer *writer) {
	if (packet == NULL || writer == NULL || query_id == 0) {
		return RESOLVER_IPC_CODEC_BAD_ARGUMENT;
	}
	if (packet_size > RESOLVER_IPC_PACKET_BYTE_LIMIT || packet_size > UINT16_MAX || packet_capacity < packet_size) {
		return RESOLVER_IPC_CODEC_LIMIT;
	}
	uint16_t encoded_kind;
	if (!resolver_ipc_packet_kind_encode(kind, &encoded_kind)) {
		return RESOLVER_IPC_CODEC_BAD_ARGUMENT;
	}
	writer->data = packet;
	writer->offset = 0;
	writer->size = packet_size;
	if (!resolver_ipc_writer_u32(writer, RESOLVER_IPC_MAGIC) || !resolver_ipc_writer_u16(writer, RESOLVER_IPC_PROTOCOL_VERSION)
		|| !resolver_ipc_writer_u16(writer, encoded_kind) || !resolver_ipc_writer_u16(writer, (uint16_t)packet_size) || !resolver_ipc_writer_u16(writer, 0)
		|| !resolver_ipc_writer_u64(writer, query_id)) {
		return RESOLVER_IPC_CODEC_LIMIT;
	}
	return RESOLVER_IPC_CODEC_OK;
}

static bool resolver_ipc_response_count_valid(uint16_t query_type, size_t cname_count, size_t record_count) {
	if (cname_count > DNS_CNAME_DEPTH_LIMIT) {
		return false;
	}
	if (query_type == ns_t_a || query_type == ns_t_aaaa) {
		return record_count <= DNS_ADDRESS_RECORD_LIMIT;
	}
	return query_type == ns_t_srv && record_count <= DNS_SRV_RECORD_LIMIT;
}

/* section: functions (exported) */
bool resolver_ipc_lookup_status_from_address(dns_address_lookup_status source, resolver_ipc_lookup_status *result) {
	if (result == NULL) {
		return false;
	}
	switch (source) {
		case DNS_ADDRESS_LOOKUP_OK:
			*result = RESOLVER_IPC_LOOKUP_OK;
			return true;
		case DNS_ADDRESS_LOOKUP_BAD_ARGUMENT:
			*result = RESOLVER_IPC_LOOKUP_BAD_ARGUMENT;
			return true;
		case DNS_ADDRESS_LOOKUP_LIMIT:
			*result = RESOLVER_IPC_LOOKUP_LIMIT;
			return true;
		case DNS_ADDRESS_LOOKUP_MALFORMED:
			*result = RESOLVER_IPC_LOOKUP_MALFORMED;
			return true;
		case DNS_ADDRESS_LOOKUP_MEMORY:
			*result = RESOLVER_IPC_LOOKUP_MEMORY;
			return true;
		case DNS_ADDRESS_LOOKUP_NODATA:
			*result = RESOLVER_IPC_LOOKUP_NODATA;
			return true;
		case DNS_ADDRESS_LOOKUP_NOT_FOUND:
			*result = RESOLVER_IPC_LOOKUP_NOT_FOUND;
			return true;
		case DNS_ADDRESS_LOOKUP_PERMANENT_ERROR:
			*result = RESOLVER_IPC_LOOKUP_PERMANENT_ERROR;
			return true;
		case DNS_ADDRESS_LOOKUP_TEMPORARY_ERROR:
			*result = RESOLVER_IPC_LOOKUP_TEMPORARY_ERROR;
			return true;
		case DNS_ADDRESS_LOOKUP_TRUNCATED:
			*result = RESOLVER_IPC_LOOKUP_TRUNCATED;
			return true;
	}
	return false;
}

bool resolver_ipc_lookup_status_from_srv(dns_srv_lookup_status source, resolver_ipc_lookup_status *result) {
	if (result == NULL) {
		return false;
	}
	switch (source) {
		case DNS_SRV_LOOKUP_OK:
			*result = RESOLVER_IPC_LOOKUP_OK;
			return true;
		case DNS_SRV_LOOKUP_BAD_ARGUMENT:
			*result = RESOLVER_IPC_LOOKUP_BAD_ARGUMENT;
			return true;
		case DNS_SRV_LOOKUP_LIMIT:
			*result = RESOLVER_IPC_LOOKUP_LIMIT;
			return true;
		case DNS_SRV_LOOKUP_MALFORMED:
			*result = RESOLVER_IPC_LOOKUP_MALFORMED;
			return true;
		case DNS_SRV_LOOKUP_MEMORY:
			*result = RESOLVER_IPC_LOOKUP_MEMORY;
			return true;
		case DNS_SRV_LOOKUP_NODATA:
			*result = RESOLVER_IPC_LOOKUP_NODATA;
			return true;
		case DNS_SRV_LOOKUP_NOT_FOUND:
			*result = RESOLVER_IPC_LOOKUP_NOT_FOUND;
			return true;
		case DNS_SRV_LOOKUP_PERMANENT_ERROR:
			*result = RESOLVER_IPC_LOOKUP_PERMANENT_ERROR;
			return true;
		case DNS_SRV_LOOKUP_TEMPORARY_ERROR:
			*result = RESOLVER_IPC_LOOKUP_TEMPORARY_ERROR;
			return true;
		case DNS_SRV_LOOKUP_TRUNCATED:
			*result = RESOLVER_IPC_LOOKUP_TRUNCATED;
			return true;
	}
	return false;
}

bool resolver_ipc_lookup_status_to_address(resolver_ipc_lookup_status source, dns_address_lookup_status *result) {
	if (result == NULL) {
		return false;
	}
	switch (source) {
		case RESOLVER_IPC_LOOKUP_OK:
			*result = DNS_ADDRESS_LOOKUP_OK;
			return true;
		case RESOLVER_IPC_LOOKUP_BAD_ARGUMENT:
			*result = DNS_ADDRESS_LOOKUP_BAD_ARGUMENT;
			return true;
		case RESOLVER_IPC_LOOKUP_LIMIT:
			*result = DNS_ADDRESS_LOOKUP_LIMIT;
			return true;
		case RESOLVER_IPC_LOOKUP_MALFORMED:
			*result = DNS_ADDRESS_LOOKUP_MALFORMED;
			return true;
		case RESOLVER_IPC_LOOKUP_MEMORY:
			*result = DNS_ADDRESS_LOOKUP_MEMORY;
			return true;
		case RESOLVER_IPC_LOOKUP_NODATA:
			*result = DNS_ADDRESS_LOOKUP_NODATA;
			return true;
		case RESOLVER_IPC_LOOKUP_NOT_FOUND:
			*result = DNS_ADDRESS_LOOKUP_NOT_FOUND;
			return true;
		case RESOLVER_IPC_LOOKUP_PERMANENT_ERROR:
			*result = DNS_ADDRESS_LOOKUP_PERMANENT_ERROR;
			return true;
		case RESOLVER_IPC_LOOKUP_TEMPORARY_ERROR:
			*result = DNS_ADDRESS_LOOKUP_TEMPORARY_ERROR;
			return true;
		case RESOLVER_IPC_LOOKUP_TRUNCATED:
			*result = DNS_ADDRESS_LOOKUP_TRUNCATED;
			return true;
	}
	return false;
}

bool resolver_ipc_lookup_status_to_srv(resolver_ipc_lookup_status source, dns_srv_lookup_status *result) {
	if (result == NULL) {
		return false;
	}
	switch (source) {
		case RESOLVER_IPC_LOOKUP_OK:
			*result = DNS_SRV_LOOKUP_OK;
			return true;
		case RESOLVER_IPC_LOOKUP_BAD_ARGUMENT:
			*result = DNS_SRV_LOOKUP_BAD_ARGUMENT;
			return true;
		case RESOLVER_IPC_LOOKUP_LIMIT:
			*result = DNS_SRV_LOOKUP_LIMIT;
			return true;
		case RESOLVER_IPC_LOOKUP_MALFORMED:
			*result = DNS_SRV_LOOKUP_MALFORMED;
			return true;
		case RESOLVER_IPC_LOOKUP_MEMORY:
			*result = DNS_SRV_LOOKUP_MEMORY;
			return true;
		case RESOLVER_IPC_LOOKUP_NODATA:
			*result = DNS_SRV_LOOKUP_NODATA;
			return true;
		case RESOLVER_IPC_LOOKUP_NOT_FOUND:
			*result = DNS_SRV_LOOKUP_NOT_FOUND;
			return true;
		case RESOLVER_IPC_LOOKUP_PERMANENT_ERROR:
			*result = DNS_SRV_LOOKUP_PERMANENT_ERROR;
			return true;
		case RESOLVER_IPC_LOOKUP_TEMPORARY_ERROR:
			*result = DNS_SRV_LOOKUP_TEMPORARY_ERROR;
			return true;
		case RESOLVER_IPC_LOOKUP_TRUNCATED:
			*result = DNS_SRV_LOOKUP_TRUNCATED;
			return true;
	}
	return false;
}

resolver_ipc_codec_status resolver_ipc_packet_inspect(const void *packet, size_t packet_size, resolver_ipc_packet_header *result) {
	if (result != NULL) {
		memset(result, 0, sizeof(*result));
	}
	if (result == NULL) {
		return RESOLVER_IPC_CODEC_BAD_ARGUMENT;
	}
	resolver_ipc_reader reader;
	resolver_ipc_packet_header candidate;
	resolver_ipc_codec_status status = resolver_ipc_header_decode(packet, packet_size, 0, &reader, &candidate);
	if (status == RESOLVER_IPC_CODEC_OK) {
		*result = candidate;
	}
	return status;
}

resolver_ipc_codec_status resolver_ipc_request_decode(const void *packet, size_t packet_size, resolver_ipc_request *result) {
	if (result != NULL) {
		memset(result, 0, sizeof(*result));
	}
	if (result == NULL) {
		return RESOLVER_IPC_CODEC_BAD_ARGUMENT;
	}
	resolver_ipc_reader reader;
	resolver_ipc_packet_header header;
	resolver_ipc_codec_status status = resolver_ipc_header_decode(packet, packet_size, RESOLVER_IPC_PACKET_REQUEST, &reader, &header);
	if (status != RESOLVER_IPC_CODEC_OK) {
		return status;
	}
	uint16_t name_size;
	if (!resolver_ipc_reader_u16(&reader, &result->query_class) || !resolver_ipc_reader_u16(&reader, &result->query_type) || !resolver_ipc_reader_u16(&reader, &name_size)
		|| result->query_class != ns_c_in || !resolver_ipc_query_type_valid(result->query_type) || !resolver_ipc_reader_name(&reader, name_size, false, result->query_name)
		|| reader.offset != reader.size) {
		memset(result, 0, sizeof(*result));
		return RESOLVER_IPC_CODEC_MALFORMED;
	}
	result->query_id = header.query_id;
	return RESOLVER_IPC_CODEC_OK;
}

resolver_ipc_codec_status resolver_ipc_request_encode(const resolver_ipc_request *request, void *packet, size_t packet_capacity, size_t *packet_size) {
	if (packet_size != NULL) {
		*packet_size = 0;
	}
	if (request == NULL || packet == NULL || packet_size == NULL || request->query_class != ns_c_in || !resolver_ipc_query_type_valid(request->query_type)) {
		return RESOLVER_IPC_CODEC_BAD_ARGUMENT;
	}
	size_t name_size;
	if (!resolver_ipc_name_size(request->query_name, false, &name_size)) {
		return RESOLVER_IPC_CODEC_BAD_ARGUMENT;
	}
	size_t encoded_size = RESOLVER_IPC_HEADER_SIZE + sizeof(uint16_t) * 3 + name_size;
	resolver_ipc_writer writer;
	resolver_ipc_codec_status status = resolver_ipc_header_encode(RESOLVER_IPC_PACKET_REQUEST, request->query_id, packet, packet_capacity, encoded_size, &writer);
	if (status != RESOLVER_IPC_CODEC_OK) {
		return status;
	}
	if (!resolver_ipc_writer_u16(&writer, request->query_class) || !resolver_ipc_writer_u16(&writer, request->query_type) || !resolver_ipc_writer_u16(&writer, (uint16_t)name_size)
		|| !resolver_ipc_writer_bytes(&writer, request->query_name, name_size) || writer.offset != writer.size) {
		return RESOLVER_IPC_CODEC_LIMIT;
	}
	*packet_size = encoded_size;
	return RESOLVER_IPC_CODEC_OK;
}

resolver_ipc_codec_status resolver_ipc_response_address_decode(const void *packet, size_t packet_size, resolver_ipc_response_address *result) {
	if (result != NULL) {
		memset(result, 0, sizeof(*result));
	}
	if (result == NULL) {
		return RESOLVER_IPC_CODEC_BAD_ARGUMENT;
	}
	resolver_ipc_reader reader;
	resolver_ipc_packet_header header;
	resolver_ipc_codec_status status = resolver_ipc_header_decode(packet, packet_size, RESOLVER_IPC_PACKET_RESPONSE_ADDRESS, &reader, &header);
	if (status != RESOLVER_IPC_CODEC_OK) {
		return status;
	}
	uint16_t family;
	uint16_t address_size;
	sa_family_t decoded_family;
	if (!resolver_ipc_reader_u16(&reader, &result->index) || !resolver_ipc_reader_u16(&reader, &family) || !resolver_ipc_reader_u32(&reader, &result->record.record_ttl)
		|| !resolver_ipc_reader_u32(&reader, &result->record.effective_ttl) || !resolver_ipc_reader_u16(&reader, &address_size) || result->index >= DNS_ADDRESS_RECORD_LIMIT
		|| result->record.effective_ttl > result->record.record_ttl || !resolver_ipc_address_family_decode(family, &decoded_family)) {
		memset(result, 0, sizeof(*result));
		return RESOLVER_IPC_CODEC_MALFORMED;
	}
	const uint8_t *address = resolver_ipc_reader_take(&reader, address_size);
	if (address == NULL || reader.offset != reader.size || (decoded_family == AF_INET && address_size != sizeof(result->record.address.addr.v4))
		|| (decoded_family == AF_INET6 && address_size != sizeof(result->record.address.addr.v6))) {
		memset(result, 0, sizeof(*result));
		return RESOLVER_IPC_CODEC_MALFORMED;
	}
	result->query_id = header.query_id;
	result->record.address.family = decoded_family;
	if (decoded_family == AF_INET) {
		memcpy(&result->record.address.addr.v4, address, address_size);
	} else {
		memcpy(result->record.address.addr.v6, address, address_size);
	}
	return RESOLVER_IPC_CODEC_OK;
}

resolver_ipc_codec_status resolver_ipc_response_address_encode(const resolver_ipc_response_address *response, void *packet, size_t packet_capacity, size_t *packet_size) {
	if (packet_size != NULL) {
		*packet_size = 0;
	}
	if (response == NULL || packet == NULL || packet_size == NULL || response->index >= DNS_ADDRESS_RECORD_LIMIT || response->record.address.err != NET_OK
		|| response->record.effective_ttl > response->record.record_ttl || (response->record.address.family != AF_INET && response->record.address.family != AF_INET6)) {
		return RESOLVER_IPC_CODEC_BAD_ARGUMENT;
	}
	size_t address_size = response->record.address.family == AF_INET ? sizeof(response->record.address.addr.v4) : sizeof(response->record.address.addr.v6);
	size_t encoded_size = RESOLVER_IPC_HEADER_SIZE + sizeof(uint16_t) * 3 + sizeof(uint32_t) * 2 + address_size;
	resolver_ipc_writer writer;
	resolver_ipc_codec_status status = resolver_ipc_header_encode(RESOLVER_IPC_PACKET_RESPONSE_ADDRESS, response->query_id, packet, packet_capacity, encoded_size, &writer);
	if (status != RESOLVER_IPC_CODEC_OK) {
		return status;
	}
	uint16_t encoded_family;
	if (!resolver_ipc_address_family_encode(response->record.address.family, &encoded_family)) {
		return RESOLVER_IPC_CODEC_BAD_ARGUMENT;
	}
	const void *address = response->record.address.family == AF_INET ? (const void *)&response->record.address.addr.v4 : response->record.address.addr.v6;
	if (!resolver_ipc_writer_u16(&writer, response->index) || !resolver_ipc_writer_u16(&writer, encoded_family)
		|| !resolver_ipc_writer_u32(&writer, response->record.record_ttl) || !resolver_ipc_writer_u32(&writer, response->record.effective_ttl)
		|| !resolver_ipc_writer_u16(&writer, (uint16_t)address_size) || !resolver_ipc_writer_bytes(&writer, address, address_size) || writer.offset != writer.size) {
		return RESOLVER_IPC_CODEC_LIMIT;
	}
	*packet_size = encoded_size;
	return RESOLVER_IPC_CODEC_OK;
}

resolver_ipc_codec_status resolver_ipc_response_begin_decode(const void *packet, size_t packet_size, resolver_ipc_response_begin *result) {
	if (result != NULL) {
		memset(result, 0, sizeof(*result));
	}
	if (result == NULL) {
		return RESOLVER_IPC_CODEC_BAD_ARGUMENT;
	}
	resolver_ipc_reader reader;
	resolver_ipc_packet_header header;
	resolver_ipc_codec_status status = resolver_ipc_header_decode(packet, packet_size, RESOLVER_IPC_PACKET_RESPONSE_BEGIN, &reader, &header);
	if (status != RESOLVER_IPC_CODEC_OK) {
		return status;
	}
	uint16_t encoded_status;
	uint8_t negative_valid;
	uint64_t seconds;
	uint32_t nanoseconds;
	uint16_t cname_count;
	uint16_t record_count;
	uint16_t question_size;
	uint16_t canonical_size;
	uint16_t negative_owner_size;
	if (!resolver_ipc_reader_u16(&reader, &result->query_class) || !resolver_ipc_reader_u16(&reader, &result->query_type) || !resolver_ipc_reader_u16(&reader, &encoded_status)
		|| !resolver_ipc_reader_u8(&reader, &result->rcode) || !resolver_ipc_reader_u8(&reader, &negative_valid) || !resolver_ipc_reader_u64(&reader, &seconds)
		|| !resolver_ipc_reader_u32(&reader, &nanoseconds) || !resolver_ipc_reader_u16(&reader, &cname_count) || !resolver_ipc_reader_u16(&reader, &record_count)
		|| !resolver_ipc_reader_u16(&reader, &question_size) || !resolver_ipc_reader_u16(&reader, &canonical_size) || !resolver_ipc_reader_u16(&reader, &negative_owner_size)
		|| !resolver_ipc_reader_u32(&reader, &result->negative.effective_ttl) || !resolver_ipc_reader_u32(&reader, &result->negative.minimum)
		|| !resolver_ipc_reader_u32(&reader, &result->negative.record_ttl) || result->query_class != ns_c_in || !resolver_ipc_query_type_valid(result->query_type)
		|| !resolver_ipc_status_decode(encoded_status, &result->status) || result->rcode > 15 || negative_valid > 1
		|| !resolver_ipc_time_decode(seconds, nanoseconds, &result->completed_at) || !resolver_ipc_response_count_valid(result->query_type, cname_count, record_count)
		|| !resolver_ipc_reader_name(&reader, question_size, true, result->question_name) || !resolver_ipc_reader_name(&reader, canonical_size, true, result->canonical_name)
		|| !resolver_ipc_reader_name(&reader, negative_owner_size, !negative_valid, result->negative.owner) || reader.offset != reader.size) {
		memset(result, 0, sizeof(*result));
		return RESOLVER_IPC_CODEC_MALFORMED;
	}
	result->negative.valid = negative_valid != 0;
	if (!resolver_ipc_negative_valid(&result->negative)) {
		memset(result, 0, sizeof(*result));
		return RESOLVER_IPC_CODEC_MALFORMED;
	}
	result->cname_count = cname_count;
	result->query_id = header.query_id;
	result->record_count = record_count;
	return RESOLVER_IPC_CODEC_OK;
}

resolver_ipc_codec_status resolver_ipc_response_begin_encode(const resolver_ipc_response_begin *response, void *packet, size_t packet_capacity, size_t *packet_size) {
	if (packet_size != NULL) {
		*packet_size = 0;
	}
	if (response == NULL || packet == NULL || packet_size == NULL || response->query_class != ns_c_in || !resolver_ipc_query_type_valid(response->query_type)
		|| !resolver_ipc_lookup_status_valid(response->status) || response->rcode > 15 || !resolver_ipc_negative_valid(&response->negative)
		|| !resolver_ipc_response_count_valid(response->query_type, response->cname_count, response->record_count)) {
		return RESOLVER_IPC_CODEC_BAD_ARGUMENT;
	}
	uint64_t seconds;
	uint32_t nanoseconds;
	if (!resolver_ipc_time_encode(&response->completed_at, &seconds, &nanoseconds)) {
		return RESOLVER_IPC_CODEC_BAD_ARGUMENT;
	}
	size_t question_size;
	size_t canonical_size;
	size_t negative_owner_size;
	if (!resolver_ipc_name_size(response->question_name, true, &question_size) || !resolver_ipc_name_size(response->canonical_name, true, &canonical_size)
		|| !resolver_ipc_name_size(response->negative.owner, !response->negative.valid, &negative_owner_size)) {
		return RESOLVER_IPC_CODEC_BAD_ARGUMENT;
	}
	size_t encoded_size = RESOLVER_IPC_HEADER_SIZE + sizeof(uint16_t) * 8 + sizeof(uint8_t) * 2 + sizeof(uint64_t) + sizeof(uint32_t) * 4
		+ question_size + canonical_size + negative_owner_size;
	resolver_ipc_writer writer;
	resolver_ipc_codec_status status = resolver_ipc_header_encode(RESOLVER_IPC_PACKET_RESPONSE_BEGIN, response->query_id, packet, packet_capacity, encoded_size, &writer);
	if (status != RESOLVER_IPC_CODEC_OK) {
		return status;
	}
	uint16_t encoded_status;
	if (!resolver_ipc_status_encode(response->status, &encoded_status) || !resolver_ipc_writer_u16(&writer, response->query_class)
		|| !resolver_ipc_writer_u16(&writer, response->query_type) || !resolver_ipc_writer_u16(&writer, encoded_status) || !resolver_ipc_writer_u8(&writer, response->rcode)
		|| !resolver_ipc_writer_u8(&writer, response->negative.valid ? 1 : 0) || !resolver_ipc_writer_u64(&writer, seconds) || !resolver_ipc_writer_u32(&writer, nanoseconds)
		|| !resolver_ipc_writer_u16(&writer, (uint16_t)response->cname_count) || !resolver_ipc_writer_u16(&writer, (uint16_t)response->record_count)
		|| !resolver_ipc_writer_u16(&writer, (uint16_t)question_size) || !resolver_ipc_writer_u16(&writer, (uint16_t)canonical_size)
		|| !resolver_ipc_writer_u16(&writer, (uint16_t)negative_owner_size) || !resolver_ipc_writer_u32(&writer, response->negative.effective_ttl)
		|| !resolver_ipc_writer_u32(&writer, response->negative.minimum) || !resolver_ipc_writer_u32(&writer, response->negative.record_ttl)
		|| !resolver_ipc_writer_bytes(&writer, response->question_name, question_size) || !resolver_ipc_writer_bytes(&writer, response->canonical_name, canonical_size)
		|| !resolver_ipc_writer_bytes(&writer, response->negative.owner, negative_owner_size) || writer.offset != writer.size) {
		return RESOLVER_IPC_CODEC_LIMIT;
	}
	*packet_size = encoded_size;
	return RESOLVER_IPC_CODEC_OK;
}

resolver_ipc_codec_status resolver_ipc_response_cname_decode(const void *packet, size_t packet_size, resolver_ipc_response_cname *result) {
	if (result != NULL) {
		memset(result, 0, sizeof(*result));
	}
	if (result == NULL) {
		return RESOLVER_IPC_CODEC_BAD_ARGUMENT;
	}
	resolver_ipc_reader reader;
	resolver_ipc_packet_header header;
	resolver_ipc_codec_status status = resolver_ipc_header_decode(packet, packet_size, RESOLVER_IPC_PACKET_RESPONSE_CNAME, &reader, &header);
	if (status != RESOLVER_IPC_CODEC_OK) {
		return status;
	}
	uint16_t owner_size;
	uint16_t target_size;
	if (!resolver_ipc_reader_u16(&reader, &result->index) || !resolver_ipc_reader_u32(&reader, &result->record.ttl) || !resolver_ipc_reader_u16(&reader, &owner_size)
		|| !resolver_ipc_reader_u16(&reader, &target_size) || result->index >= DNS_CNAME_DEPTH_LIMIT || !resolver_ipc_reader_name(&reader, owner_size, false, result->record.owner)
		|| !resolver_ipc_reader_name(&reader, target_size, false, result->record.target) || reader.offset != reader.size) {
		memset(result, 0, sizeof(*result));
		return RESOLVER_IPC_CODEC_MALFORMED;
	}
	result->query_id = header.query_id;
	return RESOLVER_IPC_CODEC_OK;
}

resolver_ipc_codec_status resolver_ipc_response_cname_encode(const resolver_ipc_response_cname *response, void *packet, size_t packet_capacity, size_t *packet_size) {
	if (packet_size != NULL) {
		*packet_size = 0;
	}
	if (response == NULL || packet == NULL || packet_size == NULL || response->index >= DNS_CNAME_DEPTH_LIMIT) {
		return RESOLVER_IPC_CODEC_BAD_ARGUMENT;
	}
	size_t owner_size;
	size_t target_size;
	if (!resolver_ipc_name_size(response->record.owner, false, &owner_size) || !resolver_ipc_name_size(response->record.target, false, &target_size)) {
		return RESOLVER_IPC_CODEC_BAD_ARGUMENT;
	}
	size_t encoded_size = RESOLVER_IPC_HEADER_SIZE + sizeof(uint16_t) * 3 + sizeof(uint32_t) + owner_size + target_size;
	resolver_ipc_writer writer;
	resolver_ipc_codec_status status = resolver_ipc_header_encode(RESOLVER_IPC_PACKET_RESPONSE_CNAME, response->query_id, packet, packet_capacity, encoded_size, &writer);
	if (status != RESOLVER_IPC_CODEC_OK) {
		return status;
	}
	if (!resolver_ipc_writer_u16(&writer, response->index) || !resolver_ipc_writer_u32(&writer, response->record.ttl) || !resolver_ipc_writer_u16(&writer, (uint16_t)owner_size)
		|| !resolver_ipc_writer_u16(&writer, (uint16_t)target_size) || !resolver_ipc_writer_bytes(&writer, response->record.owner, owner_size)
		|| !resolver_ipc_writer_bytes(&writer, response->record.target, target_size) || writer.offset != writer.size) {
		return RESOLVER_IPC_CODEC_LIMIT;
	}
	*packet_size = encoded_size;
	return RESOLVER_IPC_CODEC_OK;
}

resolver_ipc_codec_status resolver_ipc_response_end_decode(const void *packet, size_t packet_size, resolver_ipc_response_end *result) {
	if (result != NULL) {
		memset(result, 0, sizeof(*result));
	}
	if (result == NULL) {
		return RESOLVER_IPC_CODEC_BAD_ARGUMENT;
	}
	resolver_ipc_reader reader;
	resolver_ipc_packet_header header;
	resolver_ipc_codec_status status = resolver_ipc_header_decode(packet, packet_size, RESOLVER_IPC_PACKET_RESPONSE_END, &reader, &header);
	if (status != RESOLVER_IPC_CODEC_OK) {
		return status;
	}
	uint16_t cname_count;
	uint16_t record_count;
	if (!resolver_ipc_reader_u16(&reader, &cname_count) || !resolver_ipc_reader_u16(&reader, &record_count) || cname_count > DNS_CNAME_DEPTH_LIMIT
		|| (record_count > DNS_ADDRESS_RECORD_LIMIT && record_count > DNS_SRV_RECORD_LIMIT) || reader.offset != reader.size) {
		memset(result, 0, sizeof(*result));
		return RESOLVER_IPC_CODEC_MALFORMED;
	}
	result->cname_count = cname_count;
	result->query_id = header.query_id;
	result->record_count = record_count;
	return RESOLVER_IPC_CODEC_OK;
}

resolver_ipc_codec_status resolver_ipc_response_end_encode(const resolver_ipc_response_end *response, void *packet, size_t packet_capacity, size_t *packet_size) {
	if (packet_size != NULL) {
		*packet_size = 0;
	}
	if (response == NULL || packet == NULL || packet_size == NULL || response->cname_count > DNS_CNAME_DEPTH_LIMIT
		|| (response->record_count > DNS_ADDRESS_RECORD_LIMIT && response->record_count > DNS_SRV_RECORD_LIMIT)) {
		return RESOLVER_IPC_CODEC_BAD_ARGUMENT;
	}
	size_t encoded_size = RESOLVER_IPC_HEADER_SIZE + sizeof(uint16_t) * 2;
	resolver_ipc_writer writer;
	resolver_ipc_codec_status status = resolver_ipc_header_encode(RESOLVER_IPC_PACKET_RESPONSE_END, response->query_id, packet, packet_capacity, encoded_size, &writer);
	if (status != RESOLVER_IPC_CODEC_OK) {
		return status;
	}
	if (!resolver_ipc_writer_u16(&writer, (uint16_t)response->cname_count) || !resolver_ipc_writer_u16(&writer, (uint16_t)response->record_count) || writer.offset != writer.size) {
		return RESOLVER_IPC_CODEC_LIMIT;
	}
	*packet_size = encoded_size;
	return RESOLVER_IPC_CODEC_OK;
}

resolver_ipc_codec_status resolver_ipc_response_srv_decode(const void *packet, size_t packet_size, resolver_ipc_response_srv *result) {
	if (result != NULL) {
		memset(result, 0, sizeof(*result));
	}
	if (result == NULL) {
		return RESOLVER_IPC_CODEC_BAD_ARGUMENT;
	}
	resolver_ipc_reader reader;
	resolver_ipc_packet_header header;
	resolver_ipc_codec_status status = resolver_ipc_header_decode(packet, packet_size, RESOLVER_IPC_PACKET_RESPONSE_SRV, &reader, &header);
	if (status != RESOLVER_IPC_CODEC_OK) {
		return status;
	}
	uint16_t port;
	uint16_t target_size;
	if (!resolver_ipc_reader_u16(&reader, &result->index) || !resolver_ipc_reader_u16(&reader, &result->record.priority) || !resolver_ipc_reader_u16(&reader, &result->record.weight)
		|| !resolver_ipc_reader_u16(&reader, &port) || !resolver_ipc_reader_u32(&reader, &result->record.record_ttl)
		|| !resolver_ipc_reader_u32(&reader, &result->record.effective_ttl) || !resolver_ipc_reader_u16(&reader, &target_size) || result->index >= DNS_SRV_RECORD_LIMIT
		|| result->record.effective_ttl > result->record.record_ttl || !resolver_ipc_reader_name(&reader, target_size, false, result->record.target) || reader.offset != reader.size) {
		memset(result, 0, sizeof(*result));
		return RESOLVER_IPC_CODEC_MALFORMED;
	}
	result->query_id = header.query_id;
	result->record.port = (in_port_t)port;
	return RESOLVER_IPC_CODEC_OK;
}

resolver_ipc_codec_status resolver_ipc_response_srv_encode(const resolver_ipc_response_srv *response, void *packet, size_t packet_capacity, size_t *packet_size) {
	if (packet_size != NULL) {
		*packet_size = 0;
	}
	if (response == NULL || packet == NULL || packet_size == NULL || response->index >= DNS_SRV_RECORD_LIMIT || response->record.effective_ttl > response->record.record_ttl) {
		return RESOLVER_IPC_CODEC_BAD_ARGUMENT;
	}
	size_t target_size;
	if (!resolver_ipc_name_size(response->record.target, false, &target_size)) {
		return RESOLVER_IPC_CODEC_BAD_ARGUMENT;
	}
	size_t encoded_size = RESOLVER_IPC_HEADER_SIZE + sizeof(uint16_t) * 5 + sizeof(uint32_t) * 2 + target_size;
	resolver_ipc_writer writer;
	resolver_ipc_codec_status status = resolver_ipc_header_encode(RESOLVER_IPC_PACKET_RESPONSE_SRV, response->query_id, packet, packet_capacity, encoded_size, &writer);
	if (status != RESOLVER_IPC_CODEC_OK) {
		return status;
	}
	if (!resolver_ipc_writer_u16(&writer, response->index) || !resolver_ipc_writer_u16(&writer, response->record.priority) || !resolver_ipc_writer_u16(&writer, response->record.weight)
		|| !resolver_ipc_writer_u16(&writer, response->record.port) || !resolver_ipc_writer_u32(&writer, response->record.record_ttl)
		|| !resolver_ipc_writer_u32(&writer, response->record.effective_ttl) || !resolver_ipc_writer_u16(&writer, (uint16_t)target_size)
		|| !resolver_ipc_writer_bytes(&writer, response->record.target, target_size) || writer.offset != writer.size) {
		return RESOLVER_IPC_CODEC_LIMIT;
	}
	*packet_size = encoded_size;
	return RESOLVER_IPC_CODEC_OK;
}

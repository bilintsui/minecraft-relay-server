/*
 * connsetup_short.c: Prepare listener-owned short connection setup plans
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* section: headers (project) */
#include "basic.h"
#include "network.h"
#include "protocol/common.h"
#include "protocol/handshake.h"
#include "protocol/handshake_legacy.h"

/* section: headers (self) */
#include "connsetup_short.h"

/* section: defines */
#define CONNSETUP_SHORT_PACKET_SCRATCH_SIZE	(BUFSIZ + ROUTE_ENDPOINT_TEXT_SIZE + 32U)

/* section: functions (local) */
static bool connsetup_short_address_valid(const net_addr *address) {
	return address != NULL && address->err == 0 && (address->family == AF_INET || address->family == AF_INET6);
}

static bool connsetup_short_bundle_valid(const net_addrbundle *address) {
	if (address == NULL || (address->family != AF_INET && address->family != AF_INET6) || address->port == 0
		|| memchr(&address->address, '\0', sizeof(address->address)) == NULL || memchr(&address->address_clean, '\0', sizeof(address->address_clean)) == NULL) {
		return false;
	}
	return true;
}

static bool connsetup_short_packet_complete(const uint8_t *initial, size_t initial_size, uint8_t protocol, size_t *packet_size_result) {
	size_t packet_size = 0;
	enum protocol_packet_status status = protocol_packet_length(initial, initial_size, &packet_size);
	if (packet_size_result != NULL) {
		*packet_size_result = packet_size;
	}
	if ((protocol == PVER_LEGACYM1 || protocol == PVER_LEGACYM2) && (status == PROTOCOL_PACKET_AMBIGUOUS || status == PROTOCOL_PACKET_COMPLETE)) {
		return true;
	}
	return status == PROTOCOL_PACKET_COMPLETE && packet_size <= initial_size;
}

static bool connsetup_short_plan_endpoint_valid(const connsetup_snapshot *snapshot) {
	const route_endpoint_snapshot *endpoint = &snapshot->endpoint;
	if (!connsetup_short_address_valid(&endpoint->address) || endpoint->port == 0 || endpoint->generation_identity == 0
		|| memchr(endpoint->configured_address, '\0', sizeof(endpoint->configured_address)) == NULL
		|| memchr(endpoint->target_name, '\0', sizeof(endpoint->target_name)) == NULL || memchr(endpoint->vhost, '\0', sizeof(endpoint->vhost)) == NULL
		|| endpoint->configured_address[0] == '\0' || endpoint->vhost[0] == '\0') {
		return false;
	}
	if (endpoint->pheader && (!connsetup_short_address_valid(&endpoint->inbound_proxy.srcaddr) || !connsetup_short_address_valid(&endpoint->inbound_proxy.dstaddr)
		|| endpoint->inbound_proxy.family != endpoint->inbound_proxy.srcaddr.family || endpoint->inbound_proxy.family != endpoint->inbound_proxy.dstaddr.family)) {
		return false;
	}
	return true;
}

static bool connsetup_short_plan_request_payload(connsetup_short_plan *plan, const uint8_t *payload, size_t payload_size) {
	if (plan == NULL || (payload == NULL && payload_size != 0) || plan->pheader_size > SIZE_MAX - payload_size) {
		return false;
	}
	size_t request_size = plan->pheader_size + payload_size;
	uint8_t *request = malloc(request_size == 0 ? 1U : request_size);
	if (request == NULL) {
		return false;
	}
	if (plan->pheader_size > 0) {
		memcpy(request, plan->pheader, plan->pheader_size);
	}
	if (payload_size > 0) {
		memcpy(request + plan->pheader_size, payload, payload_size);
	}
	free(plan->request);
	plan->request = request;
	plan->request_size = request_size;
	return true;
}

static bool connsetup_short_plan_request_legacy(connsetup_short_plan *plan, const uint8_t *initial, size_t initial_size, size_t packet_size, bool rewrite) {
	if (packet_size > initial_size) {
		return false;
	}
	p_motd_legacy packet = packet_read_legacy_motd(initial);
	if (packet.address == NULL || strlen(packet.address) >= ROUTE_ENDPOINT_TEXT_SIZE) {
		packet_destroy_legacy_motd(packet);
		return false;
	}
	if (!rewrite) {
		bool result = connsetup_short_plan_request_payload(plan, initial, initial_size);
		packet_destroy_legacy_motd(packet);
		return result;
	}
	const char *destination = plan->snapshot.endpoint.target_name[0] == '\0' ? plan->snapshot.endpoint.configured_address : plan->snapshot.endpoint.target_name;
	size_t destination_size = strlen(destination);
	if (destination_size > UINT16_MAX || destination_size > (SIZE_MAX - 36U) / 2U) {
		packet_destroy_legacy_motd(packet);
		return false;
	}
	size_t payload_size = 36U + destination_size * 2U;
	uint8_t *payload = malloc(payload_size);
	if (payload == NULL) {
		packet_destroy_legacy_motd(packet);
		return false;
	}
	void *old_address = packet.address;
	in_port_t old_port = packet.port;
	packet.address = (void *)destination;
	packet.port = plan->snapshot.endpoint.port;
	size_t written = packet_write_legacy_motd(payload, packet);
	packet.address = old_address;
	packet.port = old_port;
	packet_destroy_legacy_motd(packet);
	if (written != payload_size) {
		free(payload);
		return false;
	}
	if (initial_size - packet_size > SIZE_MAX - written) {
		free(payload);
		return false;
	}
	size_t combined_size = written + initial_size - packet_size;
	uint8_t *combined = malloc(combined_size);
	if (combined == NULL) {
		free(payload);
		return false;
	}
	memcpy(combined, payload, written);
	memcpy(combined + written, initial + packet_size, initial_size - packet_size);
	bool result = connsetup_short_plan_request_payload(plan, combined, combined_size);
	free(combined);
	free(payload);
	return result;
}

static bool connsetup_short_plan_request_modern(connsetup_short_plan *plan, const uint8_t *initial, size_t initial_size, size_t packet_size, bool rewrite) {
	if (packet_size > initial_size) {
		return false;
	}
	if (!rewrite) {
		return connsetup_short_plan_request_payload(plan, initial, initial_size);
	}
	p_handshake packet = packet_read((void *)initial, (void *)(initial + initial_size));
	if (packet.address == NULL || packet.nextstate != CLIENT_INTENT_STATUS) {
		packet_destroy(packet);
		return false;
	}
	uint8_t *payload = malloc(CONNSETUP_SHORT_PACKET_SCRATCH_SIZE);
	if (payload == NULL) {
		packet_destroy(packet);
		return false;
	}
	void *old_address = packet.address;
	in_port_t old_port = packet.port;
	const char *destination = plan->snapshot.endpoint.target_name[0] == '\0' ? plan->snapshot.endpoint.configured_address : plan->snapshot.endpoint.target_name;
	packet.address = (void *)destination;
	packet.port = plan->snapshot.endpoint.port;
	size_t written = packet_write(payload, packet);
	packet.address = old_address;
	packet.port = old_port;
	packet_destroy(packet);
	size_t rewritten_packet_size = 0;
	bool valid = written > 0 && protocol_packet_length(payload, written, &rewritten_packet_size) == PROTOCOL_PACKET_COMPLETE
		&& rewritten_packet_size <= written && initial_size - packet_size <= SIZE_MAX - rewritten_packet_size;
	uint8_t *combined = NULL;
	size_t combined_size = 0;
	if (valid) {
		combined_size = rewritten_packet_size + initial_size - packet_size;
		combined = malloc(combined_size);
		valid = combined != NULL;
	}
	if (valid) {
		memcpy(combined, payload, rewritten_packet_size);
		memcpy(combined + rewritten_packet_size, initial + packet_size, initial_size - packet_size);
	}
	bool result = valid && connsetup_short_plan_request_payload(plan, combined, combined_size);
	free(combined);
	free(payload);
	return result;
}

static bool connsetup_short_plan_response_legacy(connsetup_short_plan *plan, const char *message, uint8_t motd_version, uint8_t version) {
	if (plan == NULL || message == NULL) {
		return false;
	}
	uint8_t *response = malloc(BUFSIZ);
	if (response == NULL) {
		return false;
	}
	size_t response_size = make_motd_legacy(response, message, motd_version, version);
	if (response_size == 0) {
		free(response);
		return false;
	}
	uint8_t *resized = realloc(response, response_size);
	if (resized != NULL) {
		response = resized;
	}
	free(plan->response);
	plan->response = response;
	plan->response_size = response_size;
	return true;
}

static bool connsetup_short_plan_response_modern(connsetup_short_plan *plan, const char *message, varint_t version) {
	if (plan == NULL || message == NULL || memchr(plan->snapshot.icon_b64, '\0', sizeof(plan->snapshot.icon_b64)) == NULL) {
		return false;
	}
	uint8_t *response = malloc(BUFSIZ);
	if (response == NULL) {
		return false;
	}
	size_t response_size = make_motd(response, message, version, plan->snapshot.icon_b64);
	if (response_size == 0) {
		free(response);
		return false;
	}
	uint8_t *resized = realloc(response, response_size);
	if (resized != NULL) {
		response = resized;
	}
	free(plan->response);
	plan->response = response;
	plan->response_size = response_size;
	return true;
}

static bool connsetup_short_plan_response_unavailable(connsetup_short_plan *plan, uint8_t protocol, varint_t modern_version, uint8_t legacy_version) {
	if (protocol == PVER_LEGACYM3) {
		return connsetup_short_plan_response_legacy(plan, "[Proxy] Server Temporarily Unavailable.", protocol, legacy_version);
	}
	return connsetup_short_plan_response_modern(plan, "[Proxy] Server Temporarily Unavailable.", modern_version);
}

static int connsetup_short_result_for_route(const connsetup_snapshot *snapshot) {
	return snapshot->route_status == CONNSETUP_ROUTE_NO_ROUTE ? CONNSETUP_ENOVHOST : CONNSETUP_ENORECORD;
}

/* section: functions (exported) */
void connsetup_short_destroy(connsetup_short_plan *plan) {
	if (plan == NULL) {
		return;
	}
	free(plan->request);
	free(plan->response);
	memset(plan, 0, sizeof(*plan));
}

connsetup_short_action connsetup_short_prepare(connsetup_short_plan *plan, const connsetup_snapshot *snapshot, net_addrbundle inbound_address,
	const uint8_t *initial, size_t initial_size) {
	if (plan == NULL) {
		return CONNSETUP_SHORT_ABORT;
	}
	memset(plan, 0, sizeof(*plan));
	plan->result = CONNSETUP_EABORT;
	if (snapshot == NULL || !connsetup_short_bundle_valid(&inbound_address) || initial == NULL || initial_size == 0 || initial_size > BUFSIZ
		|| memchr(snapshot->icon_b64, '\0', sizeof(snapshot->icon_b64)) == NULL || memchr(snapshot->log_filename, '\0', sizeof(snapshot->log_filename)) == NULL
		|| snapshot->route_status < CONNSETUP_ROUTE_BYPASS || snapshot->route_status > CONNSETUP_ROUTE_UNAVAILABLE) {
		return CONNSETUP_SHORT_ABORT;
	}
	plan->snapshot = *snapshot;
	plan->inbound_address = inbound_address;
	plan->protocol = protocol_identify(initial, initial_size, &plan->intent);
	size_t packet_size = 0;
	if (plan->protocol == PVER_UNIDENT || !connsetup_short_packet_complete(initial, initial_size, plan->protocol, &packet_size)) {
		return CONNSETUP_SHORT_ABORT;
	}
	if (plan->protocol == PVER_LEGACYM1 || plan->protocol == PVER_LEGACYM2) {
		plan->result = CONNSETUP_EOLDCLIENT;
		return connsetup_short_plan_response_legacy(plan, "Proxy: Please use direct connect.", plan->protocol, 0) ? CONNSETUP_SHORT_RESPOND : CONNSETUP_SHORT_ABORT;
	}
	if (plan->protocol == PVER_ORIGPRO || plan->protocol == PVER_LEGACYL1 || plan->protocol == PVER_LEGACYL2 || plan->protocol == PVER_LEGACYL3
		|| plan->protocol == PVER_LEGACYL4) {
		return CONNSETUP_SHORT_ABORT;
	}
	if (plan->protocol == PVER_MODERN1) {
		if (plan->intent != CLIENT_INTENT_STATUS) {
			return CONNSETUP_SHORT_ABORT;
		}
		plan->result = CONNSETUP_EOLDCLIENT;
		return connsetup_short_plan_response_modern(plan, "[Proxy] Use 13w42a or later to play!", 0) ? CONNSETUP_SHORT_RESPOND : CONNSETUP_SHORT_ABORT;
	}
	uint8_t legacy_version = 0;
	varint_t modern_version = 0;
	if (plan->protocol == PVER_LEGACYM3) {
		p_motd_legacy packet = packet_read_legacy_motd(initial);
		if (packet.address == NULL || strlen(packet.address) >= ROUTE_ENDPOINT_TEXT_SIZE) {
			packet_destroy_legacy_motd(packet);
			return CONNSETUP_SHORT_ABORT;
		}
		legacy_version = packet.version;
		packet_destroy_legacy_motd(packet);
		if (snapshot->route_status != CONNSETUP_ROUTE_READY) {
			plan->result = connsetup_short_result_for_route(snapshot);
			return connsetup_short_plan_response_unavailable(plan, plan->protocol, 0, legacy_version) ? CONNSETUP_SHORT_RESPOND : CONNSETUP_SHORT_ABORT;
		}
		if (!connsetup_short_plan_endpoint_valid(snapshot)) {
			return CONNSETUP_SHORT_ABORT;
		}
	} else if (plan->protocol == PVER_MODERN2) {
		p_handshake packet = packet_read((void *)initial, (void *)(initial + initial_size));
		if (packet.address == NULL || packet.nextstate != CLIENT_INTENT_STATUS) {
			packet_destroy(packet);
			return CONNSETUP_SHORT_ABORT;
		}
		modern_version = packet.version;
		packet_destroy(packet);
		if (snapshot->route_status != CONNSETUP_ROUTE_READY) {
			plan->result = connsetup_short_result_for_route(snapshot);
			return connsetup_short_plan_response_unavailable(plan, plan->protocol, modern_version, 0) ? CONNSETUP_SHORT_RESPOND : CONNSETUP_SHORT_ABORT;
		}
		if (!connsetup_short_plan_endpoint_valid(snapshot)) {
			return CONNSETUP_SHORT_ABORT;
		}
	} else {
		return CONNSETUP_SHORT_ABORT;
	}
	if (snapshot->endpoint.pheader) {
		plan->pheader_size = protocol_proxy_write(plan->pheader, snapshot->endpoint.inbound_proxy);
		if (plan->pheader_size == 0 || plan->pheader_size > PROTOPROXY_PACKETMAXLEN) {
			return CONNSETUP_SHORT_ABORT;
		}
	}
	bool request_result = plan->protocol == PVER_LEGACYM3
		? connsetup_short_plan_request_legacy(plan, initial, initial_size, packet_size, snapshot->endpoint.rewrite)
		: connsetup_short_plan_request_modern(plan, initial, initial_size, packet_size, snapshot->endpoint.rewrite);
	if (!request_result || !connsetup_short_plan_response_unavailable(plan, plan->protocol, modern_version, legacy_version)) {
		return CONNSETUP_SHORT_ABORT;
	}
	plan->result = CONNSETUP_OK;
	return CONNSETUP_SHORT_CONNECT;
}

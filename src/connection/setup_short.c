/*
 * connection/setup_short.c: Prepare listener-owned short connection setup plans
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
#include "../basic.h"
#include "../network.h"
#include "../protocol/common.h"
#include "../protocol/handshake.h"
#include "../protocol/handshake_legacy.h"

/* section: headers (self) */
#include "setup_short.h"

/* section: defines */
#define CONNECTION_SETUP_SHORT_PACKET_SCRATCH_SIZE	(BUFSIZ + ROUTE_ENDPOINT_TEXT_SIZE + 32U)

/* section: functions (local) */
static bool connection_setup_short_packet_complete(const uint8_t *initial, size_t initial_size, protocol_version protocol, size_t *packet_size_result) {
	size_t packet_size = 0;
	protocol_packet_status status = protocol_packet_length(initial, initial_size, &packet_size);
	if (packet_size_result != NULL) {
		*packet_size_result = packet_size;
	}
	if ((protocol == PVER_LEGACYM1 || protocol == PVER_LEGACYM2) && (status == PROTOCOL_PACKET_AMBIGUOUS || status == PROTOCOL_PACKET_COMPLETE)) {
		return true;
	}
	return status == PROTOCOL_PACKET_COMPLETE && packet_size <= initial_size;
}

static bool connection_setup_short_plan_endpoint_valid(const connection_setup_snapshot *snapshot) {
	const route_endpoint_snapshot *endpoint = &snapshot->endpoint;
	if (!connection_setup_address_valid(&endpoint->address) || endpoint->port == 0 || endpoint->generation_identity == 0
		|| memchr(endpoint->configured_address, '\0', sizeof(endpoint->configured_address)) == NULL
		|| memchr(endpoint->target_name, '\0', sizeof(endpoint->target_name)) == NULL || memchr(endpoint->vhost, '\0', sizeof(endpoint->vhost)) == NULL
		|| endpoint->configured_address[0] == '\0' || endpoint->vhost[0] == '\0') {
		return false;
	}
	if (endpoint->pheader && (!connection_setup_address_valid(&endpoint->inbound_proxy.srcaddr) || !connection_setup_address_valid(&endpoint->inbound_proxy.dstaddr)
		|| endpoint->inbound_proxy.family != endpoint->inbound_proxy.srcaddr.family || endpoint->inbound_proxy.family != endpoint->inbound_proxy.dstaddr.family)) {
		return false;
	}
	return true;
}

static bool connection_setup_short_plan_request_payload(connection_setup_short_plan *plan, const uint8_t *payload, size_t payload_size) {
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

static bool connection_setup_short_plan_request_legacy(connection_setup_short_plan *plan, const uint8_t *initial, size_t initial_size, size_t packet_size, bool rewrite) {
	if (packet_size > initial_size) {
		return false;
	}
	p_motd_legacy packet = packet_read_legacy_motd(initial, packet_size);
	if (packet.address == NULL || strlen(packet.address) >= ROUTE_ENDPOINT_TEXT_SIZE) {
		packet_destroy_legacy_motd(packet);
		return false;
	}
	if (!rewrite) {
		bool result = connection_setup_short_plan_request_payload(plan, initial, initial_size);
		packet_destroy_legacy_motd(packet);
		return result;
	}
	const char *destination = connection_setup_destination(&plan->snapshot.endpoint);
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
	bool result = connection_setup_short_plan_request_payload(plan, combined, combined_size);
	free(combined);
	free(payload);
	return result;
}

static bool connection_setup_short_plan_request_modern(connection_setup_short_plan *plan, const uint8_t *initial, size_t initial_size, size_t packet_size, bool rewrite) {
	if (packet_size > initial_size) {
		return false;
	}
	if (!rewrite) {
		return connection_setup_short_plan_request_payload(plan, initial, initial_size);
	}
	p_handshake packet = packet_read((void *)initial, (void *)(initial + initial_size));
	if (packet.address == NULL || packet.nextstate != CLIENT_INTENT_STATUS) {
		packet_destroy(packet);
		return false;
	}
	uint8_t *payload = malloc(CONNECTION_SETUP_SHORT_PACKET_SCRATCH_SIZE);
	if (payload == NULL) {
		packet_destroy(packet);
		return false;
	}
	void *old_address = packet.address;
	in_port_t old_port = packet.port;
	const char *destination = connection_setup_destination(&plan->snapshot.endpoint);
	packet.address = (void *)destination;
	packet.port = plan->snapshot.endpoint.port;
	size_t written = packet_write(payload, CONNECTION_SETUP_SHORT_PACKET_SCRATCH_SIZE, packet);
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
	bool result = valid && connection_setup_short_plan_request_payload(plan, combined, combined_size);
	free(combined);
	free(payload);
	return result;
}

static bool connection_setup_short_plan_response_commit(connection_setup_short_plan *plan, uint8_t *response, size_t response_size) {
	if (plan == NULL || response == NULL || response_size == 0) {
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

static bool connection_setup_short_plan_response_legacy(connection_setup_short_plan *plan, const char *message, protocol_version motd_version, uint8_t version) {
	if (plan == NULL || message == NULL) {
		return false;
	}
	uint8_t *response = malloc(BUFSIZ);
	if (response == NULL) {
		return false;
	}
	size_t response_size = make_motd_legacy(response, BUFSIZ, message, motd_version, version);
	if (response_size == 0) {
		free(response);
		return false;
	}
	return connection_setup_short_plan_response_commit(plan, response, response_size);
}

static bool connection_setup_short_plan_response_modern(connection_setup_short_plan *plan, const char *message, varint_t version) {
	if (plan == NULL || message == NULL || memchr(plan->snapshot.icon_b64, '\0', sizeof(plan->snapshot.icon_b64)) == NULL) {
		return false;
	}
	uint8_t *response = malloc(BUFSIZ);
	if (response == NULL) {
		return false;
	}
	size_t response_size = make_motd(response, BUFSIZ, message, version, plan->snapshot.icon_b64);
	if (response_size == 0) {
		free(response);
		return false;
	}
	return connection_setup_short_plan_response_commit(plan, response, response_size);
}

static bool connection_setup_short_plan_response_unavailable(connection_setup_short_plan *plan, protocol_version protocol, varint_t modern_version, uint8_t legacy_version) {
	if (protocol == PVER_LEGACYM3) {
		return connection_setup_short_plan_response_legacy(plan, "[Proxy] Server Temporarily Unavailable.", protocol, legacy_version);
	}
	return connection_setup_short_plan_response_modern(plan, "[Proxy] Server Temporarily Unavailable.", modern_version);
}

static int connection_setup_short_result_for_route(const connection_setup_snapshot *snapshot) {
	return snapshot->route_status == CONNECTION_SETUP_ROUTE_NO_ROUTE ? CONNECTION_SETUP_ENOVHOST : CONNECTION_SETUP_ENORECORD;
}

static connection_setup_short_action connection_setup_short_route_prepare(connection_setup_short_plan *plan, const connection_setup_snapshot *snapshot,
	protocol_version protocol, varint_t modern_version, uint8_t legacy_version) {
	if (snapshot->route_status != CONNECTION_SETUP_ROUTE_READY) {
		plan->result = connection_setup_short_result_for_route(snapshot);
		return connection_setup_short_plan_response_unavailable(plan, protocol, modern_version, legacy_version) ? CONNECTION_SETUP_SHORT_RESPOND : CONNECTION_SETUP_SHORT_ABORT;
	}
	return connection_setup_short_plan_endpoint_valid(snapshot) ? CONNECTION_SETUP_SHORT_CONNECT : CONNECTION_SETUP_SHORT_ABORT;
}

/* section: functions (exported) */
void connection_setup_short_destroy(connection_setup_short_plan *plan) {
	if (plan == NULL) {
		return;
	}
	free(plan->request);
	free(plan->response);
	memset(plan, 0, sizeof(*plan));
}

connection_setup_short_action connection_setup_short_prepare(connection_setup_short_plan *plan, const connection_setup_snapshot *snapshot, net_addrbundle inbound_address,
	const uint8_t *initial, size_t initial_size) {
	if (plan == NULL) {
		return CONNECTION_SETUP_SHORT_ABORT;
	}
	memset(plan, 0, sizeof(*plan));
	plan->result = CONNECTION_SETUP_EABORT;
	if (!connection_setup_snapshot_valid(snapshot) || !connection_setup_bundle_valid(&inbound_address) || initial == NULL || initial_size == 0 || initial_size > BUFSIZ) {
		return CONNECTION_SETUP_SHORT_ABORT;
	}
	plan->snapshot = *snapshot;
	plan->inbound_address = inbound_address;
	plan->protocol = protocol_identify(initial, initial_size, &plan->intent);
	size_t packet_size = 0;
	if (plan->protocol == PVER_UNIDENT || !connection_setup_short_packet_complete(initial, initial_size, plan->protocol, &packet_size)) {
		return CONNECTION_SETUP_SHORT_ABORT;
	}
	if (plan->protocol == PVER_LEGACYM1 || plan->protocol == PVER_LEGACYM2) {
		plan->result = CONNECTION_SETUP_EOLDCLIENT;
		return connection_setup_short_plan_response_legacy(plan, "Proxy: Please use direct connect.", plan->protocol, 0) ? CONNECTION_SETUP_SHORT_RESPOND : CONNECTION_SETUP_SHORT_ABORT;
	}
	if (plan->protocol == PVER_ORIGPRO || plan->protocol == PVER_LEGACYL1 || plan->protocol == PVER_LEGACYL2 || plan->protocol == PVER_LEGACYL3
		|| plan->protocol == PVER_LEGACYL4) {
		return CONNECTION_SETUP_SHORT_ABORT;
	}
	if (plan->protocol == PVER_MODERN1) {
		if (plan->intent != CLIENT_INTENT_STATUS) {
			return CONNECTION_SETUP_SHORT_ABORT;
		}
		plan->result = CONNECTION_SETUP_EOLDCLIENT;
		return connection_setup_short_plan_response_modern(plan, "[Proxy] Use 13w42a or later to play!", 0) ? CONNECTION_SETUP_SHORT_RESPOND : CONNECTION_SETUP_SHORT_ABORT;
	}
	uint8_t legacy_version = 0;
	varint_t modern_version = 0;
	if (plan->protocol == PVER_LEGACYM3) {
		p_motd_legacy packet = packet_read_legacy_motd(initial, packet_size);
		if (packet.address == NULL || strlen(packet.address) >= ROUTE_ENDPOINT_TEXT_SIZE) {
			packet_destroy_legacy_motd(packet);
			return CONNECTION_SETUP_SHORT_ABORT;
		}
		legacy_version = packet.version;
		packet_destroy_legacy_motd(packet);
		connection_setup_short_action route_action = connection_setup_short_route_prepare(plan, snapshot, plan->protocol, 0, legacy_version);
		if (route_action != CONNECTION_SETUP_SHORT_CONNECT) {
			return route_action;
		}
	} else if (plan->protocol == PVER_MODERN2) {
		p_handshake packet = packet_read((void *)initial, (void *)(initial + initial_size));
		if (packet.address == NULL || packet.nextstate != CLIENT_INTENT_STATUS) {
			packet_destroy(packet);
			return CONNECTION_SETUP_SHORT_ABORT;
		}
		modern_version = packet.version;
		packet_destroy(packet);
		connection_setup_short_action route_action = connection_setup_short_route_prepare(plan, snapshot, plan->protocol, modern_version, 0);
		if (route_action != CONNECTION_SETUP_SHORT_CONNECT) {
			return route_action;
		}
	} else {
		return CONNECTION_SETUP_SHORT_ABORT;
	}
	if (snapshot->endpoint.pheader) {
		plan->pheader_size = protocol_proxy_write(plan->pheader, snapshot->endpoint.inbound_proxy);
		if (plan->pheader_size == 0 || plan->pheader_size > PROTOPROXY_PACKETMAXLEN) {
			return CONNECTION_SETUP_SHORT_ABORT;
		}
	}
	bool request_result = plan->protocol == PVER_LEGACYM3
		? connection_setup_short_plan_request_legacy(plan, initial, initial_size, packet_size, snapshot->endpoint.rewrite)
		: connection_setup_short_plan_request_modern(plan, initial, initial_size, packet_size, snapshot->endpoint.rewrite);
	if (!request_result || !connection_setup_short_plan_response_unavailable(plan, plan->protocol, modern_version, legacy_version)) {
		return CONNECTION_SETUP_SHORT_ABORT;
	}
	plan->result = CONNECTION_SETUP_OK;
	return CONNECTION_SETUP_SHORT_CONNECT;
}

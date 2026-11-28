/*
 * listener/admission.c: Client acceptance, peer policy and initial packet assembly
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* section: headers (project) */
#include "../config.h"
#include "../connection/setup.h"
#include "../log.h"
#include "../network.h"
#include "../protocol/common.h"
#include "../protocol/proxy.h"
#include "../route/generation.h"
#include "../route/generation_registry.h"
#include "connection.h"
#include "context.h"
#include "events.h"
#include "metrics.h"

/* section: headers (self) */
#include "admission.h"

/* section: defines */
#ifndef LISTENER_ACCEPT_BATCH
#define LISTENER_ACCEPT_BATCH	128
#endif

/* section: functions (local) */
static bool listener_accept_error_retryable(int error) {
	switch (error) {
		case ECONNABORTED:
		case EHOSTDOWN:
		case EHOSTUNREACH:
		case ENETDOWN:
		case ENETUNREACH:
		case ENONET:
		case ENOPROTOOPT:
		case EOPNOTSUPP:
		case EPROTO:
			return true;
		default:
			return false;
	}
}

static const char *listener_protocol_label(proxy_prefix prefix) {
	switch (prefix) {
		case PROXY_PREFIX_OTHER:
			return "minecraft";
		case PROXY_PREFIX_V1:
			return "proxy_v1";
		case PROXY_PREFIX_V2:
			return "proxy_v2";
		default:
			return "unknown";
	}
}

static listener_connection_progress listener_protocol_mismatch(const char *log_filename, uint8_t log_level, const listener_connection *connection, const char *received, proxy_prefix expected) {
	net_addrp peer = net_ntop(connection->peer_address.family, &connection->peer_address.addr, true);
	MKSYS_LOG(log_filename, log_level, MKSYS_LEVEL_WARNING,
		"src: %s:%u, status: reject_invalid_protocol, received: %s, expected: %s",
		peer.v6, connection->peer_port, received, listener_protocol_label(expected)
	);
	return LISTENER_CONNECTION_CLOSED;
}

static listener_connection_progress listener_proxy_exception(const char *log_filename, uint8_t log_level, const net_addr *address, in_port_t port, const char *exception, int error) {
	net_addrp peer = net_ntop(address->family, &address->addr, true);
	MKSYS_LOG(log_filename, log_level, MKSYS_LEVEL_WARNING,
		"peer: %s:%u, status: reject_proxy_exception, exception: %s%s%s",
		peer.v6, port, exception, error ? ", error: " : "", error ? strerror(error) : ""
	);
	return LISTENER_CONNECTION_CLOSED;
}

static bool listener_admission_peer(const conf *config, const char *log_filename, const net_addr *address, in_port_t port, connection_proxy_origin *origin) {
	if (!config->listen.allow_proxy) {
		*origin = CONNECTION_PROXY_DIRECT;
	} else if (config_peer_trusted(config, *address)) {
		*origin = CONNECTION_PROXY_TRUSTED;
	} else if (config->listen.untrusted_policy == CONF_UNTRUSTED_REJECT) {
		(void)listener_proxy_exception(log_filename, config->log.level, address, port, "untrusted_source", 0);
		return false;
	} else {
		*origin = config->listen.untrusted_policy == CONF_UNTRUSTED_IGNORE ? CONNECTION_PROXY_UNTRUSTED_IGNORE : CONNECTION_PROXY_UNTRUSTED_ACCEPT;
	}
	return true;
}

static listener_connection_progress listener_connection_prefix(listener_connection *connection, const char *log_filename, uint8_t log_level) {
	size_t consumed = 0;
	p_proxy *pair = &connection->inbound_proxy;
	if (connection->proxy_remaining == 0) {
		const conf *config = route_generation_config(connection->generation);
		proxy_prefix expected = config->listen.allow_proxy ? config->listen.proxy_version : PROXY_PREFIX_OTHER;
		proxy_prefix prefix = protocol_proxy_detect(connection->inbound, connection->inbound_size);
		if (prefix == PROXY_PREFIX_PARTIAL) {
			return LISTENER_CONNECTION_PENDING;
		}
		if (prefix != expected) {
			bool unknown = prefix == PROXY_PREFIX_OTHER && protocol_identify(connection->inbound, connection->inbound_size, NULL) == PVER_UNIDENT;
			return listener_protocol_mismatch(log_filename, log_level, connection, unknown ? "unknown" : listener_protocol_label(prefix), expected);
		}
		if (prefix == PROXY_PREFIX_OTHER) {
			connection->prefix_checked = true;
			return LISTENER_CONNECTION_READY;
		}
		proxy_read_status status = prefix == PROXY_PREFIX_V2
			? protocol_proxy_v2_prefix_read(connection->inbound, connection->inbound_size, pair, &consumed, &connection->proxy_remaining)
			: protocol_proxy_read(connection->inbound, connection->inbound_size, pair, &consumed);
		if (status == PROXY_READ_INCOMPLETE) {
			return LISTENER_CONNECTION_PENDING;
		}
		if (status != PROXY_READ_COMPLETE) {
			return listener_proxy_exception(log_filename, log_level, &connection->peer_address, connection->peer_port, status == PROXY_READ_TOO_LONG ? "header_too_long" : "malformed_header", 0);
		}
	}
	/* Reuse the assembly buffer for the opaque tail. Only bytes beyond its declared end belong to Minecraft. */
	size_t available = connection->inbound_size - consumed;
	if (available < connection->proxy_remaining) {
		connection->proxy_remaining -= (uint16_t)available;
		connection->inbound_size = 0;
		return LISTENER_CONNECTION_PENDING;
	}
	consumed += connection->proxy_remaining;
	connection->proxy_remaining = 0;
	connection->inbound_size -= consumed;
	memmove(connection->inbound, connection->inbound + consumed, connection->inbound_size);
	if (pair->family == AF_UNSPEC || connection->proxy_origin == CONNECTION_PROXY_UNTRUSTED_IGNORE) {
		if (pair->family == AF_UNSPEC && connection->proxy_origin == CONNECTION_PROXY_TRUSTED) {
			connection->proxy_origin = CONNECTION_PROXY_UNKNOWN;
		}
		if (!protocol_proxy_socket_read(connection->socket_fd, pair)) {
			return listener_proxy_exception(log_filename, log_level, &connection->peer_address, connection->peer_port, "socket_endpoints_unavailable", errno);
		}
	}
	connection->prefix_checked = true;
	return LISTENER_CONNECTION_READY;
}

/* section: functions (exported) */
int listener_admission_accept_batch(listener_context *context, int listen_fd, const listener_events *events, listener_connection **connections, size_t *connection_count, size_t connection_limit) {
	for (size_t accept_attempt = 0; accept_attempt < LISTENER_ACCEPT_BATCH; accept_attempt++) {
		struct sockaddr_storage client_address;
		socklen_t address_length = sizeof(client_address);
		int client_fd = accept4(listen_fd, (struct sockaddr *)&client_address, &address_length, SOCK_CLOEXEC | SOCK_NONBLOCK);
		if (client_fd == -1) {
			if (errno == EINTR) {
				continue;
			}
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				break;
			}
			if (listener_accept_error_retryable(errno)) {
				continue;
			}
			if (errno == EMFILE || errno == ENFILE) {
				listener_metrics_accept_fd_exhausted_record(&context->metrics);
				LISTENER_LOG(context, MKSYS_LEVEL_WARNING, "Cannot accept client connection: %s", strerror(errno));
				listener_backoff();
				break;
			}
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot accept client connection: %s", strerror(errno));
			return -1;
		}
		listener_metrics_accept_record(&context->metrics);
		net_addr peer_address;
		in_port_t peer_port;
		if (!net_addr_from_socket(&client_address, &peer_address, &peer_port)) {
			close(client_fd);
			continue;
		}
		net_addr_unmap(&peer_address);
		connection_proxy_origin origin;
		if (!listener_admission_peer(context->config, context->log_filename, &peer_address, peer_port, &origin)) {
			close(client_fd);
			continue;
		}
		if (*connection_count >= connection_limit || context->workers.count >= connection_limit - *connection_count) {
			listener_metrics_accept_capacity_rejected_record(&context->metrics);
			close(client_fd);
			continue;
		}
		route_generation *generation = route_generation_registry_active_retain(context->generations);
		if (generation == NULL) {
			close(client_fd);
			LISTENER_LOG(context, MKSYS_LEVEL_CRITICAL, "Cannot retain the active route generation for a client connection.");
			return -1;
		}
		listener_connection *connection = listener_connection_create(client_fd, &peer_address, peer_port, events, generation);
		if (connection == NULL) {
			int saved_errno = errno;
			listener_metrics_connection_track_failure_record(&context->metrics);
			LISTENER_LOG(context, MKSYS_LEVEL_WARNING, "Cannot track client connection: %s", strerror(saved_errno));
			listener_backoff();
			break;
		}
		connection->proxy_origin = origin;
		connection->next = *connections;
		*connections = connection;
		(*connection_count)++;
		listener_metrics_connection_add(&context->metrics);
	}
	return 0;
}

listener_connection_progress listener_admission_receive(listener_connection *connection, uint32_t event_flags, const char *log_filename, uint8_t log_level) {
	while (connection->inbound_size < sizeof(connection->inbound)) {
		ssize_t receive_size = recv(connection->socket_fd, connection->inbound + connection->inbound_size, sizeof(connection->inbound) - connection->inbound_size, 0);
		if (receive_size > 0) {
			connection->inbound_size += (size_t)receive_size;
			if (!connection->prefix_checked) {
				listener_connection_progress prefix = listener_connection_prefix(connection, log_filename, log_level);
				if (prefix == LISTENER_CONNECTION_PENDING || (prefix == LISTENER_CONNECTION_READY && connection->inbound_size == 0)) {
					continue;
				}
				if (prefix != LISTENER_CONNECTION_READY) {
					return prefix;
				}
			}
			size_t packet_size;
			protocol_packet_status packet_status = protocol_packet_length(connection->inbound, connection->inbound_size, &packet_size);
			if (packet_status == PROTOCOL_PACKET_COMPLETE) {
				if (protocol_identify(connection->inbound, connection->inbound_size, NULL) != PVER_UNIDENT) {
					return LISTENER_CONNECTION_READY;
				}
				packet_status = PROTOCOL_PACKET_INVALID;
			}
			if (packet_status == PROTOCOL_PACKET_INVALID || packet_size > sizeof(connection->inbound)) {
				if (connection->proxy_origin == CONNECTION_PROXY_DIRECT && protocol_identify(connection->inbound, connection->inbound_size, NULL) == PVER_UNIDENT) {
					return listener_protocol_mismatch(log_filename, log_level, connection, "unknown", PROXY_PREFIX_OTHER);
				}
				return LISTENER_CONNECTION_ABORT;
			}
			listener_connection_timer timer = packet_status == PROTOCOL_PACKET_AMBIGUOUS ? LISTENER_CONNECTION_TIMER_GRACE : LISTENER_CONNECTION_TIMER_ASSEMBLY;
			if (listener_connection_timer_arm(connection, timer) == -1) {
				return LISTENER_CONNECTION_ABORT;
			}
			continue;
		}
		bool header_pending = !connection->prefix_checked && connection->proxy_origin != CONNECTION_PROXY_DIRECT;
		if (receive_size == 0) {
			if (header_pending) {
				return listener_proxy_exception(log_filename, log_level, &connection->peer_address, connection->peer_port, "header_eof", 0);
			}
			size_t packet_size;
			return protocol_packet_length(connection->inbound, connection->inbound_size, &packet_size) == PROTOCOL_PACKET_AMBIGUOUS
				&& protocol_identify(connection->inbound, connection->inbound_size, NULL) != PVER_UNIDENT ? LISTENER_CONNECTION_READY : LISTENER_CONNECTION_ABORT;
		}
		if (errno == EINTR) {
			continue;
		}
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if (!(event_flags & (EPOLLERR | EPOLLHUP | EPOLLRDHUP))) {
				return LISTENER_CONNECTION_PENDING;
			}
			return header_pending ? listener_proxy_exception(log_filename, log_level, &connection->peer_address, connection->peer_port, "header_eof", 0) : LISTENER_CONNECTION_ABORT;
		}
		return header_pending ? listener_proxy_exception(log_filename, log_level, &connection->peer_address, connection->peer_port, "read_error", errno) : LISTENER_CONNECTION_ABORT;
	}
	return LISTENER_CONNECTION_ABORT;
}

listener_connection_progress listener_admission_timeout(const listener_connection *connection, const char *log_filename, uint8_t log_level) {
	if (!connection->prefix_checked && connection->proxy_origin != CONNECTION_PROXY_DIRECT) {
		return listener_proxy_exception(log_filename, log_level, &connection->peer_address, connection->peer_port, "header_timeout", 0);
	}
	return connection->timer == LISTENER_CONNECTION_TIMER_GRACE && protocol_identify(connection->inbound, connection->inbound_size, NULL) != PVER_UNIDENT
		? LISTENER_CONNECTION_READY : LISTENER_CONNECTION_ABORT;
}

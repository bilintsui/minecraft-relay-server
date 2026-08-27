/*
 * connection/setup_long.c: Worker-owned long connection setup
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* section: headers (project) */
#include "../define/global.h"
#include "../log.h"
#include "../network.h"
#include "../protocol/common.h"
#include "../protocol/handshake.h"
#include "../protocol/handshake_legacy.h"
#include "../protocol/proxy.h"
#include "../timeutil.h"

/* section: headers (self) */
#include "setup_long.h"

/* section: defines */
#define CONNECTION_SETUP_LONG_REWRITE_BUFFER_SIZE	(BUFSIZ + ROUTE_ENDPOINT_TEXT_SIZE + 32U)

#ifndef CONNECTION_SETUP_LONG_CONNECT_TIMEOUT_SEC
#define CONNECTION_SETUP_LONG_CONNECT_TIMEOUT_SEC	5
#endif

#if CONNECTION_SETUP_LONG_CONNECT_TIMEOUT_SEC < 1 || CONNECTION_SETUP_LONG_CONNECT_TIMEOUT_SEC > INT_MAX
#error "The long-worker connect timeout must be between 1 and INT_MAX seconds."
#endif

/* section: types */
typedef struct {
	const char *address;
	bool pheader;
	in_port_t port;
	bool rewrite;
	bool valid;
} connection_setup_long_proxy;

/* section: functions (local) */
static net_error connection_setup_long_connect_outbound(int *socket_out, const connection_setup_snapshot *snapshot) {
	if (socket_out == NULL) {
		return NET_EARGADDR;
	}
	*socket_out = -1;
	if (snapshot == NULL || snapshot->route_status != CONNECTION_SETUP_ROUTE_READY) {
		return NET_ENORECORD;
	}
	const net_addr *address = &snapshot->endpoint.address;
	if (!connection_setup_address_valid(address) || snapshot->endpoint.port == 0) {
		return NET_ENORECORD;
	}
	struct timespec start;
	struct timespec deadline;
	if (clock_gettime(CLOCK_MONOTONIC, &start) == -1 || !timeutil_add_seconds(&start, CONNECTION_SETUP_LONG_CONNECT_TIMEOUT_SEC, &deadline)) {
		return NET_ECONNECT;
	}
	int socket_fd = -1;
	net_connect_status connect_status = net_connect_nonblocking(address, snapshot->endpoint.port, &socket_fd);
	if (connect_status == NET_CONNECT_OK && socket_fd >= 0) {
		struct timespec now;
		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
			close(socket_fd);
			return NET_ECONNECT;
		}
		if (timeutil_compare(&now, &deadline) >= 0) {
			errno = ETIMEDOUT;
			close(socket_fd);
			return NET_ECONNECT;
		}
		*socket_out = socket_fd;
		return NET_OK;
	}
	if (connect_status != NET_CONNECT_PENDING || socket_fd < 0) {
		if (socket_fd >= 0) {
			close(socket_fd);
		}
		return NET_ECONNECT;
	}
	while (true) {
		struct timespec now;
		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
			close(socket_fd);
			return NET_ECONNECT;
		}
		if (timeutil_compare(&now, &deadline) >= 0) {
			errno = ETIMEDOUT;
			close(socket_fd);
			return NET_ECONNECT;
		}
		uintmax_t seconds = (uintmax_t)deadline.tv_sec - (uintmax_t)now.tv_sec;
		long nanoseconds = deadline.tv_nsec - now.tv_nsec;
		if (nanoseconds < 0) {
			seconds--;
			nanoseconds += 1000000000L;
		}
		uintmax_t milliseconds = seconds > (uintmax_t)INT_MAX / 1000U ? (uintmax_t)INT_MAX : seconds * 1000U;
		uintmax_t rounded_nanoseconds = ((uintmax_t)nanoseconds + 999999U) / 1000000U;
		if (milliseconds > (uintmax_t)INT_MAX - rounded_nanoseconds) {
			milliseconds = INT_MAX;
		} else {
			milliseconds += rounded_nanoseconds;
		}
		struct pollfd poll_fd = { .fd = socket_fd, .events = POLLOUT, .revents = 0 };
		int poll_result = poll(&poll_fd, 1, (int)milliseconds);
		if (poll_result == 0) {
			errno = ETIMEDOUT;
			close(socket_fd);
			return NET_ECONNECT;
		}
		if (poll_result == -1) {
			if (errno == EINTR) {
				continue;
			}
			close(socket_fd);
			return NET_ECONNECT;
		}
		if (poll_fd.revents & POLLNVAL) {
			errno = EBADF;
			close(socket_fd);
			return NET_ECONNECT;
		}
		if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
			close(socket_fd);
			return NET_ECONNECT;
		}
		if (timeutil_compare(&now, &deadline) >= 0) {
			errno = ETIMEDOUT;
			close(socket_fd);
			return NET_ECONNECT;
		}
		connect_status = net_connect_nonblocking_complete(socket_fd);
		if (connect_status == NET_CONNECT_OK) {
			*socket_out = socket_fd;
			return NET_OK;
		}
		close(socket_fd);
		return NET_ECONNECT;
	}
}

static connection_setup_long_proxy connection_setup_long_proxyinfo_prepare(const connection_setup_snapshot *snapshot) {
	connection_setup_long_proxy proxyinfo;
	memset(&proxyinfo, 0, sizeof(proxyinfo));
	if (snapshot == NULL || snapshot->route_status == CONNECTION_SETUP_ROUTE_BYPASS || snapshot->route_status == CONNECTION_SETUP_ROUTE_NO_ROUTE) {
		return proxyinfo;
	}
	if (memchr(snapshot->endpoint.configured_address, '\0', sizeof(snapshot->endpoint.configured_address)) == NULL
		|| memchr(snapshot->endpoint.target_name, '\0', sizeof(snapshot->endpoint.target_name)) == NULL) {
		return proxyinfo;
	}
	proxyinfo.address = connection_setup_destination(&snapshot->endpoint);
	proxyinfo.pheader = snapshot->endpoint.pheader;
	proxyinfo.port = snapshot->endpoint.port;
	proxyinfo.rewrite = snapshot->endpoint.rewrite;
	proxyinfo.valid = proxyinfo.address != NULL;
	return proxyinfo;
}

static bool connection_setup_long_seed_append(uint8_t *seed, size_t *seed_size, const void *data, size_t data_size) {
	if (seed_size == NULL || *seed_size > CONNECTION_SETUP_LONG_PENDING_MAX || data_size > CONNECTION_SETUP_LONG_PENDING_MAX - *seed_size
		|| (data_size > 0 && (seed == NULL || data == NULL))) {
		return false;
	}
	if (data_size > 0) {
		memcpy(seed + *seed_size, data, data_size);
		*seed_size += data_size;
	}
	return true;
}

static bool connection_setup_long_seed_proxy_header(uint8_t *seed, size_t *seed_size, const connection_setup_snapshot *snapshot) {
	char pheader[PROTOPROXY_PACKETMAXLEN + 1U];
	memset(pheader, 0, sizeof(pheader));
	size_t pheader_size = protocol_proxy_write(pheader, snapshot->endpoint.inbound_proxy);
	if (pheader_size == 0 || pheader_size > PROTOPROXY_PACKETMAXLEN) {
		return false;
	}
	return connection_setup_long_seed_append(seed, seed_size, pheader, pheader_size);
}

static bool connection_setup_long_seed_tail(uint8_t *seed, size_t *seed_size, const uint8_t *inbound, size_t inbound_size) {
	size_t initial_size;
	if (protocol_packet_length(inbound, inbound_size, &initial_size) != PROTOCOL_PACKET_COMPLETE || initial_size > inbound_size) {
		return false;
	}
	return connection_setup_long_seed_append(seed, seed_size, inbound + initial_size, inbound_size - initial_size);
}

static bool connection_setup_long_send_client(int socket_fd, const void *data, size_t size) {
	if (socket_fd < 0 || (data == NULL && size > 0)) {
		return false;
	}
	const uint8_t *bytes = data;
	size_t sent = 0;
	while (sent < size) {
		ssize_t write_size = send(socket_fd, bytes + sent, size - sent, MSG_NOSIGNAL);
		if (write_size > 0) {
			sent += (size_t)write_size;
			continue;
		}
		if (write_size == -1 && errno == EINTR) {
			continue;
		}
		return false;
	}
	return true;
}

static bool connection_setup_long_set_nonblocking(int socket_fd) {
	int flags = fcntl(socket_fd, F_GETFL);
	if (flags == -1) {
		return false;
	}
	return fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK) != -1;
}

static connection_setup_status connection_setup_long_handle_legacy_login(int socket_in, int *socket_out, net_addrbundle addrinfo_in, const uint8_t *inbound,
	size_t inbound_size, const connection_setup_snapshot *snapshot, uint8_t *seed, size_t *seed_size) {
	uint8_t rewrited[BUFSIZ];
	size_t packlen_rewrited = 0;
	memset(rewrited, 0, sizeof(rewrited));
	protocol_version login_version = protocol_identify(inbound, inbound_size, NULL);
	if (login_version == PVER_LEGACYL1) {
		CONNECTION_SETUP_LOG(snapshot, MKSYS_LEVEL_WARNING,
			"src: %s:%d, type: game, status: reject_gamerelay_oldclient",
			(char *)&(addrinfo_in.address), addrinfo_in.port
		);
		packlen_rewrited = make_kickreason_legacy(rewrited, sizeof(rewrited), "Proxy: Unsupported client, use 12w04a or later!");
		connection_setup_long_send_client(socket_in, rewrited, packlen_rewrited);
		close(socket_in);
		return CONNECTION_SETUP_EOLDCLIENT;
	}
	if (login_version == PVER_LEGACYL3) {
		CONNECTION_SETUP_LOG(snapshot, MKSYS_LEVEL_WARNING,
			"src: %s:%d, type: game, status: reject_gamerelay_12w17a",
			(char *)&(addrinfo_in.address), addrinfo_in.port
		);
		packlen_rewrited = make_kickreason_legacy(rewrited, sizeof(rewrited), "Proxy: Unsupported client, use 12w18a or later!");
		connection_setup_long_send_client(socket_in, rewrited, packlen_rewrited);
		close(socket_in);
		return CONNECTION_SETUP_EOLDCLIENT;
	}
	if (login_version != PVER_LEGACYL2 && login_version != PVER_LEGACYL4) {
		close(socket_in);
		return CONNECTION_SETUP_EABORT;
	}
	p_login_legacy inbound_info = packet_read_legacy_login(inbound, inbound_size, login_version);
	connection_setup_long_proxy proxyinfo = connection_setup_long_proxyinfo_prepare(snapshot);
	if (!proxyinfo.valid) {
		CONNECTION_SETUP_LOG(snapshot, MKSYS_LEVEL_WARNING,
			"src: %s:%d, type: game, vhost: %s, status: reject_vhostinvalid, username: %s",
			(char *)&(addrinfo_in.address), addrinfo_in.port, inbound_info.address, inbound_info.username
		);
		packlen_rewrited = make_kickreason_legacy(rewrited, sizeof(rewrited), "Proxy: Please use a legit name to connect!");
		connection_setup_long_send_client(socket_in, rewrited, packlen_rewrited);
		close(socket_in);
		return CONNECTION_SETUP_ENOVHOST;
	}
	net_error connect_status = connection_setup_long_connect_outbound(socket_out, snapshot);
	mksys_level outmsg_level = connect_status == NET_OK ? MKSYS_LEVEL_INFORMATION : MKSYS_LEVEL_WARNING;
	if (connect_status == NET_OK) {
		CONNECTION_SETUP_LOG(snapshot, outmsg_level,
			"src: %s:%d, type: game, vhost: %s, dst: %s:%d, status: accept, username: %s",
			(char *)&(addrinfo_in.address), addrinfo_in.port, inbound_info.address, proxyinfo.address, proxyinfo.port, inbound_info.username
		);
		bool seed_done = !proxyinfo.pheader || connection_setup_long_seed_proxy_header(seed, seed_size, snapshot);
		if (seed_done && proxyinfo.rewrite) {
			int rewrite_size = snprintf(inbound_info.address, sizeof(inbound_info.address), "%s", proxyinfo.address);
			if (rewrite_size < 0 || (size_t)rewrite_size >= sizeof(inbound_info.address)) {
				seed_done = false;
			} else {
				inbound_info.port = proxyinfo.port;
				packlen_rewrited = packet_write_legacy_login(inbound_info, rewrited);
				seed_done = packlen_rewrited > 0 && connection_setup_long_seed_append(seed, seed_size, rewrited, packlen_rewrited)
					&& connection_setup_long_seed_tail(seed, seed_size, inbound, inbound_size);
			}
		} else if (seed_done) {
			seed_done = connection_setup_long_seed_append(seed, seed_size, inbound, inbound_size);
		}
		if (!seed_done) {
			CONNECTION_SETUP_LOG(snapshot, MKSYS_LEVEL_WARNING,
				"src: %s:%d, type: game, vhost: %s, dst: %s:%d, status: reject_seedoverflow, username: %s",
				(char *)&(addrinfo_in.address), addrinfo_in.port, inbound_info.address, proxyinfo.address, proxyinfo.port, inbound_info.username
			);
			close(*socket_out);
			*socket_out = -1;
			close(socket_in);
			return CONNECTION_SETUP_EABORT;
		}
		return CONNECTION_SETUP_OK;
	}
	if (connect_status == NET_ENORECORD) {
		CONNECTION_SETUP_LOG(snapshot, outmsg_level,
			"src: %s:%d, type: game, vhost: %s, dst: %s:%d, status: reject_dstnoresolve, username: %s",
			(char *)&(addrinfo_in.address), addrinfo_in.port, inbound_info.address, proxyinfo.address, proxyinfo.port, inbound_info.username
		);
		packlen_rewrited = make_kickreason_legacy(rewrited, sizeof(rewrited), "Proxy(Internal): Temporarily failed to resolve the address for the target server, please try again later.");
	} else {
		CONNECTION_SETUP_LOG(snapshot, outmsg_level,
			"src: %s:%d, type: game, vhost: %s, dst: %s:%d, status: reject_dstnoconnect, username: %s",
			(char *)&(addrinfo_in.address), addrinfo_in.port, inbound_info.address, proxyinfo.address, proxyinfo.port, inbound_info.username
		);
		packlen_rewrited = make_kickreason_legacy(rewrited, sizeof(rewrited), "Proxy(Internal): Failed to connect to the target server, please try again later.");
	}
	connection_setup_long_send_client(socket_in, rewrited, packlen_rewrited);
	close(socket_in);
	return connect_status == NET_ENORECORD ? CONNECTION_SETUP_ENORECORD : CONNECTION_SETUP_ENOCONNECT;
}

static connection_setup_status connection_setup_long_handle_modern_handshake(int socket_in, int *socket_out, net_addrbundle addrinfo_in, const uint8_t *inbound,
	size_t inbound_size, const connection_setup_snapshot *snapshot, uint8_t *seed, size_t *seed_size) {
	uint8_t rewrited[CONNECTION_SETUP_LONG_REWRITE_BUFFER_SIZE];
	size_t packlen_rewrited = 0;
	memset(rewrited, 0, sizeof(rewrited));
	p_handshake inbound_info = packet_read((void *)inbound, (void *)(inbound + inbound_size));
	if (inbound_info.address == NULL) {
		packet_destroy(inbound_info);
		close(socket_in);
		return CONNECTION_SETUP_EABORT;
	}
	if (inbound_info.version == 0) {
		intent_t intent;
		protocol_identify(inbound, inbound_size, &intent);
		if (intent != CLIENT_INTENT_LOGIN) {
			packet_destroy(inbound_info);
			close(socket_in);
			return CONNECTION_SETUP_EABORT;
		}
		CONNECTION_SETUP_LOG(snapshot, MKSYS_LEVEL_WARNING,
			"src: %s:%d, type: game, status: reject_gamerelay_13w41*",
			(char *)&(addrinfo_in.address), addrinfo_in.port
		);
		packlen_rewrited = make_kickreason(rewrited, sizeof(rewrited), "Proxy: Unsupported client, use 13w42a or later!");
		connection_setup_long_send_client(socket_in, rewrited, packlen_rewrited);
		packet_destroy(inbound_info);
		close(socket_in);
		return CONNECTION_SETUP_EOLDCLIENT;
	}
	if ((inbound_info.nextstate != CLIENT_INTENT_LOGIN && inbound_info.nextstate != CLIENT_INTENT_TRANSFER) || inbound_info.username == NULL) {
		packet_destroy(inbound_info);
		close(socket_in);
		return CONNECTION_SETUP_EABORT;
	}
	const char *typestr = inbound_info.nextstate == CLIENT_INTENT_TRANSFER ? "transfer" : "game";
	connection_setup_long_proxy proxyinfo = connection_setup_long_proxyinfo_prepare(snapshot);
	if (!proxyinfo.valid) {
		CONNECTION_SETUP_LOG(snapshot, MKSYS_LEVEL_WARNING,
			"src: %s:%d, type: %s, vhost: %s, status: reject_vhostinvalid, username: %s",
			(char *)&(addrinfo_in.address), addrinfo_in.port, typestr, inbound_info.address, inbound_info.username
		);
		packlen_rewrited = make_kickreason(rewrited, sizeof(rewrited), "Proxy: Please use a legit name to connect!");
		connection_setup_long_send_client(socket_in, rewrited, packlen_rewrited);
		packet_destroy(inbound_info);
		close(socket_in);
		return CONNECTION_SETUP_ENOVHOST;
	}
	net_error connect_status = connection_setup_long_connect_outbound(socket_out, snapshot);
	mksys_level outmsg_level = connect_status == NET_OK ? MKSYS_LEVEL_INFORMATION : MKSYS_LEVEL_WARNING;
	if (connect_status == NET_OK) {
		CONNECTION_SETUP_LOG(snapshot, outmsg_level,
			"src: %s:%d, type: %s, vhost: %s, dst: %s:%d, status: accept, username: %s",
			(char *)&(addrinfo_in.address), addrinfo_in.port, typestr, inbound_info.address, proxyinfo.address, proxyinfo.port, inbound_info.username
		);
		bool seed_done = !proxyinfo.pheader || connection_setup_long_seed_proxy_header(seed, seed_size, snapshot);
		bool rewrite_failed = false;
		if (seed_done && proxyinfo.rewrite) {
			void *inbound_addr_new = realloc(inbound_info.address, strlen(proxyinfo.address) + 1U);
			if (inbound_addr_new == NULL) {
				seed_done = false;
				rewrite_failed = true;
			} else {
				inbound_info.address = inbound_addr_new;
				strcpy(inbound_info.address, proxyinfo.address);
				inbound_info.port = proxyinfo.port;
				packlen_rewrited = packet_write(rewrited, sizeof(rewrited), inbound_info);
				if (packlen_rewrited == 0) {
					seed_done = false;
					rewrite_failed = true;
				} else {
					seed_done = connection_setup_long_seed_append(seed, seed_size, rewrited, packlen_rewrited)
						&& connection_setup_long_seed_tail(seed, seed_size, inbound, inbound_size);
				}
			}
		} else if (seed_done) {
			seed_done = connection_setup_long_seed_append(seed, seed_size, inbound, inbound_size);
		}
		if (!seed_done) {
			if (rewrite_failed) {
				CONNECTION_SETUP_LOG(snapshot, MKSYS_LEVEL_WARNING,
					"src: %s:%d, type: %s, dst: %s:%d, status: reject_rewritefailed, username: %s",
					(char *)&(addrinfo_in.address), addrinfo_in.port, typestr, proxyinfo.address, proxyinfo.port, inbound_info.username
				);
			} else {
				CONNECTION_SETUP_LOG(snapshot, MKSYS_LEVEL_WARNING,
					"src: %s:%d, type: %s, vhost: %s, dst: %s:%d, status: reject_seedoverflow, username: %s",
					(char *)&(addrinfo_in.address), addrinfo_in.port, typestr, inbound_info.address, proxyinfo.address, proxyinfo.port, inbound_info.username
				);
			}
			close(*socket_out);
			*socket_out = -1;
			close(socket_in);
			packet_destroy(inbound_info);
			return CONNECTION_SETUP_EABORT;
		}
		packet_destroy(inbound_info);
		return CONNECTION_SETUP_OK;
	}
	if (connect_status == NET_ENORECORD) {
		CONNECTION_SETUP_LOG(snapshot, outmsg_level,
			"src: %s:%d, type: %s, vhost: %s, dst: %s:%d, status: reject_dstnoresolve, username: %s",
			(char *)&(addrinfo_in.address), addrinfo_in.port, typestr, inbound_info.address, proxyinfo.address, proxyinfo.port, inbound_info.username
		);
		packlen_rewrited = make_kickreason(rewrited, sizeof(rewrited), "Proxy(Internal): Temporarily failed to resolve the address for the target server, please try again later.");
	} else {
		CONNECTION_SETUP_LOG(snapshot, outmsg_level,
			"src: %s:%d, type: %s, vhost: %s, dst: %s:%d, status: reject_dstnoconnect, username: %s",
			(char *)&(addrinfo_in.address), addrinfo_in.port, typestr, inbound_info.address, proxyinfo.address, proxyinfo.port, inbound_info.username
		);
		packlen_rewrited = make_kickreason(rewrited, sizeof(rewrited), "Proxy(Internal): Failed to connect to the target server, please try again later.");
	}
	connection_setup_long_send_client(socket_in, rewrited, packlen_rewrited);
	close(socket_in);
	packet_destroy(inbound_info);
	return connect_status == NET_ENORECORD ? CONNECTION_SETUP_ENORECORD : CONNECTION_SETUP_ENOCONNECT;
}

static connection_setup_status connection_setup_long_prepared_run(int socket_in, int *socket_out, net_addrbundle addrinfo_in, const uint8_t *inbound,
	size_t inbound_size, const connection_setup_snapshot *snapshot, uint8_t *seed, size_t *seed_size) {
	if (socket_out == NULL || seed == NULL || seed_size == NULL || inbound == NULL || inbound_size == 0 || inbound_size > BUFSIZ) {
		close(socket_in);
		return CONNECTION_SETUP_EABORT;
	}
	*socket_out = -1;
	*seed_size = 0;
	if (!connection_setup_long_set_nonblocking(socket_in)) {
		close(socket_in);
		return CONNECTION_SETUP_EABORT;
	}
	intent_t intent;
	protocol_version protocol = protocol_identify(inbound, inbound_size, &intent);
	if (protocol == PVER_UNIDENT) {
		CONNECTION_SETUP_LOG(snapshot, MKSYS_LEVEL_WARNING,
			"src: %s:%d, status: reject_unidentproto",
			(char *)&(addrinfo_in.address), addrinfo_in.port
		);
		close(socket_in);
		return CONNECTION_SETUP_EUNIDENT;
	}
	switch (protocol) {
		case PVER_LEGACYL1:
		case PVER_LEGACYL2:
		case PVER_LEGACYL3:
		case PVER_LEGACYL4:
			return connection_setup_long_handle_legacy_login(socket_in, socket_out, addrinfo_in, inbound, inbound_size, snapshot, seed, seed_size);
		case PVER_MODERN1:
		case PVER_MODERN2:
			if (intent == CLIENT_INTENT_LOGIN || intent == CLIENT_INTENT_TRANSFER) {
				return connection_setup_long_handle_modern_handshake(socket_in, socket_out, addrinfo_in, inbound, inbound_size, snapshot, seed, seed_size);
			}
			break;
		case PVER_ORIGPRO:
			close(socket_in);
			return CONNECTION_SETUP_EOLDCLIENT;
		default:
			break;
	}
	close(socket_in);
	return CONNECTION_SETUP_EABORT;
}

/* section: functions (exported) */
connection_setup_status connection_setup_long_prepared(int socket_in, int *socket_out, const connection_setup_snapshot *snapshot, net_addrbundle addrinfo_in,
	const uint8_t *inbound, size_t inbound_size, uint8_t *seed, size_t *seed_size) {
	if (socket_out != NULL) {
		*socket_out = -1;
	}
	if (seed_size != NULL) {
		*seed_size = 0;
	}
	if (!connection_setup_snapshot_valid(snapshot) || seed == NULL || seed_size == NULL) {
		close(socket_in);
		return CONNECTION_SETUP_EABORT;
	}
	return connection_setup_long_prepared_run(socket_in, socket_out, addrinfo_in, inbound, inbound_size, snapshot, seed, seed_size);
}

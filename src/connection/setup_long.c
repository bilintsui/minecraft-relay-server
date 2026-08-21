/*
 * connection/setup_long.c: Worker-owned long connection setup
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* section: headers (project) */
#include "../define/global.h"
#include "../log.h"
#include "../network.h"
#include "../protocol/common.h"
#include "../protocol/handshake.h"
#include "../protocol/handshake_legacy.h"
#include "../protocol/proxy.h"

/* section: headers (self) */
#include "setup_long.h"

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
	if (snapshot->route_status != CONNECTION_SETUP_ROUTE_READY) {
		*socket_out = -1;
		return NET_ENORECORD;
	}
	const net_addr *address = &snapshot->endpoint.address;
	if (!connection_setup_address_valid(address) || snapshot->endpoint.port == 0) {
		*socket_out = -1;
		return NET_ENORECORD;
	}
	*socket_out = net_socket(NETSOCK_CONN, address->family, &address->addr, snapshot->endpoint.port, false);
	return *socket_out == -1 ? NET_ECONNECT : NET_OK;
}

static connection_setup_long_proxy connection_setup_long_proxyinfo_prepare(const connection_setup_snapshot *snapshot) {
	connection_setup_long_proxy proxyinfo;
	memset(&proxyinfo, 0, sizeof(proxyinfo));
	if (snapshot->route_status == CONNECTION_SETUP_ROUTE_BYPASS || snapshot->route_status == CONNECTION_SETUP_ROUTE_NO_ROUTE) {
		return proxyinfo;
	}
	proxyinfo.address = connection_setup_destination(&snapshot->endpoint);
	proxyinfo.pheader = snapshot->endpoint.pheader;
	proxyinfo.port = snapshot->endpoint.port;
	proxyinfo.rewrite = snapshot->endpoint.rewrite;
	proxyinfo.valid = true;
	return proxyinfo;
}

static void connection_setup_long_send_proxy_header(int socket_out, char *pheader, const connection_setup_snapshot *snapshot) {
	size_t packlen_pheader = protocol_proxy_write(pheader, snapshot->endpoint.inbound_proxy);
	if (packlen_pheader > 0) {
		send(socket_out, pheader, packlen_pheader, 0);
	}
}

static connection_setup_status connection_setup_long_handle_legacy_login(int socket_in, int *socket_out, net_addrbundle addrinfo_in, const uint8_t *inbound,
	size_t packlen_inbound, const connection_setup_snapshot *snapshot) {
	uint8_t rewrited[BUFSIZ];
	char pheader[PROTOPROXY_PACKETMAXLEN + 1];
	size_t packlen_rewrited = 0;
	memset(rewrited, 0, BUFSIZ);
	memset(pheader, 0, PROTOPROXY_PACKETMAXLEN + 1);
	protocol_version login_version = protocol_identify(inbound, packlen_inbound, NULL);
	if (login_version == PVER_LEGACYL1) {
		mksysmsg(MKSYS_PREFIX_ON, snapshot->log_filename, snapshot->log_level, MKSYS_LEVEL_WARNING,
			"src: %s:%d, type: game, status: reject_gamerelay_oldclient\n",
			(char *)&(addrinfo_in.address), addrinfo_in.port
		);
		packlen_rewrited = make_kickreason_legacy(rewrited, "Proxy: Unsupported client, use 12w04a or later!");
		send(socket_in, rewrited, packlen_rewrited, 0);
		close(socket_in);
		return CONNECTION_SETUP_EOLDCLIENT;
	} else if (login_version == PVER_LEGACYL3) {
		mksysmsg(MKSYS_PREFIX_ON, snapshot->log_filename, snapshot->log_level, MKSYS_LEVEL_WARNING,
			"src: %s:%d, type: game, status: reject_gamerelay_12w17a\n",
			(char *)&(addrinfo_in.address), addrinfo_in.port
		);
		packlen_rewrited = make_kickreason_legacy(rewrited, "Proxy: Unsupported client, use 12w18a or later!");
		send(socket_in, rewrited, packlen_rewrited, 0);
		close(socket_in);
		return CONNECTION_SETUP_EOLDCLIENT;
	} else if ((login_version == PVER_LEGACYL2) || (login_version == PVER_LEGACYL4)) {
		p_login_legacy inbound_info = packet_read_legacy_login(inbound, packlen_inbound, login_version);
		connection_setup_long_proxy proxyinfo = connection_setup_long_proxyinfo_prepare(snapshot);
		if (!proxyinfo.valid) {
			mksysmsg(MKSYS_PREFIX_ON, snapshot->log_filename, snapshot->log_level, MKSYS_LEVEL_WARNING,
				"src: %s:%d, type: game, vhost: %s, status: reject_vhostinvalid, username: %s\n",
				(char *)&(addrinfo_in.address), addrinfo_in.port, inbound_info.address, inbound_info.username
			);
			packlen_rewrited = make_kickreason_legacy(rewrited, "Proxy: Please use a legit name to connect!");
			send(socket_in, rewrited, packlen_rewrited, 0);
			close(socket_in);
			return CONNECTION_SETUP_ENOVHOST;
		}
		net_error mkoutbound_status;
		mksys_level outmsg_level;
		mkoutbound_status = connection_setup_long_connect_outbound(socket_out, snapshot);
		if (mkoutbound_status != NET_OK) {
			outmsg_level = MKSYS_LEVEL_WARNING;
		} else {
			outmsg_level = MKSYS_LEVEL_INFORMATION;
		}
		switch (mkoutbound_status) {
			case NET_OK:
				mksysmsg(MKSYS_PREFIX_ON, snapshot->log_filename, snapshot->log_level, outmsg_level,
					"src: %s:%d, type: game, vhost: %s, dst: %s:%d, status: accept, username: %s\n",
					(char *)&(addrinfo_in.address), addrinfo_in.port, inbound_info.address, proxyinfo.address, proxyinfo.port, inbound_info.username
				);
				if (proxyinfo.pheader) {
					connection_setup_long_send_proxy_header(*socket_out, pheader, snapshot);
				}
				if (proxyinfo.rewrite) {
					snprintf(inbound_info.address, sizeof(inbound_info.address), "%s", proxyinfo.address);
					inbound_info.port = proxyinfo.port;
					packlen_rewrited = packet_write_legacy_login(inbound_info, rewrited);
					send(*socket_out, rewrited, packlen_rewrited, 0);
				} else {
					send(*socket_out, inbound, packlen_inbound, 0);
				}
				return CONNECTION_SETUP_OK;
			case NET_ENORECORD:
			case NET_ECONNECT:
				if (mkoutbound_status == NET_ENORECORD) {
					mksysmsg(MKSYS_PREFIX_ON, snapshot->log_filename, snapshot->log_level, outmsg_level,
						"src: %s:%d, type: game, vhost: %s, dst: %s:%d, status: reject_dstnoresolve, username: %s\n",
						(char *)&(addrinfo_in.address), addrinfo_in.port, inbound_info.address, proxyinfo.address, proxyinfo.port, inbound_info.username
					);
					packlen_rewrited = make_kickreason_legacy(rewrited, "Proxy(Internal): Temporarily failed to resolve the address for the target server, please try again later.");
				} else if (mkoutbound_status == NET_ECONNECT) {
					mksysmsg(MKSYS_PREFIX_ON, snapshot->log_filename, snapshot->log_level, outmsg_level,
						"src: %s:%d, type: game, vhost: %s, dst: %s:%d, status: reject_dstnoconnect, username: %s\n",
						(char *)&(addrinfo_in.address), addrinfo_in.port, inbound_info.address, proxyinfo.address, proxyinfo.port, inbound_info.username
					);
					packlen_rewrited = make_kickreason_legacy(rewrited, "Proxy(Internal): Failed to connect to the target server, please try again later.");
				}
				send(socket_in, rewrited, packlen_rewrited, 0);
				close(socket_in);
				return (mkoutbound_status == NET_ENORECORD) ? CONNECTION_SETUP_ENORECORD : CONNECTION_SETUP_ENOCONNECT;
			default:
				break;
		}
	}
	close(socket_in);
	return CONNECTION_SETUP_EABORT;
}

static connection_setup_status connection_setup_long_handle_modern_handshake(int socket_in, int *socket_out, net_addrbundle addrinfo_in, const uint8_t *inbound,
	size_t packlen_inbound, const connection_setup_snapshot *snapshot) {
	uint8_t rewrited[BUFSIZ];
	char pheader[PROTOPROXY_PACKETMAXLEN + 1];
	size_t packlen_rewrited = 0;
	memset(rewrited, 0, BUFSIZ);
	memset(pheader, 0, PROTOPROXY_PACKETMAXLEN + 1);
	p_handshake inbound_info = packet_read((void *)inbound, (void *)(inbound + packlen_inbound));
	if (inbound_info.version == 0) {
		intent_t intent;
		protocol_identify(inbound, (size_t)packlen_inbound, &intent);
		if (intent != CLIENT_INTENT_LOGIN) {
			packet_destroy(inbound_info);
			close(socket_in);
			return CONNECTION_SETUP_EABORT;
		}
		mksysmsg(MKSYS_PREFIX_ON, snapshot->log_filename, snapshot->log_level, MKSYS_LEVEL_WARNING,
			"src: %s:%d, type: game, status: reject_gamerelay_13w41*\n",
			(char *)&(addrinfo_in.address), addrinfo_in.port
		);
		packlen_rewrited = make_kickreason(rewrited, "Proxy: Unsupported client, use 13w42a or later!");
		send(socket_in, rewrited, packlen_rewrited, 0);
		packet_destroy(inbound_info);
		close(socket_in);
		return CONNECTION_SETUP_EOLDCLIENT;
	}
	if (inbound_info.nextstate != CLIENT_INTENT_LOGIN && inbound_info.nextstate != CLIENT_INTENT_TRANSFER) {
		packet_destroy(inbound_info);
		close(socket_in);
		return CONNECTION_SETUP_EABORT;
	}
	const char *typestr = (inbound_info.nextstate == CLIENT_INTENT_TRANSFER) ? "transfer" : "game";
	connection_setup_long_proxy proxyinfo = connection_setup_long_proxyinfo_prepare(snapshot);
	if (!proxyinfo.valid) {
		mksysmsg(MKSYS_PREFIX_ON, snapshot->log_filename, snapshot->log_level, MKSYS_LEVEL_WARNING,
			"src: %s:%d, type: %s, vhost: %s, status: reject_vhostinvalid, username: %s\n",
			(char *)&(addrinfo_in.address), addrinfo_in.port, typestr, inbound_info.address, inbound_info.username
		);
		packlen_rewrited = make_kickreason(rewrited, "Proxy: Please use a legit name to connect!");
		send(socket_in, rewrited, packlen_rewrited, 0);
		packet_destroy(inbound_info);
		close(socket_in);
		return CONNECTION_SETUP_ENOVHOST;
	}
	net_error mkoutbound_status;
	mkoutbound_status = connection_setup_long_connect_outbound(socket_out, snapshot);
	mksys_level outmsg_level = mkoutbound_status == NET_OK ? MKSYS_LEVEL_INFORMATION : MKSYS_LEVEL_WARNING;
	switch (mkoutbound_status) {
		case NET_OK:
			mksysmsg(MKSYS_PREFIX_ON, snapshot->log_filename, snapshot->log_level, outmsg_level,
				"src: %s:%d, type: %s, vhost: %s, dst: %s:%d, status: accept, username: %s\n",
				(char *)&(addrinfo_in.address), addrinfo_in.port, typestr, inbound_info.address, proxyinfo.address, proxyinfo.port, inbound_info.username
			);
			if (proxyinfo.pheader) {
				connection_setup_long_send_proxy_header(*socket_out, pheader, snapshot);
			}
			if (proxyinfo.rewrite) {
				void *inbound_addr_new = realloc(inbound_info.address, strlen(proxyinfo.address) + 1);
				if (inbound_addr_new != NULL) {
					inbound_info.address = inbound_addr_new;
					strcpy(inbound_info.address, proxyinfo.address);
					inbound_info.port = proxyinfo.port;
					packlen_rewrited = packet_write(rewrited, inbound_info);
					send(*socket_out, rewrited, packlen_rewrited, 0);
				} else {
					send(*socket_out, inbound, packlen_inbound, 0);
				}
			} else {
				send(*socket_out, inbound, packlen_inbound, 0);
			}
			packet_destroy(inbound_info);
			return CONNECTION_SETUP_OK;
		case NET_ENORECORD:
		case NET_ECONNECT:
			if (mkoutbound_status == NET_ENORECORD) {
				mksysmsg(MKSYS_PREFIX_ON, snapshot->log_filename, snapshot->log_level, outmsg_level,
					"src: %s:%d, type: %s, vhost: %s, dst: %s:%d, status: reject_dstnoresolve, username: %s\n",
					(char *)&(addrinfo_in.address), addrinfo_in.port, typestr, inbound_info.address, proxyinfo.address, proxyinfo.port, inbound_info.username
				);
				packlen_rewrited = make_kickreason(rewrited, "Proxy(Internal): Temporarily failed to resolve the address for the target server, please try again later.");
			} else if (mkoutbound_status == NET_ECONNECT) {
				mksysmsg(MKSYS_PREFIX_ON, snapshot->log_filename, snapshot->log_level, outmsg_level,
					"src: %s:%d, type: %s, vhost: %s, dst: %s:%d, status: reject_dstnoconnect, username: %s\n",
					(char *)&(addrinfo_in.address), addrinfo_in.port, typestr, inbound_info.address, proxyinfo.address, proxyinfo.port, inbound_info.username
				);
				packlen_rewrited = make_kickreason(rewrited, "Proxy(Internal): Failed to connect to the target server, please try again later.");
			}
			send(socket_in, rewrited, packlen_rewrited, 0);
			close(socket_in);
			packet_destroy(inbound_info);
			return (mkoutbound_status == NET_ENORECORD) ? CONNECTION_SETUP_ENORECORD : CONNECTION_SETUP_ENOCONNECT;
		default:
			break;
	}
	close(socket_in);
	return CONNECTION_SETUP_EABORT;
}

static connection_setup_status connection_setup_long_prepared_run(int socket_in, int *socket_out, net_addrbundle addrinfo_in, const uint8_t *inbound,
	size_t inbound_size, const connection_setup_snapshot *snapshot) {
	if (socket_out == NULL || inbound == NULL || inbound_size == 0 || inbound_size > BUFSIZ) {
		close(socket_in);
		return CONNECTION_SETUP_EABORT;
	}
	intent_t intent;
	protocol_version protocol = protocol_identify(inbound, inbound_size, &intent);
	if (protocol == PVER_UNIDENT) {
		mksysmsg(MKSYS_PREFIX_ON, snapshot->log_filename, snapshot->log_level, MKSYS_LEVEL_WARNING,
			"src: %s:%d, status: reject_unidentproto\n",
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
			return connection_setup_long_handle_legacy_login(socket_in, socket_out, addrinfo_in, inbound, inbound_size, snapshot);
		case PVER_MODERN1:
		case PVER_MODERN2:
			if (intent == CLIENT_INTENT_LOGIN || intent == CLIENT_INTENT_TRANSFER) {
				return connection_setup_long_handle_modern_handshake(socket_in, socket_out, addrinfo_in, inbound, inbound_size, snapshot);
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
connection_setup_status connection_setup_long_prepared(int socket_in, int *socket_out, const connection_setup_snapshot *snapshot, net_addrbundle addrinfo_in, const uint8_t *inbound, size_t inbound_size) {
	if (!connection_setup_snapshot_valid(snapshot)) {
		close(socket_in);
		return CONNECTION_SETUP_EABORT;
	}
	return connection_setup_long_prepared_run(socket_in, socket_out, addrinfo_in, inbound, inbound_size, snapshot);
}

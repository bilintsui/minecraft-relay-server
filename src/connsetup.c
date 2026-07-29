/*
 * connsetup.c: Functions for initial connection setup
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
#include <sys/types.h>
#include <unistd.h>

/* section: headers (project) */
#include "config.h"
#include "define/global.h"
#include "log.h"
#include "network.h"
#include "protocol/common.h"
#include "protocol/handshake.h"
#include "protocol/handshake_legacy.h"
#include "protocol/proxy.h"

/* section: headers (self) */
#include "connsetup.h"

/* section: functions (local) */
static void connsetup_proxyinfo_resolve_srv(conf_proxy *proxyinfo) {
	if (!proxyinfo->srvenabled) {
		return;
	}
	net_srvrecord srvrecords[128];
	if (net_srvresolve(proxyinfo->address, srvrecords) > 0) {
		char *proxyaddr_new = (char *)realloc(proxyinfo->address, strlen(srvrecords[0].target) + 1);
		if (proxyaddr_new != NULL) {
			proxyinfo->address = proxyaddr_new;
			strcpy(proxyinfo->address, srvrecords[0].target);
			proxyinfo->port = srvrecords[0].port;
			proxyinfo->srvenabled = false;
		}
	}
}

static int connsetup_connect_outbound(int *socket_out, net_addr *connaddr_out, conf_proxy *proxyinfo, sa_family_t family, bool netpriority_enabled) {
	int mkoutbound_status;
	connsetup_proxyinfo_resolve_srv(proxyinfo);
	mkoutbound_status = 0;
	*connaddr_out = net_resolve_dual(proxyinfo->address, family, netpriority_enabled);
	if (connaddr_out->family == 0) {
		mkoutbound_status = NET_ENORECORD;
		*socket_out = -1;
	} else {
		*socket_out = net_socket(NETSOCK_CONN, connaddr_out->family, &(connaddr_out->addr), proxyinfo->port, false);
		if (*socket_out == -1) {
			mkoutbound_status = NET_ECONNECT;
		}
	}
	return mkoutbound_status;
}

static void connsetup_send_proxy_header(int socket_out, char *pheader, int *packlen_pheader, const net_addr *connaddr, const net_addrbundle *addrinfo_in, const conf_proxy *proxyinfo) {
	if (connaddr->family != addrinfo_in->family) {
		return;
	}
	net_addrp addrinfo_out = net_ntop(connaddr->family, &(connaddr->addr), false);
	if (addrinfo_in->family == AF_INET) {
		*packlen_pheader = snprintf(pheader, PROTOPROXY_PACKETMAXLEN + 1,
			"PROXY TCP4 %s %s %d %d\r\n",
			(char *)&(addrinfo_in->address_clean), (char *)&addrinfo_out, addrinfo_in->port, proxyinfo->port
		);
		send(socket_out, pheader, *packlen_pheader, 0);
	} else if (addrinfo_in->family == AF_INET6) {
		*packlen_pheader = snprintf(pheader, PROTOPROXY_PACKETMAXLEN + 1,
			"PROXY TCP6 %s %s %d %d\r\n",
			(char *)&(addrinfo_in->address_clean), (char *)&addrinfo_out, addrinfo_in->port, proxyinfo->port
		);
		send(socket_out, pheader, *packlen_pheader, 0);
	}
}

static int connsetup_handle_legacy_login(int socket_in, int *socket_out, const char *logfile, conf *conf_in, net_addrbundle addrinfo_in, bool netpriority_enabled, uint8_t *inbound, ssize_t packlen_inbound) {
	uint8_t rewrited[BUFSIZ];
	char pheader[PROTOPROXY_PACKETMAXLEN + 1];
	size_t packlen_rewrited = 0;
	int packlen_pheader;
	memset(rewrited, 0, BUFSIZ);
	memset(pheader, 0, PROTOPROXY_PACKETMAXLEN + 1);
	uint8_t login_version = protocol_identify(inbound);
	if (login_version == PVER_LEGACYL1) {
		mksysmsg(MKSYS_PREFIX_ON, logfile, conf_in->log.level, MKSYS_LEVEL_WARNING,
			"src: %s:%d, type: game, status: reject_gamerelay_oldclient\n",
			(char *)&(addrinfo_in.address), addrinfo_in.port
		);
		packlen_rewrited = make_kickreason_legacy(rewrited, "Proxy: Unsupported client, use 12w04a or later!");
		send(socket_in, rewrited, packlen_rewrited, 0);
		close(socket_in);
		return CONNSETUP_EOLDCLIENT;
	} else if (login_version == PVER_LEGACYL3) {
		mksysmsg(MKSYS_PREFIX_ON, logfile, conf_in->log.level, MKSYS_LEVEL_WARNING,
			"src: %s:%d, type: game, status: reject_gamerelay_12w17a\n",
			(char *)&(addrinfo_in.address), addrinfo_in.port
		);
		packlen_rewrited = make_kickreason_legacy(rewrited, "Proxy: Unsupported client, use 12w18a or later!");
		send(socket_in, rewrited, packlen_rewrited, 0);
		close(socket_in);
		return CONNSETUP_EOLDCLIENT;
	} else if ((login_version == PVER_LEGACYL2) || (login_version == PVER_LEGACYL4)) {
		p_login_legacy inbound_info = packet_read_legacy_login(inbound, packlen_inbound, login_version);
		conf_proxy proxyinfo = config_proxy_search(conf_in, inbound_info.address);
		if (!proxyinfo.valid) {
			mksysmsg(MKSYS_PREFIX_ON, logfile, conf_in->log.level, MKSYS_LEVEL_WARNING,
				"src: %s:%d, type: game, vhost: %s, status: reject_vhostinvalid, username: %s\n",
				(char *)&(addrinfo_in.address), addrinfo_in.port, inbound_info.address, inbound_info.username
			);
			packlen_rewrited = make_kickreason_legacy(rewrited, "Proxy: Please use a legit name to connect!");
			send(socket_in, rewrited, packlen_rewrited, 0);
			close(socket_in);
			return CONNSETUP_ENOVHOST;
		}
		int mkoutbound_status, outmsg_level;
		net_addr connaddr;
		mkoutbound_status = connsetup_connect_outbound(socket_out, &connaddr, &proxyinfo, addrinfo_in.family, netpriority_enabled);
		if (mkoutbound_status != 0) {
			outmsg_level = MKSYS_LEVEL_WARNING;
		} else {
			outmsg_level = MKSYS_LEVEL_INFORMATION;
		}
		switch (mkoutbound_status) {
			case 0:
				mksysmsg(MKSYS_PREFIX_ON, logfile, conf_in->log.level, outmsg_level,
					"src: %s:%d, type: game, vhost: %s, dst: %s:%d, status: accept, username: %s\n",
					(char *)&(addrinfo_in.address), addrinfo_in.port, inbound_info.address, proxyinfo.address, proxyinfo.port, inbound_info.username
				);
				if (proxyinfo.pheader) {
					connsetup_send_proxy_header(*socket_out, pheader, &packlen_pheader, &connaddr, &addrinfo_in, &proxyinfo);
				}
				if (proxyinfo.rewrite) {
					snprintf(inbound_info.address, sizeof(inbound_info.address), "%s", proxyinfo.address);
					inbound_info.port = proxyinfo.port;
					packlen_rewrited = packet_write_legacy_login(inbound_info, rewrited);
					send(*socket_out, rewrited, packlen_rewrited, 0);
				} else {
					send(*socket_out, inbound, packlen_inbound, 0);
				}
				config_proxy_search_destroy(&proxyinfo);
				return 0;
			case NET_ENORECORD:
			case NET_ECONNECT:
				if (mkoutbound_status == NET_ENORECORD) {
					mksysmsg(MKSYS_PREFIX_ON, logfile, conf_in->log.level, outmsg_level,
						"src: %s:%d, type: game, vhost: %s, dst: %s:%d, status: reject_dstnoresolve, username: %s\n",
						(char *)&(addrinfo_in.address), addrinfo_in.port, inbound_info.address, proxyinfo.address, proxyinfo.port, inbound_info.username
					);
					packlen_rewrited = make_kickreason_legacy(rewrited, "Proxy(Internal): Temporarily failed to resolve the address for the target server, please try again later.");
				} else if (mkoutbound_status == NET_ECONNECT) {
					mksysmsg(MKSYS_PREFIX_ON, logfile, conf_in->log.level, outmsg_level,
						"src: %s:%d, type: game, vhost: %s, dst: %s:%d, status: reject_dstnoconnect, username: %s\n",
						(char *)&(addrinfo_in.address), addrinfo_in.port, inbound_info.address, proxyinfo.address, proxyinfo.port, inbound_info.username
					);
					packlen_rewrited = make_kickreason_legacy(rewrited, "Proxy(Internal): Failed to connect to the target server, please try again later.");
				}
				send(socket_in, rewrited, packlen_rewrited, 0);
				close(socket_in);
				config_proxy_search_destroy(&proxyinfo);
				return (mkoutbound_status == NET_ENORECORD) ? CONNSETUP_ENORECORD : CONNSETUP_ENOCONNECT;
		}
	}
	close(socket_in);
	return CONNSETUP_EABORT;
}

static int connsetup_handle_legacy_motd(int socket_in, int *socket_out, const char *logfile, conf *conf_in, net_addrbundle addrinfo_in, bool netpriority_enabled, uint8_t *inbound, ssize_t packlen_inbound) {
	uint8_t rewrited[BUFSIZ];
	char pheader[PROTOPROXY_PACKETMAXLEN + 1];
	size_t packlen_rewrited = 0;
	int packlen_pheader;
	memset(rewrited, 0, BUFSIZ);
	memset(pheader, 0, PROTOPROXY_PACKETMAXLEN + 1);
	uint8_t motd_version = protocol_identify(inbound);
	if (motd_version == PVER_LEGACYM3) {
		p_motd_legacy inbound_info = packet_read_legacy_motd(inbound);
		conf_proxy proxyinfo = config_proxy_search(conf_in, inbound_info.address);
		if (!proxyinfo.valid) {
			mksysmsg(MKSYS_PREFIX_ON, logfile, conf_in->log.level, MKSYS_LEVEL_WARNING,
				"src: %s:%d, type: motd, vhost: %s, status: reject_vhostinvalid\n",
				(char *)&(addrinfo_in.address), addrinfo_in.port, inbound_info.address
			);
			packlen_rewrited = make_motd_legacy(rewrited, "[Proxy] Use a legit address to play!", motd_version, inbound_info.version);
			send(socket_in, rewrited, packlen_rewrited, 0);
			packet_destroy_legacy_motd(inbound_info);
			close(socket_in);
			return CONNSETUP_ENOVHOST;
		}
		int mkoutbound_status, outmsg_level;
		net_addr connaddr;
		mkoutbound_status = connsetup_connect_outbound(socket_out, &connaddr, &proxyinfo, addrinfo_in.family, netpriority_enabled);
		if (mkoutbound_status != 0) {
			outmsg_level = MKSYS_LEVEL_WARNING;
		} else {
			outmsg_level = MKSYS_LEVEL_INFORMATION + 1;
		}
		switch (mkoutbound_status) {
			case 0:
				mksysmsg(MKSYS_PREFIX_ON, logfile, conf_in->log.level, outmsg_level,
					"src: %s:%d, type: motd, vhost: %s, dst: %s:%d, status: accept\n",
					(char *)&(addrinfo_in.address), addrinfo_in.port, inbound_info.address, proxyinfo.address, proxyinfo.port
				);
				if (proxyinfo.pheader) {
					connsetup_send_proxy_header(*socket_out, pheader, &packlen_pheader, &connaddr, &addrinfo_in, &proxyinfo);
				}
				if (proxyinfo.rewrite) {
					void *inbound_addr_new = realloc(inbound_info.address, strlen(proxyinfo.address) + 1);
					if (inbound_addr_new != NULL) {
						inbound_info.address = inbound_addr_new;
						strcpy(inbound_info.address, proxyinfo.address);
						inbound_info.port = proxyinfo.port;
						packlen_rewrited = packet_write_legacy_motd(rewrited, inbound_info);
						send(*socket_out, rewrited, packlen_rewrited, 0);
					} else {
						send(*socket_out, inbound, packlen_inbound, 0);
					}
				} else {
					send(*socket_out, inbound, packlen_inbound, 0);
				}
				config_proxy_search_destroy(&proxyinfo);
				packet_destroy_legacy_motd(inbound_info);
				return 0;
			case NET_ENORECORD:
			case NET_ECONNECT:
				if (mkoutbound_status == NET_ENORECORD) {
					mksysmsg(MKSYS_PREFIX_ON, logfile, conf_in->log.level, outmsg_level,
						"src: %s:%d, type: motd, vhost: %s, dst: %s:%d, status: reject_dstnoresolve\n",
						(char *)&(addrinfo_in.address), addrinfo_in.port, inbound_info.address, proxyinfo.address, proxyinfo.port
					);
				} else if (mkoutbound_status == NET_ECONNECT) {
					mksysmsg(MKSYS_PREFIX_ON, logfile, conf_in->log.level, outmsg_level,
						"src: %s:%d, type: motd, vhost: %s, dst: %s:%d, status: reject_dstnoconnect\n",
						(char *)&(addrinfo_in.address), addrinfo_in.port, inbound_info.address, proxyinfo.address, proxyinfo.port
					);
				}
				packlen_rewrited = make_motd_legacy(rewrited, "[Proxy] Server Temporarily Unavailable.", motd_version, inbound_info.version);
				send(socket_in, rewrited, packlen_rewrited, 0);
				close(socket_in);
				packet_destroy_legacy_motd(inbound_info);
				config_proxy_search_destroy(&proxyinfo);
				return (mkoutbound_status == NET_ENORECORD) ? CONNSETUP_ENORECORD : CONNSETUP_ENOCONNECT;
		}
	} else {
		mksysmsg(MKSYS_PREFIX_ON, logfile, conf_in->log.level, MKSYS_LEVEL_WARNING,
			"src: %s:%d, type: motd, status: reject_motdrelay_oldclient\n",
			(char *)&(addrinfo_in.address), addrinfo_in.port
		);
		packlen_rewrited = make_motd_legacy(rewrited, "Proxy: Please use direct connect.", protocol_identify(inbound), 0);
		send(socket_in, rewrited, packlen_rewrited, 0);
		close(socket_in);
		return CONNSETUP_EOLDCLIENT;
	}
	close(socket_in);
	return CONNSETUP_EABORT;
}

static int connsetup_handle_modern_handshake(int socket_in, int *socket_out, const char *logfile, conf *conf_in, net_addrbundle addrinfo_in, bool netpriority_enabled,
	uint8_t *inbound, ssize_t packlen_inbound) {
	uint8_t rewrited[BUFSIZ];
	char pheader[PROTOPROXY_PACKETMAXLEN + 1];
	size_t packlen_rewrited = 0;
	int packlen_pheader;
	memset(rewrited, 0, BUFSIZ);
	memset(pheader, 0, PROTOPROXY_PACKETMAXLEN + 1);
	p_handshake inbound_info = packet_read(inbound, inbound + packlen_inbound);
	if (inbound_info.version == 0) {
		if (inbound[inbound[0]] == 1) {
			mksysmsg(MKSYS_PREFIX_ON, logfile, conf_in->log.level, MKSYS_LEVEL_WARNING,
				"src: %s:%d, type: motd, status: reject_motdrelay_13w41*\n",
				(char *)&(addrinfo_in.address), addrinfo_in.port
			);
			packlen_rewrited = make_motd(rewrited, "[Proxy] Use 13w42a or later to play!", inbound_info.version, conf_in->icon_b64);
		} else if (inbound[inbound[0]] == 2) {
			mksysmsg(MKSYS_PREFIX_ON, logfile, conf_in->log.level, MKSYS_LEVEL_WARNING,
				"src: %s:%d, type: game, status: reject_gamerelay_13w41*\n",
				(char *)&(addrinfo_in.address), addrinfo_in.port
			);
			packlen_rewrited = make_kickreason(rewrited, "Proxy: Unsupported client, use 13w42a or later!");
		}
		send(socket_in, rewrited, packlen_rewrited, 0);
		packet_destroy(inbound_info);
		close(socket_in);
		return CONNSETUP_EOLDCLIENT;
	}
	const char *typestr = (inbound_info.nextstate == CLIENT_INTENT_TRANSFER) ? "transfer" : "game";
	conf_proxy proxyinfo = config_proxy_search(conf_in, inbound_info.address);
	if (!proxyinfo.valid) {
		if (inbound_info.nextstate == CLIENT_INTENT_STATUS) {
			mksysmsg(MKSYS_PREFIX_ON, logfile, conf_in->log.level, MKSYS_LEVEL_WARNING,
				"src: %s:%d, type: motd, vhost: %s, status: reject_vhostinvalid\n",
				(char *)&(addrinfo_in.address), addrinfo_in.port, inbound_info.address
			);
			packlen_rewrited = make_motd(rewrited, "[Proxy] Use a legit address to play!", inbound_info.version, conf_in->icon_b64);
		} else if ((inbound_info.nextstate == CLIENT_INTENT_LOGIN) || (inbound_info.nextstate == CLIENT_INTENT_TRANSFER)) {
			mksysmsg(MKSYS_PREFIX_ON, logfile, conf_in->log.level, MKSYS_LEVEL_WARNING,
				"src: %s:%d, type: %s, vhost: %s, status: reject_vhostinvalid, username: %s\n",
				(char *)&(addrinfo_in.address), addrinfo_in.port, typestr, inbound_info.address, inbound_info.username
			);
			packlen_rewrited = make_kickreason(rewrited, "Proxy: Please use a legit name to connect!");
		}
		send(socket_in, rewrited, packlen_rewrited, 0);
		packet_destroy(inbound_info);
		close(socket_in);
		return CONNSETUP_ENOVHOST;
	}
	int mkoutbound_status, outmsg_level;
	net_addr connaddr;
	mkoutbound_status = connsetup_connect_outbound(socket_out, &connaddr, &proxyinfo, addrinfo_in.family, netpriority_enabled);
	if (mkoutbound_status != 0) {
		outmsg_level = MKSYS_LEVEL_WARNING;
	} else {
		if (inbound_info.nextstate == CLIENT_INTENT_STATUS) {
			outmsg_level = MKSYS_LEVEL_INFORMATION + 1;
		} else if ((inbound_info.nextstate == CLIENT_INTENT_LOGIN) || (inbound_info.nextstate == CLIENT_INTENT_TRANSFER)) {
			outmsg_level = MKSYS_LEVEL_INFORMATION;
		}
	}
	switch (mkoutbound_status) {
		case 0:
			if (inbound_info.nextstate == CLIENT_INTENT_STATUS) {
				mksysmsg(MKSYS_PREFIX_ON, logfile, conf_in->log.level, outmsg_level,
					"src: %s:%d, type: motd, vhost: %s, dst: %s:%d, status: accept\n",
					(char *)&(addrinfo_in.address), addrinfo_in.port, inbound_info.address, proxyinfo.address, proxyinfo.port
				);
			} else if ((inbound_info.nextstate == CLIENT_INTENT_LOGIN) || (inbound_info.nextstate == CLIENT_INTENT_TRANSFER)) {
				mksysmsg(MKSYS_PREFIX_ON, logfile, conf_in->log.level, outmsg_level,
					"src: %s:%d, type: %s, vhost: %s, dst: %s:%d, status: accept, username: %s\n",
					(char *)&(addrinfo_in.address), addrinfo_in.port, typestr, inbound_info.address, proxyinfo.address, proxyinfo.port, inbound_info.username
				);
			}
			if (proxyinfo.pheader) {
				connsetup_send_proxy_header(*socket_out, pheader, &packlen_pheader, &connaddr, &addrinfo_in, &proxyinfo);
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
			config_proxy_search_destroy(&proxyinfo);
			packet_destroy(inbound_info);
			return 0;
		case NET_ENORECORD:
		case NET_ECONNECT:
			if (inbound_info.nextstate == CLIENT_INTENT_STATUS) {
				packlen_rewrited = make_motd(rewrited, "[Proxy] Server Temporarily Unavailable.", inbound_info.version, conf_in->icon_b64);
				if (mkoutbound_status == NET_ENORECORD) {
					mksysmsg(MKSYS_PREFIX_ON, logfile, conf_in->log.level, outmsg_level,
						"src: %s:%d, type: motd, vhost: %s, dst: %s:%d, status: reject_dstnoresolve\n",
						(char *)&(addrinfo_in.address), addrinfo_in.port, inbound_info.address, proxyinfo.address, proxyinfo.port
					);
				} else if (mkoutbound_status == NET_ECONNECT) {
					mksysmsg(MKSYS_PREFIX_ON, logfile, conf_in->log.level, outmsg_level,
						"src: %s:%d, type: motd, vhost: %s, dst: %s:%d, status: reject_dstnoconnect\n",
						(char *)&(addrinfo_in.address), addrinfo_in.port, inbound_info.address, proxyinfo.address, proxyinfo.port
					);
				}
			} else if ((inbound_info.nextstate == CLIENT_INTENT_LOGIN) || (inbound_info.nextstate == CLIENT_INTENT_TRANSFER)) {
				if (mkoutbound_status == NET_ENORECORD) {
					mksysmsg(MKSYS_PREFIX_ON, logfile, conf_in->log.level, outmsg_level,
						"src: %s:%d, type: %s, vhost: %s, dst: %s:%d, status: reject_dstnoresolve, username: %s\n",
						(char *)&(addrinfo_in.address), addrinfo_in.port, typestr, inbound_info.address, proxyinfo.address, proxyinfo.port, inbound_info.username
					);
					packlen_rewrited = make_kickreason(rewrited, "Proxy(Internal): Temporarily failed to resolve the address for the target server, please try again later.");
				} else if (mkoutbound_status == NET_ECONNECT) {
					mksysmsg(MKSYS_PREFIX_ON, logfile, conf_in->log.level, outmsg_level,
						"src: %s:%d, type: %s, vhost: %s, dst: %s:%d, status: reject_dstnoconnect, username: %s\n",
						(char *)&(addrinfo_in.address), addrinfo_in.port, typestr, inbound_info.address, proxyinfo.address, proxyinfo.port, inbound_info.username
					);
					packlen_rewrited = make_kickreason(rewrited, "Proxy(Internal): Failed to connect to the target server, please try again later.");
				}
			}
			send(socket_in, rewrited, packlen_rewrited, 0);
			close(socket_in);
			config_proxy_search_destroy(&proxyinfo);
			packet_destroy(inbound_info);
			return (mkoutbound_status == NET_ENORECORD) ? CONNSETUP_ENORECORD : CONNSETUP_ENOCONNECT;
	}
	close(socket_in);
	return CONNSETUP_EABORT;
}

static bool connsetup_read_more(int socket_in, uint8_t *inbound, ssize_t *packlen_inbound, const char *logfile, uint8_t loglevel, const net_addrbundle *addrinfo_in) {
	ssize_t n;
	n = recv(socket_in, inbound + *packlen_inbound, BUFSIZ - *packlen_inbound, 0);
	if (n <= 0) {
		mksysmsg(MKSYS_PREFIX_ON, logfile, loglevel, MKSYS_LEVEL_WARNING, "src: %s:%d, status: abort_init\n", (char *)&(addrinfo_in->address), addrinfo_in->port);
		close(socket_in);
		return false;
	}
	*packlen_inbound += n;
	return true;
}

/* section: functions (exported) */
int connsetup(int socket_in, int *socket_out, const char *logfile, conf *conf_in, net_addrbundle addrinfo_in, bool netpriority_enabled) {
	uint8_t inbound[BUFSIZ];
	ssize_t packlen_inbound;
	memset(inbound, 0, BUFSIZ);
	packlen_inbound = recv(socket_in, inbound, BUFSIZ, 0);
	if (packlen_inbound == 0) {
		mksysmsg(MKSYS_PREFIX_ON, logfile, conf_in->log.level, MKSYS_LEVEL_WARNING,
			"src: %s:%d, status: abort_init\n",
			(char *)&(addrinfo_in.address), addrinfo_in.port
		);
		close(socket_in);
		return CONNSETUP_EABORT;
	}
	switch (inbound[0]) {
		case 0xFE:
			if (packlen_inbound > 2) {
				while (packlen_inbound < 0x20) {
					if (!connsetup_read_more(socket_in, inbound, &packlen_inbound, logfile, conf_in->log.level, &addrinfo_in)) {
						return CONNSETUP_EABORT;
					}
				}
				while (packlen_inbound < (0x20 + inbound[0x1F] * 2 + 4)) {
					if (!connsetup_read_more(socket_in, inbound, &packlen_inbound, logfile, conf_in->log.level, &addrinfo_in)) {
						return CONNSETUP_EABORT;
					}
				}
			}
			break;
		case 0x02:
			break;
		default: {
			intent_t intent = inbound[packlen_inbound - 1];
			if ((intent == CLIENT_INTENT_STATUS) || (intent == CLIENT_INTENT_LOGIN) || (intent == CLIENT_INTENT_TRANSFER)) {
				if (!connsetup_read_more(socket_in, inbound, &packlen_inbound, logfile, conf_in->log.level, &addrinfo_in)) {
					return CONNSETUP_EABORT;
				}
			}
			break;
		}
	}
	if (protocol_identify(inbound) == PVER_UNIDENT) {
		mksysmsg(MKSYS_PREFIX_ON, logfile, conf_in->log.level, MKSYS_LEVEL_WARNING,
			"src: %s:%d, status: reject_unidentproto\n",
			(char *)&(addrinfo_in.address), addrinfo_in.port
		);
		close(socket_in);
		return CONNSETUP_EUNIDENT;
	}
	if (inbound[0] == 0xFE) {
		return connsetup_handle_legacy_motd(socket_in, socket_out, logfile, conf_in, addrinfo_in, netpriority_enabled, inbound, packlen_inbound);
	} else if (inbound[0] == 2) {
		return connsetup_handle_legacy_login(socket_in, socket_out, logfile, conf_in, addrinfo_in, netpriority_enabled, inbound, packlen_inbound);
	} else {
		return connsetup_handle_modern_handshake(socket_in, socket_out, logfile, conf_in, addrinfo_in, netpriority_enabled, inbound, packlen_inbound);
	}
}

/*
 * connsetup.c: Functions for initial connection setup
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

/* section: headers (library) */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <time.h>
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

/* section: defines */
/* initial packet */
#define CONNSETUP_INITIAL_TIMEOUT_SEC	10
#define CONNSETUP_LEGACY_PING_GRACE_MS	100

/* section: types */
enum connsetup_receive_status {
	CONNSETUP_RECEIVE_DATA,
	CONNSETUP_RECEIVE_END,
	CONNSETUP_RECEIVE_ERROR,
	CONNSETUP_RECEIVE_GRACE_TIMEOUT,
	CONNSETUP_RECEIVE_TIMEOUT
};

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

static int connsetup_connect_outbound(int *socket_out, conf_proxy *proxyinfo, sa_family_t family) {
	int mkoutbound_status;
	connsetup_proxyinfo_resolve_srv(proxyinfo);
	mkoutbound_status = 0;
	net_addr connaddr = net_resolve_dual(proxyinfo->address, family, true);
	if (connaddr.family == 0) {
		mkoutbound_status = NET_ENORECORD;
		*socket_out = -1;
	} else {
		*socket_out = net_socket(NETSOCK_CONN, connaddr.family, &connaddr.addr, proxyinfo->port, false);
		if (*socket_out == -1) {
			mkoutbound_status = NET_ECONNECT;
		}
	}
	return mkoutbound_status;
}

static void connsetup_send_proxy_header(int socket_in, int socket_out, char *pheader) {
	size_t packlen_pheader = protocol_proxy_write_socket(pheader, socket_in);
	if (packlen_pheader > 0) {
		send(socket_out, pheader, packlen_pheader, 0);
	}
}

static int connsetup_handle_legacy_login(int socket_in, int *socket_out, const char *logfile, conf *conf_in, net_addrbundle addrinfo_in, uint8_t *inbound, ssize_t packlen_inbound) {
	uint8_t rewrited[BUFSIZ];
	char pheader[PROTOPROXY_PACKETMAXLEN + 1];
	size_t packlen_rewrited = 0;
	memset(rewrited, 0, BUFSIZ);
	memset(pheader, 0, PROTOPROXY_PACKETMAXLEN + 1);
	uint8_t login_version = protocol_identify(inbound, (size_t)packlen_inbound, NULL);
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
		mkoutbound_status = connsetup_connect_outbound(socket_out, &proxyinfo, addrinfo_in.family);
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
					connsetup_send_proxy_header(socket_in, *socket_out, pheader);
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

static int connsetup_handle_legacy_motd(int socket_in, int *socket_out, const char *logfile, conf *conf_in, net_addrbundle addrinfo_in, uint8_t *inbound, ssize_t packlen_inbound) {
	uint8_t rewrited[BUFSIZ];
	char pheader[PROTOPROXY_PACKETMAXLEN + 1];
	size_t packlen_rewrited = 0;
	memset(rewrited, 0, BUFSIZ);
	memset(pheader, 0, PROTOPROXY_PACKETMAXLEN + 1);
	uint8_t motd_version = protocol_identify(inbound, (size_t)packlen_inbound, NULL);
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
		mkoutbound_status = connsetup_connect_outbound(socket_out, &proxyinfo, addrinfo_in.family);
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
					connsetup_send_proxy_header(socket_in, *socket_out, pheader);
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
		packlen_rewrited = make_motd_legacy(rewrited, "Proxy: Please use direct connect.", protocol_identify(inbound, (size_t)packlen_inbound, NULL), 0);
		send(socket_in, rewrited, packlen_rewrited, 0);
		close(socket_in);
		return CONNSETUP_EOLDCLIENT;
	}
	close(socket_in);
	return CONNSETUP_EABORT;
}

static int connsetup_handle_modern_handshake(int socket_in, int *socket_out, const char *logfile, conf *conf_in, net_addrbundle addrinfo_in, uint8_t *inbound, ssize_t packlen_inbound) {
	uint8_t rewrited[BUFSIZ];
	char pheader[PROTOPROXY_PACKETMAXLEN + 1];
	size_t packlen_rewrited = 0;
	memset(rewrited, 0, BUFSIZ);
	memset(pheader, 0, PROTOPROXY_PACKETMAXLEN + 1);
	p_handshake inbound_info = packet_read(inbound, inbound + packlen_inbound);
	if (inbound_info.version == 0) {
		intent_t intent;
		protocol_identify(inbound, (size_t)packlen_inbound, &intent);
		if (intent == CLIENT_INTENT_STATUS) {
			mksysmsg(MKSYS_PREFIX_ON, logfile, conf_in->log.level, MKSYS_LEVEL_WARNING,
				"src: %s:%d, type: motd, status: reject_motdrelay_13w41*\n",
				(char *)&(addrinfo_in.address), addrinfo_in.port
			);
			packlen_rewrited = make_motd(rewrited, "[Proxy] Use 13w42a or later to play!", inbound_info.version, conf_in->icon_b64);
		} else if (intent == CLIENT_INTENT_LOGIN) {
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
	mkoutbound_status = connsetup_connect_outbound(socket_out, &proxyinfo, addrinfo_in.family);
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
				connsetup_send_proxy_header(socket_in, *socket_out, pheader);
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

static enum connsetup_receive_status connsetup_receive_more(int event_fd, int socket_in, int timeout_fd, uint8_t *inbound, ssize_t *packlen_inbound, int timeout_ms) {
	struct epoll_event events[2];
	int event_count;
	do {
		event_count = epoll_wait(event_fd, events, 2, timeout_ms);
	} while (event_count == -1 && errno == EINTR);
	if (event_count == 0) {
		return CONNSETUP_RECEIVE_GRACE_TIMEOUT;
	}
	if (event_count == -1) {
		return CONNSETUP_RECEIVE_ERROR;
	}
	const struct epoll_event *socket_event = NULL;
	for (int event_index = 0; event_index < event_count; event_index++) {
		if (events[event_index].data.fd == timeout_fd) {
			return (events[event_index].events & EPOLLIN) ? CONNSETUP_RECEIVE_TIMEOUT : CONNSETUP_RECEIVE_ERROR;
		}
		if (events[event_index].data.fd != socket_in) {
			return CONNSETUP_RECEIVE_ERROR;
		}
		socket_event = &events[event_index];
	}
	if (socket_event == NULL || !(socket_event->events & (EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP)) || *packlen_inbound >= BUFSIZ) {
		return CONNSETUP_RECEIVE_ERROR;
	}
	ssize_t receive_size;
	do {
		receive_size = recv(socket_in, inbound + *packlen_inbound, BUFSIZ - (size_t)*packlen_inbound, 0);
	} while (receive_size == -1 && errno == EINTR);
	if (receive_size == 0) {
		return CONNSETUP_RECEIVE_END;
	}
	if (receive_size == -1) {
		return CONNSETUP_RECEIVE_ERROR;
	}
	*packlen_inbound += receive_size;
	return CONNSETUP_RECEIVE_DATA;
}

static bool connsetup_receive_initial(int socket_in, uint8_t *inbound, ssize_t *packlen_inbound, const char *logfile, uint8_t loglevel, const net_addrbundle *addrinfo_in) {
	bool result = false;
	int event_fd = epoll_create1(EPOLL_CLOEXEC);
	struct epoll_event socket_event = {
		.events = EPOLLIN | EPOLLRDHUP,
		.data.fd = socket_in
	};
	int timeout_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
	struct epoll_event timeout_event = {
		.events = EPOLLIN,
		.data.fd = timeout_fd
	};
	const struct itimerspec timeout = {
		.it_value.tv_sec = CONNSETUP_INITIAL_TIMEOUT_SEC
	};
	*packlen_inbound = 0;
	if (event_fd == -1 || timeout_fd == -1 || timerfd_settime(timeout_fd, 0, &timeout, NULL) == -1 || epoll_ctl(event_fd, EPOLL_CTL_ADD, socket_in, &socket_event) == -1
		|| epoll_ctl(event_fd, EPOLL_CTL_ADD, timeout_fd, &timeout_event) == -1) {
		goto cleanup;
	}
	while (1) {
		size_t packet_size;
		enum protocol_packet_status packet_status = protocol_packet_length(inbound, (size_t)*packlen_inbound, &packet_size);
		if (packet_status == PROTOCOL_PACKET_COMPLETE || packet_status == PROTOCOL_PACKET_INVALID) {
			result = true;
			break;
		}
		if (packet_size > BUFSIZ) {
			break;
		}
		int timeout_ms = (packet_status == PROTOCOL_PACKET_AMBIGUOUS) ? CONNSETUP_LEGACY_PING_GRACE_MS : -1;
		enum connsetup_receive_status receive_status = connsetup_receive_more(event_fd, socket_in, timeout_fd, inbound, packlen_inbound, timeout_ms);
		if (receive_status == CONNSETUP_RECEIVE_DATA) {
			continue;
		}
		if (packet_status == PROTOCOL_PACKET_AMBIGUOUS && (receive_status == CONNSETUP_RECEIVE_END || receive_status == CONNSETUP_RECEIVE_GRACE_TIMEOUT)) {
			result = true;
		}
		break;
	}
cleanup:
	if (timeout_fd != -1) {
		close(timeout_fd);
	}
	if (event_fd != -1) {
		close(event_fd);
	}
	if (!result) {
		mksysmsg(MKSYS_PREFIX_ON, logfile, loglevel, MKSYS_LEVEL_WARNING, "src: %s:%d, status: abort_init\n", (char *)&(addrinfo_in->address), addrinfo_in->port);
		close(socket_in);
	}
	return result;
}

/* section: functions (exported) */
int connsetup(int socket_in, int *socket_out, const char *logfile, conf *conf_in, net_addrbundle addrinfo_in) {
	uint8_t inbound[BUFSIZ];
	ssize_t packlen_inbound;
	memset(inbound, 0, BUFSIZ);
	if (!connsetup_receive_initial(socket_in, inbound, &packlen_inbound, logfile, conf_in->log.level, &addrinfo_in)) {
		return CONNSETUP_EABORT;
	}
	if (protocol_identify(inbound, (size_t)packlen_inbound, NULL) == PVER_UNIDENT) {
		mksysmsg(MKSYS_PREFIX_ON, logfile, conf_in->log.level, MKSYS_LEVEL_WARNING,
			"src: %s:%d, status: reject_unidentproto\n",
			(char *)&(addrinfo_in.address), addrinfo_in.port
		);
		close(socket_in);
		return CONNSETUP_EUNIDENT;
	}
	if (inbound[0] == 0xFE) {
		return connsetup_handle_legacy_motd(socket_in, socket_out, logfile, conf_in, addrinfo_in, inbound, packlen_inbound);
	} else if (inbound[0] == 2) {
		return connsetup_handle_legacy_login(socket_in, socket_out, logfile, conf_in, addrinfo_in, inbound, packlen_inbound);
	} else {
		return connsetup_handle_modern_handshake(socket_in, socket_out, logfile, conf_in, addrinfo_in, inbound, packlen_inbound);
	}
}

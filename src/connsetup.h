/*
 * connsetup.h: Header file of connsetup.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_CONNSETUP_H_INCLUDED_

#define _MRS_CONNSETUP_H_INCLUDED_

/* section: headers (project) */
#include "config.h"
#include "network.h"

/* section: defines */
/* error code */
#define CONNSETUP_OK	0
#define CONNSETUP_EABORT	1
#define CONNSETUP_EUNIDENT	2
#define CONNSETUP_ENOVHOST	3
#define CONNSETUP_ENORECORD	4
#define CONNSETUP_ENOCONNECT	5
#define CONNSETUP_EOLDCLIENT	6

/* section: functions (exported) */
int connsetup(int socket_in, int *socket_out, const char *logfile, conf *conf_in, net_addrbundle addrinfo_in);

#endif

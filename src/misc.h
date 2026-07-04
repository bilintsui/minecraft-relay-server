/*
 * misc.h: Header file of misc.c
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_MISC_H_INCLUDED_

#define _MRS_MISC_H_INCLUDED_

#include "config.h"
#include "network.h"

int backbone(int socket_in, int *socket_out, char *logfile, unsigned short runmode, conf * conf_in, net_addrbundle addrinfo_in, short netpriority_enabled);

#endif

/*
 * listener/admission.h: Client acceptance, peer policy and initial packet assembly
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_LISTENER_ADMISSION_H_INCLUDED_

#define _MRS_LISTENER_ADMISSION_H_INCLUDED_

/* section: headers (library) */
#include <stddef.h>
#include <stdint.h>

/* section: headers (project) */
#include "connection.h"
#include "events.h"

/* section: types */
struct listener_context;

/* section: functions (exported) */
int listener_admission_accept_batch(struct listener_context *context, int listen_fd, const listener_events *events, listener_connection **connections, size_t *connection_count, size_t connection_limit);
listener_connection_progress listener_admission_receive(listener_connection *connection, uint32_t event_flags, const char *log_filename, uint8_t log_level);
listener_connection_progress listener_admission_timeout(const listener_connection *connection, const char *log_filename, uint8_t log_level);

#endif

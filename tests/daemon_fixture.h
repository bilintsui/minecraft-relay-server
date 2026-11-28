/*
 * daemon_fixture.h: Process and loopback socket support for daemon integration tests
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef MCRELAY_TEST_DAEMON_FIXTURE_H

#define MCRELAY_TEST_DAEMON_FIXTURE_H

/* section: headers (library) */
#include <netinet/in.h>
#include <stddef.h>
#include <sys/types.h>

/* section: functions (exported) */
pid_t test_child_start(const char *binary, const char *config_filename, const char *notify_socket);
int test_child_wait(pid_t child, int timeout_ms);
int test_client_connect(in_port_t port);
ssize_t test_notify_receive(int socket_fd, char *message, size_t message_size, int timeout_ms);
/* Returns the port selected for a loopback bind and closes the probe socket. */
int test_port_find(in_port_t *result);
int test_server_open(in_port_t *port);
int test_socket_send_all(int socket_fd, const void *data, size_t size);

#endif

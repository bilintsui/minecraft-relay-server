/*
 * process.h: Signal setup for forked daemon children
 *
 * SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2020-2026 Bilin Tsui
 */

#ifndef _MRS_PROCESS_H_INCLUDED_

#define _MRS_PROCESS_H_INCLUDED_

/* section: headers (library) */
#include <signal.h>

/* section: functions (exported) */
/* Set child dispositions before restoring the signal mask inherited from listener startup. */
int process_child_signals_restore(const sigset_t *signal_mask);

#endif

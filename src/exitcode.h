/*
	exitcode.h: Exit codes for Minecraft Relay Server
	A component of Minecraft Relay Server.

	Minecraft Relay Server, version 1.2-beta4
	(c) 2020-2026 Bilin Tsui.
	This is a Free Software, absolutely no warranty.

	Licensed under GNU General Public License Version 3 (GNU GPL v3).
	For detailed license text, see: https://www.gnu.org/licenses/gpl-3.0.html
*/

#ifndef _MRS_EXITCODE_H_INCLUDED_

#define _MRS_EXITCODE_H_INCLUDED_

#include <errno.h>
#include <sysexits.h>

#define EXITCODE_OK		EX_OK	/* successful termination */

/* errno aliases */
#define EXITCODE_NOPIDFILE	ENOENT	/* PID file not found */
#define EXITCODE_NOSIGNAL	ESRCH	/* target process not running */
#define EXITCODE_NOMEM		ENOMEM	/* memory allocation failed */
#define EXITCODE_BADARG		EINVAL	/* invalid arguments or config */
#define EXITCODE_FILELARGE	EFBIG	/* configuration file too large */

/* sysexits aliases */
#define EXITCODE_FORKFAIL	EX_OSERR	/* fork() system call failed */
#define EXITCODE_CANTCREAT	EX_CANTCREAT	/* cannot create output file */
#define EXITCODE_BADPORT	EX_CONFIG	/* invalid bind port */
#define EXITCODE_INTERNAL	EX_SOFTWARE	/* unknown internal error */

/* custom */
#define EXITCODE_BADJSON	(EX__MAX + 1)	/* JSON parse error */
#define EXITCODE_BINDFAIL	(EX__MAX + 2)	/* socket bind failed */
#define EXITCODE_NOCONFFILE	(EX__MAX + 3)	/* config file not found */
#define EXITCODE_MULTIINSTANCE	(EX__MAX + 4)	/* another instance is already running */

#endif

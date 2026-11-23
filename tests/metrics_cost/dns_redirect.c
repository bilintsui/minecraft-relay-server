/* Test-host-only resolver destination override; all query/parse code remains real. */

/* section: headers (library) */
#include <arpa/inet.h>
#include <dlfcn.h>
#include <resolv.h>
#include <stdlib.h>
#include <string.h>

/* section: functions (exported) */
int res_ninit(res_state state) {
	void *symbol = dlsym(RTLD_NEXT, "__res_ninit");
	int (*initialize)(res_state) = NULL;
	memcpy(&initialize, &symbol, sizeof(initialize));
	if (initialize == NULL) {
		return -1;
	}
	int status = initialize(state);
	const char *value = getenv("MCRELAY_BENCH_DNS_PORT");
	if (status != 0 || value == NULL) {
		return status;
	}
	char *end = NULL;
	long port = strtol(value, &end, 10);
	if (*value == '\0' || *end != '\0' || port < 1 || port > 65535) {
		return -1;
	}
	state->nscount = 1;
	state->nsaddr_list[0] = (struct sockaddr_in){ .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = htons((unsigned short)port) };
	return 0;
}

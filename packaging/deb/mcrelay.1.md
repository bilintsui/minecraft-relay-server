% MCRELAY(1) mcrelay | User Commands
% Bilin Tsui
% July 2026

# NAME
mcrelay - Minecraft reverse proxy server with server address rewrite

# SYNOPSIS
**mcrelay** **dumpconfig** [**-c** _config_file_ | **--config** _config_file_]

**mcrelay** **run** [**-c** _config_file_ | **--config** _config_file_]

**mcrelay** **version**

**mcrelay** **help** [_command_]

# DESCRIPTION
**mcrelay** is a reverse proxy for Minecraft servers. It routes incoming
client connections to upstream servers based on the server address sent in
the Minecraft handshake packet.

It can rewrite the address and port fields in the outgoing handshake packet
to disguise a connection as one to an official server.

To receive original endpoints from a service that sends PROXY protocol headers,
set **listen.allow_proxy** to true. Set **listen.proxy_settings.version** to 1
(the default) or 2 to match the sender. Every connection to that listener
must start with the selected header. The default policy accepts
connections only from TCP peers in **listen.proxy_settings.trusted_sources**.
The list accepts numeric IPv4 and IPv6 addresses and CIDR networks.
It defaults to 127.0.0.0/8 and ::1. An explicit list replaces both defaults.
To send a header to a backend, set **pheader** to true on its route.
The optional **pheader_version** selects 1 (the default) or 2 independently
of the listener. Incoming v2 TLVs are discarded. An outgoing v2 header
contains only the effective TCP endpoints.

The program runs in the foreground. Use a service manager such as systemd
when it should run as a background service. Multiple instances can run with
separate configuration files as long as their listening addresses do not
conflict.

# COMMANDS
**dumpconfig**
: Parse a configuration file and display its parsed values. See
**mcrelay-dumpconfig**(1).

**run**
: Start a server instance. See **mcrelay-run**(1).

**version**
: Print the version in a single line. See **mcrelay-version**(1).

**help** [_command_]
: Display help. See **mcrelay-help**(1).

# FILES
*/etc/mcrelay/config.json*
: Default configuration file.

*/etc/mcrelay/&lt;name&gt;.json*
: Per-instance configuration, used by the template unit **mcrelay@&lt;name&gt;**.

*/var/log/mcrelay/access.log*
: Default log file.

# SIGNALS
**SIGUSR1**
: Reload the configuration file without restarting (sent by `systemctl reload`).

**SIGINT**, **SIGTERM**
: Stop the server.

# SEE ALSO
**mcrelay-dumpconfig**(1),
**mcrelay-run**(1),
**mcrelay-version**(1),
**mcrelay-help**(1),
**systemctl**(1),
**logrotate**(8)

Documentation and source: <https://github.com/bilintsui/minecraft-relay-server>

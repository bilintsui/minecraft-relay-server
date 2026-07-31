% MCRELAY-RUN(1) mcrelay | User Commands
% Bilin Tsui
% July 2026

# NAME

mcrelay-run - start an mcrelay server instance

# SYNOPSIS

**mcrelay run** [**-c** _config_file_ | **--config** _config_file_]

# DESCRIPTION

Start a Minecraft Relay Server instance. The server listens on the address and
port declared in the configuration file and forwards incoming connections to
upstream servers according to the virtual host sent in the Minecraft handshake
packet.

The program runs in the foreground. Use a service manager such as systemd
when it should run as a background service. Multiple instances can run with
separate configuration files as long as their listening addresses do not
conflict.

Sending **SIGUSR1** reloads the configuration file without restarting;
**SIGINT** and **SIGTERM** stop the server.

# OPTIONS

**-c**, **--config** _config_file_
: Specify a configuration file to read. Default:
*/etc/mcrelay/config.json*.

# FILES

*/etc/mcrelay/config.json*
: Default configuration file.

*/etc/mcrelay/&lt;name&gt;.json*
: Per-instance configuration, used by the template unit **mcrelay@&lt;name&gt;**.

*/var/log/mcrelay/access.log*
: Default log file.

# SEE ALSO

**mcrelay**(1), **mcrelay-dumpconfig**(1), **systemctl**(1)

Documentation and source: <https://github.com/bilintsui/minecraft-relay-server>

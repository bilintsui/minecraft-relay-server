% MCRELAY-DUMPCONFIG(1) mcrelay | User Commands
% Bilin Tsui
% July 2026

# NAME

mcrelay-dumpconfig - parse and display an mcrelay configuration file

# SYNOPSIS

**mcrelay dumpconfig** [**-c** _config_file_ | **--config** _config_file_]

# DESCRIPTION

Parse a configuration file and display its parsed values without starting a
server instance. Useful for validating the syntax and inspecting how the
configuration is interpreted before actually running the server.

# OPTIONS

**-c**, **--config** _config_file_
: Specify a configuration file to read. Default:
*/etc/mcrelay/config.json*.

# FILES

*/etc/mcrelay/config.json*
: Default configuration file.

# SEE ALSO

**mcrelay**(1), **mcrelay-run**(1)

Documentation and source: <https://github.com/bilintsui/minecraft-relay-server>

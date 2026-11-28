% MCRELAY-DUMPCONFIG(1) mcrelay | User Commands
% Bilin Tsui
% November 2026

# NAME
mcrelay-dumpconfig - parse and display an mcrelay configuration file

# SYNOPSIS
**mcrelay dumpconfig** [**-c** _config_file_ | **--config** _config_file_]

# DESCRIPTION
Parse a JSON configuration file and print its effective values, including
defaults. The output lists the inbound PROXY settings and each route's
outgoing header version even when header processing is disabled.

The **run** command performs additional checks. For example, **dumpconfig**
can display a listen port of 0, which **run** rejects before binding.

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

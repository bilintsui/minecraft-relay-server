# Minecraft Relay Server (mcrelay)

A Minecraft reverse proxy server with server address rewrite.

Supports Minecraft Servers and Clients with version 12w04a or later. (Basically means release 1.2.1 and later.)

Minecraft Versions before 12w04a are **NOT SUPPORTED**!

## Features
* Support reverse proxy for Minecraft servers by server address in the handshake packet which the client sends.
* Support rewrite server address and server port to camouflage a connection which uses an official server address. (e.g., pretend to be a normal connection to Hypixel, avoiding their server address check.)
* Support IP forwarding using HAProxy's Proxy Protocol. (But it refuses any incoming connection using this protocol.)

## Requirements
* Linux
* libresolv.so (usually pre-installed)
* libcjson.so (on Debian-like systems, contained in package "libcjson1")

## Compatibility
**Due to Minecraft Handshake restrictions, this server supports:**

* Game relay on server & client with version 12w04a and later, except version 12w17a, 13w41a and 13w41b.
* MOTD relay / MOTD status notice on server & client with version 1.6.1 and later, except version 13w41a and 13w41b.

## Files
* CMakeLists.txt: CMake configuration for compiling
* doc: Folder of documents
* doc/loglevel.info: Definitions of log levels
* doc/versions.json: Version manifest
* examples: File templates
* examples/config: Folder of example configurations
* examples/systemd: Folder of example systemd service files
* src: Folder of source codes

## Compile
Before compiling, you need to install cJSON at first.

For example, you can install it on Debian-like systems by <code>apt install libcjson-dev</code>.

Then you can use CMake to compile it, by following:
<pre>
mkdir build
cd build
cmake ..
make
</pre>
Additionally, if you want cross-compiling, the following CMake properties will be helpful:
* <code>-DCMAKE_C_COMPILER</code>: Specify an alternative compiler, CMake uses <code>cc</code> by default.
* <code>-DEXEC_SUFFIX</code>: Add a suffix to the final binary file, the file will be generated called <code>mcrelay</code>.

## Usage
<pre>
mcrelay < arguments | config_file >
</pre>

The program will run as a non-exit-style program by default.

When using the "-f" or "--forking" option, the program will become daemonized, and store its main process's PID into /tmp/mcrelay.pid.

## Config
See "examples/config/config.json" for instructions.

## Instructions for using DNS-based redirection (SRV)
If you are using an SRV record to provide your service, you should follow the instructions below.

Otherwise, your users will see a message about using an incorrect address to connect.

For example, your SRV record should be like this:
<pre>
_minecraft._tcp.srvrecord.example.com. => PRIORITY WEIGHT PORT host.example.com
</pre>
If you provide "srvrecord.example.com" to your user, you should set your vhostname in the configuration file as follows:
* For most Minecraft versions, use "host.example.com".
* For Minecraft versions from 21w20a to 1.17, use "srvrecord.example.com".

For compatibility, it's recommended to add both of them to your configuration.

## IP Forwarding
You can provide the real client address and port through HAProxy's Proxy Protocol by this feature.

It's compatible with any server which supports this protocol. (e.g. Bungeecord)

### Bungeecord
To use this feature correctly, turn on the "proxy_protocol" in the "config.yml". ("false" to "true")

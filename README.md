# mcrelay
Minecraft Relay Server

A minecraft reverse proxy server with server address rewrite.

Supports Minecraft Servers and Clients with version 12w04a or later. (Basically means release 1.2.1 and later.)

Minecraft Versions before 12w04a are **NOT SUPPORTED**!

## Features
* Support reverse proxy for Minecraft servers by server address in the handshake packet which client send to.
* Support rewrite server address and server port to camouflage connection which using official server address. (eg: pretend to be a normal connection to Hypixel, avoiding their server address check.)
* Support IP forwarding using HAProxy's Proxy Protocol. (But refuses any incoming connection using this protocol.)

## Requirements
* Linux
* libresolv.so
* libcjson.so

## Compatibility
**Due to Minecraft Handshake restrictions, this server supports:**

* Game relay on server & client with version 12w04a and later, except version 12w17a, 13w41a and 13w41b.
* MOTD relay / MOTD status notice on server & client with version 1.6.1 and later, except version 13w41a and 13w41b.

## Files
* mcrelay.c: Source code of Main program.
* config.json.example: config file example.
* mcrelay.service.forking.example: service unit file of mcrelay for systemd. (using runmode: forking)
* mcrelay.service.simple.example: service unit file of mcrelay for systemd. (using runmode: simple)
* mod: directory of essential modules.
* version.json: version manifest.
* loglevel.info: definations for messages.

## Compile
<pre>
gcc -o mcrelay mcrelay.c -lresolv -lcjson
</pre>
or
<pre>
make
</pre>

## Usage
<pre>
mcrelay < arguments | config_file >
</pre>

The program will run as a non-exit-style program by default.

When using "-f" or "--forking" option, the program will become daemonized, and store its main process' PID into /tmp/mcrelay.pid.

## Config
See "config.json.example" for instructions.

## Instruction of using a DNS-based redirection (SRV)
If you are using a SRV record to provide your service, you should follow the instructions below.

Otherwise, your user will see the message of using a wrong address to connect.

For example, your SRV record should be like this:
<pre>
_minecraft._tcp.srvrecord.example.com. => PRIVORITY WEIGHT PORT host.example.com
</pre>
If you provide "srvrecord.example.com" to your user, you should set your vhostname in the configuration file as follow:
* For most Minecraft versions, use "host.example.com".
* For Minecraft version from 21w20a to 1.17, use "srvrecord.example.com".

For compatibility, it's recommended to add both of them to your configuration.

## IP Forwarding
You can provide the real client address and port through HAProxy's Proxy Protocol by this feature.

It's compatible with any server which support this protocol. (e.g. Bungeecord)

### Bungeecord
To use this feature correctly, turn on the "proxy_protocol" in the "config.yml". ("false" to "true")

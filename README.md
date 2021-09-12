# mcrelay
Minecraft Relay Server

A minecraft reverse proxy server with server address rewrite.

Supports Minecraft Servers and Clients with version 12w04a or later. (Basically means release 1.2.1 and later.)

Minecraft Versions before 12w04a are **NOT SUPPORTED**!

## Features
* Support reverse proxy for Minecraft servers by server address in the handshake packet which client send to.
* Support rewrite server address and server port to camouflage connection which using official server address. (eg: pretend to be a normal connection to Hypixel, avoiding their server address check.)

## Requirements
* Linux
* libresolv.so

## Compatibility
**Due to Minecraft Handshake restrictions, this server supports:**

* Game relay on server & client with version 12w04a and later, except version 12w17a, 13w41a and 13w41b.
* MOTD relay / MOTD status notice on server & client with version 1.6.1 and later, except version 13w41a and 13w41b.

## Files
* mcrelay.c: Source code of Main program.
* mcrelay.conf.example: config file example of mcrelay.
* mcrelay.service.forking.example: service unit file of mcrelay for systemd(using runmode: forking).
* mcrelay.service.simple.example: service unit file of mcrelay for systemd(using runmode: simple).
* mod: directory of essential modules.
* version.json: version manifest
* loglevel.info: definations for messages.

## Compile
<pre>
gcc -o mcrelay mcrelay.c -lresolv
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
### Format
<pre>
log logfile_path
loglevel loglvl
bind bind_object
proxy_pass proxy_type
	ident_name destination_object
proxy_pass proxy_type
	ident_name destination_object
default destination_object
</pre>
### Explanation
* log: set log file.
>* logfile_path: path of the file which logs saved to.
* loglevel: set max message level in logging message.
>* loglvl: a unsigned short integer, range 0-255. This program will not log message with level higher than this level. 0: Critical, 1: Warning, 2+: Information. For more information, watch loglevel.info.
* bind: set bind information.
>* bind_object: (format: "address:port") default: "0.0.0.0:25565".
>>* address: the address you wish to bind as an Internet Service. Only x.x.x.x allowed.
>>* port: the port you wish to bind as an Internet Service. Valid range: 1-65535.
* proxy_pass: list of relay/relay+rewrites.
>* proxy_type: type of proxies, "relay" for raw relay, "rewrite" for relay with server address camouflage enabled.
>* ident_name: name of destination identification. Usually a Fully Qualified Domain Name(FQDN) by CNAME to your server.
>* destination_object: (format: "address_d[:port]")
>>* address_d: the address you wish to connect. Both FQDN or x.x.x.x allowed.
>>* port: optional, the port you wish to connect. Valid range: 1-65535.

If not set, the server will detect SRV record first(defined in address_d).

If SRV record resolve failed, it will fallback to normal address resolve, also connect to this address with port 25565.

**For rewrite enabled relay, it will use actual connect configuration to rewrite.**
>>* path: the socket file you wish to connect.
* default: optional, set a default server to connect when client don't match any valid virtual host. (Intentionally not support rewrite here.) (Security suggestion: Don't use this feature unless you know what you are doing.)
### Example
<pre>
log /var/log/mcrelay/mcrelay.log
bind 0.0.0.0:25565
proxy_pass rewrite
	hypixel.example.com mc.hypixel.net:25565
	hivemc.example.com play.hivemc.com:25565
proxy_pass relay
	mc1.example.com 127.0.0.1:25566
	mc2.example.com 192.168.1.254:25565
default 192.168.1.254:25565
</pre>

## Instruction of using a DNS-based redirection(SRV)
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

# mcrelay
Minecraft Relay Server<br/>
A minecraft reverse proxy server with server address rewrite.<br/>
Supports Minecraft Servers and Clients with version 12w04a or later. (Basically means release 1.2.1 and later.)<br/>
Minecraft Versions before 12w04a are **NOT SUPPORTED**!<br/>

## Features
* Support reverse proxy for Minecraft servers by server address in the handshake packet which client send to.
* Support rewrite server address and server port to camouflage connection which using official server address. (eg: pretend to be a normal connection to Hypixel, avoiding their server address check.)
* Support listening on an UNIX socket or relay to an UNIX socket. (eg: using nginx as your front-end server, connnect to this UNIX socket.)

## Requirements
* Linux
* libresolv.so

## Compatibility
**Due to Minecraft Handshake restrictions, this server supports:**<br/>
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

## Config
### Format
<pre>
runmode run_mode
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
* runmode: set program's runmode.
>* run_mode: type of program's runmode, "simple" for a normal, non-exit program, "forking" for a daemonized program. In forking, it will store the PID in /tmp/mcrelay.pid.
* log: set log file.
>* logfile_path: path of the file which logs saved to.
* loglevel: set max message level in logging message.
>* loglvl: a unsigned short integer, range 0-255. This program will not log message with level higher than this level. 0: Critical, 1: Warning, 2+: Information. For more information, watch loglevel.info.
* bind: set bind information.
>* bind_object: (format: "address:port" or "unix:path") default: "0.0.0.0:25565".
>>* address: the address you wish to bind as an Internet Service. Only x.x.x.x allowed.
>>* port: the port you wish to bind as an Internet Service. Valid range: 1-65535.
>>* path: the socket file you wish to bind as an UNIX Socket.
* proxy_pass: list of relay/relay+rewrites.
>* proxy_type: type of proxies, "relay" for raw relay, "rewrite" for relay with server address camouflage enabled.
>* ident_name: name of destination identification. Usually a Fully Qualified Domain Name(FQDN) by CNAME to your server.
>* destination_object: (format: "address_d[:port]" or "unix:path")
>>* address_d: the address you wish to connect. Both FQDN or x.x.x.x allowed.
>>* port: optional, the port you wish to connect. Valid range: 1-65535.<br/>
If not set, the server will detect SRV record first(defined in address_d).<br/>
If SRV record resolve failed, it will fallback to normal address resolve, also connect to this address with port 25565.<br/>
**For rewrite enabled relay, it will use actual connect configuration to rewrite.**
>>* path: the socket file you wish to connect.
* default: optional, set a default server to connect when client don't match any valid virtual host. (Intentionally not support rewrite here.) (Security suggestion: Don't use this feature unless you know what you are doing.)
### Example
<pre>
runmode forking
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

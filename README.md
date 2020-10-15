# mcrelay
>**Minecraft Relay Server**<br/>
>**A minecraft reverse proxy server with server address rewrite.**<br/>

## Features
* Support reverse proxy for Minecraft servers by server address in the handshake packet which client send to.
* Support rewrite server address and server port to camouflage connection which using official server address. (eg: pretend to be a normal connection to Hypixel, avoiding their server address check.)
* Support listening on an UNIX socket or relay to an UNIX socket. (eg: using nginx as your front-end server, connnect to this UNIX socket.)

## Requirements
* Linux(Windows currently not supported)

## Files
* mcrelay.c: Source code of Main program.
* mcrelay.conf.example: config file example of mcrelay.

## Compiles
<pre>
gcc -o mcrelay mcrelay.c
</pre>

## Usage
<pre>
mcrelay config_file
</pre>

## Config
### Format
<pre>
bind bind_object
proxy_pass proxy_type
	ident_name destination_object
proxy_pass proxy_type
	ident_name destination_object
</pre>
### Explanation
* bind: set bind information.
* proxy_pass: list of relay/relay+rewrites.
* bind_object: (format: "address:port" or "unix:path") default: "0.0.0.0:25565".
>* address: the address you wish to bind as an Internet Service. Only x.x.x.x allowed.
>* port: the address you wish to bind as an Internet Service. Valid range: 1-65535.
>* path: the socket file you wish to bind as an UNIX Socket.
* proxy_type: type of proxies, "relay" for raw relay, "rewrite" for relay with server address camouflage enabled.
* ident_name: name of destination identification. Usually a Fully Qualified Domain Name(FQDN) by CNAME to your server.
* destination_object: (format: "address_d:port" or "unix:path")
>* address_d: the address you wish to bind as an Internet Service. Both FQDN or x.x.x.x allowed.
>* port: the address you wish to bind as an Internet Service. Valid range: 1-65535.
>* path: the socket file you wish to bind as an UNIX Socket.
### Example
<pre>
bind 0.0.0.0:25565
proxy_pass rewrite
	hypixel.example.com mc.hypixel.net:25565
	hivemc.example.com play.hivemc.com:25565
proxy_pass relay
	mc1.example.com 127.0.0.1:25566
	mc2.example.com 192.168.1.254:25565
</pre>

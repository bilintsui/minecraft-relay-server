# Minecraft Relay Server (mcrelay)

A Minecraft reverse proxy server with server address rewrite.

Supports Minecraft servers and clients with version 12w04a and later (basically means release 1.2.1 and later).

Minecraft versions before 12w04a are **NOT SUPPORTED**!

## Features
* Support reverse proxy for Minecraft servers by server address in the handshake packet which the client sends.
* Support rewrite server address and server port to camouflage a connection which uses an official server address (e.g., pretend to be a normal connection to Hypixel, avoiding their server address check).
* Support IP forwarding using HAProxy's Proxy Protocol (but it refuses any incoming connection using this protocol).

## Requirements
* Linux
* <code>libresolv.so</code> (usually pre-installed)
* <code>libcjson.so</code> (on Debian-like systems, contained in package <code>libcjson1</code>)

## Compatibility
**Due to Minecraft handshake restrictions, this server supports:**

* Game relay on server & client with version 12w04a and later, except version 12w17a, 13w41a and 13w41b.
* MOTD relay or MOTD status notice on server and client with version 1.6.1 and later, except version 13w41a and 13w41b.

## Files
* <code>CMakeLists.txt</code> CMake configuration for compiling.
* <code>doc</code> Folder of documents.
* <code>doc/information</code> Informational documents.
* <code>doc/information/loglevel.info</code> Definitions of log levels.
* <code>doc/information/versions.json</code> Version manifest.
* <code>doc/configuration</code> Configuration examples.
* <code>doc/configuration/logrotate</code> Configuration used by logrotate.
* <code>doc/configuration/mcrelay</code> Configurations read by mcrelay itself.
* <code>doc/configuration/systemd</code> Configuration used by systemd, when using mcrelay as a service.
* <code>src</code> Folder of source codes.

## Compile
Before compiling, you need to install cJSON at first.

For example, you can install it on Debian-like systems by <code>apt install libcjson-dev</code>.

Then you can use CMake to compile it by <code>cmake -B build && cmake --build build</code>, the executable file is <code>build/mcrelay</code>.

Additionally, if you want cross-compiling, the following CMake properties will be helpful:
* <code>-DCMAKE_C_COMPILER</code>: Specify an alternative compiler, CMake uses <code>cc</code> by default.
* <code>-DEXEC_SUFFIX</code>: Add a suffix to the final binary file, the file will be generated called <code>mcrelay</code>.

## Usage
<pre>
mcrelay run [-c &lt;config_file&gt; | --config &lt;config_file&gt;]
mcrelay version
mcrelay help [&lt;command&gt;]
</pre>

The default configuration file is <code>/etc/mcrelay/config.json</code>.

The program runs in the foreground. Use a service manager such as systemd when it should run as a background service.

Multiple instances can run with separate configuration files as long as their listening addresses do not conflict.

## Config
See [<code>doc/configuration/mcrelay/config.jsonc</code>](doc/configuration/mcrelay/config.jsonc) for instructions.

## Instructions for using DNS-based redirection (SRV)
If you are using an SRV record to provide your service, you should follow the instructions below.

Otherwise, your users will see a message about using an incorrect address to connect.

For example, your SRV record should be like this:
<pre>
_minecraft._tcp.srvrecord.example.com. => PRIORITY WEIGHT PORT host.example.com
</pre>
If you provide <code>srvrecord.example.com</code> to your user, you should set your virtual hostname in the configuration file as follows:
* For most Minecraft versions, use <code>host.example.com</code>.
* For Minecraft versions from 21w20a to 1.17, use <code>srvrecord.example.com</code>.

For compatibility, it's recommended to add both of them to your configuration.

## IP Forwarding
You can provide the real client address and port through HAProxy's Proxy Protocol by this feature.

It's compatible with any server which supports this protocol (e.g. Bungeecord).

### Bungeecord
To use this feature correctly, turn on the <code>proxy_protocol</code> in the <code>config.yml</code> (<code>false</code> to <code>true</code>).

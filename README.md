# Minecraft Relay Server (mcrelay)
A Minecraft reverse proxy server with server address rewrite.

Supports Minecraft servers and clients with version 12w04a and later (basically means release 1.2.1 and later).

Minecraft versions before 12w04a are **NOT SUPPORTED**!

## Features
* Support reverse proxy for Minecraft servers by server address in the handshake packet which the client sends.
* Support rewrite server address and server port to camouflage a connection which uses an official server address (e.g., pretend to be a normal connection to Hypixel, avoiding their server address check).
* Preserve the original client address and port across services that send or receive PROXY protocol v1 headers.
* Provide optional bounded operational metrics and rate-limited resolver-helper state events through the existing log.

## Requirements
* Linux
* <code>libresolv.so.2</code> (usually pre-installed. On debian-like systems, contained in package <code>libc6</code>)
* <code>libcjson.so.1</code> (on Debian-like systems, contained in package <code>libcjson1</code>)
* <code>libsystemd.so.0</code> (on Debian-like systems, contained in package <code>libsystemd0</code>)

## Compatibility
**Due to Minecraft handshake restrictions, this server supports:**

* Game relay on server & client with version 12w04a and later, except version 12w17a, 13w41a and 13w41b.
* MOTD relay or MOTD status notice on server and client with version 1.6.1 and later, except version 13w41a and 13w41b.

## Files
* <code>CMakeLists.txt</code> CMake configuration for compiling.
* <code>doc</code> Folder of documents.
* <code>doc/information</code> Informational documents.
* <code>doc/information/loglevel.info</code> Definitions of log levels.
* <code>doc/information/metrics.md</code> Operational metrics configuration, schema and consumer guidance.
* <code>doc/information/versions.json</code> Version manifest.
* <code>doc/configuration</code> Configuration examples.
* <code>doc/configuration/logrotate</code> Configuration used by logrotate.
* <code>doc/configuration/mcrelay</code> Configurations read by mcrelay itself.
* <code>doc/configuration/systemd</code> Configuration used by systemd, when using mcrelay as a service.
* <code>src</code> Folder of source codes.

See the [systemd configuration notes](doc/configuration/systemd/README.md) for compatibility and synchronous reload modes.

## Compile
Before compiling, you need to install the cJSON and systemd development files at first.

For example, you can install them on Debian-like systems by <code>apt install libcjson-dev libsystemd-dev</code>.

Then you can use CMake to compile it by <code>cmake -B build && cmake --build build --parallel "$(nproc)"</code>, the executable file is <code>build/mcrelay</code>.

See the [build and test guide](doc/building.md) for all project switches, build types, compiler/linker flags, cross-compiling, advanced capacity/deadline overrides and Debian packaging options. For example, <code>-DCMAKE_C_COMPILER=clang</code> selects another compiler, and <code>-DEXEC_SUFFIX=_custom</code> names the executable <code>mcrelay_custom</code> without changing its version.

### Debug builds
Run the following commands from the repository root:

```sh
cmake -S . -B build-debug -DCMAKE_BUILD_TYPE=Debug -DDEBUG_MODE=ON -DBUILD_TESTING=ON
cmake --build build-debug --parallel "$(nproc)"
```

The executable is <code>build-debug/mcrelay</code>. <code>Debug</code> selects compiler debugging flags; the separate <code>DEBUG_MODE=ON</code> switch allows blocking FIFO configuration input during <code>dumpconfig</code>, startup and reload, and adds <code>-debug</code> only to <code>mcrelay version</code>. The help banner is unchanged. FIFO input can stall configuration loading if its writer is absent or does not close its output; icon input still requires a regular file.

The marker follows <code>DEBUG_MODE</code>, not the build type. Neither setting automatically enables sanitizers, verbose logging or runtime test hooks in <code>mcrelay</code>. See the [detailed debug effects](doc/building.md#debug-mode-and-version-identification) and [Testing](#testing).

For production, use a Release build with FIFO configuration input disabled:

```sh
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release -DDEBUG_MODE=OFF -DBUILD_TESTING=OFF -DUBSAN_TEST=OFF
cmake --build build-release --parallel "$(nproc)"
```

### Resolver helper capacity
By default, mcrelay starts two resolver helper processes, and each helper performs at most one blocking DNS lookup at a time. Configured destinations are normally prewarmed before mcrelay reports readiness, but a large startup or reload configuration, or a burst of distinct uncached names, can contend for the two helpers and each connection's independent default 10-second route-wait deadline.

The helper count is a compile-time limit rather than a runtime configuration option. Deployments that need more parallel DNS lookups must rebuild with a larger <code>RESOLVER_SUPERVISOR_HELPER_COUNT</code>, for example:

```sh
cmake -S . -B build-capacity -DCMAKE_BUILD_TYPE=Release -DDEBUG_MODE=OFF -DBUILD_TESTING=OFF \
  -DCMAKE_C_FLAGS="-DRESOLVER_SUPERVISOR_HELPER_COUNT=4"
cmake --build build-capacity --parallel "$(nproc)"
```

See [advanced compile-time overrides](doc/building.md#advanced-compile-time-overrides) for related limits, validation requirements and test-target interactions.

## Testing
<code>BUILD_TESTING</code> defaults to ON and builds separate test runners/daemons; it does not add their hooks or reduced limits to <code>mcrelay</code>. To build and run the regular suite:

```sh
cmake -S . -B build-tests -DCMAKE_BUILD_TYPE=Release -DDEBUG_MODE=OFF -DBUILD_TESTING=ON -DUBSAN_TEST=OFF
cmake --build build-tests --parallel "$(nproc)"
ctest --test-dir build-tests --output-on-failure -j4
```

<code>UBSAN_TEST</code> defaults to OFF; enabling it with GCC or Clang adds sanitized copies of selected module tests, not a sanitized <code>mcrelay</code>. Global sanitizer flags are needed to instrument every target. See [testing configurations](doc/building.md#testing-configurations) for the full commands, target isolation, test selection and native Linux verification requirements. Always run CTest against the corresponding build directory, not the repository root.

## Usage
<pre>
mcrelay dumpconfig [-c &lt;config_file&gt; | --config &lt;config_file&gt;]
mcrelay run [-c &lt;config_file&gt; | --config &lt;config_file&gt;]
mcrelay version
mcrelay help [&lt;command&gt;]
</pre>

The default configuration file is <code>/etc/mcrelay/config.json</code>.

Use <code>mcrelay dumpconfig</code> to parse a configuration file and display its parsed values without starting a server instance.

The program runs in the foreground. Use a service manager such as systemd when it should run as a background service.

Multiple instances can run with separate configuration files as long as their listening addresses do not conflict.

## Config
See the [JSON configuration example](doc/configuration/mcrelay/config.json) or the [annotated JSONC example](doc/configuration/mcrelay/config.jsonc).

## Operational metrics
Aggregate operational metrics are disabled by default. Set <code>metrics.interval</code> to an integer from 300 to 86400 seconds and keep <code>log.level</code> at 2 or higher to emit them through the configured log. For example:

```json
{
  "metrics": {
    "interval": 300
  }
}
```

The output is a fixed 48-line schema-1 snapshot interleaved with ordinary access-log records. See the [operational metrics guide](doc/information/metrics.md) before writing a consumer or alert: it defines batch grouping, line validation, lifecycle records, histogram units and important limits on what the signals mean.

The standalone [offline report tool](doc/information/metrics-report.md) reads plain/gzip logs and numbered rotations using Python 3.8+ with no third-party dependencies:

```sh
python3 tools/metrics-report.py /var/log/mcrelay
```

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
By default the listener accepts direct Minecraft connections. To receive the original client address and port from a service that supports PROXY v1, add the following fields to the existing `listen` object. Configure the sending service to start every connection with a v1 header (for example, `send-proxy` on an HAProxy `server` line).

```json
{
  "allow_proxy": true,
  "proxy_settings": {
    "trusted_sources": [
      "192.0.2.10"
    ]
  }
}
```

Replace `192.0.2.10` with the TCP source address of the service sending the header. An explicit list replaces the default entries `127.0.0.1` and `::1`. The default policy closes connections from other peers immediately. Access records for admitted connections put the actual TCP peer in `peer`, the header handling result in `proxy`, and the effective client endpoint in `src`. [All listener settings](doc/configuration/mcrelay/config.jsonc)

In an incoming `TCP6` header, mcrelay accepts both `::ffff:c000:201` and `::ffff:192.0.2.1` for the same IPv4-mapped address. The dotted form is accepted only for IPv4-mapped addresses, for compatibility with dual-stack senders such as HAProxy. When forwarding a `TCP6` pair, mcrelay emits `TCP4` if both addresses are IPv4-mapped. Otherwise it emits `TCP6` with both addresses in hexadecimal IPv6 notation. [PROXY protocol v1, section 2.1](https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt)

Outgoing headers are configured per route. Set `pheader` to `true` on any route whose backend accepts PROXY v1. To chain two mcrelay instances, enable `pheader` on the route from the first to the second, then enable `allow_proxy` on the second and trust the first instance's TCP source address. Keep `rewrite` disabled on the intermediate route when both instances route by the original Minecraft hostname.

### BungeeCord
For a BungeeCord backend, set `proxy_protocol` to `true` in its `config.yml` and enable `pheader` on the corresponding mcrelay route.

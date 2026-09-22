# Building and testing mcrelay

This guide separates project switches, generic CMake settings, advanced compile-time overrides and packaging-script arguments. Build options are not runtime JSON configuration: changing them requires reconfiguration and rebuilding.

Operational metrics require no special build option. They are enabled at runtime with `metrics.interval`; see the [operational metrics guide](information/metrics.md). The production minimum interval is fixed at 300 seconds.

## Requirements and defaults

The project requires Linux, a C99 compiler, CMake (minimum declared version: 3.12), and the cJSON/systemd development files. For example, on Debian-like systems:

```sh
sudo apt install build-essential cmake libcjson-dev libsystemd-dev
```

Git is optional for compilation; it provides build-version metadata and enables the version-generation test. Ubuntu 22.04 is the release ABI baseline; compiling on a newer distribution does not guarantee that the resulting binary runs on Ubuntu 22.04.

Examples below use a single-configuration generator such as Unix Makefiles or Ninja. They assume CMake/CTest with `-S`, `-B` and `--test-dir` support, as available on Ubuntu 22.04; with older tools, configure from the build directory and run CTest there. Use separate build directories for different compilers, generators and sanitizer configurations. Cached options persist when an existing build directory is reconfigured.

For a production executable without test targets:

```sh
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release \
  -DDEBUG_MODE=OFF -DBUILD_TESTING=OFF -DUBSAN_TEST=OFF
cmake --build build-release --parallel "$(nproc)"
```

The output is `build-release/mcrelay` unless `EXEC_SUFFIX` is set.

## Project switches

| Setting | Default | Scope and effect |
|---|---|---|
| `DEBUG_MODE` | OFF | Allows FIFO configuration input in `mcrelay` and adds `-debug` to its `version` command. Does not select the compiler build type or enable extra logging/sanitizers/test hooks. |
| `BUILD_TESTING` | ON, through CTest | Creates test runners, test daemons and registered CTest tests. Their private definitions/wrappers do not enter the production target. OFF suppresses all these test targets. |
| `UBSAN_TEST` | OFF | With testing enabled and GCC or Clang, adds UBSan copies of selected module tests. Does not instrument the production executable or all runtime targets. Has no effect with `BUILD_TESTING=OFF`. |
| `EXEC_SUFFIX` | Empty | A filename/target suffix, not a boolean switch. For example `_custom` produces target/executable `mcrelay_custom`. Does not change version metadata, process names, configuration paths or packaged service definitions. |

For example:

```sh
cmake -S . -B build-custom -DEXEC_SUFFIX=_custom -DBUILD_TESTING=OFF
cmake --build build-custom --target mcrelay_custom --parallel "$(nproc)"
```

This produces `build-custom/mcrelay_custom`. Commands elsewhere in this guide assume an empty suffix; substitute the actual target/executable name when using one.

## Build types and hardening

For single-configuration generators, an unspecified `CMAKE_BUILD_TYPE` defaults to `Release`:

| Build type | Compiler configuration | Project `_FORTIFY_SOURCE=2` definition |
|---|---|---|
| `Release` | Toolchain release/optimization flags | Enabled |
| `Debug` | Toolchain debugging flags | Omitted |
| `RelWithDebInfo` | Toolchain optimized build with debugging information | Enabled |
| `MinSizeRel` | Toolchain size-oriented release flags | Enabled |

Exact optimization/debugging flags depend on the selected toolchain. Independently of these types, the project adds stack protection (`-fstack-protector-strong`), PIE (`-fPIE`/`-pie`), full RELRO (`-Wl,-z,relro -Wl,-z,now`) and a non-executable stack (`-Wl,-z,noexecstack`) to its targets. There is no project hardening-disable switch; custom flags must remain compatible with this baseline.

With a multi-configuration generator, choose the configuration when building, for example `cmake --build build-multi --config Debug --parallel "$(nproc)"`, and run CTest with the matching `-C Debug`. `CMAKE_BUILD_TYPE` is not the configuration selector in that case. `DEBUG_MODE` remains a separate configure-time switch.

### Debug mode and version identification

```sh
cmake -S . -B build-debug -DCMAKE_BUILD_TYPE=Debug \
  -DDEBUG_MODE=ON -DBUILD_TESTING=ON
cmake --build build-debug --parallel "$(nproc)"
```

`DEBUG_MODE=ON` changes configuration input in `dumpconfig`, startup and reload: FIFO input is allowed and deliberately blocking. A missing writer or a writer that never closes its output can stall the read, including the listener during reload. Configuration parsing, validation and size limits still apply. Icon loading does not opt into FIFO input and still requires a regular file. Prefer regular-file configuration and `DEBUG_MODE=OFF` for production.

The mode adds `-debug` only to `mcrelay version`, for example `v1.3-alpha+<commit>-debug`. The help banner stays unchanged. Existing Git/hash/dirty and internal-version information is retained; the mode is still identified for tagged builds or source archives with no Git suffix. The marker follows `DEBUG_MODE`, not debugging symbols or `CMAKE_BUILD_TYPE`: Debug with the switch OFF has no marker, while Release with it ON does.

Neither Debug nor this mode automatically enables sanitizers, verbose logging or production test hooks. Base version strings come from `src/define/global.h`, and Git suffixes are generated by `cmake/version.cmake`; they are not user-settable CMake version options.

## Generic CMake parameters

These are CMake facilities, not additional project boolean switches:

| Parameter | Use and scope |
|---|---|
| `-DCMAKE_C_COMPILER=...` | Select GCC, Clang, a compiler path or a cross-compiler. On a fresh build tree, selection also depends on the toolchain/environment (including `CC`); specify it explicitly when reproducibility matters. Use a new build tree when changing compilers. |
| `-DCMAKE_BUILD_TYPE=...` | Select one of the single-configuration build types above. Independent of `DEBUG_MODE` and testing. |
| `-DCMAKE_TOOLCHAIN_FILE=...` | Configure a cross-toolchain, target platform, sysroot and dependency search rules. Requires target-compatible libc/resolver, cJSON and systemd headers/libraries. Selecting another architecture does not provide those dependencies. |
| `-DCMAKE_C_FLAGS="..."` | Add global C compiler flags, including warnings, sanitizer instrumentation or `-D` macro overrides. A new value replaces the cached string; combine all needed custom flags explicitly. Applies to all compiled targets, not just `mcrelay`. |
| `-DCMAKE_EXE_LINKER_FLAGS="..."` | Add global executable linker flags, for example sanitizer runtime linkage. The project appends its hardening linker flags. |
| `-G "..."` | Select a generator when creating the build tree, for example `Ninja` (requires Ninja). Generator selection does not change runtime policy. |
| `cmake --build ... --parallel N` | Set build parallelism where supported by CMake/the generator; not a configure-time option or a runtime limit. |

Build examples use `nproc` to select the available CPU count. On memory-constrained machines, replace it with a smaller positive number. A bare `--parallel` selects the native tool's default rather than an explicit CPU-based limit. Alternatively, export `CMAKE_BUILD_PARALLEL_LEVEL` and omit `--parallel`; an explicit command-line setting takes precedence over that environment default.

CTest parallelism is independent of compiler parallelism. Regular/UBSan examples use four concurrent tests, matching the project's native regression practice; full ASan/leak checks remain sequential to limit peak memory and timing pressure. Do not assume a test's single CTest slot means it uses only one process.

For example, using Clang and Ninja:

```sh
cmake -S . -B build-clang -G Ninja -DCMAKE_C_COMPILER=clang \
  -DCMAKE_BUILD_TYPE=Release -DDEBUG_MODE=OFF -DBUILD_TESTING=OFF
cmake --build build-clang --parallel "$(nproc)"
```

For cross-compilation, supply the actual toolchain, for example `-DCMAKE_TOOLCHAIN_FILE=/path/to/linux-toolchain.cmake`, and ensure all linked dependencies match its target architecture and ABI. A different compiler name alone is not a complete cross-build recipe.

The project fixes ISO C99 and disables C language extensions; it does not expose a language-standard switch. It has no `install()` rules, so `CMAKE_INSTALL_PREFIX` does not select installation paths and there is no CMake install workflow. Nor are there project switches for static linking or disabling the required resolver/cJSON/systemd dependencies. Use the Debian script or arrange installation separately.

## Advanced compile-time overrides

The following values are guarded by `#ifndef` and can be overridden with compiler definitions. They are **not** standalone CMake cache options. For example, `-DRESOLVER_SUPERVISOR_HELPER_COUNT=4` passed directly to CMake only creates a cache variable; it does not define the C macro. Pass it inside compiler flags instead:

```sh
cmake -S . -B build-capacity -DCMAKE_BUILD_TYPE=Release \
  -DDEBUG_MODE=OFF -DBUILD_TESTING=OFF \
  -DCMAKE_C_FLAGS="-DRESOLVER_SUPERVISOR_HELPER_COUNT=4 -DLISTENER_WORKER_LIMIT=512"
cmake --build build-capacity --parallel "$(nproc)"
```

These settings change runtime capacity, memory use or timing and require relevant build/test/native validation after modification. Source declarations and their validation are authoritative. Not every combination is sensible: for example, helpers/jobs must be positive, interactive reserve must not exceed the job limit, retry/respawn maxima must not be below their initial values, and jitter percentage must be in 0–100.

Global compiler flags also reach tests. Some test targets intentionally provide different values for the same macros; avoid conflicting redefinitions and do not assume their fixtures validate an arbitrary deployment override. Validate the actual custom production configuration as well as the regular regression suite.

### Resolver jobs, retries and helpers

Defined in [`src/resolver/supervisor.h`](../src/resolver/supervisor.h):

| Macro | Default | Meaning |
|---|---|---|
| `RESOLVER_SUPERVISOR_HELPER_COUNT` | 2 | Parallel helper slots; each helper handles at most one lookup at a time. |
| `RESOLVER_SUPERVISOR_JOB_LIMIT` | 4096 | Unique jobs, including queued, sending/dispatched, retry-wait and completed-not-delivered work. |
| `RESOLVER_SUPERVISOR_INTERACTIVE_RESERVE` | 256 | Job headroom reserved from new background admission; interactive work can use the full job limit. |
| `RESOLVER_SUPERVISOR_QUERY_TIMEOUT_SEC` | 10 | Absolute deadline for one dispatched helper attempt, including any CNAME continuation/TCP fallback. |
| `RESOLVER_SUPERVISOR_QUERY_RETRY_INITIAL_MS` | 1000 | Initial query retry base delay. |
| `RESOLVER_SUPERVISOR_QUERY_RETRY_MAX_MS` | 60000 | Query retry delay cap; retries use exponential backoff and deterministic jitter. |
| `RESOLVER_SUPERVISOR_RESPAWN_INITIAL_MS` | 100 | Repeated helper-loss respawn base delay; the first unexpected loss has immediate replacement. |
| `RESOLVER_SUPERVISOR_RESPAWN_MAX_MS` | 30000 | Helper-respawn backoff cap. |
| `RESOLVER_SUPERVISOR_RESPAWN_RESET_STABLE_SEC` | 60 | Stable helper lifetime after which recovery state resets. |
| `RESOLVER_SUPERVISOR_RESPAWN_RESET_SUCCESS_COUNT` | 3 | Consecutive valid responses after which recovery state resets. |
| `RESOLVER_SUPERVISOR_JITTER_PERCENT` | 20 | Deterministic jitter range for query retry and helper respawn, bounded by their caps. |
| `RESOLVER_SUPERVISOR_SHUTDOWN_GRACE_MS` | 1000 | Resolver-helper shutdown grace before forced termination. |

Increasing helper parallelism does not extend the independent connection route-wait deadline or add proactive refresh/stale-on-error. These controls do not make temporary failures into DNS negatives.

### Cache and transient reply capacity

Defined in [`src/resolver/cache.h`](../src/resolver/cache.h) and [`src/resolver/ipc_assembly.h`](../src/resolver/ipc_assembly.h):

| Macro | Default | Meaning |
|---|---|---|
| `RESOLVER_CACHE_ENTRY_LIMIT` | 16384 | DNS cache entry/key limit, including referenced pending entries. |
| `RESOLVER_CACHE_OWNED_BYTE_LIMIT` | 67108864 (64 MiB) | Steady-state requested allocation budget for cache metadata and payloads, not RSS. |
| `RESOLVER_CACHE_RESULT_BYTE_LIMIT` | 262144 (256 KiB) | Maximum requested size of one publishable DNS result. |
| `RESOLVER_REPLY_ASSEMBLY_BYTE_LIMIT` | 1048576 (1 MiB) | Separate aggregate budget for listener-owned transient reply assembly. |

Changing one budget does not remove the other checks. A larger result still needs to fit the steady-state and assembly budgets and all DNS/protocol validation limits. Capacity rejection does not authorize eviction of unrelated referenced fresh data or use beyond strict expiry.

### Listener and connection limits

Defined in [`src/listener.c`](../src/listener.c), [`src/route/waiter.h`](../src/route/waiter.h), [`src/network.h`](../src/network.h) and [`src/connection/setup_long.c`](../src/connection/setup_long.c):

| Macro | Default | Meaning |
|---|---|---|
| `LISTENER_CONNECTION_LIMIT` | 4096 | Total connection capacity ceiling shared by listener-held connections and live workers; the descriptor-derived limit can be lower. |
| `LISTENER_WORKER_LIMIT` | 256 | Maximum live LOGIN/TRANSFER workers; cannot override the shared connection capacity. |
| `LISTENER_ACCEPT_BATCH` | 128 | Maximum accept attempts per listener turn. |
| `LISTENER_EVENT_BATCH` | 128 | Maximum listener epoll events returned per batch. |
| `LISTENER_ROUTE_PREWARM_BATCH_LIMIT` | 64 | Background route-prewarm scheduling batch size. |
| `LISTENER_ROUTE_WARMUP_TIMEOUT_SEC` | 10 | Startup warm-up readiness deadline, not a DNS TTL or a connection waiter deadline. |
| `LISTENER_ROUTE_WAIT_TIMEOUT_SEC` | 10 | Independent absolute route-wait deadline measured from waiter creation. |
| `LISTENER_INITIAL_TIMEOUT_SEC` | 10 | Initial protocol packet assembly deadline. |
| `LISTENER_LEGACY_PING_GRACE_MS` | 100 | Assembly grace for the legacy ping path. |
| `LISTENER_SHORT_CONNECT_TIMEOUT_SEC` | 5 | Listener-owned short connection's outbound connect deadline. |
| `LISTENER_SHORT_LIFETIME_TIMEOUT_SEC` | 30 | Absolute listener-held connection lifetime measured from accept, also bounding initial/route-wait phases. |
| `LISTENER_SHORT_RELAY_BUFFER_BYTES` | 8192 | Short-connection relay buffer size. |
| `LISTENER_SHORT_RELAY_IDLE_TIMEOUT_SEC` | 10 | Short-connection idle deadline. |
| `LISTENER_WORKER_REFUSAL_TIMEOUT_SEC` | 1 | Deadline for sending a worker-cap refusal response. |
| `LISTENER_WORKER_LOG_INTERVAL_SEC` | 10 | Minimum interval between worker-cap refusal warnings. |
| `CONNECTION_SETUP_LONG_CONNECT_TIMEOUT_SEC` | 5 | Long worker's nonblocking outbound connect deadline. |
| `NET_RELAY_BUFFER_BYTES` | 16384 | Long relay buffer size per direction. |
| `NET_RELAY_IDLE_TIMEOUT_SEC` | 300 | Long relay sliding idle deadline, refreshed by positive-byte transfers. |

Descriptor-based admission additionally uses `LISTENER_CONNECTION_FD_COUNT=3`, `LISTENER_CONNECTION_FD_RESERVE=16` and `LISTENER_CONNECTION_LIMIT_FALLBACK=256`. Normally the listener uses the smaller of the configured connection ceiling and `(RLIMIT_NOFILE - reserve) / fd_count`; fallback applies when `getrlimit()` fails. These are internal sizing assumptions, not substitutes for raising OS limits, and should not be reduced merely to force higher admission.

`LISTENER_HOSTS_FILENAME` defaults to the C string `"/etc/hosts"` and can select another local-static hosts input at compilation. String-valued overrides must retain valid C string quoting. The hosts snapshot is loaded at startup/reload; this does not enable inotify or NSS/search-domain lookup.

### libc resolver call bounds

Defined in [`src/resolver/dns.h`](../src/resolver/dns.h):

| Macro | Default | Meaning |
|---|---|---|
| `DNS_QUERY_ATTEMPT_LIMIT` | 1 | Cap on the libc resolver's nameserver-attempt rounds for one `res_nsend()` call, preserving stricter system settings. |
| `DNS_QUERY_RETRANSMIT_TIMEOUT_SEC` | 2 | Cap on its retransmission timeout, preserving stricter system settings. |

These do not bound a whole multi-query CNAME lookup; the supervisor attempt deadline remains the outer hard bound. They do not enable search/`ndots` expansion or change exact-QNAME query semantics.

### Test-only and fixed implementation constants

`RESOLVER_SUPERVISOR_INTEREST_COUNT_LIMIT` defaults to `SIZE_MAX`; supervisor tests override it to 2 to exercise overflow admission. It is an intentional test seam, not an ordinary production tuning option.

`RESOLVER_SUPERVISOR_TEST_API`, `LISTENER_TIMER_REARM_TEST`, `LISTENER_ROUTE_TIMER_ARMED_TEST`, `LISTENER_EARLY_COLLECT_TEST` and `LISTENER_READY_FLIP_TEST` are private test-target definitions, not deployment switches. `CONF_METRICS_MINIMUM_INTERVAL` is overridden to one second only for the short-runtime test daemon; lowering the 300-second production minimum is not a supported deployment option. Do not put private test definitions in global production compiler flags: doing so would reintroduce test APIs/hooks or test timing into `mcrelay`. Test environment variables activate only the separately built test support; they are not production configuration.

Not every `#define` is overrideable or a supported setting. Unguarded wire-version/packet limits, parser record/depth limits, text sizes and private implementation constants are not part of this tuning interface; do not treat arbitrary compiler `-D` definitions as permission to change protocol or parser contracts.

## Testing configurations

Configure with `BUILD_TESTING=ON`, build the test targets, then run CTest against the matching build directory. Building only `--target mcrelay` does not build its separate test runners or daemons. Test-only definitions, reduced deadlines/capacities, fault injection and linker wrappers remain scoped to their test targets.

### Regular suite

```sh
cmake -S . -B build-tests -DCMAKE_BUILD_TYPE=Release \
  -DDEBUG_MODE=OFF -DBUILD_TESTING=ON -DUBSAN_TEST=OFF
cmake --build build-tests --parallel "$(nproc)"
ctest --test-dir build-tests --output-on-failure -j4
```

To list tests or select cases:

```sh
ctest --test-dir build-tests -N
ctest --test-dir build-tests --output-on-failure -R '^(resolver_supervisor|listener_short_runtime)$'
```

Do not run a bare CTest command at the repository root and assume it ran the configured suite. On older CTest, change into `build-tests` before invoking it. Test availability/count depends on compiler support and Git availability; inspect the configured list rather than relying on a fixed total.

### Additional UBSan module tests

```sh
cmake -S . -B build-rel-ubsan -DCMAKE_BUILD_TYPE=Release \
  -DDEBUG_MODE=OFF -DBUILD_TESTING=ON -DUBSAN_TEST=ON
cmake --build build-rel-ubsan --parallel "$(nproc)"
ctest --test-dir build-rel-ubsan --output-on-failure -j4
```

With GCC or Clang, the additional `_ubsan` targets use `-fsanitize=undefined -fno-sanitize-recover=all` and `UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`. The regular tests run too. This option does not instrument `mcrelay` or every runtime target.

### Full ASan, UBSan and leak detection

With GCC or Clang, global flags instrument every compiled target, including the real executable used by runtime tests:

```sh
cmake -S . -B build-asan-ubsan -DCMAKE_BUILD_TYPE=Debug -DDEBUG_MODE=OFF \
  -DBUILD_TESTING=ON -DUBSAN_TEST=OFF \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"
cmake --build build-asan-ubsan --parallel "$(nproc)"
ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  ctest --test-dir build-asan-ubsan --output-on-failure
```

Here `UBSAN_TEST=OFF` avoids duplicate instrumented module tests because all targets already have sanitizer instrumentation. The compiler and linker flags are both required for this recipe. Sanitizers do not enable FIFO input or the debug-mode version marker; `DEBUG_MODE` controls those separately.

Runtime tests require IPv4/IPv6 loopback sockets and process/signal support. Use native Linux for authoritative epoll/timer and liveness verification; WSL1 does not reproduce native Linux behavior reliably. Missing IPv6 or restricted socket access can cause environment failures, but compare against the baseline rather than automatically dismissing a failed test.

## Debian packaging

[`packaging/deb/build-deb.sh`](../packaging/deb/build-deb.sh) has its own arguments:

| Argument | Default | Effect |
|---|---|---|
| `--arch ARCH` | `dpkg --print-architecture` | Select package Architecture, build-directory suffix and output filename. Does not configure a cross-toolchain or provide target dependencies. |
| `--cc CC` | `gcc` | Pass the compiler to `CMAKE_C_COMPILER`. A foreign architecture requires a matching compiler and target development libraries. |
| `-h`, `--help` | N/A | Print script usage without building. |

For a native package:

```sh
./packaging/deb/build-deb.sh
```

For an already prepared cross-build environment, for example:

```sh
./packaging/deb/build-deb.sh --arch arm64 --cc aarch64-linux-gnu-gcc
```

The script always configures Release, `DEBUG_MODE=OFF` and `BUILD_TESTING=OFF`; it does not run the test suite or expose arbitrary CMake flags/toolchain-file arguments. Besides compilation dependencies, it requires Debian packaging tools, `pandoc`, `gzip` and suitable stripping tools. It expects the top Debian changelog version to match the source display version converted to Debian ordering plus package revision `-1`.

It builds under `build-deb-<arch>`, outputs packages under `packaging/deb/out`, and selects system paths such as `/usr/bin/mcrelay` and `/etc/mcrelay`. These are script-defined paths, not controlled by `CMAKE_INSTALL_PREFIX` or `EXEC_SUFFIX`. The script **deletes and recreates its architecture-specific build directory** and replaces an existing output package with the same filename; keep unrelated files out of those generated paths. Building a `.deb` does not install it on the host.

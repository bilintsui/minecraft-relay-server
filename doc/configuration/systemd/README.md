# systemd configuration
The supplied `mcrelay.service` and `mcrelay@.service` units use `Type=simple` by default. This compatibility mode works with older systemd releases and reloads through `ExecReload=/bin/kill -USR1 $MAINPID`. In this mode, `systemctl reload` waits only for the signal command, not for mcrelay to finish reloading its configuration.

Use `mcrelay.service` for one instance or `mcrelay@INSTANCE.service` for a named instance. Choose the configuration path for the units you installed.

| Installation | Service user | Default service | Named instance |
|---|---|---|---|
| Manual units in this directory | `nobody` | `/usr/local/etc/mcrelay/config.json` | `/usr/local/etc/mcrelay/INSTANCE.json` |
| Debian package | `mcrelay` | `/etc/mcrelay/config.json` | `/etc/mcrelay/INSTANCE.json` |

The supplied units set `TasksMax=512` as defense in depth around the program's default 256-worker limit while leaving room for the listener and resolver helpers. If `LISTENER_WORKER_LIMIT` is changed at build time, adjust `TasksMax` with equivalent headroom. Set `MemoryMax` only after measuring the deployment's worker resident set and expected concurrency; a universal memory ceiling would otherwise reject valid configurations unpredictably.

## Built-in sandboxing
The supplied units enable `NoNewPrivileges`, clear `CapabilityBoundingSet`, and use `PrivateTmp`, `PrivateDevices` and `ProtectSystem=strict`. They also protect home directories, kernel settings and control groups, lock the process personality, and restrict executable memory mappings, namespaces, realtime scheduling and set-ID files. The native-architecture `SystemCallFilter=@system-service` allowlist uses `EPERM` for denied calls. The full set of directives requires systemd 245 or later for `ProtectClock=`. Ubuntu 22.04 ships a compatible systemd 249. [Service unit](mcrelay.service) · [Template unit](mcrelay@.service)

The units allow writes to `/var/log/mcrelay`. If `log.filename` points elsewhere on the read-only host filesystem, create its parent directory, give the service user write access, and add the directory to `ReadWritePaths` in a drop-in.

For a privileged listening port, grant the service `CAP_NET_BIND_SERVICE` with the following drop-in. The kernel's `net.ipv4.ip_unprivileged_port_start` sets the first unprivileged port in the network namespace and defaults to 1024. [Linux IP sysctl reference](https://docs.kernel.org/networking/ip-sysctl.html)

```ini
[Service]
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

## Optional synchronous reload
The `notify-reload.conf` drop-ins require systemd 253 or later. They switch the corresponding service to `Type=notify-reload`, clear the compatibility `ExecReload`, and request reload with `SIGUSR1`. systemd then waits for mcrelay's `RELOADING=1` and `READY=1` notifications.

For the regular service, install:

```sh
sudo install -Dm0644 doc/configuration/systemd/mcrelay.service.d/notify-reload.conf /etc/systemd/system/mcrelay.service.d/notify-reload.conf
sudo systemctl daemon-reload
sudo systemctl restart mcrelay.service
```

For all template instances, install:

```sh
sudo install -Dm0644 doc/configuration/systemd/mcrelay@.service.d/notify-reload.conf /etc/systemd/system/mcrelay@.service.d/notify-reload.conf
sudo systemctl daemon-reload
sudo systemctl restart 'mcrelay@INSTANCE.service'
```

Install only the drop-in matching the unit form in use. A restart is required after enabling it because the running process must first send its startup `READY=1` notification under the new service type.

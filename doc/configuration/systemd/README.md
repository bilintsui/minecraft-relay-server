# systemd configuration

The supplied `mcrelay.service` and `mcrelay@.service` units use `Type=simple` by default. This compatibility mode works with older systemd releases and reloads through `ExecReload=/bin/kill -USR1 $MAINPID`. In this mode, `systemctl reload` waits only for the signal command, not for mcrelay to finish reloading its configuration.

Use `mcrelay.service` for one server instance. Use `mcrelay@.service` for multiple named instances whose configuration files are installed as `/usr/local/etc/mcrelay/INSTANCE.json`.

The supplied units set `TasksMax=512` as defense in depth around the program's default 256-worker limit while leaving room for the listener and resolver helpers. If `LISTENER_WORKER_LIMIT` is changed at build time, adjust `TasksMax` with equivalent headroom. Set `MemoryMax` only after measuring the deployment's worker resident set and expected concurrency; a universal memory ceiling would otherwise reject valid configurations unpredictably.

## Built-in sandboxing

The supplied units run mcrelay inside a restrictive sandbox: `NoNewPrivileges`, an empty `CapabilityBoundingSet`, `PrivateTmp`/`PrivateDevices`, `ProtectSystem=strict` with `ProtectHome`, kernel and control-group protection, `LockPersonality`, `MemoryDenyWriteExecute`, `RestrictNamespaces`/`RestrictRealtime`/`RestrictSUIDSGID`, and a native-architecture `SystemCallFilter=@system-service` allowlist with `SystemCallErrorNumber=EPERM`. The complete sandbox requires systemd 245 or later because `ProtectClock=` was introduced in that release. This is a sandbox compatibility requirement, not a runtime dependency of mcrelay: older systemd releases may still start the service but ignore unsupported directives. Ubuntu 22.04 ships a compatible systemd 249. On systemd 252 and later you may additionally set `NoExec=true` in a drop-in: mcrelay serves connections purely through `fork()` and never executes another program.

Two directives need attention when you change defaults. `ReadWritePaths=/var/log/mcrelay` is the only writable path, matching the packaged log directory; if your configuration points `log.filename` elsewhere, extend `ReadWritePaths` with a drop-in (prefix a path with `-` to tolerate a missing directory), or the service will fail to open its log. `CapabilityBoundingSet=` drops every capability, so binding a listen port below 1024 fails with `EACCES`; restore only the required capability in both sets if you need a low port:

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

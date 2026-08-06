# systemd configuration

The supplied `mcrelay.service` and `mcrelay@.service` units use `Type=simple` by default. This compatibility mode works with older systemd releases and reloads through `ExecReload=/bin/kill -USR1 $MAINPID`. In this mode, `systemctl reload` waits only for the signal command, not for mcrelay to finish reloading its configuration.

Use `mcrelay.service` for one server instance. Use `mcrelay@.service` for multiple named instances whose configuration files are installed as `/usr/local/etc/mcrelay/INSTANCE.json`.

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

#!/usr/bin/env python3
"""Native-only paired Metrics measurements; stdlib, existing user systemd manager."""

import argparse
import asyncio
from collections import Counter
import csv
import errno
import gzip
import hashlib
import json
import os
from pathlib import Path
import random
import signal
import socket
import struct
import subprocess
import time


VHOST = b"metrics-cost.example"
USER = b"cost-player"
ACK = b"MCRELAY_COST_OK"
PAYLOAD = bytes(range(256)) * 16
ROOT = Path(__file__).resolve().parents[2]


def varint(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def frame(data):
    return varint(len(data)) + data


STATUS = frame(b"\0" + varint(2) + b"{}")


async def read_varint(reader):
    value = 0
    for shift in range(0, 35, 7):
        byte = (await reader.readexactly(1))[0]
        value |= (byte & 127) << shift
        if byte < 128:
            return value
    raise AssertionError("overlong packet varint")


async def read_frame(reader):
    size = await read_varint(reader)
    assert size <= 65536, size
    return await reader.readexactly(size)


def take_varint(data, offset):
    value = 0
    for shift in range(0, 35, 7):
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
    raise AssertionError("overlong packet varint")


def request(intent):
    handshake = frame(b"\0" + varint(767 if intent == 3 else 47) + varint(len(VHOST)) + VHOST + b"\x63\xdd" + bytes([intent]))
    following = frame(b"\0") if intent == 1 else frame(b"\0" + varint(len(USER)) + USER + (b"\0" * 16 if intent == 3 else b""))
    return handshake + following


class DNS(asyncio.DatagramProtocol):
    def __init__(self, path, a_delay_ms):
        self.output = path.open("w")
        self.a_delay_ms = a_delay_ms
        self.counts = Counter()
        self.errors = []
        self.pending = set()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        try:
            identifier, flags, questions, answers, authority, additional = struct.unpack("!6H", data[:12])
            assert questions == 1
            offset, labels = 12, []
            while data[offset]:
                size = data[offset]
                labels.append(data[offset + 1:offset + 1 + size].decode("ascii"))
                offset += size + 1
            offset += 1
            qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
            assert qtype in (1, 28) and qclass == 1
            end = offset + 4
            name = ".".join(labels)
            assert name == "metrics-cost.invalid", name
            self.counts[str(qtype)] += 1
            answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4) + socket.inet_aton("127.0.0.1") if qtype == 1 else b""
            response = struct.pack("!6H", identifier, 0x8580, 1, int(bool(answer)), 0, 0) + data[12:end] + answer
            query_time = time.monotonic_ns()
            def reply():
                self.transport.sendto(response, address)
                self.output.write(json.dumps({"mono_ns": time.monotonic_ns(), "query_mono_ns": query_time, "name": name, "qtype": qtype,
                                              "a_delay_ms": self.a_delay_ms, "query_hex": data.hex(), "response_hex": response.hex()}) + "\n")
                if handle is not None:
                    self.pending.discard(handle)
            handle = None
            if qtype == 1 and self.a_delay_ms:
                handle = asyncio.get_running_loop().call_later(self.a_delay_ms / 1000, reply)
                self.pending.add(handle)
            else:
                reply()
        except Exception as error:
            self.errors.append(repr(error))

    def close(self):
        for handle in self.pending:
            handle.cancel()
        self.transport.close()
        self.output.close()


class Backend:
    def __init__(self):
        self.counts = Counter()
        self.errors = []
        self.writers = set()

    async def handle(self, reader, writer):
        self.writers.add(writer)
        try:
            handshake = await read_frame(reader)
            packet, offset = take_varint(handshake, 0)
            protocol, offset = take_varint(handshake, offset)
            length, offset = take_varint(handshake, offset)
            offset += length + 2
            intent, offset = take_varint(handshake, offset)
            assert packet == 0 and offset == len(handshake)
            following = await read_frame(reader)
            self.counts["intent_" + str(intent)] += 1
            if intent == 1:
                assert protocol == 47 and following == b"\0"
                writer.write(STATUS)
                await writer.drain()
                await reader.read()
            else:
                assert intent in (2, 3)
                packet, offset = take_varint(following, 0)
                length, offset = take_varint(following, offset)
                assert packet == 0 and following[offset:offset + length] == USER
                assert protocol == (767 if intent == 3 else 47)
                writer.write(ACK)
                await writer.drain()
                while True:
                    data = await reader.read(65536)
                    if not data:
                        break
                    self.counts["payload_bytes"] += len(data)
                    writer.write(data)
                    await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            self.errors.append("unexpected backend connection reset")
        except Exception as error:
            self.errors.append(repr(error))
        finally:
            self.writers.discard(writer)
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass


def command(*args, **kwargs):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, **kwargs)


def key_values(path):
    result = {}
    for line in path.read_text().splitlines():
        parts = line.replace(":", "").split()
        if len(parts) >= 2 and parts[1].isdigit():
            result[parts[0]] = int(parts[1])
    return result


class Instance:
    def __init__(self, binary, interval, directory, backend_port, redirect, dns_port, service_cpu, protocol_trace=False):
        self.directory = directory
        self.log = directory / "access.log"
        self.unit = "mcrelay-cost-{}-{}".format(os.getpid(), directory.name)
        self.unit_live = False
        config = {
            "log": {"filename": str(self.log), "level": 2},
            "metrics": {"interval": interval}, "icon": "",
            "listen": {"address": "127.0.0.1", "port": 0},
            "proxy": [{"vhost": VHOST.decode(), "address": "metrics-cost.invalid" if dns_port else "127.0.0.1", "port": backend_port}],
        }
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.port = reservation.getsockname()[1]
        config["listen"]["port"] = self.port
        self.config = directory / "config.json"
        self.config.write_text(json.dumps(config, indent=2) + "\n")
        args = ["systemd-run", "--user", "--quiet", "--collect", "--unit=" + self.unit,
                "--property=Type=exec", "--property=RemainAfterExit=yes", "--property=KillMode=control-group",
                "--property=CPUAccounting=yes", "--property=MemoryAccounting=yes", "--property=CPUAffinity=" + str(service_cpu),
                "--property=StandardInput=null", "--property=StandardOutput=null", "--property=StandardError=file:" + str(directory / "stderr.log")]
        if dns_port:
            args += ["--setenv=LD_PRELOAD=" + str(redirect), "--setenv=MCRELAY_BENCH_DNS_PORT=" + str(dns_port)]
        if protocol_trace:
            args += ["--setenv=MCRELAY_COST_TRACE_PATH=" + str(directory / "protocol-trace.log")]
        args += [str(binary), "run", "-c", str(self.config)]
        self.launch_command = args
        subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.unit_live = True
        try:
            properties = command("systemctl", "--user", "show", self.unit, "--property=MainPID,ControlGroup")
            properties = dict(line.split("=", 1) for line in properties.splitlines())
            self.pid = int(properties["MainPID"])
            assert self.pid > 0
            self.cgroup = Path("/sys/fs/cgroup") / properties["ControlGroup"].lstrip("/")
            assert (self.cgroup / "cpu.stat").is_file() and (self.cgroup / "memory.current").is_file()
        except BaseException:
            command("systemctl", "--user", "stop", self.unit)
            self.unit_live = False
            raise

    async def ready(self):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.log.exists() and "accepting connections." in self.log.read_text():
                await self.quiet()
                return
            await asyncio.sleep(0.02)
        raise AssertionError("readiness timed out: " + str(self.directory))

    async def quiet(self):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if len((self.cgroup / "cgroup.procs").read_text().split()) == 3:
                await asyncio.sleep(0.05)
                return
            await asyncio.sleep(0.02)
        raise AssertionError("worker processes not reaped")

    async def dns_quiet(self):
        # A valid IPv4 route may answer before the other helper finishes AAAA.
        # Require two idle observations before admitting the next request, so
        # legitimate orphan-job reacquisition cannot change the work count.
        deadline = time.monotonic() + 2
        previously_idle = False
        while time.monotonic() < deadline:
            parent = Path("/proc") / str(self.pid)
            children = (parent / "task" / str(self.pid) / "children").read_text().split()
            idle = len(children) == 2 and parent.joinpath("stat").read_text().rsplit(")", 1)[1].split()[0] == "S"
            for child in children:
                proc = Path("/proc") / child
                idle = idle and "poll" in (proc / "wchan").read_text()
                idle = idle and all(int(fd.name) <= 3 for fd in (proc / "fd").iterdir())
            if idle and previously_idle:
                return
            previously_idle = idle
            await asyncio.sleep(0.001)
        raise AssertionError("DNS helpers did not reach an independent-request boundary")

    def helper_identities(self):
        parent = Path("/proc") / str(self.pid)
        children = (parent / "task" / str(self.pid) / "children").read_text().split()
        assert len(children) == 2, children
        return sorted((int(value), int((Path("/proc") / value / "stat").read_text().rsplit(")", 1)[1].split()[19])) for value in children)

    def sample(self):
        processes = []
        unavailable = []
        for value in (self.cgroup / "cgroup.procs").read_text().split():
            proc = Path("/proc") / value
            try:
                memory = key_values(proc / "smaps_rollup")
                stat = (proc / "stat").read_text().rsplit(")", 1)[1].split()
                processes.append({"pid": int(value), "comm": (proc / "comm").read_text().strip(), "memory_kib": memory,
                                  "cpu_ticks": {"user": int(stat[11]), "system": int(stat[12]), "waited_user": int(stat[13]), "waited_system": int(stat[14])}})
            except OSError as error:
                if error.errno not in (errno.ENOENT, errno.ESRCH, errno.ENODEV):
                    raise
                unavailable.append({"pid": int(value), "errno": error.errno})
        return {"mono_ns": time.monotonic_ns(), "cpu_stat": key_values(self.cgroup / "cpu.stat"),
                "memory_current": int((self.cgroup / "memory.current").read_text()), "memory_stat": key_values(self.cgroup / "memory.stat"),
                "processes": processes, "unavailable_processes": unavailable, "pss_kib": sum(p["memory_kib"].get("Pss", 0) for p in processes),
                "private_kib": sum(p["memory_kib"].get("Private_Clean", 0) + p["memory_kib"].get("Private_Dirty", 0) for p in processes)}

    async def stop(self):
        if not self.unit_live:
            return
        cleanup = {"unit": self.unit, "pid": self.pid, "cgroup": str(self.cgroup), "removed_cgroup_errno": None}
        try:
            try:
                os.kill(self.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                try:
                    remaining = (self.cgroup / "cgroup.procs").read_text().strip()
                except OSError as error:
                    if error.errno not in (errno.ENOENT, errno.ENODEV):
                        raise
                    cleanup["removed_cgroup_errno"] = error.errno
                    remaining = ""
                if not remaining:
                    break
                await asyncio.sleep(0.02)
            else:
                raise AssertionError("service left processes")
        finally:
            command("systemctl", "--user", "stop", self.unit)
            self.unit_live = False
            save(self.directory / "cleanup.json", cleanup)


async def connect(instance, intent):
    reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", instance.port), 5)
    writer.write(request(intent))
    await writer.drain()
    expected = STATUS if intent == 1 else ACK
    actual = await asyncio.wait_for(reader.readexactly(len(expected)), 5)
    assert actual == expected
    return reader, writer


async def workload(instance, profile, count, concurrency):
    latencies = []
    next_index = 0

    async def lane():
        nonlocal next_index
        while next_index < count:
            index = next_index
            next_index += 1
            intent = 1 if profile in ("status", "dns") else 2 + index % 2
            start = time.monotonic_ns()
            reader, writer = await connect(instance, intent)
            if intent != 1:
                writer.write(PAYLOAD)
                await writer.drain()
                assert await asyncio.wait_for(reader.readexactly(len(PAYLOAD)), 5) == PAYLOAD
            writer.close()
            await writer.wait_closed()
            latencies.append(time.monotonic_ns() - start)
            if profile == "dns":
                await instance.dns_quiet()

    await asyncio.gather(*(lane() for _ in range(concurrency)))
    await instance.quiet()
    assert len(latencies) == count
    return latencies


async def services(directory, dns, a_delay_ms=0):
    backend = Backend()
    server = await asyncio.start_server(backend.handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    provider = None
    dns_port = 0
    if dns:
        provider = DNS(directory / "dns.jsonl", a_delay_ms)
        transport, protocol = await asyncio.get_running_loop().create_datagram_endpoint(lambda: provider, local_addr=("127.0.0.1", 0))
        dns_port = transport.get_extra_info("sockname")[1]
    return backend, server, port, provider, dns_port


def save(path, data):
    path.write_text(json.dumps(data, indent=2, default=str) + "\n")


def compress(path):
    if path.exists():
        with path.open("rb") as source, gzip.open(str(path) + ".gz", "wb") as target:
            while True:
                chunk = source.read(65536)
                if not chunk:
                    break
                target.write(chunk)
        path.unlink()


def validate_trial_log(directory):
    text = gzip.decompress((directory / "access.log.gz").read_bytes()).decode()
    unexpected = [line for line in text.splitlines() if "[CRIT]" in line or "resolver_helper status=" in line]
    assert not unexpected, (directory, unexpected)


async def trial(args, variant, profile, repetition, count, concurrency):
    directory = args.results / "{}-{}-r{}".format(profile, variant, repetition)
    directory.mkdir()
    backend, server, port, provider, dns_port = await services(directory, profile == "dns", args.dns_a_delay_ms)
    binary = args.control if variant == "A" else args.normal
    instance = None
    samples = []
    sampling = True

    async def sampler():
        while sampling:
            samples.append(instance.sample())
            await asyncio.sleep(0.5)

    try:
        instance = Instance(binary, 900 if variant == "C" else 0, directory, port, args.tools / "libdns_redirect.so", dns_port, args.service_cpu, args.protocol_trace)
        await instance.ready()
        initial_helpers = instance.helper_identities()
        await workload(instance, profile, min(count, 100 if profile != "dns" else 20), concurrency)
        await asyncio.sleep(0.2)
        before_backend, before_dns = backend.counts.copy(), provider.counts.copy() if provider else Counter()
        before = instance.sample()
        task = asyncio.create_task(sampler())
        start = time.monotonic_ns()
        if profile == "idle":
            await asyncio.sleep(args.idle_seconds)
            latencies = []
        else:
            latencies = await workload(instance, profile, count, concurrency)
        elapsed = time.monotonic_ns() - start
        after = instance.sample()
        final_helpers = instance.helper_identities()
        sampling = False
        await task
        samples += [before, after]
        save(directory / "samples.json", samples)
        with (directory / "latency.csv").open("w") as output:
            output.write("sample,elapsed_ns\n")
            for index, value in enumerate(latencies):
                output.write("{},{}\n".format(index, value))
        assert not backend.errors and not (provider and provider.errors), (backend.errors, provider.errors if provider else [])
        counters = dict(backend.counts - before_backend)
        if profile in ("status", "dns"):
            assert counters.get("intent_1", 0) == count
        elif profile == "workers":
            assert counters.get("intent_2", 0) == count // 2 and counters.get("intent_3", 0) == count // 2
            assert counters.get("payload_bytes", 0) == count * len(PAYLOAD)
        dns_counts = dict(provider.counts - before_dns) if provider else {}
        if profile == "dns":
            assert dns_counts == {"1": count, "28": count}, dns_counts
        record = {"variant": variant, "profile": profile, "repetition": repetition, "count": count, "concurrency": concurrency,
                  "elapsed_ns": elapsed, "cpu_usec": after["cpu_stat"]["usage_usec"] - before["cpu_stat"]["usage_usec"],
                  "cpu_user_usec": after["cpu_stat"]["user_usec"] - before["cpu_stat"]["user_usec"],
                  "cpu_system_usec": after["cpu_stat"]["system_usec"] - before["cpu_stat"]["system_usec"],
                  "before": before, "after": after, "backend": counters, "dns": dns_counts,
                  "dns_pacing": "two helper-idle/closed-DNS-socket observations separated by 1ms" if profile == "dns" else None,
                  "dns_a_delay_ms": args.dns_a_delay_ms if profile == "dns" else None,
                  "protocol_trace_enabled": args.protocol_trace,
                  "initial_helpers": initial_helpers, "final_helpers": final_helpers,
                  "binary": str(binary), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "command": instance.launch_command}
        save(directory / "result.json", record)
        assert initial_helpers == final_helpers, (directory, initial_helpers, final_helpers)
        print(json.dumps({key: record[key] for key in ["profile", "variant", "repetition", "count", "cpu_usec", "elapsed_ns"]}), flush=True)
    finally:
        sampling = False
        if instance:
            await instance.stop()
        server.close()
        await server.wait_closed()
        if provider:
            provider.close()
        for writer in list(backend.writers):
            writer.close()
        compress(directory / "access.log")
        compress(directory / "dns.jsonl")
    validate_trial_log(directory)


async def memory_trial(args, variant, repetition, counts):
    directory = args.results / "memory-{}-r{}".format(variant, repetition)
    directory.mkdir()
    backend, server, port, provider, dns_port = await services(directory, False)
    instance = None
    channels = []
    result = []
    try:
        instance = Instance(args.control if variant == "A" else args.normal, 900 if variant == "C" else 0, directory,
                            port, args.tools / "libdns_redirect.so", 0, args.service_cpu)
        await instance.ready()
        await workload(instance, "status", 100, 8)
        for count in counts:
            while len(channels) < count:
                reader, writer = await connect(instance, 2 + len(channels) % 2)
                writer.write(PAYLOAD)
                await writer.drain()
                assert await reader.readexactly(len(PAYLOAD)) == PAYLOAD
                channels.append((reader, writer))
            await asyncio.sleep(0.5)
            samples = []
            for _ in range(4):
                sample = instance.sample()
                assert len(sample["processes"]) == count + 3, (count, sample)
                samples.append(sample)
                await asyncio.sleep(0.15)
            result.append({"workers": count, "samples": samples})
        for reader, writer in channels:
            writer.close()
        for reader, writer in channels:
            await writer.wait_closed()
        channels.clear()
        await instance.quiet()
        result.append({"workers": "after_close", "samples": [instance.sample()]})
        assert not backend.errors, backend.errors
        save(directory / "result.json", {"variant": variant, "repetition": repetition, "profile": "memory", "stages": result,
                                         "command": instance.launch_command, "binary": str(args.control if variant == "A" else args.normal)})
        print(json.dumps({"profile": "memory", "variant": variant, "repetition": repetition, "workers": counts}), flush=True)
    finally:
        for reader, writer in channels:
            writer.close()
        if instance:
            await instance.stop()
        server.close()
        await server.wait_closed()
        compress(directory / "access.log")


async def cadence(args):
    instances = []
    backend, server, port, provider, dns_port = await services(args.results, False)
    try:
        for repetition in range(args.repetitions):
            for variant in ("B", "C") if repetition % 2 == 0 else ("C", "B"):
                directory = args.results / "cadence-{}-r{}".format(variant, repetition)
                directory.mkdir()
                instance = Instance(args.normal, 900 if variant == "C" else 0, directory, port, args.tools / "libdns_redirect.so", 0, args.service_cpu)
                instances.append((variant, repetition, instance))
                await instance.ready()
                await asyncio.sleep(0.2)
        before = {instance.unit: instance.sample() for variant, repetition, instance in instances}
        save(args.results / "cadence-start.json", {"started_utc": time.time(), "instances": [{"variant": v, "repetition": r, "pid": i.pid, "unit": i.unit,
                                                                                          "directory": str(i.directory)} for v, r, i in instances]})
        start = time.monotonic()
        while True:
            complete = all("reason=periodic " in instance.log.read_text() for variant, repetition, instance in instances if variant == "C")
            if complete:
                # Meta is the first line: seeing it alone does not cover the
                # remaining 47 lines in the periodic CPU accounting window.
                for variant, repetition, instance in instances:
                    if variant != "C":
                        continue
                    result = subprocess.run(["python3", str(ROOT / "tools/metrics-report.py"), "--format", "json", str(instance.log)],
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    if result.returncode != 0 or json.loads(result.stdout)["counts"]["complete_snapshots"] != 2:
                        complete = False
                        break
                if complete:
                    await asyncio.sleep(0.05)
                    break
            assert time.monotonic() - start < 950, "900-second cadence timed out"
            await asyncio.sleep(1)
        for variant, repetition, instance in instances:
            after = instance.sample()
            text = instance.log.read_text()
            periodic = sum("family=meta " in line and "reason=periodic " in line for line in text.splitlines())
            assert periodic == int(variant == "C"), (variant, periodic)
            save(instance.directory / "result.json", {"profile": "cadence", "variant": variant, "repetition": repetition,
                 "before": before[instance.unit], "after": after, "periodic_snapshots": periodic,
                 "cpu_usec": after["cpu_stat"]["usage_usec"] - before[instance.unit]["cpu_stat"]["usage_usec"],
                 "command": instance.launch_command, "elapsed_seconds": time.monotonic() - start,
                 "end_gate": "all five complete periodic frames validated, followed by 50ms idle"})
        print("900-second cadence complete for {} independently accounted, co-resident idle pairs".format(args.repetitions), flush=True)
    finally:
        for variant, repetition, instance in instances:
            await instance.stop()
            compress(instance.directory / "access.log")
        server.close()
        await server.wait_closed()


async def main(args):
    args.results.mkdir(parents=True, exist_ok=False)
    os.environ["XDG_RUNTIME_DIR"] = "/run/user/{}".format(os.getuid())
    allowed = sorted(os.sched_getaffinity(0))
    args.service_cpu = allowed[1]
    os.sched_setaffinity(0, {allowed[0]})
    save(args.results / "environment.json", {"kernel": command("uname", "-a"), "os_release": Path("/etc/os-release").read_text(),
          "cpuinfo": Path("/proc/cpuinfo").read_text(), "clock_ticks": os.sysconf("SC_CLK_TCK"), "page_size": os.sysconf("SC_PAGE_SIZE"),
          "service_cpu": args.service_cpu, "driver_cpu": allowed[0], "argv": vars(args), "cgroup": Path("/proc/self/cgroup").read_text()})
    if args.mode == "cadence":
        await cadence(args)
        return
    profiles = {"status": (args.status_requests, 16), "dns": (args.dns_requests, 1), "workers": (args.worker_requests, 8), "idle": (0, 1)}
    if args.mode == "dns":
        profiles = {"dns": profiles["dns"]}
    for profile, (count, concurrency) in profiles.items():
        for repetition in range(args.repetitions):
            order = list("ABC")
            random.Random(701 + repetition * 13 + len(profile)).shuffle(order)
            for variant in order:
                await trial(args, variant, profile, repetition, count, concurrency)
    if args.mode == "dns":
        return
    for repetition in range(args.repetitions):
        order = list("ABC")
        random.Random(2003 + repetition).shuffle(order)
        for variant in order:
            await memory_trial(args, variant, repetition, [0, 1, 16, 64] if args.mode != "smoke" else [0, 1, 4])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("smoke", "suite", "cadence", "dns"))
    parser.add_argument("--control", type=lambda value: Path(value).resolve(), required=True)
    parser.add_argument("--normal", type=lambda value: Path(value).resolve(), required=True)
    parser.add_argument("--tools", type=lambda value: Path(value).resolve(), required=True)
    parser.add_argument("--results", type=lambda value: Path(value).resolve(), required=True)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--status-requests", type=int, default=30000)
    parser.add_argument("--dns-requests", type=int, default=5000)
    parser.add_argument("--dns-a-delay-ms", type=float, default=2)
    parser.add_argument("--protocol-trace", action="store_true", help="diagnostic patched binaries only; excluded from cost results")
    parser.add_argument("--worker-requests", type=int, default=2000)
    parser.add_argument("--idle-seconds", type=float, default=3)
    arguments = parser.parse_args()
    if arguments.mode == "smoke":
        arguments.repetitions = 1
        arguments.status_requests, arguments.dns_requests, arguments.worker_requests = 100, 20, 20
        arguments.idle_seconds = 0.5
    asyncio.run(main(arguments))

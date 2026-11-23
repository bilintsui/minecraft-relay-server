#!/usr/bin/env python3
"""Read actual GCC DWARF sizes/member offsets from the two measured binaries."""

import argparse
import json
from pathlib import Path
import re
import subprocess


NAMES = ("conf", "listener_connection", "listener_context", "listener_events", "listener_requests", "listener_metrics_aggregate_snapshot",
         "resolver_cache", "resolver_cache_entry", "resolver_cache_payload", "resolver_ipc_assembly", "resolver_ipc_assembly_budget",
         "resolver_supervisor", "resolver_supervisor_helper", "resolver_supervisor_job")


def layouts(binary):
    output = subprocess.check_output(["readelf", "--debug-dump=info", str(binary)], text=True)
    entries, stack, current = {}, {}, None
    for line in output.splitlines():
        match = re.match(r"\s*<(\d+)><([0-9a-f]+)>: Abbrev Number: \d+(?: \((DW_TAG_\w+)\))?", line)
        if match:
            depth, identifier, tag = int(match[1]), int(match[2], 16), match[3]
            current = entries[identifier] = {"tag": tag, "parent": stack.get(depth - 1)}
            stack[depth] = identifier
            continue
        if current is None:
            continue
        if "DW_AT_name" in line:
            current["name"] = line.rsplit(": ", 1)[-1].strip()
        elif "DW_AT_byte_size" in line:
            current["bytes"] = int(line.rsplit(":", 1)[-1].strip(), 0)
        elif "DW_AT_type" in line:
            match = re.search(r"<0x([0-9a-f]+)>", line)
            if match:
                current["type"] = int(match[1], 16)
        elif "DW_AT_data_member_location" in line:
            value = line.rsplit(":", 1)[-1].strip()
            if re.fullmatch(r"[0-9]+", value):
                current["offset"] = int(value)
    result = {}
    for name in NAMES:
        found = []
        for identifier, entry in entries.items():
            if entry.get("name") != name or entry["tag"] not in ("DW_TAG_typedef", "DW_TAG_structure_type"):
                continue
            seen = set()
            while entry["tag"] == "DW_TAG_typedef" and "type" in entry and identifier not in seen:
                seen.add(identifier)
                identifier = entry["type"]
                entry = entries[identifier]
            if "bytes" in entry:
                members = [{"name": value.get("name"), "offset": value.get("offset"), "type_die": value.get("type")}
                           for value in entries.values() if value["tag"] == "DW_TAG_member" and value["parent"] == identifier]
                found.append({"bytes": entry["bytes"], "members": members})
        if found:
            assert len(set(value["bytes"] for value in found)) == 1, (name, found)
            result[name] = found[0]
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--normal", type=Path, required=True)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    normal, control = layouts(args.normal), layouts(args.control)
    differences = {name: normal[name]["bytes"] - control[name]["bytes"] for name in NAMES if name in normal and name in control}
    args.output.write_text(json.dumps({"normal": normal, "control": control, "size_difference_bytes": differences}, indent=2) + "\n")
    print(json.dumps(differences))

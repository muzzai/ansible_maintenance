#!/usr/bin/env python3
import argparse, json, subprocess, sys, textwrap

def run_cli(cmd):
    try:
        out = subprocess.check_output(cmd, text=True)
        return json.loads(out)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Command failed: {' '.join(cmd)}", file=sys.stderr)
        sys.exit(1)

def collect_ip_name_map(region, tag_key):
    ip_to_name = {}
    cmd = ["aws", "ec2", "describe-instances", "--region", region, "--output", "json"]
    data = run_cli(cmd)

    for reservation in data.get("Reservations", []):
        for inst in reservation.get("Instances", []):
            # get tag value
            tags = inst.get("Tags", [])
            name = next((t["Value"] for t in tags if t["Key"] == tag_key), inst.get("InstanceId"))
            # primary ip
            if "PrivateIpAddress" in inst:
                ip_to_name.setdefault(inst["PrivateIpAddress"], name)
            # eni ips
            for eni in inst.get("NetworkInterfaces", []):
                if "PrivateIpAddress" in eni:
                    ip_to_name.setdefault(eni["PrivateIpAddress"], name)
                for pip in eni.get("PrivateIpAddresses", []):
                    ip_to_name.setdefault(pip.get("PrivateIpAddress"), name)
    return ip_to_name

def make_lua(ip_to_name):
    items = sorted(ip_to_name.items())
    table_lines = [f'  ["{ip}"] = "{name}",' for ip, name in items]
    lua_table = "local ip_to_name = {\n" + "\n".join(table_lines) + "\n}"

    return textwrap.dedent(f"""\
    {lua_table}

    local function map_instance_name(ip)
      if not ip then return nil end
      return ip_to_name[ip]
    end

    function append_time(tag, timestamp, record)
      if record.log and type(record.log) == "string" and string.sub(record.log, 1, 1) == "#" then
        return -1, timestamp, record
      end
      if record["datetime"] then
        record["@timestamp"] = record["datetime"] .. "Z"
      end
      record["log_type"] = "iis"
      local server_ip = record["s_ip"] or record["server_ip"]
      local inst_name = map_instance_name(server_ip)
      if inst_name then
        record["instance_name"] = inst_name
      end
      return 1, timestamp, record
    end
    """)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--region", required=True)
    p.add_argument("--tag-key", default="Name")
    p.add_argument("--out", default="append_time_corrected.lua")
    args = p.parse_args()

    ip_to_name = collect_ip_name_map(args.region, args.tag_key)
    lua_src = make_lua(ip_to_name)

    with open(args.out, "w") as f:
        f.write(lua_src)
    print(f"[OK] Wrote {len(ip_to_name)} mappings to {args.out}")

if __name__ == "__main__":
    main()
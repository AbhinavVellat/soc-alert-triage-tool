#!/usr/bin/env python3
"""
generate_logs.py
Generates realistic synthetic SOC log data across three common sources:
  - firewall.log   (iptables/pfSense-style ALLOW/DENY entries)
  - auth.log        (Linux sshd-style authentication log)
  - ids.log          (Suricata/Snort-style IDS alerts)

The data is randomly generated but seeded so it's reproducible, and it
deliberately embeds realistic attack patterns (brute force, port scans,
malware beaconing, exfil-looking traffic) mixed in with benign noise,
so the analyzer script has real signal to detect.
"""

import random
from datetime import datetime, timedelta

random.seed(42)

START = datetime(2026, 7, 28, 0, 0, 0)

INTERNAL_HOSTS = [f"10.0.{n}.{random.randint(10,250)}" for n in range(1, 15)]
SERVERS = {
    "10.0.0.10": "WEB-01",
    "10.0.0.11": "WEB-02",
    "10.0.0.20": "DB-01",
    "10.0.0.30": "DC-01",
    "10.0.0.40": "MAIL-01",
}
USERS = ["jsmith", "agarcia", "mchen", "root", "admin", "backup_svc", "rwilson", "tpatel"]

EXTERNAL_IPS_BENIGN = [f"172.217.{random.randint(0,255)}.{random.randint(0,255)}" for _ in range(20)]
EXTERNAL_IPS_MALICIOUS = [
    "185.220.101.47", "45.155.204.12", "194.36.190.53", "91.219.237.244",
    "89.248.165.74", "193.106.31.98", "5.188.62.140", "80.94.95.116",
    "185.220.102.8", "146.70.184.33",
]

lines_fw = []
lines_auth = []
lines_ids = []

def ts(offset_seconds):
    return START + timedelta(seconds=offset_seconds)

def fmt_fw(t):
    return t.strftime("%b %d %H:%M:%S")

def fmt_auth(t):
    return t.strftime("%b %d %H:%M:%S")

def fmt_ids(t):
    return t.strftime("%m/%d/%Y-%H:%M:%S.%f")[:-3]

t_cursor = 0

# ---------------------------------------------------------------
# 1. Benign background traffic (firewall)
# ---------------------------------------------------------------
for _ in range(400):
    t_cursor += random.randint(5, 40)
    src = random.choice(INTERNAL_HOSTS)
    dst = random.choice(list(SERVERS.keys()) + EXTERNAL_IPS_BENIGN)
    dport = random.choice([80, 443, 443, 443, 53, 123])
    action = "ALLOW"
    lines_fw.append(
        f"{fmt_fw(ts(t_cursor))} fw01 kernel: ACTION={action} PROTO=TCP "
        f"SRC={src} DST={dst} SPT={random.randint(1024,65000)} DPT={dport}"
    )

# ---------------------------------------------------------------
# 2. Port scan pattern (single external IP hitting many ports on one server, fast)
# ---------------------------------------------------------------
scan_start = t_cursor + 200
scanner = EXTERNAL_IPS_MALICIOUS[0]
target = "10.0.0.10"
for i in range(60):
    t = scan_start + i * random.uniform(0.2, 1.0)
    lines_fw.append(
        f"{fmt_fw(ts(t))} fw01 kernel: ACTION=DENY PROTO=TCP "
        f"SRC={scanner} DST={target} SPT={random.randint(1024,65000)} DPT={random.randint(1,1024)}"
    )
t_cursor = int(scan_start) + 80

# ---------------------------------------------------------------
# 2a-extra. Two more port scans, different scanners/targets, for more variety
# ---------------------------------------------------------------
for scanner2, target2 in [(EXTERNAL_IPS_MALICIOUS[4], "10.0.0.20"), (EXTERNAL_IPS_MALICIOUS[5], "10.0.0.40")]:
    scan2_start = t_cursor + 150
    for i in range(40):
        t = scan2_start + i * random.uniform(0.2, 1.2)
        lines_fw.append(
            f"{fmt_fw(ts(t))} fw01 kernel: ACTION=DENY PROTO=TCP "
            f"SRC={scanner2} DST={target2} SPT={random.randint(1024,65000)} DPT={random.randint(1,1024)}"
        )
    t_cursor = int(scan2_start) + 60

# ---------------------------------------------------------------
# 2b. Moderate deny burst - below full port-scan threshold (medium severity)
# ---------------------------------------------------------------
mod_start = t_cursor + 150
mod_src = "172.217.9.201"
mod_target = "10.0.0.40"
for i, port in enumerate([25, 587, 993, 143, 110, 465, 21]):
    t = mod_start + i * random.uniform(3, 10)
    lines_fw.append(
        f"{fmt_fw(ts(t))} fw01 kernel: ACTION=DENY PROTO=TCP "
        f"SRC={mod_src} DST={mod_target} SPT={random.randint(1024,65000)} DPT={port}"
    )
t_cursor = int(mod_start) + 100

# ---------------------------------------------------------------
# 2b-extra. Two more moderate deny bursts (medium severity) for balance
# ---------------------------------------------------------------
for mod_src2, mod_target2, ports in [
    ("172.217.44.12", "10.0.0.20", [3306, 5432, 27017, 6379, 9200]),
    ("172.217.88.9", "10.0.0.11", [22, 3389, 5900, 8080, 8443]),
    ("172.217.51.3", "10.0.0.10", [21, 23, 445, 1433, 5985]),
    ("172.217.19.60", "10.0.0.30", [88, 389, 636, 3268, 88]),
]:
    mod2_start = t_cursor + 120
    for i, port in enumerate(ports):
        t = mod2_start + i * random.uniform(3, 10)
        lines_fw.append(
            f"{fmt_fw(ts(t))} fw01 kernel: ACTION=DENY PROTO=TCP "
            f"SRC={mod_src2} DST={mod_target2} SPT={random.randint(1024,65000)} DPT={port}"
        )
    t_cursor = int(mod2_start) + 80

# ---------------------------------------------------------------
# 3. Normal + failed SSH auth traffic
# ---------------------------------------------------------------
auth_cursor = 0
for _ in range(80):
    auth_cursor += random.randint(30, 300)
    user = random.choice(USERS)
    src = random.choice(INTERNAL_HOSTS + EXTERNAL_IPS_BENIGN)
    ok = random.random() > 0.08
    if ok:
        lines_auth.append(
            f"{fmt_auth(ts(auth_cursor))} dc01 sshd[{random.randint(1000,9999)}]: "
            f"Accepted password for {user} from {src} port {random.randint(1024,65000)} ssh2"
        )
    else:
        lines_auth.append(
            f"{fmt_auth(ts(auth_cursor))} dc01 sshd[{random.randint(1000,9999)}]: "
            f"Failed password for {user} from {src} port {random.randint(1024,65000)} ssh2"
        )

# ---------------------------------------------------------------
# 4. Brute-force SSH pattern (many failed logins, one source, one/few users, tight timing)
# ---------------------------------------------------------------
bf_start = auth_cursor + 150
brute_src = EXTERNAL_IPS_MALICIOUS[1]
for i in range(45):
    t = bf_start + i * random.uniform(1, 4)
    user = random.choice(["root", "admin", "root", "root"])
    lines_auth.append(
        f"{fmt_auth(ts(t))} dc01 sshd[{random.randint(1000,9999)}]: "
        f"Failed password for {user} from {brute_src} port {random.randint(1024,65000)} ssh2"
    )
# one successful login right after -> looks like a compromised credential
lines_auth.append(
    f"{fmt_auth(ts(bf_start + 45*3 + 5))} dc01 sshd[{random.randint(1000,9999)}]: "
    f"Accepted password for root from {brute_src} port {random.randint(1024,65000)} ssh2"
)
auth_cursor = int(bf_start + 45 * 3 + 60)

# ---------------------------------------------------------------
# 4a-extra. Two more brute-force sources, different targets/users
# ---------------------------------------------------------------
for brute_src2, target_user in [(EXTERNAL_IPS_MALICIOUS[6], "backup_svc"), (EXTERNAL_IPS_MALICIOUS[7], "mchen"), (EXTERNAL_IPS_MALICIOUS[8], "rwilson")]:
    bf2_start = auth_cursor + 100
    for i in range(30):
        t = bf2_start + i * random.uniform(1, 4)
        lines_auth.append(
            f"{fmt_auth(ts(t))} dc01 sshd[{random.randint(1000,9999)}]: "
            f"Failed password for {target_user} from {brute_src2} port {random.randint(1024,65000)} ssh2"
        )
    auth_cursor = int(bf2_start + 30 * 3 + 40)

# ---------------------------------------------------------------
# 4b. Moderate failed-login pattern (below brute-force threshold, likely a typo)
# ---------------------------------------------------------------
typo_start = auth_cursor + 100
typo_src = "10.0.7.67"
for i in range(5):
    t = typo_start + i * random.uniform(15, 45)
    lines_auth.append(
        f"{fmt_auth(ts(t))} dc01 sshd[{random.randint(1000,9999)}]: "
        f"Failed password for tpatel from {typo_src} port {random.randint(1024,65000)} ssh2"
    )
lines_auth.append(
    f"{fmt_auth(ts(typo_start + 5*30 + 10))} dc01 sshd[{random.randint(1000,9999)}]: "
    f"Accepted password for tpatel from {typo_src} port {random.randint(1024,65000)} ssh2"
)
auth_cursor = int(typo_start + 5*30 + 60)

# ---------------------------------------------------------------
# 4b-extra. Two more moderate/low failed-login patterns for balance
# ---------------------------------------------------------------
for typo_src2, typo_user2, n in [("10.0.3.44", "jsmith", 4), ("10.0.9.12", "agarcia", 6), ("10.0.11.5", "rwilson", 5)]:
    t2_start = auth_cursor + 80
    for i in range(n):
        t = t2_start + i * random.uniform(15, 45)
        lines_auth.append(
            f"{fmt_auth(ts(t))} dc01 sshd[{random.randint(1000,9999)}]: "
            f"Failed password for {typo_user2} from {typo_src2} port {random.randint(1024,65000)} ssh2"
        )
    lines_auth.append(
        f"{fmt_auth(ts(t2_start + n*30 + 10))} dc01 sshd[{random.randint(1000,9999)}]: "
        f"Accepted password for {typo_user2} from {typo_src2} port {random.randint(1024,65000)} ssh2"
    )
    auth_cursor = int(t2_start + n*30 + 50)

# ---------------------------------------------------------------
# 5. IDS alerts: mix of low-priority noise + real signatures
# ---------------------------------------------------------------
ids_cursor = 0
noise_sigs = [
    (2013504, "ET POLICY GNU/Linux APT User-Agent Outbound likely related to package management", 3),
    (2001219, "ET SCAN Potential SSH Scan", 3),
    (2009582, "ET POLICY DNS Query for TOR", 3),
]
attack_sigs = [
    (2024766, "ET MALWARE Cobalt Strike Beacon C2 Checkin", 1),
    (2023924, "ET EXPLOIT Possible Log4j RCE Attempt (Log4Shell)", 1),
    (2027056, "ET TROJAN Generic Trojan Data Exfiltration Attempt", 1),
    (2100498, "GPL SQL_INJECTION SELECT FROM", 1),
]

for _ in range(60):
    ids_cursor += random.randint(20, 200)
    sid, msg, prio = random.choice(noise_sigs)
    src = random.choice(INTERNAL_HOSTS)
    dst = random.choice(EXTERNAL_IPS_BENIGN)
    lines_ids.append(
        f"{fmt_ids(ts(ids_cursor))} [**] [1:{sid}:1] {msg} [**] "
        f"[Classification: Not Suspicious Traffic] [Priority: {prio}] "
        f"{{TCP}} {src}:{random.randint(1024,65000)} -> {dst}:{random.choice([80,443,53])}"
    )

# ---------------------------------------------------------------
# 5a-extra. Concentrated noise cluster at one src/dst pair -- crosses the
# low-severity ticket threshold (20+ events) for one more low ticket
# ---------------------------------------------------------------
noise_src = "10.0.4.19"
noise_dst = EXTERNAL_IPS_BENIGN[3]
noise_start = ids_cursor + 100
for i in range(24):
    t = noise_start + i * random.uniform(5, 20)
    lines_ids.append(
        f"{fmt_ids(ts(t))} [**] [1:2001219:1] ET SCAN Potential SSH Scan [**] "
        f"[Classification: Not Suspicious Traffic] [Priority: 3] "
        f"{{TCP}} {noise_src}:{random.randint(1024,65000)} -> {noise_dst}:22"
    )
ids_cursor = int(noise_start + 24 * 20 + 30)

# real malware beacon pattern - periodic C2 checkins
c2_target = EXTERNAL_IPS_MALICIOUS[2]
victim = "10.0.0.11"
beacon_start = ids_cursor + 300
for i in range(10):
    t = beacon_start + i * 62  # ~beacon interval
    lines_ids.append(
        f"{fmt_ids(ts(t))} [**] [1:2024766:2] {attack_sigs[0][1]} [**] "
        f"[Classification: A Network Trojan was Detected] [Priority: 1] "
        f"{{TCP}} {victim}:{random.randint(1024,65000)} -> {c2_target}:443"
    )
ids_cursor = int(beacon_start + 10 * 62 + 30)

# one Log4Shell exploit attempt
lines_ids.append(
    f"{fmt_ids(ts(ids_cursor + 20))} [**] [1:2023924:3] {attack_sigs[1][1]} [**] "
    f"[Classification: Attempted Administrator Privilege Gain] [Priority: 1] "
    f"{{TCP}} {EXTERNAL_IPS_MALICIOUS[3]}:51422 -> 10.0.0.10:443"
)

# SQL injection attempts against DB server
sqli_start = ids_cursor + 200
for i in range(6):
    t = sqli_start + i * random.uniform(2, 10)
    lines_ids.append(
        f"{fmt_ids(ts(t))} [**] [1:2100498:8] {attack_sigs[3][1]} [**] "
        f"[Classification: Web Application Attack] [Priority: 1] "
        f"{{TCP}} {EXTERNAL_IPS_MALICIOUS[0]}:44231 -> 10.0.0.20:3306"
    )

# exfil-looking large outbound transfer alert
lines_ids.append(
    f"{fmt_ids(ts(sqli_start + 400))} [**] [1:2027056:1] {attack_sigs[2][1]} [**] "
    f"[Classification: A Network Trojan was Detected] [Priority: 1] "
    f"{{TCP}} 10.0.0.20:51900 -> {EXTERNAL_IPS_MALICIOUS[1]}:8443"
)
ids_cursor = int(sqli_start + 420)

# ---------------------------------------------------------------
# 5-extra. More IDS variety: second beacon, second Log4Shell target,
# an XSS attempt (new signature type), a second SQLi cluster, second exfil
# ---------------------------------------------------------------
beacon2_target = EXTERNAL_IPS_MALICIOUS[8]
victim2 = "10.0.0.40"
beacon2_start = ids_cursor + 150
for i in range(8):
    t = beacon2_start + i * 55
    lines_ids.append(
        f"{fmt_ids(ts(t))} [**] [1:2024766:2] {attack_sigs[0][1]} [**] "
        f"[Classification: A Network Trojan was Detected] [Priority: 1] "
        f"{{TCP}} {victim2}:{random.randint(1024,65000)} -> {beacon2_target}:443"
    )
ids_cursor = int(beacon2_start + 8 * 55 + 30)

lines_ids.append(
    f"{fmt_ids(ts(ids_cursor + 20))} [**] [1:2023924:3] {attack_sigs[1][1]} [**] "
    f"[Classification: Attempted Administrator Privilege Gain] [Priority: 1] "
    f"{{TCP}} {EXTERNAL_IPS_MALICIOUS[9]}:52210 -> 10.0.0.11:443"
)
ids_cursor += 60

xss_src = EXTERNAL_IPS_MALICIOUS[4]
for i in range(5):
    t = ids_cursor + i * random.uniform(3, 8)
    lines_ids.append(
        f"{fmt_ids(ts(t))} [**] [1:2018961:5] ET WEB_SERVER Possible XSS Attempt in URI [**] "
        f"[Classification: Web Application Attack] [Priority: 1] "
        f"{{TCP}} {xss_src}:41220 -> 10.0.0.10:443"
    )
ids_cursor += 100

sqli2_start = ids_cursor
for i in range(6):
    t = sqli2_start + i * random.uniform(2, 10)
    lines_ids.append(
        f"{fmt_ids(ts(t))} [**] [1:2100498:8] {attack_sigs[3][1]} [**] "
        f"[Classification: Web Application Attack] [Priority: 1] "
        f"{{TCP}} {EXTERNAL_IPS_MALICIOUS[5]}:44890 -> 10.0.0.11:3306"
    )
ids_cursor = int(sqli2_start + 200)

lines_ids.append(
    f"{fmt_ids(ts(ids_cursor + 30))} [**] [1:2027056:1] {attack_sigs[2][1]} [**] "
    f"[Classification: A Network Trojan was Detected] [Priority: 1] "
    f"{{TCP}} 10.0.0.11:52011 -> {EXTERNAL_IPS_MALICIOUS[6]}:8443"
)

# sort each log by embedded timestamp isn't necessary for realism (logs are already
# roughly chronological per-source), write files as-is

with open("logs/firewall.log", "w") as f:
    f.write("\n".join(lines_fw) + "\n")

with open("logs/auth.log", "w") as f:
    f.write("\n".join(lines_auth) + "\n")

with open("logs/ids.log", "w") as f:
    f.write("\n".join(lines_ids) + "\n")

print(f"Generated {len(lines_fw)} firewall lines, {len(lines_auth)} auth lines, {len(lines_ids)} IDS lines")

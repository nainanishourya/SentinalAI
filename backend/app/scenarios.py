import random
from datetime import datetime, timedelta, timezone

USERS = ["jsmith", "a.patel", "svc-backup", "root", "admin", "m.wong", "k.ortiz", "guest"]
INTERNAL_IPS = ["10.0.{}.{}", "172.16.{}.{}", "192.168.{}.{}"]
EXTERNAL_IPS = ["185.220.{}.{}", "45.155.{}.{}", "103.98.{}.{}", "91.240.{}.{}"]


def _ip(pool):
    tpl = random.choice(pool)
    return tpl.format(random.randint(1, 254), random.randint(1, 254))


def _now_seq(n, start_offset_min=0):
    base = datetime.now(timezone.utc) - timedelta(minutes=start_offset_min)
    return [base + timedelta(seconds=i * random.randint(4, 25)) for i in range(n)]


SCENARIOS = [
    {
        "id": "brute_force",
        "name": "SSH Brute Force Login Attempt",
        "category": "Credential Access",
        "severity": "high",
        "mitre": [{"tactic": "Credential Access", "technique_id": "T1110", "technique": "Brute Force"}],
        "build": lambda: _brute_force(),
    },
    {
        "id": "sql_injection",
        "name": "SQL Injection Against Web Application",
        "category": "Initial Access",
        "severity": "critical",
        "mitre": [{"tactic": "Initial Access", "technique_id": "T1190", "technique": "Exploit Public-Facing Application"}],
        "build": lambda: _sql_injection(),
    },
    {
        "id": "ransomware",
        "name": "Ransomware Mass File Encryption",
        "category": "Impact",
        "severity": "critical",
        "mitre": [{"tactic": "Impact", "technique_id": "T1486", "technique": "Data Encrypted for Impact"}],
        "build": lambda: _ransomware(),
    },
    {
        "id": "port_scan",
        "name": "Network Reconnaissance / Port Scan",
        "category": "Reconnaissance",
        "severity": "medium",
        "mitre": [{"tactic": "Reconnaissance", "technique_id": "T1046", "technique": "Network Service Discovery"}],
        "build": lambda: _port_scan(),
    },
    {
        "id": "priv_esc",
        "name": "Privilege Escalation via Token Manipulation",
        "category": "Privilege Escalation",
        "severity": "high",
        "mitre": [{"tactic": "Privilege Escalation", "technique_id": "T1134", "technique": "Access Token Manipulation"}],
        "build": lambda: _priv_esc(),
    },
    {
        "id": "data_exfil",
        "name": "Data Exfiltration Over HTTPS",
        "category": "Exfiltration",
        "severity": "critical",
        "mitre": [{"tactic": "Exfiltration", "technique_id": "T1041", "technique": "Exfiltration Over C2 Channel"}],
        "build": lambda: _data_exfil(),
    },
    {
        "id": "lateral_movement",
        "name": "Lateral Movement via SMB Admin Shares",
        "category": "Lateral Movement",
        "severity": "high",
        "mitre": [{"tactic": "Lateral Movement", "technique_id": "T1021.002", "technique": "SMB/Windows Admin Shares"}],
        "build": lambda: _lateral_movement(),
    },
    {
        "id": "phishing",
        "name": "Phishing Email with Malicious Attachment",
        "category": "Initial Access",
        "severity": "high",
        "mitre": [{"tactic": "Initial Access", "technique_id": "T1566.001", "technique": "Spearphishing Attachment"}],
        "build": lambda: _phishing(),
    },
    {
        "id": "dns_tunneling",
        "name": "DNS Tunneling Command & Control",
        "category": "Command and Control",
        "severity": "high",
        "mitre": [{"tactic": "Command and Control", "technique_id": "T1071.004", "technique": "Application Layer Protocol: DNS"}],
        "build": lambda: _dns_tunnel(),
    },
    {
        "id": "malicious_upload",
        "name": "Masqueraded Executable Upload (Disguised File Type)",
        "category": "Defense Evasion",
        "severity": "high",
        "mitre": [
            {"tactic": "Defense Evasion", "technique_id": "T1036.008", "technique": "Masquerading: Masquerade File Type"},
            {"tactic": "Execution", "technique_id": "T1204.002", "technique": "User Execution: Malicious File"},
        ],
        "build": lambda: _malicious_upload(),
    },
]

_BY_ID = {s["id"]: s for s in SCENARIOS}


def list_scenarios():
    return [{"id": s["id"], "name": s["name"], "category": s["category"], "severity": s["severity"]} for s in SCENARIOS]


def generate_scenario(scenario_id: str | None = None) -> dict:
    scenario = _BY_ID[scenario_id] if scenario_id else random.choice(SCENARIOS)
    logs = scenario["build"]()
    return {
        "scenario_id": scenario["id"],
        "name": scenario["name"],
        "category": scenario["category"],
        "severity": scenario["severity"],
        "ground_truth_mitre": scenario["mitre"],
        "logs": logs,
    }


def _fmt(ts, src, msg):
    return f"[{ts.strftime('%Y-%m-%d %H:%M:%S')}Z] src={src} {msg}"


_BENIGN_TEMPLATES = [
    "auth: successful login for {user} from {ip}",
    "health: service heartbeat OK",
    "proxy: dst={ip} GET /dashboard 200 OK",
    "fw: allowed dst={ip} port 443/tcp (established)",
    "dns: resolved api.internal.corp -> {ip}",
    "backup: nightly backup job completed successfully",
    "edr: scheduled AV signature update applied",
]


def benign_line() -> str:
    tpl = random.choice(_BENIGN_TEMPLATES)
    line = tpl.format(user=random.choice(USERS), ip=_ip(INTERNAL_IPS))
    ts = datetime.now(timezone.utc)
    return _fmt(ts, _ip(INTERNAL_IPS), line)


def _brute_force():
    src = _ip(EXTERNAL_IPS)
    dst = _ip(INTERNAL_IPS)
    user = random.choice(USERS)
    ts = _now_seq(9)
    lines = [_fmt(ts[i], src, f"dst={dst} sshd: Failed password for {user} from {src} port {random.randint(30000,60000)} ssh2") for i in range(8)]
    lines.append(_fmt(ts[8], src, f"dst={dst} sshd: Accepted password for {user} from {src} port {random.randint(30000,60000)} ssh2"))
    return lines


def _sql_injection():
    src = _ip(EXTERNAL_IPS)
    dst = _ip(INTERNAL_IPS)
    ts = _now_seq(5)
    payloads = [
        "GET /product?id=1' UNION SELECT username,password FROM users-- HTTP/1.1",
        "GET /search?q=%27%20OR%20%271%27%3D%271 HTTP/1.1",
        "POST /login body=\"username=admin'--&password=x\" HTTP/1.1",
        "GET /product?id=1 AND SLEEP(5)-- HTTP/1.1",
        "GET /product?id=1;DROP TABLE users;-- HTTP/1.1",
    ]
    return [_fmt(ts[i], src, f"dst={dst} webapp: {payloads[i]} status=200") for i in range(5)]


def _ransomware():
    host = f"WKS-{random.randint(100,999)}"
    ts = _now_seq(7)
    exts = [".docx.locked", ".xlsx.locked", ".pdf.locked", ".jpg.locked"]
    lines = [_fmt(ts[i], host, f"fs-audit: renamed C:\\Users\\{random.choice(USERS)}\\Documents\\file{i}{random.choice(exts)} (mass rename, {random.randint(400,900)} files/min)") for i in range(5)]
    lines.append(_fmt(ts[5], host, "fs-audit: created README_TO_DECRYPT.txt in 14 directories"))
    lines.append(_fmt(ts[6], host, "edr: shadow copy deletion detected - vssadmin delete shadows /all /quiet"))
    return lines


def _port_scan():
    src = _ip(EXTERNAL_IPS)
    dst = _ip(INTERNAL_IPS)
    ts = _now_seq(6)
    ports = random.sample([21, 22, 23, 25, 80, 135, 139, 443, 445, 3389, 8080], 6)
    return [_fmt(ts[i], src, f"dst={dst} firewall: SYN scan probe to port {ports[i]}/tcp flagged (sequential sweep)") for i in range(6)]


def _priv_esc():
    host = f"SRV-{random.randint(100,999)}"
    user = random.choice(USERS)
    ts = _now_seq(4)
    lines = [
        _fmt(ts[0], host, f"auth: {user} added to local Administrators group"),
        _fmt(ts[1], host, f"edr: process token duplication detected for {user} (SeDebugPrivilege enabled)"),
        _fmt(ts[2], host, f"edr: {user} spawned cmd.exe with SYSTEM integrity level"),
        _fmt(ts[3], host, f"auth: {user} accessed HKLM\\SAM registry hive"),
    ]
    return lines


def _data_exfil():
    host = f"WKS-{random.randint(100,999)}"
    dst = _ip(EXTERNAL_IPS)
    ts = _now_seq(5)
    lines = [
        _fmt(ts[0], host, f"dlp: archive created finance_records_{random.randint(1,9)}.zip (312MB)"),
        _fmt(ts[1], host, f"proxy: dst={dst} POST /upload HTTPS 312MB transferred to uncategorized domain"),
        _fmt(ts[2], host, f"proxy: dst={dst} outbound transfer rate anomaly (18x baseline)"),
        _fmt(ts[3], host, "dlp: sensitive data pattern (PII) matched in outbound payload"),
        _fmt(ts[4], host, f"dns: resolved suspicious-file-share-{random.randint(100,999)}.top -> {dst}"),
    ]
    return lines


def _lateral_movement():
    src_host = f"WKS-{random.randint(100,999)}"
    dst_host = f"SRV-{random.randint(100,999)}"
    user = random.choice(USERS)
    ts = _now_seq(5)
    return [
        _fmt(ts[0], src_host, f"smb: {user} authenticated to \\\\{dst_host}\\ADMIN$"),
        _fmt(ts[1], src_host, f"smb: file PsExec64.exe written to \\\\{dst_host}\\ADMIN$\\Temp"),
        _fmt(ts[2], dst_host, f"service: PSEXESVC installed and started remotely by {user}"),
        _fmt(ts[3], dst_host, "edr: lsass.exe memory access from non-standard process"),
        _fmt(ts[4], dst_host, f"auth: new interactive logon for {user} via remote service"),
    ]


def _phishing():
    user = random.choice(USERS)
    ts = _now_seq(4)
    host = f"WKS-{random.randint(100,999)}"
    return [
        _fmt(ts[0], "mail-gw", f"smtp: message to {user}@corp.local, attachment invoice_{random.randint(1000,9999)}.docm, SPF=fail"),
        _fmt(ts[1], host, f"edr: {user} opened invoice_{random.randint(1000,9999)}.docm, macro execution detected"),
        _fmt(ts[2], host, "edr: winword.exe spawned powershell.exe -enc <base64>"),
        _fmt(ts[3], host, f"proxy: dst={_ip(EXTERNAL_IPS)} powershell.exe outbound connection to newly registered domain"),
    ]


def _dns_tunnel():
    host = f"WKS-{random.randint(100,999)}"
    ts = _now_seq(6)
    return [_fmt(ts[i], host, f"dns: query {''.join(random.choices('abcdef0123456789', k=32))}.exfil-c2-{random.randint(10,99)}.net TXT (high entropy subdomain, {200+i*40} bytes)") for i in range(6)]


def _malicious_upload():
    user = random.choice(USERS)
    ts = _now_seq(2)
    host = f"WKS-{random.randint(100,999)}"
    return [
        _fmt(ts[0], host, f"webapp: {user} uploaded file 'holiday_photo.png' declared-type=image/png"),
        _fmt(ts[1], host, "upload-scanner: magic-byte inspection found PE executable header (MZ) inside file declared as PNG - upload rejected"),
    ]

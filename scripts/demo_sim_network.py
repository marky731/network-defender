"""Interactive demo for the simulated network.

Usage:
    PYTHONPATH=src python3 scripts/demo_sim_network.py
"""

from network_scanner.core.models import OSFamily, Protocol, Severity
from network_scanner.rl.sim_network import (
    SimulatedCredential,
    SimulatedHost,
    SimulatedNetwork,
    SimulatedService,
    SimulatedVulnerability,
)
from network_scanner.rl.actions import (
    ActionType,
    NOISE_LEVELS,
    compute_action_mask,
    decode_action,
    encode_action,
)
from network_scanner.rl.rewards import RewardCalculator
from network_scanner.aggregator.vectorizer import ObservationVectorizer
from network_scanner.aggregator.state_builder import StateBuilder

# ── Ağ topolojisi ──────────────────────────────────────────────────────

net = SimulatedNetwork(
    hosts=[
        SimulatedHost(
            ip="192.168.1.10",
            os_family=OSFamily.LINUX,
            os_detail="Ubuntu 22.04",
            value=1.0,
            services=[
                SimulatedService(port=22, protocol=Protocol.TCP,
                                 service_name="ssh", service_version="OpenSSH 8.9",
                                 banner="SSH-2.0-OpenSSH_8.9"),
                SimulatedService(port=80, protocol=Protocol.TCP,
                                 service_name="http", service_version="Apache 2.4",
                                 banner=""),
            ],
            vulnerabilities=[
                SimulatedVulnerability(cve_id="CVE-2023-1111", cvss_score=7.5,
                                      severity=Severity.HIGH, affected_service="ssh",
                                      exploitability_score=6.0),
            ],
            credentials=[
                SimulatedCredential(service="ssh", port=22,
                                    username="admin", password="admin"),
            ],
        ),
        SimulatedHost(
            ip="192.168.1.20",
            os_family=OSFamily.LINUX,
            os_detail="Debian 10",
            value=3.0,  # yüksek değerli DB sunucusu
            services=[
                SimulatedService(port=3306, protocol=Protocol.TCP,
                                 service_name="mysql", service_version="MySQL 5.7",
                                 banner="5.7.42"),
                SimulatedService(port=6379, protocol=Protocol.TCP,
                                 service_name="redis", service_version="Redis 7.0",
                                 banner=""),
            ],
            vulnerabilities=[
                SimulatedVulnerability(cve_id="CVE-2023-2222", cvss_score=9.1,
                                      severity=Severity.CRITICAL,
                                      affected_service="mysql",
                                      exploitability_score=8.0),
            ],
            credentials=[
                SimulatedCredential(service="mysql", port=3306,
                                    username="root", password="root"),
                SimulatedCredential(service="redis", port=6379,
                                    username="", password=""),
            ],
        ),
        SimulatedHost(ip="192.168.1.30", is_alive=False, value=0.0),
    ],
    subnet="192.168.1.0/24",
    seed=42,
)

# ── State ──────────────────────────────────────────────────────────────

ip_list = list(net.hosts.keys())
ip_to_idx = {ip: i for i, ip in enumerate(ip_list)}
discovered = {}  # host_index -> bilgi dict
reward_calc = RewardCalculator()
total_reward = 0.0
detection_level = 0.0
step = 0

ACTION_NAMES = {
    ActionType.DISCOVER_HOST: "DISCOVER_HOST",
    ActionType.PORT_SCAN: "PORT_SCAN",
    ActionType.DETECT_SERVICES: "DETECT_SERVICES",
    ActionType.FINGERPRINT_OS: "FINGERPRINT_OS",
    ActionType.VULN_ASSESS: "VULN_ASSESS",
    ActionType.CHECK_CREDENTIALS: "CHECK_CREDENTIALS",
    ActionType.EXPLOIT: "EXPLOIT",
}


def show_status():
    print(f"\n{'='*60}")
    print(f"  Adım: {step}  |  Toplam Ödül: {total_reward:.3f}  |  Tespit Riski: {detection_level:.3f}")
    print(f"{'='*60}")


def show_discovered():
    print("\n  Keşfedilen bilgiler:")
    if not discovered:
        print("    (henüz hiçbir şey keşfedilmedi)")
        return
    for idx, info in sorted(discovered.items()):
        ip = ip_list[int(idx)]
        parts = [f"    Host {idx} ({ip}):"]
        if info.get("alive"):
            parts.append("alive")
        if "ports" in info:
            parts.append(f"ports={info['ports']}")
        if "services" in info:
            parts.append(f"services={info['services']}")
        if "os_guess" in info:
            parts.append(f"os={info['os_guess']}")
        if "cves" in info:
            parts.append(f"cves={[c['cve_id'] for c in info['cves']]}")
        if "credential_results" in info:
            parts.append(f"creds={len(info['credential_results'])} found")
        if info.get("exploited"):
            parts.append("*** EXPLOITED ***")
        print(" | ".join(parts))


def show_available_actions():
    mask = compute_action_mask(discovered, num_hosts=len(ip_list))
    print("\n  Geçerli aksiyonlar:")
    actions = []
    for action_type in ActionType:
        for host_idx in range(len(ip_list)):
            encoded = encode_action(action_type, host_idx)
            if mask[encoded] == 1.0:
                ip = ip_list[host_idx]
                actions.append((encoded, action_type, host_idx, ip))
                print(f"    [{encoded:4d}] {ACTION_NAMES[action_type]:<20s} -> host {host_idx} ({ip})")
    return actions


def execute_action(action_type, host_idx):
    global total_reward, detection_level, step
    step += 1
    ip = ip_list[host_idx]
    idx_key = str(host_idx)
    is_new = False
    result = {}

    if idx_key not in discovered:
        discovered[idx_key] = {}

    info = discovered[idx_key]

    if action_type == ActionType.DISCOVER_HOST:
        alive = net.host_discover(ip)
        if alive and not info.get("alive"):
            info["alive"] = True
            is_new = True
        print(f"\n  >> DISCOVER {ip}: alive={alive}")

    elif action_type == ActionType.PORT_SCAN:
        ports = net.port_scan(ip)
        if "ports" not in info:
            info["ports"] = ports
            is_new = True
            result["num_ports"] = len(ports)
        print(f"\n  >> PORT_SCAN {ip}: {ports}")

    elif action_type == ActionType.DETECT_SERVICES:
        services = []
        for port in info.get("ports", []):
            svc = net.detect_service(ip, port)
            if svc:
                services.append({"port": port, "name": svc[0], "version": svc[1]})
        if "services" not in info:
            info["services"] = services
            is_new = True
            result["num_services"] = len(services)
        print(f"\n  >> DETECT_SERVICES {ip}: {services}")

    elif action_type == ActionType.FINGERPRINT_OS:
        os_info = net.fingerprint_os(ip)
        if "os_guess" not in info:
            info["os_guess"] = f"{os_info[0].value} {os_info[1]} ({os_info[2]:.0%})" if os_info else "unknown"
            is_new = True
        print(f"\n  >> FINGERPRINT_OS {ip}: {os_info}")

    elif action_type == ActionType.VULN_ASSESS:
        vulns = net.get_vulnerabilities(ip)
        if "cves" not in info:
            info["cves"] = [{"cve_id": v.cve_id, "cvss_score": v.cvss_score} for v in vulns]
            is_new = True
            result["cvss_scores"] = [v.cvss_score for v in vulns]
        print(f"\n  >> VULN_ASSESS {ip}: {[(v.cve_id, v.cvss_score) for v in vulns]}")

    elif action_type == ActionType.CHECK_CREDENTIALS:
        all_creds = []
        for port in info.get("ports", []):
            creds = net.check_credentials(ip, port)
            for c in creds:
                all_creds.append({"service": c.service, "port": c.port, "username": c.username})
        if "credential_results" not in info:
            info["credential_results"] = all_creds
            is_new = True
            result["num_found"] = len(all_creds)
        print(f"\n  >> CHECK_CREDENTIALS {ip}: {all_creds}")

    elif action_type == ActionType.EXPLOIT:
        cves = info.get("cves", [])
        success = False
        for cve in cves:
            if net.attempt_exploit(ip, cve["cve_id"]):
                success = True
                info["exploited"] = True
                break
        is_new = not info.get("was_exploited", False)
        if success:
            info["was_exploited"] = True
        result["success"] = success
        host = net.get_host(ip)
        host_value = host.value if host else 1.0
        print(f"\n  >> EXPLOIT {ip}: success={success} (host value={host_value})")

    noise = NOISE_LEVELS[action_type]
    detection_level += noise

    host = net.get_host(ip)
    host_value = host.value if host else 1.0
    reward = reward_calc.compute(
        action_type=action_type,
        result=result,
        is_new_info=is_new,
        host_value=host_value,
        noise_level=noise,
    )
    total_reward += reward
    print(f"     Ödül: {reward:+.4f}  (yeni bilgi: {is_new}, gürültü: {noise})")


# ── Ana döngü ──────────────────────────────────────────────────────────

print("\n" + "=" * 60)
print("  NETWORK DEFENDER - Simüle Ağ Demo")
print("=" * 60)
print(f"\n  Ağ: {net.subnet}")
print(f"  Host sayısı: {len(net.hosts)}")
for i, ip in enumerate(ip_list):
    h = net.hosts[ip]
    status = "alive" if h.is_alive else "dead"
    svc_count = len(h.services)
    vuln_count = len(h.vulnerabilities)
    print(f"    [{i}] {ip} — {status}, {svc_count} servis, {vuln_count} zafiyet, değer={h.value}")

print("\n  Komutlar:")
print("    Aksiyon numarası girin (köşeli parantez içindeki sayı)")
print("    'q' ile çıkın")

while True:
    show_status()
    show_discovered()
    actions = show_available_actions()

    if detection_level >= 3.0:
        print("\n  *** TESPİT EDİLDİN! Episode bitti. ***")
        break

    try:
        cmd = input("\n  Aksiyon > ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        break

    if cmd.lower() == "q":
        break

    try:
        encoded = int(cmd)
        action_type, host_idx = decode_action(encoded)
        if host_idx >= len(ip_list):
            print("  Geçersiz host index!")
            continue
        execute_action(action_type, host_idx)
    except (ValueError, KeyError):
        print("  Geçersiz komut! Aksiyon numarası veya 'q' girin.")

print(f"\n  Son durum: {step} adım, toplam ödül: {total_reward:.3f}, tespit: {detection_level:.3f}")

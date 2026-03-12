# Faz 1 — Temel Simulasyon Katmani

## Amac

Docker veya gercek ag baglantisindan bagimsiz, saf Python ile calisan bir in-memory ag simulasyonu olusturmak. Bu katman, RL agent'inin milyonlarca adim boyunca hizli egitim yapabilmesinin temelini olusturur.

## Olusturulacak Dosyalar

```
src/network_scanner/rl/__init__.py
src/network_scanner/rl/sim_network.py
src/network_scanner/rl/actions.py
src/network_scanner/rl/rewards.py
tests/unit/test_sim_network.py
tests/unit/test_actions.py
tests/unit/test_rewards.py
```

---

## 1. sim_network.py — In-Memory Ag Simulasyonu

### Dataclass'lar

**SimulatedService**
- `port: int` — servisin calistigi port
- `protocol: Protocol` — TCP/UDP (mevcut `core/models.py`'den)
- `service_name: str` — ornegin "http", "ssh", "mysql"
- `service_version: str` — ornegin "Apache/2.4.41", "OpenSSH_8.9p1"
- `banner: str` — servis banner metni
- `has_ssl: bool` — SSL/TLS aktif mi
- `ssl_self_signed: bool` — self-signed sertifika mi
- `ssl_expired: bool` — suresi dolmus mu

**SimulatedVulnerability**
- `cve_id: str` — ornegin "CVE-2021-41773"
- `cvss_score: float` — 0.0-10.0 arasi
- `severity: Severity` — mevcut `core/models.py`'den (LOW/MEDIUM/HIGH/CRITICAL)
- `affected_service: str` — hangi servisi etkiliyor
- `exploitability_score: float` — 0.0-10.0, exploit basari olasiligi icin kullanilir
- `requires_credential: bool` — exploit icin once credential mi gerekiyor

**SimulatedCredential**
- `service: str` — ornegin "ssh", "mysql", "ftp"
- `port: int` — hangi portta
- `username: str` — ornegin "admin", "root"
- `password: str` — ornegin "admin", "root"

**SimulatedHost**
- `ip: str` — host IP adresi
- `is_alive: bool` — host aktif mi (default True)
- `os_family: OSFamily` — mevcut enum (LINUX/WINDOWS/MACOS/BSD/NETWORK_DEVICE/UNKNOWN)
- `os_detail: str` — ornegin "Ubuntu 20.04"
- `os_confidence: float` — 0.0-1.0
- `services: List[SimulatedService]` — calistirdigi servisler
- `vulnerabilities: List[SimulatedVulnerability]` — zafiyetleri
- `credentials: List[SimulatedCredential]` — varsayilan/zayif sifreler
- `misconfigurations: List[dict]` — yanlis yapilandirmalar
- `reachable_hosts: Set[str]` — bu host'tan erisilebilen diger IP'ler (lateral movement icin)
- `value: float` — host'un onemi (odul hesaplamasinda kullanilir, default 1.0)

### SimulatedNetwork Sinifi

```python
class SimulatedNetwork:
    def __init__(self, hosts: List[SimulatedHost], subnet: str, seed: int = None)
```

**Metodlar:**

| Metod | Girdi | Cikti | Aciklama |
|-------|-------|-------|----------|
| `get_host(ip)` | IP adresi | `SimulatedHost` veya None | Host nesnesini dondurur |
| `get_alive_hosts()` | — | `List[SimulatedHost]` | Aktif host listesi |
| `host_discover(ip)` | IP adresi | `bool` | is_alive dondurur, %5 false-negative sansi |
| `port_scan(ip)` | IP adresi | `List[int]` | Acik port numaralari listesi |
| `detect_service(ip, port)` | IP, port | `(name, version, banner)` veya None | Servis bilgisi |
| `fingerprint_os(ip)` | IP | `(OSFamily, detail, confidence)` veya None | OS tahmini |
| `check_credentials(ip, port)` | IP, port | `List[SimulatedCredential]` | Calisan credential'lar |
| `get_vulnerabilities(ip)` | IP | `List[SimulatedVulnerability]` | Host zafiyetleri |
| `attempt_exploit(ip, cve_id)` | IP, CVE ID | `bool` | Basari olasiligi = exploitability_score / 10.0 |
| `to_host_observation(ip, discovered)` | IP, kesfedilen bilgi dict | `HostObservation` | **StateBuilder.build_host()** ile mevcut modele cevirir |

**Mevcut kodla entegrasyon:**
- `Protocol`, `OSFamily`, `Severity` enum'lari `core/models.py`'den import edilir
- `to_host_observation()` metodu `StateBuilder.build_host()` kullanir
- Cikti, gercek tarayicinin urettigi `HostObservation` ile ayni formatta

---

## 2. actions.py — Aksiyon Uzayi Tanimlari

### ActionType Enum (7 aksiyon)

```python
class ActionType(enum.IntEnum):
    DISCOVER_HOST    = 0  # Layer 1: Host Discovery
    PORT_SCAN        = 1  # Layer 2: Port Scanning
    DETECT_SERVICES  = 2  # Layer 3: Service Detection
    FINGERPRINT_OS   = 3  # Layer 4: OS Fingerprinting
    VULN_ASSESS      = 4  # Layer 5: Vulnerability Assessment
    CHECK_CREDENTIALS = 5 # Layer 5 alt aksiyonu
    EXPLOIT          = 6  # Exploitation
```

### Aksiyon Kodlama

```
aksiyon = aksiyon_tipi * MAX_HOSTS + host_index
MAX_HOSTS = 256 (ObservationVectorizer ile uyumlu)
Toplam aksiyon uzayi = 7 * 256 = 1792 -> Discrete(1792)
```

**Fonksiyonlar:**
- `encode_action(action_type, host_index) -> int`
- `decode_action(action) -> (ActionType, host_index)`

### Gurultu Seviyeleri (Tespit Riski)

```python
NOISE_LEVELS = {
    ActionType.DISCOVER_HOST:     0.01,
    ActionType.PORT_SCAN:         0.05,
    ActionType.DETECT_SERVICES:   0.03,
    ActionType.FINGERPRINT_OS:    0.02,
    ActionType.VULN_ASSESS:       0.04,
    ActionType.CHECK_CREDENTIALS: 0.08,
    ActionType.EXPLOIT:           0.15,
}
```

### Action Masking

`compute_action_mask(discovered_state, num_hosts) -> np.ndarray` shape (1792,)

**Kurallar (saldiri zinciri zorunlulugu):**

| Aksiyon | On Kosul |
|---------|----------|
| DISCOVER_HOST | host_index < num_hosts (her zaman gecerli) |
| PORT_SCAN | host kesfedilmis ve alive |
| DETECT_SERVICES | host port-scan edilmis |
| FINGERPRINT_OS | host port-scan edilmis |
| VULN_ASSESS | host'ta servis tespit edilmis |
| CHECK_CREDENTIALS | servis tespit edilmis + credential-checkable port var (21, 22, 2222, 3306, 5432) |
| EXPLOIT | host'ta zafiyet bulunmus |

---

## 3. rewards.py — Odul Fonksiyonu

### RewardCalculator Sinifi

**Sabit Degerler:**

| Olay | Odul/Ceza |
|------|-----------|
| Her adim maliyeti | -0.01 |
| Yeni host kesfetme | +0.05 |
| Acik port bulma (port basina) | +0.02 |
| Servis versiyonu tespiti | +0.03 |
| OS fingerprint | +0.02 |
| Zafiyet kesfetme | +0.10 * (cvss_score / 10.0) |
| Varsayilan credential bulma | +0.15 |
| Basarili exploit | +0.50 * host.value |
| Basarisiz exploit | -0.05 |
| Tekrarli aksiyon (yeni bilgi yok) | -0.02 |
| Tespit riski | -0.03 * noise_level |

**Ana metod:**

```python
def compute(self, action_type, result, is_new_info, host_value, detection_level) -> float:
    """
    R = base_reward(action, result)
        + novelty_bonus(is_new_info)
        + step_cost
        + detection_penalty
    """
```

**Tasarim mantigi:**
- Kesfetme odulleri agent'i yeni bilgi aramaya tesvik eder
- Host.value ile orantili exploit odulu, stratejik hedef secmeyi ogretir
- Adim maliyeti oyalanmayi onler
- Tekrar cezasi ayni aksiyonu tekrarlamayi caydiriri
- Tespit riski "gizli ol" davranisini ogretir

---

## Testler

### test_sim_network.py (8-10 test)

- `test_create_network_from_hosts` — temel olusturma
- `test_host_discover_alive` — aktif host icin True donmeli
- `test_host_discover_dead` — olme host icin False donmeli
- `test_port_scan_returns_open_ports` — dogru portlari dondurmeli
- `test_detect_service_returns_version` — servis adi ve versiyon
- `test_credential_check_finds_defaults` — varsayilan sifreler bulunmali
- `test_exploit_success_probability` — seed'li RNG ile deterministik test
- `test_to_host_observation_uses_state_builder` — HostObservation dogru olusturulmali
- `test_seed_reproducibility` — ayni seed ayni sonucu vermeli

### test_actions.py (6-8 test)

- `test_encode_decode_roundtrip` — tum aksiyon tipleri icin encode/decode tutarliligi
- `test_action_mask_initial_state` — baslangicta sadece DISCOVER_HOST gecerli
- `test_action_mask_after_discovery` — kesfedince PORT_SCAN acilir
- `test_action_mask_progression` — tam saldiri zinciri acilimi
- `test_invalid_host_index_masked` — aralik disi host index'ler maskelenmeli
- `test_action_space_size` — 7 * 256 = 1792

### test_rewards.py (6-8 test)

- `test_step_cost_always_applied` — her aksiyonda adim maliyeti var
- `test_discovery_reward_positive` — yeni host kesfi pozitif
- `test_redundant_action_penalty` — tekrar negatif
- `test_exploit_success_scaled_by_value` — host degeri ile orantili
- `test_exploit_failure_penalty` — basarisiz exploit cezasi
- `test_detection_penalty` — gurultu seviyesi ile orantili ceza

---

## Kabul Kriterleri

1. Tum testler geciyor: `pytest tests/unit/test_sim_network.py tests/unit/test_actions.py tests/unit/test_rewards.py -v`
2. Mevcut 34 test bozulmamis: `pytest tests/ -q` hala 34 passed
3. `SimulatedNetwork.to_host_observation()` ciktisi, gercek tarayicinin `HostObservation` formatiyla birebir ayni
4. Action mask, gecersiz aksiyonlari %100 engelliyor
5. Odul degerleri makul aralikta (episode basina -5 ile +5 arasi)

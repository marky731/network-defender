# Faz 2 — Gymnasium Ortami ve Senaryolar

## Amac

Faz 1'deki simulasyon, aksiyon ve odul bilesenlerini birlestirerek Gymnasium uyumlu bir RL ortami olusturmak. Agent'in egitim yapabilecegi, partial observability iceren, curriculum learning destekli bir ortam.

## Bagimliliklar

- Faz 1 tamamlanmis olmali (sim_network.py, actions.py, rewards.py)

## Olusturulacak Dosyalar

```
src/network_scanner/rl/env.py
src/network_scanner/rl/scenarios.py
tests/unit/test_env.py
tests/unit/test_scenarios.py
```

---

## 1. env.py — NetworkAttackEnv(gymnasium.Env)

### Uzay Tanimlari

**Observation Space:**
```python
observation_space = gymnasium.spaces.Dict({
    "network_state": gymnasium.spaces.Box(
        low=0.0, high=1.0,
        shape=(256, 47),
        dtype=np.float32,
    ),
    "action_mask": gymnasium.spaces.MultiBinary(1792),
})
```

- `network_state`: Mevcut `ObservationVectorizer` ciktisi. Her satir bir host, 47 feature.
- `action_mask`: 7 aksiyon tipi x 256 host = 1792 bit. Gecerli aksiyonlar 1, geceriz 0.

**Action Space:**
```python
action_space = gymnasium.spaces.Discrete(1792)
```

### Constructor Parametreleri

```python
def __init__(
    self,
    scenario: Optional[dict] = None,  # ag senaryosu konfigurasyonu
    max_steps: int = 300,             # episode basina maks adim
    max_hosts: int = 256,             # maks host sayisi
    detection_threshold: float = 3.0, # tespit esigi
    render_mode: Optional[str] = None,
    seed: Optional[int] = None,
)
```

### Dahili State

| Degisken | Tip | Aciklama |
|----------|-----|----------|
| `_network` | `SimulatedNetwork` | Ground truth — agin gercek durumu |
| `_discovered` | `Dict[str, dict]` | Agent'in kesfettigi bilgiler (IP -> bilgi dict) |
| `_ip_to_index` | `Dict[str, int]` | IP -> host index eslesmesi |
| `_index_to_ip` | `Dict[int, str]` | host index -> IP eslesmesi |
| `_step_count` | `int` | Mevcut adim sayisi |
| `_detection_level` | `float` | Biriken tespit riski |
| `_exploited_hosts` | `Set[str]` | Basariyla exploit edilen host'lar |
| `_total_reward` | `float` | Episode toplam odul |
| `_action_history` | `List[dict]` | Adim adim kayit (web replay icin) |

### reset() Metodu

```python
def reset(self, *, seed=None, options=None) -> Tuple[dict, dict]:
```

1. Senaryo konfigurasyonundan `SimulatedNetwork` uret (veya rastgele)
2. IP -> index eslesmesi olustur
3. `_discovered`, `_detection_level`, `_step_count`, `_exploited_hosts` sifirla
4. Baslangic observation'i dondur:
   - `network_state`: tamamen sifir matris (256, 47) — henuz hicbir sey kesfedilmemis
   - `action_mask`: sadece DISCOVER_HOST aksiyonlari gecerli
5. `info` dict'i dondur (step=0, detection=0, vs.)

### step() Metodu

```python
def step(self, action: int) -> Tuple[dict, float, bool, bool, dict]:
```

**Adim adim akis:**

1. `_step_count += 1`
2. `decode_action(action)` → `(action_type, host_index)`
3. Host index'i IP'ye cevir
4. Action mask kontrolu — gecersiz aksiyon ise:
   - `reward = REDUNDANT_ACTION_PENALTY`
   - State degismiyor, ayni observation donuyor
5. Gecerli aksiyon ise — `_execute_action(action_type, ip)` cagir:
   - SimulatedNetwork uzerinde aksiyonu calistir
   - `_discovered` dict'ini guncelle (yeni bilgi eklenir)
   - `(result_dict, is_new_info)` dondur
6. Tespit riskini guncelle: `_detection_level += NOISE_LEVELS[action_type]`
7. Odul hesapla: `RewardCalculator.compute(...)`
8. `_action_history`'ye kaydet
9. Termination kontrolleri:
   - `terminated = True` eger:
     - `_detection_level >= detection_threshold` (yakalandi!)
     - `_all_objectives_met()` (tum yuksek degerli host'lar exploit edildi)
   - `truncated = True` eger:
     - `_step_count >= max_steps`
10. Observation olustur: `_get_observation()`
11. Dondur: `(obs, reward, terminated, truncated, info)`

### _get_observation() — Kritik Entegrasyon Noktasi

Bu metod mevcut kodu tam olarak yeniden kullanir:

```
_discovered dict
    |
    v
StateBuilder.build_host() -- her kesfedilen host icin HostObservation olustur
    |
    v
StateBuilder.build_network() -- tum host'lari NetworkObservation'a birlesir
    |
    v
ObservationVectorizer.vectorize() -- (256, 47) float32 matris uretir
    |
    v
action_mask ile birlikte Dict observation dondurulur
```

Bu sayede RL ortaminin gozlem formati, gercek tarayicinin urettigi formatla **birebir ayni** kalir.

### _execute_action() — Aksiyon Dispatcher

| ActionType | SimulatedNetwork Metodu | _discovered Guncellemesi |
|------------|------------------------|-------------------------|
| DISCOVER_HOST | `host_discover(ip)` | `{ip: {"is_alive": True/False}}` |
| PORT_SCAN | `port_scan(ip)` | `discovered[ip]["ports"]` guncellenir |
| DETECT_SERVICES | `detect_service(ip, port)` — her acik port icin | `discovered[ip]["services"]` guncellenir |
| FINGERPRINT_OS | `fingerprint_os(ip)` | `discovered[ip]["os_guess"]` guncellenir |
| VULN_ASSESS | `get_vulnerabilities(ip)` | `discovered[ip]["cves"]` guncellenir |
| CHECK_CREDENTIALS | `check_credentials(ip, port)` | `discovered[ip]["credential_results"]` guncellenir |
| EXPLOIT | `attempt_exploit(ip, cve_id)` | `_exploited_hosts`'a eklenir |

### _all_objectives_met()

Senaryo konfigurasyonunda belirli "hedef" host'lar tanimlanir (yuksek `value` degerine sahip host'lar). Tumu exploit edildiginde episode basariyla biter.

Varsayilan: `value >= 2.0` olan tum host'lar exploit edilmis olmali.

### render()

- `render_mode="human"`: terminale adim ozeti yazdirir
- `render_mode="json"`: adim bilgisini JSON olarak dondurur (web replay icin)

---

## 2. scenarios.py — Senaryo Uretici

### SIM_SERVICE_TEMPLATES

`lab/lab_generator.py`'daki 8 servis sablonunu genisletir:

```python
SIM_SERVICE_TEMPLATES = {
    "web-apache": {
        "services": [
            SimulatedService(port=80, protocol=Protocol.TCP,
                           service_name="http", service_version="Apache/2.4.41",
                           banner="HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n"),
        ],
        "vulns": [
            SimulatedVulnerability(cve_id="CVE-2021-41773", cvss_score=7.5,
                                  severity=Severity.HIGH, affected_service="http",
                                  exploitability_score=6.5),
        ],
        "credentials": [],
        "os": OSFamily.LINUX,
        "os_detail": "Ubuntu 20.04",
        "value": 1.0,
    },
    "ssh-server": {
        "services": [
            SimulatedService(port=2222, protocol=Protocol.TCP,
                           service_name="ssh", service_version="OpenSSH_8.9p1",
                           banner="SSH-2.0-OpenSSH_8.9p1\r\n"),
        ],
        "vulns": [],
        "credentials": [
            SimulatedCredential(service="ssh", port=2222,
                              username="admin", password="admin"),
        ],
        "os": OSFamily.LINUX,
        "os_detail": "Ubuntu 22.04",
        "value": 1.5,  # SSH erisimi degerli
    },
    "mysql-server": {
        "services": [
            SimulatedService(port=3306, protocol=Protocol.TCP,
                           service_name="mysql", service_version="MySQL 5.7.42",
                           banner="J\x00\x00\x005.7.42\x00"),
        ],
        "vulns": [
            SimulatedVulnerability(cve_id="CVE-2020-14812", cvss_score=4.9,
                                  severity=Severity.MEDIUM, affected_service="mysql",
                                  exploitability_score=3.0),
        ],
        "credentials": [
            SimulatedCredential(service="mysql", port=3306,
                              username="root", password="root"),
        ],
        "os": OSFamily.LINUX,
        "os_detail": "Debian 10",
        "value": 3.0,  # Veritabani sunucusu yuksek degerli
    },
    # ... web-nginx, ftp-server, postgres-server, redis-server, mongodb-server
}
```

### generate_random_scenario()

```python
def generate_random_scenario(
    num_hosts: int = 6,
    seed: int = 42,
    difficulty: str = "medium",
) -> SimulatedNetwork:
```

- `lab_generator.generate_random_lab()` ile ayni mantik, ama Docker Compose yerine `SimulatedNetwork` uretir
- Difficulty seviyesine gore zafiyet ve credential sayisi ayarlanir
- Her host'un `reachable_hosts`'u rastgele atanir (ag topolojisi)
- Seed ile tam reproducibility

### Curriculum Seviyeleri

```python
CURRICULUM_SCENARIOS = {
    "tiny":   {"num_hosts": 3,  "max_vulns": 2,  "max_creds": 1},
    "small":  {"num_hosts": 6,  "max_vulns": 5,  "max_creds": 3},
    "medium": {"num_hosts": 10, "max_vulns": 10, "max_creds": 5},
    "large":  {"num_hosts": 15, "max_vulns": 15, "max_creds": 8},
}
```

### Hazir Senaryolar (test ve demo icin)

```python
def create_demo_scenario() -> SimulatedNetwork:
    """lab/docker-compose.yml'deki 6 host'luk statik lab'in birebir simulasyonu."""
```

Bu senaryo, mevcut Docker lab ile ayni yapiyi kullanir (apache, nginx, ssh, ftp, mysql, redis @ 172.30.0.0/24). Gercek lab ile simulasyon karsilastirmasi yapmak icin ideal.

---

## Testler

### test_env.py (10-12 test)

- `test_env_creation` — hatasiz olusturma
- `test_reset_returns_zero_observation` — baslangic matrisi tamamen sifir
- `test_observation_shape` — network_state (256,47), action_mask (1792,)
- `test_step_valid_action` — DISCOVER_HOST ile adim atilabilir
- `test_step_invalid_action` — maskelenmis aksiyon ceza dondurur
- `test_partial_observability` — kesfedilmemis host'lar observation'da sifir
- `test_progressive_discovery` — kesfettikce observation doluyor
- `test_action_mask_updates_after_step` — kesfedince yeni aksiyonlar aciliyor
- `test_episode_terminates_on_detection` — tespit esigi asilinca terminated=True
- `test_episode_truncates_on_max_steps` — max adim asilinca truncated=True
- `test_episode_terminates_on_success` — tum hedefler exploit edilince terminated=True
- `test_gymnasium_check_env` — `gymnasium.utils.env_checker.check_env()` geciyor
- `test_vectorizer_integration` — observation ObservationVectorizer ile uyumlu

### test_scenarios.py (4-5 test)

- `test_generate_random_scenario` — hatasiz uretim
- `test_scenario_host_count` — istenen sayi kadar host
- `test_scenario_seed_reproducibility` — ayni seed ayni ag
- `test_curriculum_scenarios_valid` — tum seviyeler gecerli ag uretiyor
- `test_demo_scenario_matches_lab` — demo senaryosu Docker lab ile ayni yapilar

---

## Kabul Kriterleri

1. `gymnasium.utils.env_checker.check_env(NetworkAttackEnv())` hatasiz geciyor
2. Bir episode baslatilip 50+ adim atilabildigi dogrulanir
3. Observation formati ObservationVectorizer ciktisiyla birebir ayni
4. Partial observability calisiyor — kesfedilmemis host'lar gozlemde sifir
5. Action mask dogru calisiyor — gecersiz aksiyonlar engelliyor
6. Curriculum senaryolari dogru zorluk kademesinde
7. Tum yeni testler + mevcut 34 test geciyor

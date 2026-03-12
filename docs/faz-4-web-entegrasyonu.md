# Faz 4 — Web Entegrasyonu ve RL Agent Replay

## Amac

Egitilmis RL agent'inin kararlarini mevcut web arayuzunde canli olarak gorsellestirmek. Kullanici tarayicidan bir senaryo secer, agent episode'u oynar, adim adim SSE ile izlenir.

## Bagimliliklar

- Faz 1, 2 ve 3 tamamlanmis olmali
- En az bir egitilmis model dosyasi mevcut olmali

## Degistirilecek / Olusturulacak Dosyalar

```
web/app.py          # Degistirilecek — yeni endpoint'ler eklenir
web/index.html      # Degistirilecek — RL replay UI eklenir
```

---

## 1. web/app.py — Yeni Endpoint'ler

Mevcut SSE progress pattern'i (`/api/scans/{scan_id}/progress`) temel alinir. Ayni event-driven mimari RL replay icin yeniden kullanilir.

### POST /api/rl/run-agent

Egitilmis modeli yukler, belirtilen senaryoda bir episode calistirir.

**Request:**
```json
{
    "model_path": "models/final/ppo_network_attack",
    "scenario": "small",
    "seed": 42
}
```

**Response:**
```json
{
    "run_id": "abc12345"
}
```

**Arka plan islemi:**
1. MaskablePPO modelini yukle
2. NetworkAttackEnv olustur (senaryo parametreleri ile)
3. Episode calistir (step by step)
4. Her adimi progress listesine event olarak ekle
5. Episode bitince "done" event'i gonder

### GET /api/rl/run-agent/{run_id}/progress

SSE stream — mevcut `scan_progress` endpoint'inin birebir aynisi, ama RL agent adimlari icin.

**Event turleri:**

```
# Episode basladi
data: {"type": "episode_start", "scenario": "small", "num_hosts": 6}

# Agent bir aksiyon aldi
data: {
    "type": "agent_step",
    "step": 1,
    "action_type": "DISCOVER_HOST",
    "target_ip": "192.168.1.10",
    "result": "alive",
    "reward": 0.04,
    "cumulative_reward": 0.04,
    "detection_level": 0.01,
    "hosts_discovered": 1,
    "hosts_exploited": 0,
    "new_info": true
}

# Agent bir host'u exploit etti
data: {
    "type": "agent_step",
    "step": 42,
    "action_type": "EXPLOIT",
    "target_ip": "192.168.1.12",
    "result": "success",
    "reward": 1.5,
    "cumulative_reward": 3.21,
    "detection_level": 1.83,
    "hosts_discovered": 5,
    "hosts_exploited": 2,
    "new_info": true
}

# Episode bitti
data: {
    "type": "episode_done",
    "reason": "objective_met",
    "total_steps": 87,
    "total_reward": 4.56,
    "hosts_discovered": 5,
    "hosts_exploited": 3,
    "detection_level": 2.14,
    "success": true
}
```

### GET /api/rl/models

Mevcut egitilmis modelleri listeler.

**Response:**
```json
[
    {
        "name": "ppo_network_attack",
        "path": "models/final/ppo_network_attack",
        "created_at": "2026-03-05T14:30:00Z",
        "scenario": "medium",
        "timesteps": 1000000
    }
]
```

### GET /api/rl/scenarios

Mevcut senaryolari listeler.

**Response:**
```json
{
    "tiny":   {"num_hosts": 3,  "description": "3 host, 2 zafiyet — isinma"},
    "small":  {"num_hosts": 6,  "description": "6 host, 5 zafiyet — temel"},
    "medium": {"num_hosts": 10, "description": "10 host, 10 zafiyet — orta"},
    "large":  {"num_hosts": 15, "description": "15 host, 15 zafiyet — ileri"}
}
```

---

## 2. web/index.html — RL Replay UI

Mevcut scan UI'ina ek olarak bir "RL Agent" sekmesi eklenir.

### UI Bilesenleri

**Kontrol Paneli:**
- Model secici (dropdown)
- Senaryo secici (dropdown)
- "Agent'i Calistir" butonu
- Replay hizi kontrolu (1x, 2x, 5x, 10x)

**Canli Gorsellestirme:**
- Ag topolojisi (basit grid veya graph gorunumu)
  - Host'lar daire olarak gosterilir
  - Renk kodlari:
    - Gri: kesfedilmemis
    - Mavi: kesfedilmis (alive)
    - Turuncu: taranmis (servisler tespit edilmis)
    - Kirmizi: zafiyet bulunmus
    - Yesil: exploit edilmis
- Adim sayaci ve progress bar
- Detection level bar (esige yaklastikca kirmizilasir)
- Odul grafigi (adim adim kumulatif odul)

**Aksiyon Log'u:**
- Tablo formatinda:
  - Adim # | Aksiyon | Hedef IP | Sonuc | Odul | Tespit
- Her yeni adimda otomatik scroll
- Onemli aksiyonlar vurgulanir (exploit basarisi = yesil, yakalanma = kirmizi)

**Episode Ozeti (bittikten sonra):**
- Basari/Basarisizlik durumu
- Toplam adim, toplam odul
- Kesfedilen/exploit edilen host sayisi
- Aksiyon dagilimi (pasta grafik)
- Tespit seviyesi

### SSE Baglantisi

Mevcut scan SSE pattern'i aynen kullanilir:

```javascript
const evtSource = new EventSource(`/api/rl/run-agent/${runId}/progress`);

evtSource.onmessage = function(event) {
    const data = JSON.parse(event.data);

    switch(data.type) {
        case 'episode_start':
            initializeNetworkView(data.num_hosts);
            break;
        case 'agent_step':
            updateHostColor(data.target_ip, data.action_type);
            appendActionLog(data);
            updateRewardChart(data.step, data.cumulative_reward);
            updateDetectionBar(data.detection_level);
            break;
        case 'episode_done':
            showEpisodeSummary(data);
            evtSource.close();
            break;
    }
};
```

---

## 3. Replay Hizi Kontrolu

Agent kararlarini hizli gormek icin replay hizi ayarlanabilir:

```python
# web/app.py — agent calistirma icinde
async def _run_agent_episode(run_id, model, env, speed=1.0):
    obs, info = env.reset()
    done = False

    while not done:
        action, _ = model.predict(obs, action_masks=env.action_masks())
        obs, reward, terminated, truncated, info = env.step(action)
        done = terminated or truncated

        # Adimi progress listesine ekle
        progress.append({
            "type": "agent_step",
            "step": info["step"],
            ...
        })

        # Replay hizina gore bekle (1x = 0.5s, 2x = 0.25s, 10x = 0.05s)
        await asyncio.sleep(0.5 / speed)
```

---

## Kabul Kriterleri

1. `POST /api/rl/run-agent` ile episode baslatilabiliyor
2. SSE stream adim adim event gonderiyor
3. `GET /api/rl/models` mevcut modelleri listeliyor
4. Web UI'da ag topolojisi gorsellestiriliyor
5. Host renkleri aksiyonlara gore degisiyor
6. Detection bar gercek zamanli guncelleniyor
7. Episode ozeti dogru metrikleri gosteriyor
8. Mevcut scan fonksiyonalitesi bozulmamis
9. Birden fazla episode art arda calistirabilir

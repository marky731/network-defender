# Faz 3 — Egitim Altyapisi ve Wrappers

## Amac

NetworkAttackEnv uzerine SB3-uyumlu wrapper'lar eklemek ve MaskablePPO ile egitim scripti olusturmak. Agent'in kucuk aglardan buyuk aglara dogru kademeli olarak ogrenebilecegi bir egitim pipeline'i kurmak.

## Bagimliliklar

- Faz 1 ve Faz 2 tamamlanmis olmali
- Yeni Python paketleri gerekli

## Olusturulacak / Degistirilecek Dosyalar

```
src/network_scanner/rl/wrappers.py         # Yeni
scripts/train_ppo.py                        # Yeni
scripts/evaluate_agent.py                   # Yeni
requirements.txt                            # Degistirilecek
```

---

## 1. requirements.txt Guncellemesi

Mevcut dosyaya eklenecek satirlar:

```
# RL training
stable-baselines3>=2.2.0
sb3-contrib>=2.2.0
tensorboard>=2.14.0
```

`gymnasium>=0.29.0` zaten mevcut.

---

## 2. wrappers.py — Gymnasium Wrapper'lari

### ActionMaskWrapper

SB3-contrib'in MaskablePPO'su `action_masks()` metodu bekler. Bu wrapper, Dict observation'daki `action_mask` anahtarini bu metoda baglar.

```python
class ActionMaskWrapper(gymnasium.Wrapper):
    """MaskablePPO icin action_masks() metodu saglar."""

    def action_masks(self) -> np.ndarray:
        """Son observation'daki action_mask'i dondur."""
        return self._last_obs["action_mask"]

    def reset(self, **kwargs):
        obs, info = self.env.reset(**kwargs)
        self._last_obs = obs
        return obs, info

    def step(self, action):
        obs, reward, terminated, truncated, info = self.env.step(action)
        self._last_obs = obs
        return obs, reward, terminated, truncated, info
```

### CurriculumWrapper

Agent'in basari oranini takip eder, belirli bir esik asildiginda zorlugu arttirir.

```python
class CurriculumWrapper(gymnasium.Wrapper):
    """Basari oranina gore zorluk kademesi arttirir."""

    LEVELS = ["tiny", "small", "medium", "large"]

    def __init__(self, env, advancement_threshold: float = 0.7,
                 window_size: int = 100):
        super().__init__(env)
        self._threshold = advancement_threshold
        self._window_size = window_size
        self._current_level = 0
        self._episode_results: List[bool] = []  # True = basarili, False = basarisiz

    def step(self, action):
        obs, reward, terminated, truncated, info = self.env.step(action)

        if terminated or truncated:
            success = info.get("objective_met", False)
            self._episode_results.append(success)

            # Son N episode'un basari oranini kontrol et
            if len(self._episode_results) >= self._window_size:
                recent = self._episode_results[-self._window_size:]
                success_rate = sum(recent) / len(recent)

                if success_rate >= self._threshold and self._current_level < len(self.LEVELS) - 1:
                    self._current_level += 1
                    self._episode_results.clear()
                    # Bir sonraki seviyeye gec
                    # env'in scenario parametresini guncelle

        return obs, reward, terminated, truncated, info
```

### EpisodeRecorderWrapper

Web UI'da replay icin episode adimlarini kaydeder.

```python
class EpisodeRecorderWrapper(gymnasium.Wrapper):
    """Episode trajectory'sini JSON-serializable formatta kaydeder."""

    def __init__(self, env, save_dir: str = "./recordings"):
        super().__init__(env)
        self._save_dir = Path(save_dir)
        self._current_episode: List[dict] = []

    def step(self, action):
        obs, reward, terminated, truncated, info = self.env.step(action)

        self._current_episode.append({
            "step": info.get("step", 0),
            "action": int(action),
            "action_type": info.get("action_type", ""),
            "target_ip": info.get("target_ip", ""),
            "reward": float(reward),
            "cumulative_reward": info.get("total_reward", 0),
            "detection_level": info.get("detection_level", 0),
            "hosts_discovered": info.get("hosts_discovered", 0),
            "hosts_exploited": info.get("hosts_exploited", 0),
        })

        if terminated or truncated:
            self._save_episode()
            self._current_episode = []

        return obs, reward, terminated, truncated, info

    def _save_episode(self):
        """Episode'u JSON dosyasina kaydet."""
        ...
```

---

## 3. scripts/train_ppo.py — Egitim Scripti

### Komut Satiri Parametreleri

```
python3 scripts/train_ppo.py \
    --timesteps 1000000 \
    --num-envs 8 \
    --scenario small \
    --learning-rate 3e-4 \
    --batch-size 64 \
    --output-dir ./models \
    --log-dir ./logs \
    --eval-freq 10000 \
    --seed 42
```

### Egitim Akisi

```python
def train(args):
    # 1. Paralel ortamlar olustur
    def make_env(rank):
        def _init():
            env = NetworkAttackEnv(
                scenario=CURRICULUM_SCENARIOS[args.scenario],
                max_steps=300,
                seed=args.seed + rank,
            )
            env = ActionMaskWrapper(env)
            return env
        return _init

    vec_env = SubprocVecEnv([make_env(i) for i in range(args.num_envs)])

    # 2. Degerlendirme ortami
    eval_env = NetworkAttackEnv(
        scenario=CURRICULUM_SCENARIOS[args.scenario],
        seed=999,
    )
    eval_env = ActionMaskWrapper(eval_env)

    # 3. Model olustur
    model = MaskablePPO(
        "MultiInputPolicy",       # Dict observation icin
        vec_env,
        learning_rate=args.learning_rate,
        n_steps=2048,
        batch_size=args.batch_size,
        n_epochs=10,
        gamma=0.99,                # Uzun vadeli odulleri degerlendir
        gae_lambda=0.95,
        clip_range=0.2,
        ent_coef=0.01,             # Kesfetmeyi tesvik et
        vf_coef=0.5,
        max_grad_norm=0.5,
        verbose=1,
        tensorboard_log=args.log_dir,
    )

    # 4. Callback'ler
    callbacks = CallbackList([
        EvalCallback(
            eval_env,
            best_model_save_path=f"{args.output_dir}/best",
            log_path=f"{args.log_dir}/eval",
            eval_freq=args.eval_freq,
            n_eval_episodes=20,
        ),
        CheckpointCallback(
            save_freq=50000,
            save_path=f"{args.output_dir}/checkpoints",
            name_prefix="ppo_network_attack",
        ),
    ])

    # 5. Egitim
    model.learn(
        total_timesteps=args.timesteps,
        callback=callbacks,
        progress_bar=True,
    )

    # 6. Final modeli kaydet
    model.save(f"{args.output_dir}/final/ppo_network_attack")
    print(f"Model kaydedildi: {args.output_dir}/final/ppo_network_attack")
```

### Hiperparametre Secimi Gerekceleri

| Parametre | Deger | Gerekce |
|-----------|-------|---------|
| `learning_rate` | 3e-4 | PPO icin standart, stabil ogrenme |
| `n_steps` | 2048 | Episode uzunlugu (300) * ~7 = yeterli ornek |
| `batch_size` | 64 | GPU memory'ye uygun, iyi gradient estimation |
| `n_epochs` | 10 | Her batch uzerinde 10 guncelleme |
| `gamma` | 0.99 | Uzun episode'lar icin uzun vadeli deger |
| `ent_coef` | 0.01 | Kesfetme bonusu — cok yuksekse rastgele davranir |
| `num_envs` | 8 | Paralel calisma ile ~8x hizlanma |

---

## 4. scripts/evaluate_agent.py — Degerlendirme Scripti

### Komut Satiri Parametreleri

```
python3 scripts/evaluate_agent.py \
    --model ./models/final/ppo_network_attack \
    --scenario medium \
    --episodes 100 \
    --render \
    --seed 123
```

### Cikti Metrikleri

| Metrik | Aciklama |
|--------|----------|
| Success Rate | Hedefleri basariyla exploit etme orani |
| Avg Episode Length | Ortalama adim sayisi |
| Avg Reward | Ortalama episode odulu |
| Discovery Rate | Kesfedilen host orani |
| Detection Rate | Yakalanma orani |
| Action Distribution | Hangi aksiyonlar ne siklikta kullaniliyor |
| Exploit Efficiency | Exploit denemesi / basarili exploit orani |

### Ornek Cikti

```
=== Evaluation Results (100 episodes, scenario=medium) ===
Success Rate:       72.0%
Avg Episode Length:  187.3 steps
Avg Reward:          2.34
Discovery Rate:      89.5%
Detection Rate:      15.0%
Action Distribution:
  DISCOVER_HOST:     18.2%
  PORT_SCAN:         22.1%
  DETECT_SERVICES:   16.4%
  FINGERPRINT_OS:     8.3%
  VULN_ASSESS:       14.7%
  CHECK_CREDENTIALS:  9.8%
  EXPLOIT:           10.5%
```

---

## Egitim Stratejisi

### Faz A: Isitma (Foundation)

```
Senaryo: tiny (3 host, 2 zafiyet)
Timestep: 200K
Hedef: Temel aksiyon-durum iliskisini ogren
       (kesif -> tarama -> exploit zinciri)
```

### Faz B: Temel Ogrenme

```
Senaryo: small (6 host, 5 zafiyet)
Timestep: 500K
Hedef: Birden fazla host arasinda strateji gelistir
       Hangi host'u once taramali? En degerli hedefi sec.
```

### Faz C: Zorluk Artisi

```
Senaryo: medium (10 host, 10 zafiyet)
Timestep: 1M
Hedef: Buyuk ag'da verimli kesfetme
       Tespit riskini yonetme (gizli kalma)
```

### Faz D: Saglamilik (Robustness)

```
Senaryo: large (15 host, 15 zafiyet) + rastgele ag'lar
Timestep: 2M+
Hedef: Farkli ag topolojilerinde genellestirme
       Daha once gormedigi ag'larda basarili olma
```

### TensorBoard ile Izleme

```bash
tensorboard --logdir ./logs
```

Izlenecek metrikler:
- `rollout/ep_rew_mean` — ortalama episode odulu (yukseliyor mu?)
- `rollout/ep_len_mean` — ortalama episode uzunlugu (kisaliyor mu?)
- `train/entropy_loss` — kesfetme duzeyi (cok duserse stuck)
- `eval/mean_reward` — degerlendirme odulu (egitim reward'dan daha guveniir)

---

## Kabul Kriterleri

1. `requirements.txt` guncellenmis, `pip install -r requirements.txt` hatasiz
2. `python3 scripts/train_ppo.py --timesteps 10000 --num-envs 2 --scenario tiny` hatasiz tamamlaniyor (smoke test)
3. Model dosyasi kaydediliyor ve yuklenebiliyor
4. `python3 scripts/evaluate_agent.py --model ... --episodes 10` hatasiz calisiyor
5. TensorBoard log'lari olusturuluyor
6. CurriculumWrapper zorluk kademesini dogru arttiriyor
7. EpisodeRecorderWrapper JSON dosyalari uretiyor
8. Mevcut 34 test + Faz 1-2 testleri hala geciyor

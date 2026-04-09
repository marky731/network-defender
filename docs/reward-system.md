# Reward Sistemi

RL ajaninin her adimda aldigi sayisal geri bildirim. Ajan bu sinyali maksimize etmeye calisarak tarama stratejisi gelistirir.

---

## Hesaplama Akisi

Her adimda `RewardCalculator.compute()` su sirayla calisir:

```
1. reward = -0.01                          (sabit adim maliyeti)
2. reward += -0.03 x noise_level           (tespit riski cezasi)
3. Eger ayni bilgiyi tekrar kesfettiysen:
     reward += -0.02                       (redundancy cezasi)
     RETURN
4. Aksiyon tipine gore odul ekle
     RETURN
```

---

## Sabit Maliyetler

Her adimda iki sabit maliyet uygulanir.

### Adim Maliyeti (STEP_COST = -0.01)

Her aksiyonda zaman geciyor. Bu maliyet ajani gereksiz adim atmaktan caydirir. 300 adimlik bir episode'da hicbir sey yapmasan bile -3.0 toplanir.

### Tespit Riski (DETECTION_RISK_FACTOR = -0.03 x noise_level)

Her aksiyonun bir gurultu seviyesi vardir:

| Aksiyon           | Gurultu | Ceza    |
|-------------------|---------|---------|
| DISCOVER_HOST     | 0.01    | -0.0003 |
| PORT_SCAN         | 0.05    | -0.0015 |
| DETECT_SERVICES   | 0.03    | -0.0009 |
| FINGERPRINT_OS    | 0.02    | -0.0006 |
| VULN_ASSESS       | 0.04    | -0.0012 |
| CHECK_CREDENTIALS | 0.08    | -0.0024 |
| EXPLOIT           | 0.15    | -0.0045 |

Kucuk sayilar ama birikim yapar. 20 exploit denemesi = -0.09 sadece gurultu cezasindan.

---

## Redundancy Cezasi (REDUNDANT_ACTION_PENALTY = -0.02)

Eger `is_new_info=False` ise, yani daha once ayni bilgiyi kesfetmissen, adim maliyeti + tespit riski + redundancy cezasi alinir ve baska odul eklenmeden geri donulur.

Ornek — Host 0'i iki kez discover etmek:

```
Ilk:    -0.01 + (-0.0003) + 0.05     = +0.0397  (yeni bilgi odulu)
Tekrar: -0.01 + (-0.0003) + (-0.02)  = -0.0303  (ceza)
```

---

## Aksiyon Odulleri

Sadece yeni bilgi kesfedildiginde (is_new_info=True) uygulanir.

### DISCOVER_HOST: +0.05

Sabit. Yeni bir host kesfedildi.

```
Net: -0.01 + (-0.0003) + 0.05 = +0.0397
```

### PORT_SCAN: +0.02 x port_sayisi

Bulunan port sayisiyla orantili. 5 port bulan tarama 1 port bulandan daha degerli.

```
3 port: -0.01 + (-0.0015) + 0.02x3 = +0.0485
1 port: -0.01 + (-0.0015) + 0.02x1 = +0.0085
```

### DETECT_SERVICES: +0.03 x servis_sayisi

Port scan'e gore biraz daha degerli cunku daha detayli bilgi iceriyor.

```
2 servis: -0.01 + (-0.0009) + 0.03x2 = +0.0491
```

### FINGERPRINT_OS: +0.02

Sabit. OS bilgisi tek bir veri noktasi.

```
Net: -0.01 + (-0.0006) + 0.02 = +0.0094
```

### VULN_ASSESS: +0.10 x toplam(cvss/10)

CVSS skoruyla olceklenir. Kritik zafiyet (9.0) dusuk zafiyetten (3.0) 3 kat daha degerli.

```
CVE-A (cvss=9.0) + CVE-B (cvss=4.0):
  -0.01 + (-0.0012) + 0.10x(0.9+0.4) = +0.1188

Tek CVE (cvss=2.0):
  -0.01 + (-0.0012) + 0.10x0.2       = +0.0088
```

### CHECK_CREDENTIALS: +0.15 x bulunan_sayisi

Yuksek odul cunku calisan credential exploit'suz erisim demek.

```
2 credential: -0.01 + (-0.0024) + 0.15x2 = +0.2876
0 credential: -0.01 + (-0.0024) + 0.15x0 = -0.0124
```

### EXPLOIT (basarili): +0.50 x host_value

En buyuk odul. Host degeriyle carpilir. DB sunucusu (value=3.0) masaustunden (value=1.0) 3 kat daha degerli.

```
DB sunucusu: -0.01 + (-0.0045) + 0.50x3.0 = +1.4855
Normal host: -0.01 + (-0.0045) + 0.50x1.0 = +0.4855
```

### EXPLOIT (basarisiz): -0.05

Gurultu yapildi ama bir sey elde edilemedi.

```
Net: -0.01 + (-0.0045) + (-0.05) = -0.0645
```

---

## Episode Ornegi

```
Adim  Aksiyon                    Yeni?  Odul     Toplam
----  -------------------------  -----  -------  ------
1     DISCOVER host_0            evet   +0.040   0.040
2     DISCOVER host_1            evet   +0.040   0.079
3     PORT_SCAN host_0 (3 port)  evet   +0.049   0.128
4     PORT_SCAN host_0 (tekrar)  hayir  -0.032   0.096
5     DETECT_SVC host_0 (2 svc)  evet   +0.049   0.145
6     VULN host_0 (cvss=7.5)     evet   +0.064   0.209
7     EXPLOIT host_0 (basarili)  evet   +0.486   0.694
8     EXPLOIT host_0 (tekrar)    hayir  -0.035   0.660
```

---

## Odullerin Ajan Davranisina Etkisi

| Tasarim karari                       | Ajani neye yonlendiriyor              |
|--------------------------------------|---------------------------------------|
| Step cost negatif                    | Gereksiz adim atma, hizli ol          |
| Gurultu cezasi exploit'ta en yuksek  | Exploit'u son care olarak kullan      |
| Redundancy cezasi                    | Ayni seyi iki kez deneme              |
| Port/servis sayiyla orantili         | Zengin host'lari tercih et            |
| CVSS ile olcekleme                   | Kritik zafiyetlere odaklan            |
| Host value carpani                   | Degerli hedefleri oncelikle exploit et|
| Credential odulu yuksek              | Credential portlari olan host'lari tara|
| Basarisiz exploit cezali             | Exploitability dusukse deneme         |

---

## Bilinen Eksiklikler

Ajan biriken toplam `detection_level` degerini observation'da goremiyor. 256x47 array'de boyle bir alan yok. Ajan "3.0 esigine ne kadar yakinim?" sorusunu cevaplayamiyor, sadece episode bittiginde ogrenebiliyor. Faz 2'de observation'a eklenmesi gereken alanlar:

```
detection_level / threshold   (0.0-1.0 normalize)
steps_remaining / max_steps   (0.0-1.0 normalize)
```

Bu sayede ajan "tespit riskim %80'de, artik sessiz aksiyonlar secmeliyim" diye bilincli karar verebilir.

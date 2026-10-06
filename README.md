# Siber Güvenlik - Kriptografi Laboratuvarı

**Öğrenci:** Onur Alkan  
**Öğrenci No:** 232923044

Bu depo, Siber Güvenlik dersi kapsamında gerçekleştirilen kriptografi laboratuvarı çalışmalarını içermektedir.

## Deneyler

### 1. AES-ECB ve AES-CTR Görüntü Karşılaştırması

Aynı görüntü AES-ECB ve AES-CTR kipleri ile şifrelenmiştir.

ECB sonucunda tekrar eden düz metin bloklarının aynı şifreli bloklara dönüşmesi nedeniyle görüntünün yapısal desenlerinin bir bölümünün korunabildiği gözlemlenmiştir.

CTR sonucunda ise görüntünün yapısal bilgisi kaybolmuş ve çıktı rastgele gürültü görünümüne yaklaşmıştır.

**Dosyalar**
- `01_ECB_CTR/ecb_ctr_karsilastirma.py`
- `01_ECB_CTR/orijinal.png`
- `01_ECB_CTR/01_ecb_sifreli.png`
- `01_ECB_CTR/02_ctr_sifreli.png`
- `01_ECB_CTR/03_yan_yana_karsilastirma.png`

### 2. AES-CTR Bütünlük Problemi ve AES-GCM

Başlangıç mesajı `Tutar: 100 TL` olarak şifrelenmiştir.

AES-CTR ile şifrelenmiş veri üzerinde anahtar bilinmeden kontrollü değişiklik yapıldığında çözülmüş mesaj `Tutar: 900 TL` olmuştur. Bu sonuç CTR kipinin tek başına bütünlük doğrulaması sağlamadığını göstermektedir.

Aynı tür değişiklik AES-GCM üzerinde gerçekleştirildiğinde doğrulama etiketi geçersiz olmuş ve veri `InvalidTag` hatasıyla reddedilmiştir.

**Dosyalar**
- `02_CTR_GCM/ctr_gcm_butunluk.py`
- `02_CTR_GCM/sonuc.txt`

### 3. SHA-256 ve Argon2id Süre Karşılaştırması

Ölçümler kullanılan bilgisayarda gerçekleştirilmiştir.

| Yöntem | Sonuç |
|---|---:|
| SHA-256 işlem başına ortalama | 0.000718 ms |
| Argon2id en kısa | 92.433 ms |
| Argon2id en uzun | 97.784 ms |
| Argon2id ortalama | 95.450 ms |

Argon2id parametreleri:
- `time_cost = 3`
- `memory_cost = 65536 KiB (64 MiB)`
- `parallelism = 2`

Bu ölçüm ortamında Argon2id, tek SHA-256 işlemine göre yaklaşık **132851 kat** daha uzun sürmüştür. Bu oran evrensel değildir; kullanılan donanıma ve Argon2id parametrelerine bağlıdır.

**Dosyalar**
- `03_SHA256_Argon2id/sha256_argon2id_sure.py`
- `03_SHA256_Argon2id/sonuc.txt`

## Kurulum

Gerekli Python paketleri:

`python -m pip install -r requirements.txt`

## Kullanılan Araçlar

- Python 3.14.4
- cryptography 50.0.2
- argon2-cffi 25.1.0
- Pillow 12.3.0

## Rapor

Laboratuvar raporu `Rapor` klasöründe bulunmaktadır.

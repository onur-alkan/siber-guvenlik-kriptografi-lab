from pathlib import Path
import hashlib
import os
import time
import statistics

from argon2.low_level import hash_secret_raw, Type

BASE = Path(r"D:\SiberGuvenlikLab\KriptografiLab\03_SHA256_Argon2id")
BASE.mkdir(parents=True, exist_ok=True)

REPORT = BASE / "sonuc.txt"

password = b"OnurAlkan-Guvenli-Parola-2026"

# Argon2id için aynı salt tüm zamanlama tekrarlarında kullanılıyor.
# Bu yalnızca kontrollü performans karşılaştırması içindir.
salt = os.urandom(16)

# --------------------------------------------------
# SHA-256
# --------------------------------------------------
# Tek SHA-256 işlemi çok kısa sürdüğü için ölçüm gürültüsünü
# azaltmak amacıyla çok kez çalıştırıp işlem başına ortalamayı buluyoruz.
SHA_RUNS = 100_000

sha_start = time.perf_counter()

for _ in range(SHA_RUNS):
    hashlib.sha256(password).digest()

sha_total = time.perf_counter() - sha_start
sha_avg = sha_total / SHA_RUNS


# --------------------------------------------------
# Argon2id
# --------------------------------------------------
ARGON_RUNS = 5
argon_times = []

for _ in range(ARGON_RUNS):
    start = time.perf_counter()

    hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=3,
        memory_cost=65536,   # 64 MiB
        parallelism=2,
        hash_len=32,
        type=Type.ID
    )

    argon_times.append(time.perf_counter() - start)

argon_avg = statistics.mean(argon_times)
argon_min = min(argon_times)
argon_max = max(argon_times)

ratio = argon_avg / sha_avg


lines = []

lines.append("=== DENEY 3: SHA-256 ve Argon2id sure karsilastirmasi ===")
lines.append("")
lines.append(f"Test verisi                    : {password.decode()}")
lines.append("")
lines.append("[A] SHA-256")
lines.append(f"Tekrar sayisi                  : {SHA_RUNS}")
lines.append(f"Toplam sure                    : {sha_total:.6f} saniye")
lines.append(f"Islem basina ortalama          : {sha_avg * 1000:.6f} ms")
lines.append("")
lines.append("[B] Argon2id")
lines.append(f"Tekrar sayisi                  : {ARGON_RUNS}")
lines.append("time_cost                      : 3")
lines.append("memory_cost                    : 65536 KiB (64 MiB)")
lines.append("parallelism                    : 2")
lines.append(f"En kisa sure                   : {argon_min * 1000:.3f} ms")
lines.append(f"En uzun sure                   : {argon_max * 1000:.3f} ms")
lines.append(f"Ortalama sure                  : {argon_avg * 1000:.3f} ms")
lines.append("")
lines.append(f"Argon2id / SHA-256 sure orani  : yaklasik {ratio:,.0f} kat")
lines.append("")
lines.append("Yorum:")
lines.append("SHA-256 genel amacli ve cok hizli bir ozet fonksiyonudur.")
lines.append("Argon2id ise parola saklama icin bilincli olarak zaman ve bellek")
lines.append("maliyeti olusturur. Bu yavaslik, cok sayida parola tahmini")
lines.append("yapilmasini daha pahali hale getirir.")

text = "\n".join(lines)

REPORT.write_text(text, encoding="utf-8")

print(text)
print("")
print(f"Rapor dosyasi: {REPORT}")

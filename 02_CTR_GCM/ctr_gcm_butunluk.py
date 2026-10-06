from pathlib import Path
import os
import binascii

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BASE = Path(r"D:\SiberGuvenlikLab\KriptografiLab\02_CTR_GCM")
BASE.mkdir(parents=True, exist_ok=True)

REPORT = BASE / "sonuc.txt"

ORIGINAL = b"Tutar: 100 TL"
TARGET   = b"Tutar: 900 TL"

if len(ORIGINAL) != len(TARGET):
    raise ValueError("Mesaj uzunluklari ayni olmali.")


def aes_ctr_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def aes_ctr_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# ORIGINAL -> TARGET dönüşümü için gereken XOR farkı.
delta = bytes(o ^ t for o, t in zip(ORIGINAL, TARGET))

lines = []

lines.append("=== DENEY 2: CTR butunluk problemi ve AES-GCM karsilastirmasi ===")
lines.append("")
lines.append(f"Orijinal mesaj              : {ORIGINAL.decode('utf-8')}")
lines.append(f"Hedef mesaj                 : {TARGET.decode('utf-8')}")
lines.append("")

# ---------------------------------------------------
# A) AES-CTR
# ---------------------------------------------------
lines.append("[A] AES-CTR")

ctr_key = os.urandom(16)
ctr_nonce = os.urandom(16)

ctr_ciphertext = aes_ctr_encrypt(ctr_key, ctr_nonce, ORIGINAL)

# Anahtar bilinmeden, bilinen düz metin farkı şifreli veriye uygulanıyor.
modified_ctr_ciphertext = bytes(
    c ^ d for c, d in zip(ctr_ciphertext, delta)
)

ctr_original_plaintext = aes_ctr_decrypt(
    ctr_key, ctr_nonce, ctr_ciphertext
)

ctr_modified_plaintext = aes_ctr_decrypt(
    ctr_key, ctr_nonce, modified_ctr_ciphertext
)

lines.append(f"CTR nonce (hex)             : {binascii.hexlify(ctr_nonce).decode()}")
lines.append(f"CTR sifreli veri (hex)      : {binascii.hexlify(ctr_ciphertext).decode()}")
lines.append(f"CTR degistirilmis veri (hex): {binascii.hexlify(modified_ctr_ciphertext).decode()}")
lines.append(f"CTR cozulmus orijinal       : {ctr_original_plaintext.decode('utf-8')}")
lines.append(f"CTR cozulmus degistirilmis  : {ctr_modified_plaintext.decode('utf-8')}")
lines.append("")
lines.append("Sonuc: CTR degisikligi fark etmeden cozdu.")
lines.append("CTR tek basina butunluk/dogrulama saglamaz.")
lines.append("")

# ---------------------------------------------------
# B) AES-GCM
# ---------------------------------------------------
lines.append("[B] AES-GCM")

gcm_key = AESGCM.generate_key(bit_length=128)
gcm = AESGCM(gcm_key)
gcm_nonce = os.urandom(12)

# cryptography AESGCM çıktısı:
# ciphertext || 16-byte authentication tag
gcm_encrypted = gcm.encrypt(gcm_nonce, ORIGINAL, None)

ciphertext_body = gcm_encrypted[:-16]
authentication_tag = gcm_encrypted[-16:]

# CTR deneyindeki AYNI ORIGINAL -> TARGET XOR farkını
# GCM'nin şifreli veri bölümüne uyguluyoruz.
modified_gcm_body = bytes(
    c ^ d for c, d in zip(ciphertext_body, delta)
)

# Etiket değiştirilmeden bırakılıyor.
modified_gcm = modified_gcm_body + authentication_tag

gcm_original_plaintext = gcm.decrypt(
    gcm_nonce, gcm_encrypted, None
)

lines.append(f"GCM nonce (hex)             : {binascii.hexlify(gcm_nonce).decode()}")
lines.append(f"GCM sifreli veri+tag (hex)  : {binascii.hexlify(gcm_encrypted).decode()}")
lines.append(f"GCM degistirilmis veri (hex): {binascii.hexlify(modified_gcm).decode()}")
lines.append(f"GCM cozulmus orijinal       : {gcm_original_plaintext.decode('utf-8')}")

try:
    result = gcm.decrypt(gcm_nonce, modified_gcm, None)
    lines.append(f"GCM cozulmus degistirilmis  : {result.decode('utf-8')}")
except Exception as e:
    lines.append(f"GCM ayni 100->900 degisikligi: REDDEDILDI ({type(e).__name__})")

lines.append("")
lines.append("Sonuc: CTR'de basarili olan ayni 100 -> 900 degisikligi")
lines.append("AES-GCM'de dogrulama etiketi nedeniyle reddedildi.")
lines.append("AES-GCM gizlilikla birlikte butunluk ve kimlik dogrulamasi da saglar.")

text = "\n".join(lines)

REPORT.write_text(text, encoding="utf-8")

print(text)
print("")
print(f"Rapor dosyasi: {REPORT}")

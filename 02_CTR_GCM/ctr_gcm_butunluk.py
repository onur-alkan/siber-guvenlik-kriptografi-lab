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


lines = []

lines.append("=== DENEY 2: CTR butunluk problemi ve AES-GCM karsilastirmasi ===")
lines.append("")

# ---------------------------------------------------
# A) AES-CTR: anahtarsiz mesaj degistirme
# ---------------------------------------------------
lines.append("[A] AES-CTR")

ctr_key = os.urandom(16)
ctr_nonce = os.urandom(16)

ctr_ciphertext = aes_ctr_encrypt(ctr_key, ctr_nonce, ORIGINAL)

# Saldirganin bildigi/eslestirdigi eski ve yeni duz metin farki ile
# sifreli veriyi degistirmesi
modified_ctr_ciphertext = bytes(
    c ^ o ^ t
    for c, o, t in zip(ctr_ciphertext, ORIGINAL, TARGET)
)

decrypted_original_ctr = aes_ctr_decrypt(ctr_key, ctr_nonce, ctr_ciphertext)
decrypted_modified_ctr = aes_ctr_decrypt(ctr_key, ctr_nonce, modified_ctr_ciphertext)

lines.append(f"Orijinal mesaj              : {ORIGINAL.decode('utf-8')}")
lines.append(f"Hedef/degistirilmis mesaj   : {TARGET.decode('utf-8')}")
lines.append(f"CTR nonce (hex)             : {binascii.hexlify(ctr_nonce).decode()}")
lines.append(f"CTR sifreli veri (hex)      : {binascii.hexlify(ctr_ciphertext).decode()}")
lines.append(f"CTR degistirilmis veri (hex): {binascii.hexlify(modified_ctr_ciphertext).decode()}")
lines.append(f"CTR cozulmus orijinal       : {decrypted_original_ctr.decode('utf-8')}")
lines.append(f"CTR cozulmus degistirilmis  : {decrypted_modified_ctr.decode('utf-8')}")
lines.append("")
lines.append("Yorum: CTR gizlilik saglar; ancak ek dogrulama yoksa sifreli veri")
lines.append("uzerinde yapilan degisiklik duz metne yansiyabilir.")
lines.append("")

# ---------------------------------------------------
# B) AES-GCM: degisikligin yakalanmasi
# ---------------------------------------------------
lines.append("[B] AES-GCM")

gcm_key = AESGCM.generate_key(bit_length=128)
gcm = AESGCM(gcm_key)
gcm_nonce = os.urandom(12)

gcm_ciphertext = gcm.encrypt(gcm_nonce, ORIGINAL, None)

tampered_gcm = bytearray(gcm_ciphertext)
tampered_gcm[3] ^= 0x01
tampered_gcm = bytes(tampered_gcm)

lines.append(f"GCM nonce (hex)             : {binascii.hexlify(gcm_nonce).decode()}")
lines.append(f"GCM sifreli veri+tag (hex)  : {binascii.hexlify(gcm_ciphertext).decode()}")

gcm_ok = gcm.decrypt(gcm_nonce, gcm_ciphertext, None)
lines.append(f"GCM cozulmus orijinal       : {gcm_ok.decode('utf-8')}")

try:
    gcm.decrypt(gcm_nonce, tampered_gcm, None)
    lines.append("GCM degistirilmis veri      : Beklenmeyen durum - cozuldu")
except Exception as e:
    lines.append(f"GCM degistirilmis veri      : REDDEDILDI ({type(e).__name__})")

lines.append("")
lines.append("Yorum: AES-GCM hem sifreleme hem butunluk/dogrulama saglar.")
lines.append("Bu nedenle sifreli veri uzerindeki oynama decryption asamasinda yakalanir.")

text = "\n".join(lines)
REPORT.write_text(text, encoding="utf-8")

print(text)
print("")
print(f"Rapor dosyasi: {REPORT}")

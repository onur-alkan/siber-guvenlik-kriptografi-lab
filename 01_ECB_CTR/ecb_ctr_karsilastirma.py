from pathlib import Path
import os

from PIL import Image, ImageDraw
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BASE = Path(r"D:\SiberGuvenlikLab\KriptografiLab\01_ECB_CTR")

INPUT = BASE / "orijinal.png"
ECB_OUT = BASE / "01_ecb_sifreli.png"
CTR_OUT = BASE / "02_ctr_sifreli.png"
COMPARE_OUT = BASE / "03_yan_yana_karsilastirma.png"


def encrypt(data, key, mode):
    cipher = Cipher(algorithms.AES(key), mode)
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


# Görüntüyü gri tonlamaya çeviriyoruz.
# Böylece her piksel = 1 byte olur ve AES'in 16 byte'lık
# blok yapısı görsel karşılaştırmada daha net izlenebilir.
original = Image.open(INPUT).convert("L")

width, height = original.size
plain_bytes = original.tobytes()

# ECB için veri uzunluğunun 16'nın katı olması gerekir.
# 1024x1024 = 1.048.576 byte ve zaten 16'nın katıdır.
if len(plain_bytes) % 16 != 0:
    raise ValueError("Goruntu verisi AES blok boyutunun kati degil.")

# Aynı AES-128 anahtarı iki deneyde de kullanılıyor.
key = os.urandom(16)

# ---------------------------------------------------
# AES-ECB
# ---------------------------------------------------
ecb_bytes = encrypt(
    plain_bytes,
    key,
    modes.ECB()
)

ecb_image = Image.frombytes(
    "L",
    (width, height),
    ecb_bytes
)

ecb_image.save(ECB_OUT)


# ---------------------------------------------------
# AES-CTR
# ---------------------------------------------------
# CTR için 16 byte başlangıç sayacı/nonce kullanılır.
counter = os.urandom(16)

ctr_bytes = encrypt(
    plain_bytes,
    key,
    modes.CTR(counter)
)

ctr_image = Image.frombytes(
    "L",
    (width, height),
    ctr_bytes
)

ctr_image.save(CTR_OUT)


# ---------------------------------------------------
# YAN YANA KARŞILAŞTIRMA
# ---------------------------------------------------
panel_width = 500
title_height = 60


def prepare(image):
    ratio = panel_width / image.width
    new_height = int(image.height * ratio)
    return image.resize((panel_width, new_height)).convert("RGB")


img_original = prepare(original)
img_ecb = prepare(ecb_image)
img_ctr = prepare(ctr_image)

panel_height = max(
    img_original.height,
    img_ecb.height,
    img_ctr.height
)

canvas = Image.new(
    "RGB",
    (panel_width * 3, panel_height + title_height),
    "white"
)

canvas.paste(img_original, (0, title_height))
canvas.paste(img_ecb, (panel_width, title_height))
canvas.paste(img_ctr, (panel_width * 2, title_height))

draw = ImageDraw.Draw(canvas)

draw.text((20, 20), "ORIJINAL", fill="black")
draw.text((panel_width + 20, 20), "AES-ECB", fill="black")
draw.text((panel_width * 2 + 20, 20), "AES-CTR", fill="black")

canvas.save(COMPARE_OUT)

print("=== DENEY 1 TAMAMLANDI ===")
print(f"Goruntu boyutu : {width}x{height}")
print(f"Veri uzunlugu  : {len(plain_bytes)} byte")
print(f"AES anahtar    : {len(key) * 8} bit")
print()
print(f"ECB sonucu     : {ECB_OUT}")
print(f"CTR sonucu     : {CTR_OUT}")
print(f"Karsilastirma  : {COMPARE_OUT}")

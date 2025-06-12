import struct
import os
from PIL import Image
import numpy as np

# Sabitler
P32 = 0xb7e15163  # Sabit P32
Q32 = 0x9e3779b9  # Sabit Q32


# Anahtar genişletme fonksiyonu
def key_expansion(key, rounds=20):
    key_words = [struct.unpack('<I', key[i:i + 4])[0] for i in
                 range(0, len(key), 4)]  # Anahtarın 32 bitlik kelimelere ayrılması
    num_key_words = len(key_words)

    S = [P32] + [0] * (2 * (rounds + 1) - 1)  # RC6 anahtar dizisi (S)

    # Anahtarın genişletilmesi
    i, j = 0, 0
    for k in range(3 * (rounds + 1)):
        S[k] = (S[k - 1] + S[k - 2] + S[k - 3] + key_words[i] + key_words[j]) & 0xffffffff
        i = (i + 1) % num_key_words
        j = (j + 1) % num_key_words

    return S


# RC6 şifreleme fonksiyonu
def rc6_encrypt(plaintext, key, rounds=20):
    # Anahtar genişletme
    S = key_expansion(key, rounds)

    # Veriyi 128-bitlik bloklara ayırma
    L = [struct.unpack('<I', plaintext[i:i + 4])[0] for i in
         range(0, len(plaintext), 4)]  # Plaintext'i 32-bit kelimelere ayırma

    # Şifreleme
    A, B, C, D = L[0], L[1], L[2], L[3]
    print(f"Başlangıç Değerleri: A={A}, B={B}, C={C}, D={D}")
    for i in range(rounds):
        t = (B * (2 * B + 1)) & 0xffffffff
        u = (D * (2 * D + 1)) & 0xffffffff
        print(f"Turu {i + 1}: t={t}, u={u}")
        A = ((A ^ t) + S[2 * i]) & 0xffffffff
        C = ((C ^ u) + S[2 * i + 1]) & 0xffffffff
        print(f"Tur {i + 1} sonrası A={A}, B={B}, C={C}, D={D}")
        A, B, C, D = B, C, D, A  # Değişkenlerin döndürülmesi

    # Sonuçları geri döndürme
    return struct.pack('<IIII', A, B, C, D)


# Metin şifreleme
def encrypt_text():
    plaintext = input("Şifrelenecek metni girin: ").encode('utf-8')  # Metin girişini al
    key = input("Anahtarınızı girin: ").encode('utf-8')  # Anahtar girişini al
    print("Şifreleme başlıyor...")
    ciphertext = rc6_encrypt(plaintext, key)
    print(f"Şifrelenmiş metin (hex): {ciphertext.hex()}")


# Dosya şifreleme
def encrypt_file():
    file_path = input("Şifrelenecek dosyanın yolunu girin: ")
    if not os.path.isfile(file_path):
        print("Dosya bulunamadı!")
        return

    with open(file_path, "rb") as file:
        plaintext = file.read()
    key = input("Anahtarınızı girin: ").encode('utf-8')  # Anahtar girişini al
    print("Şifreleme başlıyor...")
    ciphertext = rc6_encrypt(plaintext, key)
    with open("encrypted_file.bin", "wb") as file:
        file.write(ciphertext)
    print("Dosya başarıyla şifrelendi ve 'encrypted_file.bin' olarak kaydedildi.")


# Görüntü şifreleme
def encrypt_image():
    image_path = input("Şifrelenecek görüntü dosyasının yolunu girin: ")
    if not os.path.isfile(image_path):
        print("Görüntü dosyası bulunamadı!")
        return

    img = Image.open(image_path)
    img_data = np.array(img).flatten()  # Görüntü verilerini al ve tek boyutlu diziye çevir
    key = input("Anahtarınızı girin: ").encode('utf-8')  # Anahtar girişini al
    print("Şifreleme başlıyor...")
    ciphertext = rc6_encrypt(img_data.tobytes(), key)
    with open("encrypted_image.bin", "wb") as file:
        file.write(ciphertext)
    print("Görüntü başarıyla şifrelendi ve 'encrypted_image.bin' olarak kaydedildi.")


# Ana Menü
def main():
    while True:
        print("\nRC6 Şifreleme Algoritması")
        print("1. Metin Şifrele")
        print("2. Dosya Şifrele")
        print("3. Görüntü Şifrele")
        print("4. Çıkış")
        choice = input("Bir seçenek girin (1/2/3/4): ")

        if choice == '1':
            encrypt_text()
        elif choice == '2':
            encrypt_file()
        elif choice == '3':
            encrypt_image()
        elif choice == '4':
            print("Çıkılıyor...")
            break
        else:
            print("Geçersiz seçenek, tekrar deneyin.")


if __name__ == "__main__":
    main()

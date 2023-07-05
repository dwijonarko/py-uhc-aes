import os
import numpy as np
import time
from functools import reduce 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from base64 import b64decode, b64encode
#metode 2: AES
# fungsi untuk padding data
def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)
# fungsi untuk enkripsi data
def encrypt(message, key, iv):
    message = pad(message)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)
# fungsi untuk dekripsi data
def decrypt(ciphertext, key):
    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[16:])
    return plaintext.rstrip(b"\0")
    
#metode 1: UHC
def factors(n):    
    return set(reduce(list.__add__, 
                ([i, n//i] for i in range(1, int(n**0.5) + 1) if n % i == 0)))

#OBE
def r_ij(m, baris_i, baris_j, r):
    return m[baris_i] + r*m[baris_j]
#barisan logistic map
def log(x0, banyak):
    x = x0
    for i in range(1000):
        x = 3.9 * x - np.floor(3.9 * x)     # 3.9 bisa diganti bil. pada [3.7, 4]
    
    barisan = np.zeros(banyak, dtype=np.uint16)
    for i in range(banyak):
        x = 3.9 * x - np.floor(3.9 * x)     # 3.9 bisa diganti bil. pada [3.7, 4]
        barisan[i] = x*1000%55000
    return barisan
#matriks kunci
def kunci(n, x0):
    #matriks segitiga atas
    banyak = int(n * (n - 1)/2)
    barisan = log(x0, banyak + n - 1)
    msa = np.eye(n)
    indeks = 0
    for i in range(n):
        for j in range(i+1,n):
            msa[i,j] = barisan[indeks]
            indeks += 1
    for baris_i in range(1,n):
        msa[baris_i] = r_ij(msa, baris_i, 0, barisan[indeks])%55000
        indeks += 1
    augmented = np.zeros((n,2*n))
    augmented[:,:n]=msa
    augmented[:,n:]=np.eye(n)
    #OBE untuk dapatkan invers
    #mengenolkan segitiga bawah
    for kolom in range(n):
        for baris in range(kolom+1,n):
            augmented[baris] = r_ij(augmented, baris, kolom, -augmented[baris, kolom])%55000
    #mengenolkan segitiga atas
    for kolom in range(1,n):
        for baris in range(kolom):
            augmented[baris] = r_ij(augmented, baris, kolom, -augmented[baris, kolom])%55000
    mbalik = augmented[:,n:]
    return msa, mbalik
# enkripsi UHC
def enkripsi(nama_plainteks):
    teks_asli = open(nama_plainteks, 'r', encoding = 'utf-8')
    teks = teks_asli.read()
    n_teks = len(teks)
    if (n_teks % 2 == 1):
        teks = teks + "."
    n_teks = len(teks)
    print(n_teks)
    print("Teks asli:", teks)
    # convert teks ke bilangan bulat
    mteks = [ ord(i) for i in teks ]
    np_teks = np.array(mteks)
    print(np_teks)
    f = factors(n_teks)
    faktor = list(f)
    print(faktor[1:])
    str_password1 = input("Please choose one of the numbers in the set above as Password 1: ")
    password1 = int(str_password1)
    while password1 not in faktor:
        print("Your choice are {}".format(password1))
        print("Not in the given list.")
        print("-"*50, "\nThe list of numbers are: ")
        print(faktor)
        password1 = input("Please choose again the right one: ")
    # pw2 = input("Enter Password 2 in the form of a number, maximum 14 digits (example: 22021985)\nPassword 2: ")
    pw2 = "23062023"
    password2 = float("0." + pw2 + "1")
    waktu_awal = time.time()
    # membuat matriks persegi sebagai kunci berukuran password1 x password1
    ukuran = password1
    x0 = password2
    kunciku, balikku = kunci(ukuran, x0)
    print(f'Using password1: {password1} and password2: {password2}, the unimodular matrix generated is:')
    print(kunciku)
    print('='*20)
    print(f'maks = {np_teks.max()}')
    print(np_teks)
    np_teks_reshape = np_teks.reshape((ukuran, int(np_teks.size/ukuran)))
    print(f'len: {np_teks.shape}')
    print(f'len: {kunciku.shape}')
    print(f'len: {np_teks_reshape.shape}')
    np_kali = (kunciku @ np_teks_reshape)%55000
    np_chiper = np_kali.reshape(n_teks).astype(np.uint64)
    print(np_chiper)
    petaku = np.transpose(np.array([np_teks, np_chiper]))
    pwdchiper = open('password_enkripsi.txt','w', encoding = 'utf-8')
    pwdchiper.write("Message:\n")
    pwdchiper.write(teks + "\n")
    pwdchiper.write("-"*30 + "\n\n")
    pwdchiper.write("password1: ")
    pwdchiper.write(str(password1) + "\n")
    pwdchiper.write("password2: ")
    pwdchiper.write(str(pw2) + "\n\n")
    pwdchiper.write(f'waktu enkripsi: {time.time() - waktu_awal} detik\n\n')
    pwdchiper.write('np_teks, np_chiper:\n')
    np.savetxt(pwdchiper, petaku, fmt='%d', delimiter='\t')
    pwdchiper.close()
    chiper = open('enkripsi.txt','w', encoding = 'utf-8')
    chiper.write(''.join([chr(i) for i in np_chiper]))
    chiper.close()
    print('Congratulation. Encryption process finish.\n')
    print(f'waktu enkripsi: {time.time() - waktu_awal} detik')
    print('Your encrypted message saved in file: enkripsi.txt')
    print('Password saved in file: password_enkripsi.txt')
##        # membaca isi file teks.txt
##        with open("enkripsi.txt", "rb") as f:
##            plaintext = f.read()
##        # enkripsi isi file teks.txt
##        ciphertext = encrypt(plaintext, key, iv)
##        # tulis file hasil enkripsi
##        with open("teks_encrypted.txt", "wb") as f:
##            f.write(ciphertext)
##        # baca file hasil enkripsi
##        with open("teks_encrypted.txt", "rb") as f:
##            ciphertext = f.read()
    
#dekripsi UHC
def dekripsi(nama_chiperteks):
    nama_file = nama_chiperteks
    teks_asli = open(nama_file, 'r', encoding = 'utf-8')
    teks = teks_asli.read()
    teks_asli.close()
    n_teks = len(teks)
    if (n_teks % 2 == 1):
        teks = teks + "."
    n_teks = len(teks)
    # convert teks ke bilangan bulat
    mteks = [ ord(i) for i in teks ]
    np_teks = np.array(mteks)
    f = factors(n_teks)
    faktor = list(f)
    str_password1 = input("Please input password 1: ")
    password1 = int(str_password1)
    # pw2 = input("Please input password 2: ")
    pw2 = "23062023"
    password2 = float("0." + pw2 + "1")
    waktu_awal = time.time()
    # membuat matriks persegi sebagai kunci berukuran password1 x password1
    ukuran = password1
    x0 = password2
    print(ukuran)
    print(x0)
    kunciku, balikku = kunci(ukuran, x0)
    print('='*20)
    print(np.dot(kunciku, balikku)%55000)
    print("-"*30)
    #print(np_teks)
    np_teks_reshape = np_teks.reshape((ukuran, int(np_teks.size/ukuran)))
    #print(np_teks_reshape)
    print(f'len: {np_teks.shape}')
    print(f'len: {kunciku.shape}')
    print(f'len: {np_teks_reshape.shape}')
    np_kali = (balikku @ np_teks_reshape)%55000
    #print(np_kali)
    np_dechiper = np_kali.reshape(n_teks).astype(np.uint64)
    print(np_dechiper)
    chiper = open('dekripsi.txt','w', encoding = 'utf-8')
    chiper.write(''.join([chr(i) for i in np_dechiper]))
    chiper.close()
    selama = time.time() - waktu_awal
    print(f'waktu dekripsi: {selama} detik')
    print('Decrypted message saved on file: dekripsi.txt')
        # dekripsi isi file hasil enkripsi
        # plaintext = decrypt(ciphertext, key)
        # # tulis file hasil dekripsi
        # with open("teks_decrypted.txt", "wb") as f:
        #     f.write(plaintext)

################################################################################
#penggunaan
print("="*70)
print("Text Encryption Algorithm Trough Unimodular Matrix and Logistic Map")
print("-"*70)
jawaban = input("Please select, you want to encrypt (e) or decrypt (d):")
if jawaban == "e" or jawaban == "E":
    print("-------------------------")
    print("You will encrypt a plaintext")
    print("-------------------------")
    plainteks = input('Masukkan nama file plainteks beserta ekstensinya: ')
    #proses enkripsi UHC dimulai
    enkripsi('sources/original.txt') # outputnya ini nama filenya apa?
    #proses enkripsi AES dimulai
    # baca file asli
    with open("enkripsi.txt", "rb") as f:
        plaintext = f.read()
    # enkripsi isi file teks.txt
    # key dan iv yang akan digunakan
    key = os.urandom(16) # menggunakan key 16 byte
    iv = os.urandom(16) # menggunakan iv 16 byte

    print("Key:", key)
    print("iv:", iv)
    kunci_aes = open('sources/Kunci-AES.txt','bw')
    kunci_aes.write(key)
    kunci_aes.close()

    ciphertext = encrypt(plaintext, key, iv)
    # tulis file hasil enkripsi    
    with open("uhcAES_encrypted.txt", "wb") as f:
        f.write(b64encode(ciphertext))    
else:
    print("*"*80)
    print("You will decrypt a chipertext")
    print("-"*50)
    chiperteks = input('Masukkan nama file chiperteks beserta ekstensinya: ')
    #proses dekripsi AES
    # baca file hasil enkripsi
    with open("results/uhcAES_encrypted.txt", "rb") as f:
        ciphertext = f.read()
    # dekripsi isi file hasil enkripsi
    
    with open("results/Kunci-AES.txt", "rb") as f:
        key = f.read()
    plaintext = decrypt(b64decode(ciphertext), key)
    with open("results/uhcAES_decrypted.txt", "wb") as f:
        f.write(plaintext)
        
    #proses dekripsi UHC dimulai
    dekripsi("results/uhcAES_decrypted.txt")
     
    # tulis file hasil dekripsi
    #with open("Final_decrypted.txt", "wb") as f:
     #   f.write(plaintext)
